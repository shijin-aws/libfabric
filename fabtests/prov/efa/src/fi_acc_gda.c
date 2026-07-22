/*
 * Copyright (c) 2026, Amazon.com, Inc.  All rights reserved.
 *
 * This software is available to you under the BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * fi_acc_gda -- GPU Direct Async fabtest using OFI Accelerator API
 *
 * This test mirrors fabtests/prov/efa/src/efa_gda.c but replaces:
 *   - fi_open_ops(FI_EFA_GDA_OPS) → fi_acc_*_export() portable API
 *   - Manual cuMemHostRegister → provider handles via acc_info.import()
 *   - efa_cuda_create_qp/cq → fi_acc_dev_qp/cq built from exported attrs
 *   - efa-dp-direct device calls → fi_acc_dev_* device functions
 */

#include "hmem.h"
#include <cuda.h>
#include <cuda_runtime.h>
#include <getopt.h>
#include <rdma/fi_acc.h>
#include <rdma/fi_acc_device.h>
#include <shared.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "fi_acc/fi_acc_kernels.h"

/*
 * GPU-resident descriptors (device pointers).
 * Built from fi_acc_*_export() results, H2D-copied once.
 */
static struct fi_acc_dev_qp  *d_qp;
static struct fi_acc_dev_cq  *d_send_cq;
static struct fi_acc_dev_cq  *d_recv_cq;
static volatile uint64_t     *hw_send_cntr_ptr;
static volatile uint64_t     *hw_recv_cntr_ptr;
static bool                   use_hw_cntr;
static int                    gda_op; /* 0=send, 1=write, 2=writeimm, 3=read */

/*
 * =============================================================================
 * Accelerator memory callbacks for fi_acc_info
 * =============================================================================
 */

static int acc_alloc(uint64_t device, uint64_t size, uint64_t alignment,
		     uint64_t flags, void **addr, int *fd, uint64_t *offset)
{
	int ret;
	void *buf;

	ret = ft_hmem_alloc(FI_HMEM_CUDA, device, &buf, (size_t)size);
	if (ret)
		return ret;

	ret = ft_hmem_get_dmabuf_fd(FI_HMEM_CUDA, buf, (size_t)size,
				    fd, offset);
	if (ret) {
		ft_hmem_free(FI_HMEM_CUDA, buf);
		return ret;
	}

	*addr = buf;
	return 0;
}

static int acc_import(uint64_t device, int fd, uint64_t offset,
		      uint64_t size, uint64_t flags, void **addr)
{
	unsigned int cuda_flags = CU_MEMHOSTREGISTER_DEVICEMAP;
	CUdeviceptr dev_ptr = 0;
	int status;

	if (flags & FI_ACC_IMPORT_IOMEMORY)
		cuda_flags |= CU_MEMHOSTREGISTER_IOMEMORY;

	status = cuMemHostRegister(*addr, (size_t)size, cuda_flags);
	if (status != CUDA_SUCCESS) {
		FT_WARN("cuMemHostRegister failed: %d (flags=0x%lx)\n",
			status, flags);
		return -FI_EIO;
	}

	status = cuMemHostGetDevicePointer(&dev_ptr, *addr, 0);
	if (status != CUDA_SUCCESS) {
		FT_WARN("cuMemHostGetDevicePointer failed: %d\n", status);
		return -FI_EIO;
	}

	*addr = (void *)dev_ptr;
	return 0;
}

static void acc_free(uint64_t device, void *addr)
{
	ft_hmem_free(FI_HMEM_CUDA, addr);
}

/*
 * =============================================================================
 * Build GPU-resident QP/CQ descriptors from fi_acc_*_export() results
 * =============================================================================
 */

static int build_gpu_qp(struct fi_acc_ep_attr *ep_attr)
{
	struct fi_acc_dev_qp h_qp = {};

	h_qp.sq.buf             = (uint8_t *)ep_attr->sq.buffer;
	h_qp.sq.db              = (uint32_t *)ep_attr->sq.doorbell;
	h_qp.sq.queue_mask      = ep_attr->sq.num_entries - 1;
	h_qp.sq.queue_size_shift = __builtin_ctz(ep_attr->sq.num_entries);
	h_qp.sq.max_batch       = ep_attr->sq.max_batch;
	h_qp.sq.entry_size      = ep_attr->sq.entry_size;
	h_qp.sq.pc              = 0;
	h_qp.sq.phase           = 0;
	h_qp.sq.wqes_pending    = 0;

	h_qp.rq.buf             = (uint8_t *)ep_attr->rq.buffer;
	h_qp.rq.db              = (uint32_t *)ep_attr->rq.doorbell;
	h_qp.rq.queue_mask      = ep_attr->rq.num_entries - 1;
	h_qp.rq.queue_size_shift = __builtin_ctz(ep_attr->rq.num_entries);
	h_qp.rq.max_batch       = ep_attr->rq.max_batch;
	h_qp.rq.entry_size      = ep_attr->rq.entry_size;
	h_qp.rq.pc              = 0;
	h_qp.rq.phase           = 0;
	h_qp.rq.wqes_pending    = 0;

	h_qp.max_inline_data    = ep_attr->max_inline_data;
	h_qp.max_rdma_sges      = ep_attr->max_rdma_sges;

	cudaMalloc((void **)(&d_qp), sizeof(struct fi_acc_dev_qp));
	cudaMemcpy(d_qp, &h_qp, sizeof(h_qp), cudaMemcpyHostToDevice);
	return 0;
}

static int build_gpu_cq(struct fi_acc_cq_attr *cq_attr,
			struct fi_acc_dev_cq **d_cq_out)
{
	struct fi_acc_dev_cq h_cq = {};

	h_cq.buf              = (uint8_t *)cq_attr->buffer;
	h_cq.entry_size       = cq_attr->entry_size;
	h_cq.queue_mask       = cq_attr->num_entries - 1;
	h_cq.queue_size_shift = __builtin_ctz(cq_attr->num_entries);
	h_cq.cc               = 0;
	h_cq.phase            = 1; /* Initial expected phase = 1 */

	cudaMalloc((void **)(d_cq_out), sizeof(struct fi_acc_dev_cq));
	cudaMemcpy(*d_cq_out, &h_cq, sizeof(h_cq), cudaMemcpyHostToDevice);
	return 0;
}

/*
 * =============================================================================
 * Main test
 * =============================================================================
 */

int main(int argc, char **argv)
{
	int op, ret;
	struct fi_acc_info acc_info = {};
	struct fi_acc_ep_attr ep_attr = {};
	struct fi_acc_cq_attr send_cq_attr = {};
	struct fi_acc_cq_attr recv_cq_attr = {};
	struct fi_acc_cntr_attr send_cntr_attr = {};
	struct fi_acc_cntr_attr recv_cntr_attr = {};
	struct fi_acc_mr_attr mr_attr = {};
	struct fi_acc_peer_addr peer_addr = {};

	opts = INIT_OPTS;
	opts.options |= FT_OPT_OOB_SYNC;
	timeout = 5;

	hints = fi_allocinfo();
	if (!hints)
		return EXIT_FAILURE;

	while ((op = getopt(argc, argv, "vho:" ADDR_OPTS INFO_OPTS CS_OPTS)) != -1) {
		switch (op) {
		case 'o':
			if (!strcmp(optarg, "write"))      gda_op = 1;
			else if (!strcmp(optarg, "writedata")) gda_op = 2;
			else if (!strcmp(optarg, "read"))  gda_op = 3;
			else gda_op = 0; /* send */
			break;
		case 'v':
			opts.options |= FT_OPT_VERIFY_DATA;
			break;
		default:
			ft_parse_addr_opts(op, optarg, &opts);
			ft_parseinfo(op, optarg, hints, &opts);
			ft_parsecsopts(op, optarg, &opts);
			break;
		case '?':
		case 'h':
			ft_usage(argv[0],
				 "OFI Accelerator API GPU Direct Async test");
			FT_PRINT_OPTS_USAGE("-o <op>",
				"op: msg, write, writedata, read");
			return EXIT_FAILURE;
		}
	}

	if (optind < argc)
		opts.dst_addr = argv[optind];

	if (gda_op != 0)
		opts.options |= FT_OPT_BW;

	/* Request FI_ACC capability */
	hints->ep_attr->type = FI_EP_RDM;
	hints->caps |= FI_MSG | FI_RMA | FI_HMEM | FI_ACC;
	hints->domain_attr->mr_mode = FI_MR_ALLOCATED | FI_MR_LOCAL |
				      FI_MR_VIRT_ADDR | FI_MR_PROV_KEY |
				      FI_MR_HMEM;

	ret = ft_init_fabric();
	if (ret)
		return ret;

	/* Setup acc_info with CUDA callbacks */
	acc_info.iface    = FI_HMEM_CUDA;
	acc_info.device   = opts.device;
	acc_info.mem_type = FI_ACC_MEM_USER_ALLOC;
	acc_info.user.alloc  = acc_alloc;
	acc_info.user.import = acc_import;
	acc_info.user.free   = acc_free;

	/*
	 * === OFI Accelerator API: Export resources ===
	 *
	 * This replaces the entire manual sequence of:
	 *   fi_open_ops(FI_EFA_GDA_OPS)
	 *   gda_ops->query_qp_wqs() + cuMemHostRegister()
	 *   gda_ops->query_cq()
	 *   gda_ops->query_addr()
	 *   gda_ops->get_mr_lkey()
	 */

	/* Export EP (SQ/RQ with device-mapped pointers) */
	ret = fi_acc_ep_export(ep, 0, &ep_attr);
	if (ret) {
		FT_PRINTERR("fi_acc_ep_export", -ret);
		return ret;
	}

	/* Export CQs */
	ret = fi_acc_cq_export(txcq, 0, &send_cq_attr);
	if (ret) {
		FT_PRINTERR("fi_acc_cq_export (send)", -ret);
		return ret;
	}
	ret = fi_acc_cq_export(rxcq, 0, &recv_cq_attr);
	if (ret) {
		FT_PRINTERR("fi_acc_cq_export (recv)", -ret);
		return ret;
	}

	/* Export MR lkey */
	ret = fi_acc_mr_export(mr, 0, &mr_attr);
	if (ret) {
		FT_PRINTERR("fi_acc_mr_export", -ret);
		return ret;
	}

	/* Export peer address */
	ret = fi_acc_av_lookup(av, remote_fi_addr, 0, &peer_addr);
	if (ret) {
		FT_PRINTERR("fi_acc_av_lookup", -ret);
		return ret;
	}

	/* Build GPU-resident descriptors */
	build_gpu_qp(&ep_attr);
	build_gpu_cq(&send_cq_attr, &d_send_cq);
	build_gpu_cq(&recv_cq_attr, &d_recv_cq);

	/* Optionally export HW counters */
	if (use_hw_cntr) {
		ret = fi_acc_cntr_export(txcntr, 0, &send_cntr_attr);
		if (ret) {
			FT_PRINTERR("fi_acc_cntr_export (send)", -ret);
			return ret;
		}
		hw_send_cntr_ptr = send_cntr_attr.value;

		ret = fi_acc_cntr_export(rxcntr, 0, &recv_cntr_attr);
		if (ret) {
			FT_PRINTERR("fi_acc_cntr_export (recv)", -ret);
			return ret;
		}
		hw_recv_cntr_ptr = recv_cntr_attr.value;
	}

	/* Run the test */
	cudaStream_t stream;
	cudaStreamCreate(&stream);

	printf("OFI Accelerator API GDA Test\n");
	printf("  EP:  SQ depth=%u entry=%u max_batch=%u\n",
	       ep_attr.sq.num_entries, ep_attr.sq.entry_size,
	       ep_attr.sq.max_batch);
	printf("  CQ:  depth=%u entry=%u\n",
	       send_cq_attr.num_entries, send_cq_attr.entry_size);
	printf("  MR:  lkey=0x%x\n", mr_attr.lkey);
	printf("  Peer: ahn=%u qpn=%u qkey=0x%x\n",
	       peer_addr.address_handle, peer_addr.remote_qpn,
	       peer_addr.remote_qkey);

	ft_sync();
	ft_start();

	if (gda_op == 0) {
		/* Send latency */
		int is_client = opts.dst_addr ? 1 : 0;
		int rx_depth = fi->rx_attr->size / 2;
		if (rx_depth > opts.iterations) rx_depth = opts.iterations;

		ret = fi_acc_run_lat_send(
			d_qp, d_send_cq, d_recv_cq,
			hw_send_cntr_ptr, hw_recv_cntr_ptr,
			peer_addr.address_handle, peer_addr.remote_qpn,
			peer_addr.remote_qkey,
			(uint64_t)rx_buf, opts.transfer_size, mr_attr.lkey,
			(uint64_t)tx_buf, opts.transfer_size, mr_attr.lkey,
			opts.iterations, rx_depth, is_client, stream);
	} else {
		/* BW: write/read/send */
		int is_client = opts.dst_addr ? 1 : 0;
		int tx_depth = fi->tx_attr->size / 2;

		if (is_client) {
			struct fi_rma_iov remote_iov = {};
			/* Exchange RMA keys via OOB */
			struct fi_rma_iov my_iov = {
				.addr = (gda_op == 3) ? (uintptr_t)tx_buf : (uintptr_t)rx_buf,
				.key = fi_mr_key(mr),
			};
			ft_sock_send(oob_sock, &my_iov, sizeof(my_iov));
			ft_sock_recv(oob_sock, &remote_iov, sizeof(remote_iov));

			ret = fi_acc_run_bw(
				d_qp, d_send_cq, hw_send_cntr_ptr,
				gda_op,
				(uint64_t)tx_buf, opts.transfer_size,
				mr_attr.lkey,
				peer_addr.address_handle,
				peer_addr.remote_qpn,
				peer_addr.remote_qkey,
				remote_iov.addr, (uint32_t)remote_iov.key,
				opts.iterations, tx_depth, stream);
		} else {
			int rx_depth = fi->rx_attr->size / 2;
			if (rx_depth > opts.iterations) rx_depth = opts.iterations;

			ret = fi_acc_run_bw_recv(
				d_qp, d_recv_cq, hw_recv_cntr_ptr,
				(uint64_t)rx_buf, opts.transfer_size,
				mr_attr.lkey,
				opts.iterations, rx_depth, stream);
		}
	}

	ft_stop();
	if (ret)
		FT_PRINTERR("kernel execution", -ret);
	else
		show_perf(NULL, opts.transfer_size, opts.iterations,
			  &start, &end, (gda_op == 0) ? 2 : 1);

	cudaStreamDestroy(stream);
	cudaFree(d_qp);
	cudaFree(d_send_cq);
	cudaFree(d_recv_cq);

	ft_free_res();
	return ft_exit_code(ret);
}
