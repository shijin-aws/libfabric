/*
 * Copyright (c) 2026, Amazon.com, Inc.  All rights reserved.
 *
 * fi_acc_gda -- GPU Direct Async fabtest using OFI Accelerator API
 *
 * Uses opaque handles + high-level device functions (fi_acc_write,
 * fi_acc_send, fi_acc_cq_poll, fi_acc_cntr_read). The consumer never
 * touches WQE formats, ring buffers, doorbells, or phase bits.
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

/* Opaque device handles (GPU pointers, never dereferenced on host) */
static void *d_ep;
static void *d_send_cq;
static void *d_recv_cq;
static void *d_send_cntr;
static void *d_recv_cntr;
static void *d_mr_desc;
static void *d_peer;

static bool use_hw_cntr;
static int  gda_op; /* 0=send, 1=write, 2=write_imm, 3=read */

/*
 * acc_info callbacks — consumer's GPU memory management
 */
static int acc_alloc(uint64_t device, uint64_t size, uint64_t alignment,
		     uint64_t flags, void **addr, int *fd, uint64_t *offset)
{
	int ret;
	void *buf;
	ret = ft_hmem_alloc(FI_HMEM_CUDA, device, &buf, (size_t)size);
	if (ret) return ret;
	ret = ft_hmem_get_dmabuf_fd(FI_HMEM_CUDA, buf, (size_t)size, fd, offset);
	if (ret) { ft_hmem_free(FI_HMEM_CUDA, buf); return ret; }
	*addr = buf;
	return 0;
}

static int acc_import(uint64_t device, int fd, uint64_t offset,
		      uint64_t size, uint64_t flags, void **addr)
{
	unsigned int cuda_flags = CU_MEMHOSTREGISTER_DEVICEMAP;
	CUdeviceptr dev_ptr = 0;
	if (flags & FI_ACC_IMPORT_IOMEMORY)
		cuda_flags |= CU_MEMHOSTREGISTER_IOMEMORY;
	if (cuMemHostRegister(*addr, (size_t)size, cuda_flags) != CUDA_SUCCESS)
		return -FI_EIO;
	if (cuMemHostGetDevicePointer(&dev_ptr, *addr, 0) != CUDA_SUCCESS)
		return -FI_EIO;
	*addr = (void *)dev_ptr;
	return 0;
}

static void acc_free(uint64_t device, void *addr)
{
	ft_hmem_free(FI_HMEM_CUDA, addr);
}

int main(int argc, char **argv)
{
	int op, ret;
	size_t export_size;

	opts = INIT_OPTS;
	opts.options |= FT_OPT_OOB_SYNC;
	timeout = 5;
	hints = fi_allocinfo();
	if (!hints) return EXIT_FAILURE;

	while ((op = getopt(argc, argv, "vho:" ADDR_OPTS INFO_OPTS CS_OPTS)) != -1) {
		switch (op) {
		case 'o':
			if (!strcmp(optarg, "write")) gda_op = 1;
			else if (!strcmp(optarg, "writedata")) gda_op = 2;
			else if (!strcmp(optarg, "read")) gda_op = 3;
			else gda_op = 0;
			break;
		case 'v': opts.options |= FT_OPT_VERIFY_DATA; break;
		default:
			ft_parse_addr_opts(op, optarg, &opts);
			ft_parseinfo(op, optarg, hints, &opts);
			ft_parsecsopts(op, optarg, &opts);
			break;
		case '?': case 'h':
			ft_usage(argv[0], "OFI Accelerator API GDA test");
			return EXIT_FAILURE;
		}
	}
	if (optind < argc) opts.dst_addr = argv[optind];
	if (gda_op != 0) opts.options |= FT_OPT_BW;

	hints->ep_attr->type = FI_EP_RDM;
	hints->caps |= FI_MSG | FI_RMA | FI_HMEM | FI_ACC;
	hints->domain_attr->mr_mode = FI_MR_ALLOCATED | FI_MR_LOCAL |
				      FI_MR_VIRT_ADDR | FI_MR_PROV_KEY | FI_MR_HMEM;

	ret = ft_init_fabric();
	if (ret) return ret;

	/* === Export all resources as opaque device handles === */

	ret = fi_acc_ep_export(ep, 0, &d_ep, &export_size);
	if (ret) { FT_PRINTERR("fi_acc_ep_export", -ret); return ret; }

	ret = fi_acc_cq_export(txcq, 0, &d_send_cq, &export_size);
	if (ret) { FT_PRINTERR("fi_acc_cq_export tx", -ret); return ret; }

	ret = fi_acc_cq_export(rxcq, 0, &d_recv_cq, &export_size);
	if (ret) { FT_PRINTERR("fi_acc_cq_export rx", -ret); return ret; }

	ret = fi_acc_mr_export(mr, 0, &d_mr_desc, &export_size);
	if (ret) { FT_PRINTERR("fi_acc_mr_export", -ret); return ret; }

	ret = fi_acc_av_export(av, remote_fi_addr, 0, &d_peer, &export_size);
	if (ret) { FT_PRINTERR("fi_acc_av_export", -ret); return ret; }

	if (use_hw_cntr) {
		ret = fi_acc_cntr_export(txcntr, 0, &d_send_cntr, &export_size);
		if (ret) { FT_PRINTERR("fi_acc_cntr_export tx", -ret); return ret; }
		ret = fi_acc_cntr_export(rxcntr, 0, &d_recv_cntr, &export_size);
		if (ret) { FT_PRINTERR("fi_acc_cntr_export rx", -ret); return ret; }
	}

	printf("OFI Accelerator API GDA Test (opaque handles)\n");

	/* === Launch GPU kernel === */
	cudaStream_t stream;
	cudaStreamCreate(&stream);
	ft_sync();
	ft_start();

	if (gda_op == 0) {
		int is_client = opts.dst_addr ? 1 : 0;
		int rx_depth = fi->rx_attr->size / 2;
		if (rx_depth > opts.iterations) rx_depth = opts.iterations;

		ret = fi_acc_run_lat_send(
			d_ep, d_send_cq, d_recv_cq,
			d_send_cntr, d_recv_cntr,
			d_mr_desc, d_peer,
			(uint64_t)rx_buf, opts.transfer_size,
			(uint64_t)tx_buf, opts.transfer_size,
			opts.iterations, rx_depth, is_client, stream);
	} else {
		int is_client = opts.dst_addr ? 1 : 0;
		int tx_depth = fi->tx_attr->size / 2;

		if (is_client) {
			struct fi_rma_iov remote_iov = {};
			struct fi_rma_iov my_iov = {
				.addr = (uint64_t)((gda_op == 3) ? tx_buf : rx_buf),
				.key = fi_mr_key(mr),
			};
			ft_sock_send(oob_sock, &my_iov, sizeof(my_iov));
			ft_sock_recv(oob_sock, &remote_iov, sizeof(remote_iov));

			ret = fi_acc_run_bw(
				d_ep, d_send_cq, d_send_cntr,
				d_mr_desc, d_peer, gda_op,
				(uint64_t)tx_buf, opts.transfer_size,
				remote_iov.addr, (uint32_t)remote_iov.key,
				opts.iterations, tx_depth, stream);
		} else {
			int rx_depth = fi->rx_attr->size / 2;
			if (rx_depth > opts.iterations) rx_depth = opts.iterations;
			ret = fi_acc_run_bw_recv(
				d_ep, d_recv_cq, d_recv_cntr,
				d_mr_desc,
				(uint64_t)rx_buf, opts.transfer_size,
				opts.iterations, rx_depth, stream);
		}
	}

	ft_stop();
	if (ret) FT_PRINTERR("kernel", -ret);
	else show_perf(NULL, opts.transfer_size, opts.iterations, &start, &end,
		       (gda_op == 0) ? 2 : 1);

	cudaStreamDestroy(stream);
	ft_free_res();
	return ft_exit_code(ret);
}
