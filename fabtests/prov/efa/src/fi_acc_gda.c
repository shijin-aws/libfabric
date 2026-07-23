/*
 * Copyright (c) 2026, Amazon.com, Inc.  All rights reserved.
 *
 * fi_acc_gda -- GPU Direct Async fabtest using OFI Accelerator API
 *
 * Covers the same operations as efa_gda.c but through the portable API:
 *   - Send latency (ping-pong)
 *   - RDMA Write / Write+IMM / Read bandwidth
 *   - HW counter in GPU HBM (--use-hw-cntr)
 *   - CQ backed by GPU memory (via acc_info.alloc)
 */

#include "hmem.h"
#include <cuda.h>
#include <cuda_runtime.h>
#include <getopt.h>
#include <rdma/fi_acc.h>
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

enum {
	LONG_OPT_USE_HW_CNTR = 1000,
};

/*
 * =============================================================================
 * acc_info callbacks
 *
 * alloc: Allocate GPU HBM exportable via DMA-BUF.
 *        Provider calls this for CQ buffers and HW counters.
 *
 * import: Map a provider-owned host VA (BAR MMIO or host RAM) into GPU.
 *         Provider calls this for SQ buffer, doorbell, CQ buffer.
 *
 * free: Release GPU memory from alloc.
 * =============================================================================
 */
static int acc_alloc(uint64_t device, uint64_t size, uint64_t alignment,
		     uint64_t flags, void **addr, int *fd, uint64_t *offset)
{
	int ret;
	void *buf;

	ret = ft_hmem_alloc(opts.iface, opts.device, &buf, (size_t)size);
	if (ret)
		return ret;

	ret = ft_hmem_get_dmabuf_fd(opts.iface, buf, (size_t)size, fd, offset);
	if (ret) {
		ft_hmem_free(opts.iface, buf);
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
		FT_WARN("cuMemHostRegister failed: %d\n", status);
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
	ft_hmem_free(opts.iface, addr);
}

static struct fi_acc_info acc_info = {
	.iface   = FI_HMEM_CUDA,
	.device  = 0,
	.mem_type = FI_ACC_MEM_USER_ALLOC,
};

static void setup_acc_info(void)
{
	acc_info.iface = opts.iface;
	acc_info.device = opts.device;
	acc_info.user.alloc = acc_alloc;
	acc_info.user.import = acc_import;
	acc_info.user.free = acc_free;
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

	while ((op = getopt_long(argc, argv,
				 "vho:" ADDR_OPTS INFO_OPTS CS_OPTS API_OPTS,
				 (struct option[]){
					{"use-hw-cntr", no_argument, NULL,
					 LONG_OPT_USE_HW_CNTR},
					{0, 0, 0, 0}
				 }, NULL)) != -1) {
		switch (op) {
		case 'o':
			if (!strcmp(optarg, "write")) gda_op = 1;
			else if (!strcmp(optarg, "writedata")) gda_op = 2;
			else if (!strcmp(optarg, "read")) gda_op = 3;
			else gda_op = 0;
			break;
		case 'v':
			opts.options |= FT_OPT_VERIFY_DATA;
			break;
		case LONG_OPT_USE_HW_CNTR:
			use_hw_cntr = true;
			break;
		default:
			ft_parse_addr_opts(op, optarg, &opts);
			ft_parseinfo(op, optarg, hints, &opts);
			ft_parsecsopts(op, optarg, &opts);
			ret = ft_parse_api_opts(op, optarg, hints, &opts);
			if (ret) return ret;
			break;
		case '?': case 'h':
			ft_usage(argv[0], "OFI Accelerator API GDA test");
			FT_PRINT_OPTS_USAGE("-o <op>",
				"op: msg, write, writedata, read");
			FT_PRINT_OPTS_USAGE("--use-hw-cntr",
				"Use hardware counter in GPU HBM");
			return EXIT_FAILURE;
		}
	}
	if (optind < argc) opts.dst_addr = argv[optind];
	if (gda_op != 0) opts.options |= FT_OPT_BW;

	/* Setup accelerator info with CUDA callbacks */
	setup_acc_info();

	hints->ep_attr->type = FI_EP_RDM;
	hints->caps |= FI_MSG | FI_RMA | FI_HMEM | FI_ACC;
	hints->domain_attr->mr_mode = FI_MR_ALLOCATED | FI_MR_LOCAL |
				      FI_MR_VIRT_ADDR | FI_MR_PROV_KEY | FI_MR_HMEM;
	hints->domain_attr->progress = FI_PROGRESS_MANUAL;
	hints->ep_attr->acc_info = &acc_info;

	ret = ft_init_fabric();
	if (ret) return ret;

	/*
	 * === Create HW counters (GPU HBM via alloc callback) ===
	 *
	 * When use_hw_cntr is set, we create counters with FI_ACC flag.
	 * The provider calls acc_info.alloc() to get GPU HBM + DMA-BUF,
	 * then passes it to efadv_create_comp_cntr internally.
	 * This replaces: create_hw_cntr() in efa_gda.c
	 */
	if (use_hw_cntr) {
		struct fi_cntr_attr cntr_attr = {};
		cntr_attr.events = FI_CNTR_EVENTS_COMP;
		cntr_attr.wait_obj = FI_WAIT_NONE;
		cntr_attr.flags = FI_ACC;
		cntr_attr.acc_info = &acc_info;

		ret = fi_cntr_open(domain, &cntr_attr, &txcntr, NULL);
		if (ret) { FT_PRINTERR("fi_cntr_open (tx)", -ret); return ret; }

		ret = fi_cntr_open(domain, &cntr_attr, &rxcntr, NULL);
		if (ret) { FT_PRINTERR("fi_cntr_open (rx)", -ret); return ret; }

		/* Bind counters to EP */
		ret = fi_ep_bind(ep, &txcntr->fid, FI_WRITE);
		if (ret) { FT_PRINTERR("fi_ep_bind txcntr", -ret); return ret; }

		ret = fi_ep_bind(ep, &rxcntr->fid,
				 (gda_op == 2) ? FI_REMOTE_WRITE : FI_RECV);
		if (ret) { FT_PRINTERR("fi_ep_bind rxcntr", -ret); return ret; }
	}

	/* === Export all resources as opaque device handles === */

	ret = fi_ep_export_acc(ep, 0, &d_ep, &export_size);
	if (ret) { FT_PRINTERR("fi_ep_export_acc", -ret); return ret; }

	ret = fi_cq_export_acc(txcq, 0, &d_send_cq, &export_size);
	if (ret) { FT_PRINTERR("fi_cq_export_acc tx", -ret); return ret; }

	ret = fi_cq_export_acc(rxcq, 0, &d_recv_cq, &export_size);
	if (ret) { FT_PRINTERR("fi_cq_export_acc rx", -ret); return ret; }

	ret = fi_mr_export_acc(mr, 0, &d_mr_desc, &export_size);
	if (ret) { FT_PRINTERR("fi_mr_export_acc", -ret); return ret; }

	ret = fi_av_export_acc(av, remote_fi_addr, 0, &d_peer, &export_size);
	if (ret) { FT_PRINTERR("fi_av_export_acc", -ret); return ret; }

	if (use_hw_cntr) {
		ret = fi_cntr_export_acc(txcntr, 0, &d_send_cntr, &export_size);
		if (ret) { FT_PRINTERR("fi_cntr_export_acc tx", -ret); return ret; }

		ret = fi_cntr_export_acc(rxcntr, 0, &d_recv_cntr, &export_size);
		if (ret) { FT_PRINTERR("fi_cntr_export_acc rx", -ret); return ret; }
	}

	printf("OFI Accelerator API GDA Test\n");
	printf("  Operation: %s\n",
	       gda_op == 0 ? "send" : gda_op == 1 ? "write" :
	       gda_op == 2 ? "writedata" : "read");
	printf("  HW counter: %s\n", use_hw_cntr ? "yes" : "no");

	/* === Launch GPU kernel === */
	cudaStream_t stream;
	cudaStreamCreate(&stream);

	ret = ft_sync();
	if (ret) return ret;

	ft_start();

	if (gda_op == 0) {
		/* Send latency ping-pong */
		int is_client = opts.dst_addr ? 1 : 0;
		int rx_depth = fi->rx_attr->size / 2;
		if (rx_depth > opts.iterations) rx_depth = opts.iterations;

		ret = fi_acc_run_lat_send(
			d_ep, d_send_cq, d_recv_cq,
			use_hw_cntr ? d_send_cntr : NULL,
			use_hw_cntr ? d_recv_cntr : NULL,
			d_mr_desc, d_peer,
			(uint64_t)rx_buf, opts.transfer_size,
			(uint64_t)tx_buf, opts.transfer_size,
			opts.iterations, rx_depth, is_client, stream);
	} else {
		/* Bandwidth: write / writedata / read */
		int is_client = opts.dst_addr ? 1 : 0;
		int tx_depth = fi->tx_attr->size / 2;

		if (is_client) {
			/* Exchange RMA keys */
			struct fi_rma_iov remote_iov = {};
			struct fi_rma_iov my_iov = {
				.addr = (gda_op == 3) ?
					(uintptr_t)tx_buf : (uintptr_t)rx_buf,
				.key = fi_mr_key(mr),
			};
			ret = ft_sock_send(oob_sock, &my_iov, sizeof(my_iov));
			if (ret) return ret;
			ret = ft_sock_recv(oob_sock, &remote_iov, sizeof(remote_iov));
			if (ret) return ret;

			ret = fi_acc_run_bw(
				d_ep, d_send_cq,
				use_hw_cntr ? d_send_cntr : NULL,
				d_mr_desc, d_peer, gda_op,
				(uint64_t)(gda_op == 3 ? rx_buf : tx_buf),
				opts.transfer_size,
				remote_iov.addr, (uint32_t)remote_iov.key,
				opts.iterations, tx_depth, stream);
		} else {
			/* Server side: recv for writedata/send ops */
			if (gda_op == 2 || gda_op == 0) {
				int rx_depth = fi->rx_attr->size / 2;
				if (rx_depth > opts.iterations)
					rx_depth = opts.iterations;

				/* Exchange RMA keys (server side) */
				struct fi_rma_iov remote_iov = {};
				struct fi_rma_iov my_iov = {
					.addr = (uintptr_t)rx_buf,
					.key = fi_mr_key(mr),
				};
				ret = ft_sock_recv(oob_sock, &remote_iov,
						   sizeof(remote_iov));
				if (ret) return ret;
				ret = ft_sock_send(oob_sock, &my_iov,
						   sizeof(my_iov));
				if (ret) return ret;

				ret = fi_acc_run_bw_recv(
					d_ep, d_recv_cq,
					use_hw_cntr ? d_recv_cntr : NULL,
					d_mr_desc,
					(uint64_t)rx_buf, opts.transfer_size,
					opts.iterations, rx_depth, stream);
			} else {
				/* Plain write / read: server just waits */
				struct fi_rma_iov remote_iov = {};
				struct fi_rma_iov my_iov = {
					.addr = (uintptr_t)rx_buf,
					.key = fi_mr_key(mr),
				};
				ret = ft_sock_recv(oob_sock, &remote_iov,
						   sizeof(remote_iov));
				if (ret) return ret;
				ret = ft_sock_send(oob_sock, &my_iov,
						   sizeof(my_iov));
				if (ret) return ret;
				ft_sync();
			}
		}
	}

	ft_stop();

	if (ret) {
		FT_PRINTERR("kernel execution", -ret);
	} else {
		show_perf(NULL, opts.transfer_size, opts.iterations,
			  &start, &end, (gda_op == 0) ? 2 : 1);
	}

	cudaStreamDestroy(stream);
	ft_free_res();
	return ft_exit_code(ret);
}
