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

static bool use_hw_cntr = true;
static int gda_op; /* 0=send, 1=write, 2=write_imm, 3=read */

/*
 * FI_ACC_MEM_PROVIDER: the provider manages all accelerator memory
 * internally via the libfabric HMEM interface — no callbacks needed.
 */
static struct fi_acc_info acc_info = {
	.iface = FI_HMEM_CUDA,
	.device = 0,
	.mem_type = FI_ACC_MEM_PROVIDER,
};

static void setup_acc_info(void)
{
	acc_info.iface = opts.iface;
	acc_info.device = opts.device;
}

#define ACC_LOG(fmt, ...)                                        \
	do {                                                     \
		printf("[fi_acc_gda] " fmt "\n", ##__VA_ARGS__); \
		fflush(stdout);                                  \
	} while (0)

/*
 * Custom fabric init (mirrors ft_init_fabric) that passes acc_info at
 * every object creation so the provider keeps an internal copy for the
 * export calls:
 *   - EP:   fi->ep_attr->acc_info set before fi_endpoint()
 *   - CQ:   cq_attr.flags |= FI_ACC, cq_attr.acc_info
 *   - CNTR: cntr_attr.flags |= FI_ACC, cntr_attr.acc_info
 * Objects are bound and enabled here with GDA-appropriate flags.
 */
static int init_fabric_acc(void)
{
	uint64_t flags;
	int ret;

	ACC_LOG("step 1: ft_init");
	ret = ft_init();
	if (ret) {
		FT_PRINTERR("ft_init", ret);
		return ret;
	}

	ACC_LOG("step 2: ft_init_oob");
	ret = ft_init_oob();
	if (ret) {
		FT_PRINTERR("ft_init_oob", ret);
		return ret;
	}

	ACC_LOG("step 3: fi_getinfo (API %u.%u)", FI_MAJOR(ft_fiversion),
		FI_MINOR(ft_fiversion));
	ret = ft_getinfo(hints, &fi);
	if (ret) {
		FT_PRINTERR("ft_getinfo", ret);
		return ret;
	}
	ACC_LOG("  fabric=%s domain=%s", fi->fabric_attr->name,
		fi->domain_attr->name);
	ACC_LOG("  max_cntr_value=%#lx max_err_cntr_value=%#lx",
		fi->domain_attr->max_cntr_value,
		fi->domain_attr->max_err_cntr_value);

	if (use_hw_cntr && fi->domain_attr->max_cntr_value == UINT64_MAX) {
		FT_ERR("device does not support hw counters "
		       "(max_cntr_value not negotiated)");
		return -FI_ENOSYS;
	}

	ACC_LOG("step 4: ft_open_fabric_res (fabric/eq/domain)");
	ret = ft_open_fabric_res();
	if (ret)
		return ret;

	ACC_LOG("step 5: fi_cq_open tx/rx (FI_ACC, provider-managed GPU mem)");
	{
		struct fi_cq_attr acc_cq_attr = {
			.format = FI_CQ_FORMAT_MSG,
			.wait_obj = FI_WAIT_NONE,
			.flags = FI_ACC,
			.acc_info = &acc_info,
		};

		acc_cq_attr.size = fi->tx_attr->size;
		ret = fi_cq_open(domain, &acc_cq_attr, &txcq, NULL);
		if (ret) {
			FT_PRINTERR("fi_cq_open(tx, FI_ACC)", ret);
			return ret;
		}
		ACC_LOG("  txcq=%p size=%zu", (void *) txcq, acc_cq_attr.size);

		acc_cq_attr.size = fi->rx_attr->size;
		ret = fi_cq_open(domain, &acc_cq_attr, &rxcq, NULL);
		if (ret) {
			FT_PRINTERR("fi_cq_open(rx, FI_ACC)", ret);
			return ret;
		}
		ACC_LOG("  rxcq=%p size=%zu", (void *) rxcq, acc_cq_attr.size);
	}

	struct fi_cntr_attr acc_cntr_attr = {
		.events = FI_CNTR_EVENTS_COMP,
		.wait_obj = FI_WAIT_NONE,
		.flags = FI_ACC,
		.acc_info = &acc_info,
	};

	ACC_LOG("step 6: fi_cntr_open tx/rx (FI_ACC, hw cntr in GPU HBM)");
	ret = fi_cntr_open(domain, &acc_cntr_attr, &txcntr, NULL);
	if (ret) {
		FT_PRINTERR("fi_cntr_open(tx, FI_ACC)", ret);
		return ret;
	}
	ACC_LOG("  txcntr=%p", (void *) txcntr);

	ret = fi_cntr_open(domain, &acc_cntr_attr, &rxcntr, NULL);
	if (ret) {
		FT_PRINTERR("fi_cntr_open(rx, FI_ACC)", ret);
		return ret;
	}
	ACC_LOG("  rxcntr=%p", (void *) rxcntr);

	ACC_LOG("step 7: fi_av_open");
	if (fi->domain_attr->av_type != FI_AV_UNSPEC)
		av_attr.type = fi->domain_attr->av_type;
	av_attr.count = opts.av_size;
	av_attr.flags = FI_ACC;
	av_attr.acc_info = &acc_info;
	ret = fi_av_open(domain, &av_attr, &av, NULL);
	if (ret) {
		FT_PRINTERR("fi_av_open", ret);
		return ret;
	}

	/*
	 * acc_info on the info passed to fi_endpoint(): the provider
	 * copies it into the EP's internal acc state and uses it later
	 * in fi_ep_export_acc().
	 */
	ACC_LOG("step 8: fi_endpoint (ep_attr->acc_info=%p)",
		(void *) &acc_info);
	fi->ep_attr->acc_info = &acc_info;
	ret = fi_endpoint(domain, fi, &ep, NULL);
	if (ret) {
		FT_PRINTERR("fi_endpoint", ret);
		return ret;
	}

	ACC_LOG("step 9: bind av/cq/cntr + fi_enable");
	ret = fi_ep_bind(ep, &av->fid, 0);
	if (ret) {
		FT_PRINTERR("fi_ep_bind(av)", ret);
		return ret;
	}

	ret = fi_ep_bind(ep, &txcq->fid, FI_TRANSMIT | FI_SELECTIVE_COMPLETION);
	if (ret) {
		FT_PRINTERR("fi_ep_bind(txcq)", ret);
		return ret;
	}

	ret = fi_ep_bind(ep, &rxcq->fid, FI_RECV | FI_SELECTIVE_COMPLETION);
	if (ret) {
		FT_PRINTERR("fi_ep_bind(rxcq)", ret);
		return ret;
	}

	flags = FI_SEND | FI_WRITE | FI_READ;
	ACC_LOG("  bind txcntr flags=%#lx", flags);
	ret = fi_ep_bind(ep, &txcntr->fid, flags);
	if (ret) {
		FT_PRINTERR("fi_ep_bind(txcntr)", ret);
		return ret;
	}

	flags = (gda_op == 2) ? FI_REMOTE_WRITE : FI_RECV;
	ACC_LOG("  bind rxcntr flags=%#lx", flags);
	ret = fi_ep_bind(ep, &rxcntr->fid, flags);
	if (ret) {
		FT_PRINTERR("fi_ep_bind(rxcntr)", ret);
		return ret;
	}

	ret = fi_enable(ep);
	if (ret) {
		FT_PRINTERR("fi_enable", ret);
		return ret;
	}

	ACC_LOG("step 10: ft_alloc_msgs (buffers only, MR registered separately)");
	opts.options |= FT_OPT_SKIP_REG_MR;
	ret = ft_alloc_msgs();
	if (ret)
		return ret;

	/* Register MR with acc_info so the provider can export it later */
	ACC_LOG("step 10b: fi_mr_regattr (acc_info=%p)", (void *) &acc_info);
	{
		struct iovec iov = {
			.iov_base = rx_buf,
			.iov_len = buf_size,
		};
		struct fi_mr_attr mr_attr = {
			.mr_iov = &iov,
			.iov_count = 1,
			.access = ft_info_to_mr_access(fi),
			.requested_key = FT_MR_KEY,
			.iface = opts.iface,
			.acc_info = &acc_info,
		};
		mr_attr.device.cuda = opts.device;

		ret = fi_mr_regattr(domain, &mr_attr,
				    FI_HMEM_DEVICE_ONLY | FI_ACC, &mr);
		if (ret) {
			FT_PRINTERR("fi_mr_regattr", ret);
			return ret;
		}
		mr_desc = fi_mr_desc(mr);
		ACC_LOG("  mr=%p key=%#lx", (void *) mr, fi_mr_key(mr));
	}

	ACC_LOG("step 11: ft_init_av_dst_addr (address exchange, oob_sock=%d)",
		oob_sock);
	ret = ft_init_av_dst_addr(av, ep, &remote_fi_addr);
	if (ret) {
		FT_PRINTERR("ft_init_av_dst_addr", ret);
		return ret;
	}
	ACC_LOG("  peer address inserted, remote_fi_addr=%#lx", remote_fi_addr);

	ACC_LOG("fabric init complete");
	return 0;
}

int main(int argc, char **argv)
{
	int op, ret;
	size_t export_size;

	opts = INIT_OPTS;
	opts.options |= FT_OPT_OOB_SYNC;
	timeout = 5;
	hints = fi_allocinfo();
	if (!hints)
		return EXIT_FAILURE;

	while ((op = getopt_long(
			argc, argv, "vho:" ADDR_OPTS INFO_OPTS CS_OPTS API_OPTS,
			(struct option[]) {{0, 0, 0, 0}}, NULL)) != -1) {
		switch (op) {
		case 'o':
			if (!strcmp(optarg, "write"))
				gda_op = 1;
			else if (!strcmp(optarg, "writedata"))
				gda_op = 2;
			else if (!strcmp(optarg, "read"))
				gda_op = 3;
			else
				gda_op = 0;
			break;
		case 'v':
			opts.options |= FT_OPT_VERIFY_DATA;
			break;
		default:
			ft_parse_addr_opts(op, optarg, &opts);
			ft_parseinfo(op, optarg, hints, &opts);
			ft_parsecsopts(op, optarg, &opts);
			ret = ft_parse_api_opts(op, optarg, hints, &opts);
			if (ret)
				return ret;
			break;
		case '?':
		case 'h':
			ft_usage(argv[0], "OFI Accelerator API GDA test");
			FT_PRINT_OPTS_USAGE("-o <op>",
					    "op: msg, write, writedata, read");
			return EXIT_FAILURE;
		}
	}
	if (optind < argc)
		opts.dst_addr = argv[optind];
	if (gda_op != 0)
		opts.options |= FT_OPT_BW;

	/* Setup accelerator info with CUDA callbacks */
	setup_acc_info();

	hints->ep_attr->type = FI_EP_RDM;
	hints->caps |= FI_MSG | FI_RMA | FI_HMEM | FI_ACC;
	hints->domain_attr->mr_mode = FI_MR_ALLOCATED | FI_MR_LOCAL |
				      FI_MR_VIRT_ADDR | FI_MR_PROV_KEY |
				      FI_MR_HMEM;
	hints->mode |= FI_CONTEXT2;
	hints->ep_attr->acc_info = &acc_info;

	/*
	 * HW counters require API >= 2.5: the provider only negotiates
	 * max_cntr_value down to the hardware limit for 2.5+. With an
	 * older version max_cntr_value stays UINT64_MAX and hw counter
	 * creation is rejected with -FI_EOPNOTSUPP.
	 */
	ft_fiversion = FI_VERSION(2, 6);

	ret = init_fabric_acc();
	if (ret)
		return ft_exit_code(ret);

	/* === Export all resources as opaque device handles === */

	ACC_LOG("step 12a: export EP to device handle");
	ret = fi_ep_export_acc(ep, 0, &d_ep, &export_size);
	if (ret) {
		FT_PRINTERR("fi_ep_export_acc", -ret);
		return ret;
	}
	ACC_LOG("  d_ep=%p size=%zu", d_ep, export_size);

	ACC_LOG("step 12b: export TX CQ to device handle");
	ret = fi_cq_export_acc(txcq, 0, &d_send_cq, &export_size);
	if (ret) {
		FT_PRINTERR("fi_cq_export_acc tx", -ret);
		return ret;
	}
	ACC_LOG("  d_send_cq=%p size=%zu", d_send_cq, export_size);

	ACC_LOG("step 12c: export RX CQ to device handle");
	ret = fi_cq_export_acc(rxcq, 0, &d_recv_cq, &export_size);
	if (ret) {
		FT_PRINTERR("fi_cq_export_acc rx", -ret);
		return ret;
	}
	ACC_LOG("  d_recv_cq=%p size=%zu", d_recv_cq, export_size);

	ACC_LOG("step 12d: export MR to device handle");
	ret = fi_mr_export_acc(&mr, 1, 0, &d_mr_desc, &export_size);
	if (ret) {
		FT_PRINTERR("fi_mr_export_acc", -ret);
		return ret;
	}
	ACC_LOG("  d_mr_desc=%p size=%zu", d_mr_desc, export_size);

	ACC_LOG("step 12e: export AV to device handle");
	ret = fi_av_export_acc(av, &remote_fi_addr, 1, 0, &d_peer,
			       &export_size);
	if (ret) {
		FT_PRINTERR("fi_av_export_acc", -ret);
		return ret;
	}
	ACC_LOG("  d_peer=%p size=%zu", d_peer, export_size);

	ACC_LOG("step 12f: export TX CNTR to device handle");
	ret = fi_cntr_export_acc(txcntr, 0, &d_send_cntr, &export_size);
	if (ret) {
		FT_PRINTERR("fi_cntr_export_acc tx", -ret);
		return ret;
	}
	ACC_LOG("  d_send_cntr=%p size=%zu", d_send_cntr, export_size);

	ACC_LOG("step 12g: export RX CNTR to device handle");
	ret = fi_cntr_export_acc(rxcntr, 0, &d_recv_cntr, &export_size);
	if (ret) {
		FT_PRINTERR("fi_cntr_export_acc rx", -ret);
		return ret;
	}
	ACC_LOG("  d_recv_cntr=%p size=%zu", d_recv_cntr, export_size);

	printf("OFI Accelerator API GDA Test\n");
	printf("  Operation: %s\n", gda_op == 0 ? "send" :
				    gda_op == 1 ? "write" :
				    gda_op == 2 ? "writedata" :
						  "read");
	printf("  HW counter: %s\n", use_hw_cntr ? "yes" : "no");

	/* === Launch GPU kernel === */
	cudaStream_t stream;
	cudaStreamCreate(&stream);

	ACC_LOG("step 13: ft_sync");
	ret = ft_sync();
	if (ret)
		return ret;

	ACC_LOG("step 14: launch GPU kernel (iters=%d size=%zu)",
		opts.iterations, opts.transfer_size);
	ft_start();

	if (gda_op == 0) {
		/* Send latency ping-pong */
		int is_client = opts.dst_addr ? 1 : 0;
		int rx_depth = fi->rx_attr->size / 2;
		if (rx_depth > opts.iterations)
			rx_depth = opts.iterations;

		ret = fi_acc_run_lat_send(d_ep, d_send_cq, d_recv_cq,
					  use_hw_cntr ? d_send_cntr : NULL,
					  use_hw_cntr ? d_recv_cntr : NULL,
					  d_mr_desc, d_peer, (uint64_t) rx_buf,
					  opts.transfer_size, (uint64_t) tx_buf,
					  opts.transfer_size, opts.iterations,
					  rx_depth, is_client, stream);
	} else {
		/* Bandwidth: write / writedata / read */
		int is_client = opts.dst_addr ? 1 : 0;
		int tx_depth = fi->tx_attr->size / 2;

		if (is_client) {
			/* Exchange RMA keys */
			struct fi_rma_iov remote_iov = {};
			struct fi_rma_iov my_iov = {
				.addr = (gda_op == 3) ? (uintptr_t) tx_buf :
							(uintptr_t) rx_buf,
				.key = fi_mr_key(mr),
			};
			ret = ft_sock_send(oob_sock, &my_iov, sizeof(my_iov));
			if (ret)
				return ret;
			ret = ft_sock_recv(oob_sock, &remote_iov,
					   sizeof(remote_iov));
			if (ret)
				return ret;

			ret = fi_acc_run_bw(
				d_ep, d_send_cq,
				use_hw_cntr ? d_send_cntr : NULL, d_mr_desc,
				d_peer, gda_op,
				(uint64_t) (gda_op == 3 ? rx_buf : tx_buf),
				opts.transfer_size, remote_iov.addr,
				(uint32_t) remote_iov.key, opts.iterations,
				tx_depth, stream);
		} else {
			/* Server side: recv for writedata/send ops */
			if (gda_op == 2 || gda_op == 0) {
				int rx_depth = fi->rx_attr->size / 2;
				if (rx_depth > opts.iterations)
					rx_depth = opts.iterations;

				/* Exchange RMA keys (server side) */
				struct fi_rma_iov remote_iov = {};
				struct fi_rma_iov my_iov = {
					.addr = (uintptr_t) rx_buf,
					.key = fi_mr_key(mr),
				};
				ret = ft_sock_recv(oob_sock, &remote_iov,
						   sizeof(remote_iov));
				if (ret)
					return ret;
				ret = ft_sock_send(oob_sock, &my_iov,
						   sizeof(my_iov));
				if (ret)
					return ret;

				ret = fi_acc_run_bw_recv(
					d_ep, d_recv_cq,
					use_hw_cntr ? d_recv_cntr : NULL,
					d_mr_desc, (uint64_t) rx_buf,
					opts.transfer_size, opts.iterations,
					rx_depth, stream);
			} else {
				/* Plain write / read: server just waits */
				struct fi_rma_iov remote_iov = {};
				struct fi_rma_iov my_iov = {
					.addr = (uintptr_t) rx_buf,
					.key = fi_mr_key(mr),
				};
				ret = ft_sock_recv(oob_sock, &remote_iov,
						   sizeof(remote_iov));
				if (ret)
					return ret;
				ret = ft_sock_send(oob_sock, &my_iov,
						   sizeof(my_iov));
				if (ret)
					return ret;
				ft_sync();
			}
		}
	}

	ft_stop();

	if (ret) {
		FT_PRINTERR("kernel execution", -ret);
	} else {
		ACC_LOG("step 15: kernel complete, reporting perf");
		show_perf(NULL, opts.transfer_size, opts.iterations, &start,
			  &end, (gda_op == 0) ? 2 : 1);
	}

	cudaStreamDestroy(stream);
	ft_free_res();
	return ft_exit_code(ret);
}
