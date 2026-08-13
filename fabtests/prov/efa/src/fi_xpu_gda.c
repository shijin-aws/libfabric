/*
 * Copyright (c) 2026, Amazon.com, Inc.  All rights reserved.
 *
 * This software is available to you under the BSD license
 * below:
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
 * XPU GPU Direct Async (GDA) Test
 *
 * This test exercises the fi_xpu API for GPU-initiated fabric
 * operations. It exports EP, CQ, CNTR, AV addresses and MR
 * descriptors to device memory, then launches CUDA kernels that
 * call fi_xpu_send/fi_xpu_write/fi_xpu_read directly from the GPU.
 */

#include "hmem.h"
#include <cuda.h>
#include <cuda_runtime.h>
#include <getopt.h>
#include <rdma/fi_xpu.h>
#include <rdma/fi_domain.h>
#include <rdma/fi_endpoint.h>
#include <rdma/fi_eq.h>
#include <shared.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <fi_xpu/fi_xpu_kernels.h>

/* XPU context and exported handles */
static struct fid_xpu_ctx *xpu_ctx;
static struct fid_xpu_ep *xpu_ep;
static struct fid_xpu_cq *xpu_send_cq;
static struct fid_xpu_cq *xpu_recv_cq;
static struct fid_xpu_cntr *xpu_send_cntr;
static struct fid_xpu_cntr *xpu_recv_cntr;
static size_t xpu_ep_size, xpu_send_cq_size, xpu_recv_cq_size;
static size_t xpu_send_cntr_size, xpu_recv_cntr_size;

/* Device-side copies of exported handles */
static void *dev_xpu_ep;
static void *dev_xpu_send_cq;
static void *dev_xpu_recv_cq;
static void *dev_xpu_send_cntr;
static void *dev_xpu_recv_cntr;

/* Device-side AV address and MR descriptor */
static void *dev_av_addr;
static size_t av_addr_size;
static void *dev_mr_desc;
static size_t mr_desc_size;

/* XPU context query attributes */
static struct fi_xpu_ctx_attr xpu_ctx_attr;

/* Test mode */
static int gda_op_is_write;
static int gda_op_is_read;
static bool use_cntr;

enum {
	LONG_OPT_USE_CNTR = 1000,
};

static int create_xpu_ctx(void)
{
	int ret;
	struct fi_xpu_attr xpu_attr = {0};

	xpu_attr.iface = FI_HMEM_CUDA;
	xpu_attr.device = opts.device;
	/* ops = NULL means provider manages memory */
	xpu_attr.ops = NULL;

	ret = fi_xpu_ctx(domain, &xpu_attr, &xpu_ctx, NULL);
	if (ret) {
		FT_PRINTERR("fi_xpu_ctx", -ret);
		return ret;
	}

	ret = fi_xpu_ctx_query(xpu_ctx, &xpu_ctx_attr);
	if (ret) {
		FT_PRINTERR("fi_xpu_ctx_query", -ret);
		return ret;
	}

	av_addr_size = xpu_ctx_attr.av_addr_size;
	mr_desc_size = xpu_ctx_attr.mr_desc_size;

	FT_DEBUG("XPU ctx caps=0x%lx av_addr_size=%zu mr_desc_size=%zu\n",
		 xpu_ctx_attr.caps, av_addr_size, mr_desc_size);

	return 0;
}

static int export_ep(void)
{
	int ret;

	ret = fi_ep_export_xpu(ep, 0, &xpu_ep, &xpu_ep_size);
	if (ret) {
		FT_PRINTERR("fi_ep_export_xpu", -ret);
		return ret;
	}

	/* Copy exported handle to device memory */
	if (cudaMalloc(&dev_xpu_ep, xpu_ep_size) != cudaSuccess) {
		FT_ERR("cudaMalloc for xpu_ep failed\n");
		return -FI_ENOMEM;
	}
	if (cudaMemcpy(dev_xpu_ep, xpu_ep, xpu_ep_size,
		       cudaMemcpyHostToDevice) != cudaSuccess) {
		FT_ERR("cudaMemcpy for xpu_ep failed\n");
		return -FI_EIO;
	}

	return 0;
}

static int export_cqs(void)
{
	int ret;

	ret = fi_cq_export_xpu(txcq, FI_XPU, &xpu_send_cq, &xpu_send_cq_size);
	if (ret) {
		FT_PRINTERR("fi_cq_export_xpu (send)", -ret);
		return ret;
	}

	if (cudaMalloc(&dev_xpu_send_cq, xpu_send_cq_size) != cudaSuccess) {
		FT_ERR("cudaMalloc for xpu_send_cq failed\n");
		return -FI_ENOMEM;
	}
	if (cudaMemcpy(dev_xpu_send_cq, xpu_send_cq, xpu_send_cq_size,
		       cudaMemcpyHostToDevice) != cudaSuccess) {
		FT_ERR("cudaMemcpy for xpu_send_cq failed\n");
		return -FI_EIO;
	}

	ret = fi_cq_export_xpu(rxcq, FI_XPU, &xpu_recv_cq, &xpu_recv_cq_size);
	if (ret) {
		FT_PRINTERR("fi_cq_export_xpu (recv)", -ret);
		return ret;
	}

	if (cudaMalloc(&dev_xpu_recv_cq, xpu_recv_cq_size) != cudaSuccess) {
		FT_ERR("cudaMalloc for xpu_recv_cq failed\n");
		return -FI_ENOMEM;
	}
	if (cudaMemcpy(dev_xpu_recv_cq, xpu_recv_cq, xpu_recv_cq_size,
		       cudaMemcpyHostToDevice) != cudaSuccess) {
		FT_ERR("cudaMemcpy for xpu_recv_cq failed\n");
		return -FI_EIO;
	}

	return 0;
}

static int export_cntrs(void)
{
	int ret;

	ret = fi_cntr_export_xpu(txcntr, FI_XPU, &xpu_send_cntr,
				 &xpu_send_cntr_size);
	if (ret) {
		FT_PRINTERR("fi_cntr_export_xpu (send)", -ret);
		return ret;
	}

	if (cudaMalloc(&dev_xpu_send_cntr, xpu_send_cntr_size) != cudaSuccess) {
		FT_ERR("cudaMalloc for xpu_send_cntr failed\n");
		return -FI_ENOMEM;
	}
	if (cudaMemcpy(dev_xpu_send_cntr, xpu_send_cntr, xpu_send_cntr_size,
		       cudaMemcpyHostToDevice) != cudaSuccess) {
		FT_ERR("cudaMemcpy for xpu_send_cntr failed\n");
		return -FI_EIO;
	}

	ret = fi_cntr_export_xpu(rxcntr, FI_XPU, &xpu_recv_cntr,
				 &xpu_recv_cntr_size);
	if (ret) {
		FT_PRINTERR("fi_cntr_export_xpu (recv)", -ret);
		return ret;
	}

	if (cudaMalloc(&dev_xpu_recv_cntr, xpu_recv_cntr_size) != cudaSuccess) {
		FT_ERR("cudaMalloc for xpu_recv_cntr failed\n");
		return -FI_ENOMEM;
	}
	if (cudaMemcpy(dev_xpu_recv_cntr, xpu_recv_cntr, xpu_recv_cntr_size,
		       cudaMemcpyHostToDevice) != cudaSuccess) {
		FT_ERR("cudaMemcpy for xpu_recv_cntr failed\n");
		return -FI_EIO;
	}

	return 0;
}

static int export_av_addr(void)
{
	int ret;
	void *addr_buf;
	size_t len;

	addr_buf = calloc(1, av_addr_size);
	if (!addr_buf)
		return -FI_ENOMEM;

	len = av_addr_size;
	ret = fi_av_lookup2(av, remote_fi_addr, addr_buf, &len, FI_XPU,
			    xpu_ctx);
	if (ret) {
		FT_PRINTERR("fi_av_lookup2", -ret);
		free(addr_buf);
		return ret;
	}

	if (cudaMalloc(&dev_av_addr, av_addr_size) != cudaSuccess) {
		FT_ERR("cudaMalloc for av_addr failed\n");
		free(addr_buf);
		return -FI_ENOMEM;
	}
	if (cudaMemcpy(dev_av_addr, addr_buf, av_addr_size,
		       cudaMemcpyHostToDevice) != cudaSuccess) {
		FT_ERR("cudaMemcpy for av_addr failed\n");
		free(addr_buf);
		return -FI_EIO;
	}

	free(addr_buf);
	return 0;
}

static int export_mr_desc(void)
{
	int ret;
	void *desc_buf;
	size_t len;

	desc_buf = calloc(1, mr_desc_size);
	if (!desc_buf)
		return -FI_ENOMEM;

	len = mr_desc_size;
	ret = fi_mr_get_desc(mr, desc_buf, &len, FI_XPU, xpu_ctx);
	if (ret) {
		FT_PRINTERR("fi_mr_get_desc", -ret);
		free(desc_buf);
		return ret;
	}

	if (cudaMalloc(&dev_mr_desc, mr_desc_size) != cudaSuccess) {
		FT_ERR("cudaMalloc for mr_desc failed\n");
		free(desc_buf);
		return -FI_ENOMEM;
	}
	if (cudaMemcpy(dev_mr_desc, desc_buf, mr_desc_size,
		       cudaMemcpyHostToDevice) != cudaSuccess) {
		FT_ERR("cudaMemcpy for mr_desc failed\n");
		free(desc_buf);
		return -FI_EIO;
	}

	free(desc_buf);
	return 0;
}

static int run_bw(struct fi_rma_iov *remote_iov)
{
	int ret;
	cudaStream_t stream;
	int is_client;
	int tx_depth;
	int rx_depth;

	ret = ft_sync();
	if (ret) {
		FT_PRINTERR("ft_sync", -ret);
		return ret;
	}

	cudaStreamCreate(&stream);

	is_client = opts.dst_addr ? 1 : 0;
	tx_depth = fi->tx_attr->size / 2;
	rx_depth = fi->rx_attr->size / 2;
	if (rx_depth > opts.iterations)
		rx_depth = opts.iterations;

	if (ft_check_opts(FT_OPT_VERIFY_DATA)) {
		if (gda_op_is_read) {
			ret = ft_fill_buf((char *) tx_buf, opts.transfer_size);
		} else if (is_client) {
			ret = ft_fill_buf((char *) tx_buf, opts.transfer_size);
		}
		if (ret)
			goto out;
		ft_sync();
	}

	ft_start();
	if (is_client) {
		/* Client: post writes or reads */
		ret = fi_xpu_run_bw(
			dev_xpu_ep,
			dev_xpu_send_cq,
			use_cntr ? dev_xpu_send_cntr : NULL,
			gda_op_is_write || gda_op_is_read,
			gda_op_is_read ? rx_buf : tx_buf,
			opts.transfer_size,
			dev_mr_desc, mr_desc_size,
			dev_av_addr, av_addr_size,
			remote_iov->addr, remote_iov->key,
			opts.iterations, tx_depth, stream);
	} else {
		/* Server: for send/writedata, poll recv completions */
		if (!gda_op_is_write || gda_op_is_read) {
			/* For writes with no IMM, server just waits */
		}
		if (!gda_op_is_write && !gda_op_is_read) {
			/* Send mode: server receives */
			ret = fi_xpu_run_bw_recv(
				dev_xpu_ep,
				dev_xpu_recv_cq,
				use_cntr ? dev_xpu_recv_cntr : NULL,
				rx_buf, opts.transfer_size,
				dev_mr_desc, mr_desc_size,
				opts.iterations, rx_depth, stream);
		}
	}
	ft_stop();

	if (ret) {
		FT_PRINTERR("fi_xpu_run_bw", -ret);
		goto out;
	}

	show_perf(NULL, opts.transfer_size, opts.iterations, &start, &end, 1);

out:
	cudaStreamDestroy(stream);
	ft_sync();

	if (!ret && ft_check_opts(FT_OPT_VERIFY_DATA)) {
		if ((gda_op_is_read && is_client) ||
		    (!gda_op_is_read && !is_client)) {
			ret = ft_check_buf((char *) rx_buf, opts.transfer_size);
		}
	}

	return ret;
}

static int run(void)
{
	int ret;
	cudaStream_t stream;
	int is_client;
	int rx_depth;

	ret = ft_sync();
	if (ret) {
		FT_PRINTERR("ft_sync", -ret);
		return ret;
	}

	cudaStreamCreate(&stream);

	is_client = opts.dst_addr ? 1 : 0;
	rx_depth = fi->rx_attr->size / 2;
	if (rx_depth > opts.iterations)
		rx_depth = opts.iterations;

	if (is_client && ft_check_opts(FT_OPT_VERIFY_DATA)) {
		ret = ft_fill_buf((char *) tx_buf + ft_tx_prefix_size(),
				  opts.transfer_size);
		if (ret)
			goto out;
	}

	ft_start();
	ret = fi_xpu_run_lat_send(
		dev_xpu_ep,
		dev_xpu_send_cq,
		dev_xpu_recv_cq,
		use_cntr ? dev_xpu_send_cntr : NULL,
		use_cntr ? dev_xpu_recv_cntr : NULL,
		dev_av_addr, av_addr_size,
		rx_buf, opts.transfer_size,
		dev_mr_desc, mr_desc_size,
		tx_buf, opts.transfer_size,
		dev_mr_desc, mr_desc_size,
		opts.iterations, rx_depth, is_client, stream);
	ft_stop();

	if (ret) {
		FT_PRINTERR("fi_xpu_run_lat_send", -ret);
		goto out;
	}

	if (!is_client && ft_check_opts(FT_OPT_VERIFY_DATA)) {
		ret = ft_check_buf((char *) rx_buf, opts.transfer_size);
		if (ret)
			goto out;
	}

	show_perf(NULL, opts.transfer_size, opts.iterations, &start, &end, 2);

out:
	cudaStreamDestroy(stream);
	return ret;
}

static void cleanup_xpu(void)
{
	if (dev_xpu_ep)
		cudaFree(dev_xpu_ep);
	if (dev_xpu_send_cq)
		cudaFree(dev_xpu_send_cq);
	if (dev_xpu_recv_cq)
		cudaFree(dev_xpu_recv_cq);
	if (dev_xpu_send_cntr)
		cudaFree(dev_xpu_send_cntr);
	if (dev_xpu_recv_cntr)
		cudaFree(dev_xpu_recv_cntr);
	if (dev_av_addr)
		cudaFree(dev_av_addr);
	if (dev_mr_desc)
		cudaFree(dev_mr_desc);
	if (xpu_ctx)
		fi_close(&xpu_ctx->fid);
}

int main(int argc, char **argv)
{
	int op, ret, i, cleanup_ret;
	struct fi_rma_iov remote_iov = {0};

	opts = INIT_OPTS;
	opts.options |= FT_OPT_OOB_SYNC;
	opts.iface = FI_HMEM_CUDA;

	timeout = 5;

	hints = fi_allocinfo();
	if (!hints)
		return EXIT_FAILURE;

	while ((op = getopt_long(argc, argv,
			    "vh" ADDR_OPTS INFO_OPTS CS_OPTS API_OPTS,
			    (struct option[]){
				{"use-cntr", no_argument, NULL,
				 LONG_OPT_USE_CNTR},
				{0, 0, 0, 0}
			    }, NULL)) != -1) {
		switch (op) {
		case LONG_OPT_USE_CNTR:
			use_cntr = true;
			break;
		default:
			ft_parse_addr_opts(op, optarg, &opts);
			ft_parseinfo(op, optarg, hints, &opts);
			ft_parsecsopts(op, optarg, &opts);
			ret = ft_parse_api_opts(op, optarg, hints, &opts);
			if (ret)
				return ret;
			break;
		case 'v':
			opts.options |= FT_OPT_VERIFY_DATA;
			break;
		case '?':
		case 'h':
			ft_usage(argv[0], "XPU GPU Direct Async test");
			FT_PRINT_OPTS_USAGE("-o <op>",
				"op: msg, write, read\n");
			FT_PRINT_OPTS_USAGE("-v", "Enable data verification");
			FT_PRINT_OPTS_USAGE("--use-cntr",
				"Use XPU counters instead of CQ polling");
			return EXIT_FAILURE;
		}
	}

	if (optind < argc)
		opts.dst_addr = argv[optind];

	switch (opts.rma_op) {
	case FT_RMA_WRITE:
		gda_op_is_write = 1;
		break;
	case FT_RMA_READ:
		gda_op_is_read = 1;
		break;
	default:
		/* Default: send/recv latency test */
		break;
	}

	if (gda_op_is_write || gda_op_is_read)
		opts.options |= FT_OPT_BW;

	hints->ep_attr->type = FI_EP_RDM;
	hints->caps |= FI_MSG | FI_RMA | FI_HMEM | FI_XPU;
	hints->domain_attr->mr_mode = FI_MR_ALLOCATED | FI_MR_LOCAL |
				      FI_MR_VIRT_ADDR | FI_MR_PROV_KEY |
				      FI_MR_HMEM;
	hints->domain_attr->progress = FI_PROGRESS_MANUAL;
	hints->mode |= FI_CONTEXT | FI_CONTEXT2;

	ret = ft_init_fabric();
	if (ret) {
		FT_PRINTERR("ft_init_fabric", -ret);
		return ret;
	}

	/* Create XPU context */
	ret = create_xpu_ctx();
	if (ret)
		goto out;

	/* Set xpu_ctx on EP attr for the endpoint */
	fi->ep_attr->xpu_ctx = xpu_ctx;

	/* Create CQs with XPU context */
	cq_attr.format = FI_CQ_FORMAT_MSG;
	cq_attr.wait_obj = FI_WAIT_NONE;
	cq_attr.size = fi->tx_attr->size;
	cq_attr.flags = FI_XPU;
	cq_attr.xpu_ctx = xpu_ctx;

	ret = fi_cq_open(domain, &cq_attr, &txcq, &txcq);
	if (ret) {
		FT_PRINTERR("fi_cq_open (tx)", -ret);
		goto out;
	}

	cq_attr.size = fi->rx_attr->size;
	ret = fi_cq_open(domain, &cq_attr, &rxcq, &rxcq);
	if (ret) {
		FT_PRINTERR("fi_cq_open (rx)", -ret);
		goto out;
	}

	/* Create counters if requested */
	if (use_cntr) {
		struct fi_cntr_attr cntr_attr = {0};
		cntr_attr.events = FI_CNTR_EVENTS_COMP;
		cntr_attr.wait_obj = FI_WAIT_UNSPEC;
		cntr_attr.flags = FI_XPU;
		cntr_attr.xpu_ctx = xpu_ctx;

		ret = fi_cntr_open(domain, &cntr_attr, &txcntr, &txcntr);
		if (ret) {
			FT_PRINTERR("fi_cntr_open (tx)", -ret);
			goto out;
		}

		ret = fi_cntr_open(domain, &cntr_attr, &rxcntr, &rxcntr);
		if (ret) {
			FT_PRINTERR("fi_cntr_open (rx)", -ret);
			goto out;
		}
	}

	/* Create and enable endpoint */
	ret = fi_endpoint(domain, fi, &ep, NULL);
	if (ret) {
		FT_PRINTERR("fi_endpoint", -ret);
		goto out;
	}

	ret = ft_enable_ep(ep, eq, av, txcq, rxcq, txcntr, rxcntr, rma_cntr);
	if (ret)
		goto out;

	ret = ft_init_av_dst_addr(av, ep, &remote_fi_addr);
	if (ret)
		goto out;

	/* Export XPU handles */
	ret = export_ep();
	if (ret)
		goto out;

	ret = export_cqs();
	if (ret)
		goto out;

	if (use_cntr) {
		ret = export_cntrs();
		if (ret)
			goto out;
	}

	ret = export_av_addr();
	if (ret)
		goto out;

	ret = export_mr_desc();
	if (ret)
		goto out;

	/* Exchange RMA keys for write/read ops */
	if (gda_op_is_write || gda_op_is_read) {
		struct fi_rma_iov my_iov = {0};
		my_iov.addr = gda_op_is_read ?
			      (uintptr_t) tx_buf : (uintptr_t) rx_buf;
		my_iov.key = fi_mr_key(mr);

		ret = ft_sock_send(oob_sock, &my_iov, sizeof(my_iov));
		if (ret) {
			FT_PRINTERR("ft_sock_send rma_iov", -ret);
			goto out;
		}
		ret = ft_sock_recv(oob_sock, &remote_iov, sizeof(remote_iov));
		if (ret) {
			FT_PRINTERR("ft_sock_recv rma_iov", -ret);
			goto out;
		}
	}

	/* Run the test */
	if (!(opts.options & FT_OPT_SIZE)) {
		for (i = 0; i < TEST_CNT; i++) {
			if (!ft_use_size(i, opts.sizes_enabled))
				continue;
			opts.transfer_size = test_size[i].size;
			init_test(&opts, test_name, sizeof(test_name));
			if (gda_op_is_write || gda_op_is_read)
				ret = run_bw(&remote_iov);
			else
				ret = run();
			if (ret)
				break;
		}
	} else {
		init_test(&opts, test_name, sizeof(test_name));
		if (gda_op_is_write || gda_op_is_read)
			ret = run_bw(&remote_iov);
		else
			ret = run();
	}

out:
	cleanup_xpu();
	FT_CLOSE_FID(ep);
	FT_CLOSE_FID(txcq);
	FT_CLOSE_FID(rxcq);
	FT_CLOSE_FID(txcntr);
	FT_CLOSE_FID(rxcntr);

	cleanup_ret = ft_free_res();
	return ft_exit_code(ret ? ret : cleanup_ret);
}
