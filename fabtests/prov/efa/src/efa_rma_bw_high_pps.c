/*
 * Copyright Amazon.com, Inc. or its affiliates. All rights reserved.
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
 */

/*
 * EFA RMA write bandwidth test with high PPS hint support.
 *
 * This test is based on fi_rma_bw but adds the ability to pass
 * FI_EFA_WR_HIGH_PPS as a provider-specific flag to fi_writemsg(),
 * allowing benchmarking of the PPS optimization feature.
 *
 * Usage:
 *   Server: fi_efa_rma_bw_high_pps
 *   Client: fi_efa_rma_bw_high_pps -H <server_addr>
 *
 *   Add --high-pps to enable the FI_EFA_WR_HIGH_PPS flag on writes.
 *   Add -o writedata to use writedata (FI_REMOTE_CQ_DATA) instead of write.
 */

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>

#include <rdma/fi_errno.h>
#include <rdma/fi_ext.h>
#include <rdma/fi_ext_efa.h>

#include <shared.h>
#include "benchmarks/benchmark_shared.h"


static int use_high_pps;

static ssize_t post_rma_write(char *buf, size_t size,
			      struct fi_rma_iov *remote, void *context,
			      uint64_t base_flags)
{
	uint64_t flags = base_flags;

	if (use_high_pps)
		flags |= FI_EFA_WR_HIGH_PPS;

	if (opts.rma_op == FT_RMA_WRITEDATA)
		flags |= FI_REMOTE_CQ_DATA;

	return ft_post_rma_writemsg(buf, size, remote, context, flags);
}

static int bw_comp(void)
{
	int ret;

	if (opts.rma_op == FT_RMA_WRITEDATA) {
		if (opts.dst_addr) {
			ret = ft_get_tx_comp(tx_seq);
			if (ret)
				return ret;
			return ft_rx(ep, FT_RMA_SYNC_MSG_BYTES);
		}
		ret = ft_get_rx_comp(rx_seq - 1);
		if (ret)
			return ret;
		return ft_tx(ep, remote_fi_addr,
			     FT_RMA_SYNC_MSG_BYTES, &tx_ctx);
	}

	return ft_get_tx_comp(tx_seq);
}

static int bandwidth_rma_high_pps(struct fi_rma_iov *remote)
{
	int ret, i, j;
	size_t offset;
	size_t rma_start_offset;

	ret = ft_sync();
	if (ret)
		return ret;

	rma_start_offset = FT_RMA_SYNC_MSG_BYTES +
			   MAX(ft_tx_prefix_size(), ft_rx_prefix_size());

	for (i = j = 0; i < opts.iterations + opts.warmup_iterations; i++) {
		if (i == opts.warmup_iterations) {
			ret = bw_comp();
			if (ret)
				return ret;
			j = 0;
			ft_start();
		}

		offset = rma_start_offset +
			 (j % opts.window_size) * opts.transfer_size;

		if (opts.rma_op == FT_RMA_WRITEDATA && !opts.dst_addr) {
			if (fi->rx_attr->mode & FI_RX_CQ_DATA)
				ret = ft_post_rx(ep, 0,
						 &rx_ctx_arr[j].context);
			else
				rx_seq++;
		} else {
			ret = post_rma_write(tx_buf + offset,
					     opts.transfer_size, remote,
					     &tx_ctx_arr[j].context, 0);
		}
		if (ret)
			return ret;

		if (++j == opts.window_size) {
			ret = bw_comp();
			if (ret)
				return ret;
			j = 0;
		}
	}

	ret = bw_comp();
	if (ret)
		return ret;

	ft_stop();
	if (opts.machr)
		show_perf_mr(opts.transfer_size, opts.iterations, &start, &end,
			     1, opts.argc, opts.argv);
	else
		show_perf(NULL, opts.transfer_size, opts.iterations, &start,
			  &end, 1);

	return 0;
}

static int run(void)
{
	int i, ret;

	ret = ft_init_fabric();
	if (ret)
		return ret;

	ret = ft_exchange_keys(&remote);
	if (ret)
		return ret;

	if (!(opts.options & FT_OPT_SIZE)) {
		for (i = 0; i < TEST_CNT; i++) {
			if (!ft_use_size(i, opts.sizes_enabled))
				continue;
			opts.transfer_size = test_size[i].size;
			init_test(&opts, test_name, sizeof(test_name));
			ret = bandwidth_rma_high_pps(&remote);
			if (ret)
				goto out;
		}
	} else {
		init_test(&opts, test_name, sizeof(test_name));
		ret = bandwidth_rma_high_pps(&remote);
		if (ret)
			goto out;
	}

	ft_finalize();
out:
	return ret;
}

enum {
	OPT_HIGH_PPS = 256,
};

static struct option high_pps_long_opts[] = {
	{"high-pps", no_argument, NULL, OPT_HIGH_PPS},
	{0, 0, 0, 0}
};

int main(int argc, char **argv)
{
	int op, ret, cleanup_ret;

	opts = INIT_OPTS;
	opts.options |= FT_OPT_BW;
	opts.rma_op = FT_RMA_WRITE;

	hints = fi_allocinfo();
	if (!hints)
		return EXIT_FAILURE;

	hints->caps = FI_MSG | FI_RMA;
	hints->domain_attr->resource_mgmt = FI_RM_ENABLED;
	hints->mode = FI_CONTEXT | FI_CONTEXT2;
	hints->domain_attr->threading = FI_THREAD_DOMAIN;
	hints->addr_format = opts.address_format;

	while ((op = getopt_long(argc, argv, "h" CS_OPTS INFO_OPTS API_OPTS
			    BENCHMARK_OPTS, high_pps_long_opts,
			    &lopt_idx)) != -1) {
		switch (op) {
		case OPT_HIGH_PPS:
			use_high_pps = 1;
			break;
		case '?':
		case 'h':
			ft_csusage(argv[0],
				   "RMA write bandwidth with EFA high PPS hint.");
			ft_benchmark_usage();
			fprintf(stderr, "  -o <op>             "
				"RMA op type: write|writedata (default: write)\n");
			fprintf(stderr, "  --high-pps          "
				"Enable FI_EFA_WR_HIGH_PPS flag on writes\n");
			ft_longopts_usage();
			return EXIT_FAILURE;
		default:
			if (!ft_parse_long_opts(op, optarg))
				continue;
			ft_parse_benchmark_opts(op, optarg);
			ft_parse_api_opts(op, optarg, hints, &opts);
			ft_parseinfo(op, optarg, hints, &opts);
			ft_parsecsopts(op, optarg, &opts);
			break;
		}
	}

	if (optind < argc)
		opts.dst_addr = argv[optind];

	hints->domain_attr->mr_mode = opts.mr_mode;
	hints->tx_attr->tclass = FI_TC_BULK_DATA;

	if (use_high_pps)
		printf("High PPS mode: ENABLED\n");
	else
		printf("High PPS mode: DISABLED\n");

	printf("RMA op: %s\n",
	       opts.rma_op == FT_RMA_WRITEDATA ? "WRITEDATA" : "WRITE");

	ret = run();

	cleanup_ret = ft_free_res();
	return -(ret ? ret : cleanup_ret);
}
