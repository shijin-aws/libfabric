/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/* SPDX-FileCopyrightText: Copyright Amazon.com, Inc. or its affiliates. All rights reserved. */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <time.h>
#include <netdb.h>
#include <unistd.h>

#include <rdma/fabric.h>
#include <rdma/fi_errno.h>
#include <rdma/fi_tagged.h>
#include <rdma/fi_endpoint.h>
#include <rdma/fi_rma.h>
#include <rdma/fi_cm.h>

#include "shared.h"
#include "hmem.h"
#include <pthread.h>

static struct fid_ep **eps;
static char **send_bufs, **recv_bufs;
static struct fid_mr **send_mrs, **recv_mrs;
static void **send_descs, **recv_descs;
static struct fi_rma_iov *peer_iovs;
static struct fi_context2 *recv_ctx;
static struct fi_context2 *send_ctx;
static struct fid_av **avs;
static fi_addr_t *remote_fiaddr;
int num_eps = 3;
static int start_idx = 0;


struct thread_context {
	int idx;
	pthread_t thread;
	int num_cqes;
};

struct thread_context *contexts_ep;
struct thread_context context_cq;

static void free_ep_res()
{
	int i;

	for (i = 0; i < num_eps; i++) {
		if (fi->domain_attr->mr_mode & FI_MR_RAW)
			(void) fi_mr_unmap_key(domain, peer_iovs[i].key);

		FT_CLOSE_FID(send_mrs[i]);
		FT_CLOSE_FID(recv_mrs[i]);
		FT_CLOSE_FID(eps[i]);

		(void) ft_hmem_free(opts.iface, (void *) send_bufs[i]);
		(void) ft_hmem_free(opts.iface, (void *) recv_bufs[i]);
	}

	for (i = 0; i < num_eps; i++) {
		FT_CLOSE_FID(avs[i]);
	}

	free(send_bufs);
	free(recv_bufs);
	free(send_mrs);
	free(recv_mrs);
	free(peer_iovs);
	free(send_descs);
	free(recv_descs);
	free(send_ctx);
	free(recv_ctx);
	free(remote_fiaddr);
	free(eps);
	free(avs);
}

static int reg_mrs(void)
{
	int i, ret;

	for (i = 0; i < num_eps; i++) {
		ret = ft_reg_mr(fi, send_bufs[i], opts.transfer_size,
				ft_info_to_mr_access(fi),
				(FT_MR_KEY + 1) * (i + 1), opts.iface,
				opts.device, &send_mrs[i], &send_descs[i]);
		if (ret)
			return ret;

		ret = ft_reg_mr(fi, recv_bufs[i], opts.transfer_size,
				ft_info_to_mr_access(fi),
				(FT_MR_KEY + 2) * (i + 2), opts.iface,
				opts.device, &recv_mrs[i], &recv_descs[i]);
		if (ret)
			return ret;
	}

	return FI_SUCCESS;
}

static int alloc_multi_ep_res()
{
	int i, ret;

	eps = calloc(num_eps, sizeof(*eps));
	remote_fiaddr = calloc(num_eps, sizeof(*remote_fiaddr));
	send_mrs = calloc(num_eps, sizeof(*send_mrs));
	recv_mrs = calloc(num_eps, sizeof(*recv_mrs));
	send_descs = calloc(num_eps, sizeof(*send_descs));
	recv_descs = calloc(num_eps, sizeof(*recv_descs));
	peer_iovs = calloc(num_eps, sizeof(*peer_iovs));
	send_ctx = calloc(num_eps, sizeof(*send_ctx));
	recv_ctx = calloc(num_eps, sizeof(*recv_ctx));
	send_bufs = calloc(num_eps, opts.transfer_size);
	recv_bufs = calloc(num_eps, opts.transfer_size);

	avs = calloc(num_eps, sizeof(*avs));

	if (!eps || !remote_fiaddr || !send_bufs || !recv_bufs ||
	    !send_ctx || !recv_ctx || !send_bufs || !recv_bufs ||
	    !send_mrs || !recv_mrs || !send_descs || !recv_descs ||
	    !peer_iovs)
		return -FI_ENOMEM;

	for (i = 0; i < num_eps; i++) {
		ret = ft_hmem_alloc(opts.iface, opts.device,
				    (void **) &send_bufs[i], opts.transfer_size);
		if (ret)
			return ret;

		ret = ft_hmem_alloc(opts.iface, opts.device,
				    (void **) &recv_bufs[i], opts.transfer_size);
		if (ret)
			return ret;
	}

	return 0;
}

static int ep_post_rx(int idx)
{
	int ret;

	do {
		ret = fi_recv(eps[idx], recv_bufs[idx], opts.transfer_size,
			      recv_descs[idx], FI_ADDR_UNSPEC,
			      &recv_ctx[idx]);
		if (ret == -FI_EAGAIN)
			(void) fi_cq_read(rxcq, NULL, 0);

	} while (ret == -FI_EAGAIN);

	return ret;
}

static int ep_post_tx(int idx, size_t len)
{
	int ret;

	do {
		ret = fi_send(eps[idx], send_bufs[idx], len,
			      send_descs[idx], remote_fiaddr[idx],
			      &send_ctx[idx]);
		if (ret == -FI_EAGAIN)
			(void) fi_cq_read(txcq, NULL, 0);

	} while (ret == -FI_EAGAIN);

	return ret;
}

static int get_one_comp(struct fid_cq *cq)
{
	struct fi_cq_err_entry comp;
	struct fi_cq_err_entry cq_err;

	memset(&cq_err, 0, sizeof(cq_err));
	int ret, i;

	do {
		ret = fi_cq_read(cq, &comp, 1);
		if (ret > 0)
			break;

		if (ret < 0 && ret != -FI_EAGAIN) {
			printf("fi_cq_read returns error %d\n", ret);
			(void) fi_cq_readerr(cq, &cq_err, 0);
			return ret;
		}
	} while (1);

	return FI_SUCCESS;
}

static void *post_sends(void *context)
{
	int idx, ret;
	size_t len;

	idx = ((struct thread_context *) context)->idx;

	//printf("Thread %d: Send RMA info to remote EPs\n", i);
	
	len = opts.transfer_size;
	open_client(idx);

	printf("Thread %d: post send for ep %d \n", idx, idx);
	ret = ep_post_tx(idx, len);
	if (ret) {
		FT_PRINTERR("fi_send", ret);
		return NULL;
	}

	sleep(1);
	// exit
	printf("Thread %d: closing client\n", idx);
	close_client(idx);
	return NULL;
}


static void *poll_tx_cq(void *context)
{
	int i, ret;
	int num_cqes = 0;

	i = ((struct thread_context *) context)->idx;

	printf("Client: thread %d polling tx cq for %d cqes\n", i, ((struct thread_context *) context)->num_cqes);

//	while (num_cqes < ((struct thread_context *) context)->num_cqes) {
	while (true) {
		
		ret = get_one_comp(txcq);
		if (ret)
			continue;
		num_cqes++;
		printf("Client: thread %d get %d completion from tx cq \n", i, num_cqes);
	}

	return NULL;
}

static int run_server(void)
{
	int i, j, ret;
	int num_cqes = 0;

	for (i = 0; i < num_eps; i++) {
		printf("Server: posting recv to ep %d\n", i);
		// posting multiple recv buffers for each ep
		// so the sent pkts can at least find a match
		for (j = 0; j < 10; j++) {
			ret = ep_post_rx(i);
			if (ret) {
				FT_PRINTERR("fi_recv", ret);
				return ret;
			}
		}
	}

	printf("Server: wait for completions\n");
	while (true) {
		//cq_read_idx = shared_cq ? 0 : i;
		ret = get_one_comp(rxcq);
		// ignore cq error
		if (ret)
			continue;
		num_cqes++;
		printf("Server: Get %d completions from rx cq\n", num_cqes);
	}

	printf("Server: PASSED multi ep recvs\n");
	return FI_SUCCESS;
}

static int run_client(void)
{
	char temp[FT_MAX_CTRL_MSG];
	struct fi_rma_iov *rma_iov = (struct fi_rma_iov *) temp;
	int i, ret;
	size_t key_size, len;

	len = opts.transfer_size;

	for (i = 0; i < num_eps; i++) {
		len = opts.transfer_size;
		ret = ft_fill_rma_info(recv_mrs[i], recv_bufs[i], rma_iov,
				       &key_size, &len);
		if (ret)
			return ret;

		ret = ft_hmem_copy_to(opts.iface, opts.device, send_bufs[i],
				      rma_iov, len);
		if (ret)
			return ret;
	}

	memset(peer_iovs, 0, sizeof(*peer_iovs) * num_eps);

	contexts_ep = calloc(num_eps,  sizeof(struct thread_context));

	for (i=0; i< num_eps; i++) {
		contexts_ep[i].idx = i;
	}

	context_cq.num_cqes = num_eps;
	context_cq.idx = num_eps + 1;

	pthread_create(&context_cq.thread, NULL, poll_tx_cq,  &context_cq);

	for (i = 0; i < num_eps; i++) {
		ret = pthread_create(&contexts_ep[i].thread, NULL, post_sends,  &contexts_ep[i]);
		if (ret)
			printf("Client: thread %d post_sends create failed: %d\n", i, ret);
	}

	//ret = pthread_create(&contexts_ep[0].thread, NULL, close_first_av, &contexts_ep[0]);
	//if (ret)
	//	printf("Client: thread 0 close_first_av create failed: %d\n", ret);

	pthread_join(context_cq.thread, NULL);

	for (i=0; i<num_eps; i++)
		pthread_join(contexts_ep[i].thread, NULL);

	printf("Client: PASSED multi ep sends\n");
	return 0;
}

static int setup_av_ep(int idx)
{
	int ret;
	struct fi_av_attr av_attr = {0};

	if (opts.av_name) {
		av_attr.name = opts.av_name;
	}
	av_attr.count = opts.av_size;

	ret = fi_endpoint(domain, fi, &eps[idx], NULL);
	if (ret) {
		FT_PRINTERR("fi_endpoint", ret);
		return ret;
	}

	ret = fi_av_open(domain, &av_attr, &avs[idx], NULL);
	if (ret) {
		FT_PRINTERR("fi_av_open", ret);
		return ret;
	}

	return 0;
}

static int enable_ep(int idx)
{
	int ret, av_bind_idx = idx, cq_bind_idx = idx;

	cq_bind_idx = 0;

	ret = ft_enable_ep(eps[idx], eq, avs[av_bind_idx], txcq, rxcq,
			   NULL, NULL, NULL);
	if (ret)
		return ret;

	ret = ft_init_av_addr(avs[av_bind_idx], eps[idx], &remote_fiaddr[idx]);
	if (ret)
		return ret;

	return 0;
}

int open_client(int i)
{
	int ret;

	printf("opening ep %d, av %d\n", i, i);
	ret = setup_av_ep(i);
	if (ret)
		return ret;

	ret = enable_ep(i);
	if (ret)
		return ret;

	return 0;
}

void close_client(int i)
{
	printf("closing ep %d, av %d\n", i, i);
	FT_CLOSE_FID(eps[i]);
	FT_CLOSE_FID(avs[i]);
}

static int run_test(void)
{
	int i, ret;

	opts.av_size = num_eps + 1;
	ret = ft_init_fabric();
	if (ret)
		return ret;

	ret = alloc_multi_ep_res();
	if (ret)
		return ret;

	ret = reg_mrs();
	if (ret)
		goto out;

	/* Create additional endpoints. */
	if (!opts.dst_addr) {
		printf("Creating %d EPs\n", num_eps);
		for (i = 0; i < num_eps; i++) {
			ret = setup_av_ep(i);
			if (ret)
				goto out;
		}

		for (i = 0; i < num_eps; i++) {
			ret = enable_ep(i);
			if (ret)
				goto out;
		}
	}

	if (opts.dst_addr)
		ret = run_client();
	else
		ret = run_server();

	if (ret)
		goto out;

	//ret = do_rma();
	//if (ret)
	//	goto out;

	ret = ft_finalize_ep(ep);
out:
	free_ep_res();
	return ret;
}

int main(int argc, char **argv)
{
	int op;
	int ret = 0;

	opts = INIT_OPTS;
	opts.transfer_size = 256;
	opts.options |= FT_OPT_OOB_ADDR_EXCH;

	hints = fi_allocinfo();
	if (!hints)
		return EXIT_FAILURE;

	while ((op = getopt_long(argc, argv, "c:vhAQ" ADDR_OPTS INFO_OPTS CS_OPTS,
				 long_opts, &lopt_idx)) != -1) {
		switch (op) {
		default:
			if (!ft_parse_long_opts(op, optarg))
				continue;
			ft_parse_addr_opts(op, optarg, &opts);
			ft_parseinfo(op, optarg, hints, &opts);
			ft_parsecsopts(op, optarg, &opts);
			break;
		case 'c':
			num_eps = atoi(optarg);
			break;
		case 'v':
			opts.options |= FT_OPT_VERIFY_DATA;
			break;
		case '?':
		case 'h':
			ft_usage(argv[0], "Multi endpoint test");
			FT_PRINT_OPTS_USAGE("-c <int>",
				"number of endpoints to create and test (def 3)");
			FT_PRINT_OPTS_USAGE("-v", "Enable data verification");
			return EXIT_FAILURE;
		}
	}

	if (optind < argc)
		opts.dst_addr = argv[optind];

	opts.threading = FI_THREAD_SAFE;
	hints->caps = FI_MSG | FI_RMA;
	hints->mode = FI_CONTEXT | FI_CONTEXT2;
	hints->domain_attr->mr_mode = opts.mr_mode;
	hints->addr_format = opts.address_format;

	ret = run_test();

	ft_free_res();
	return ft_exit_code(ret);
}
