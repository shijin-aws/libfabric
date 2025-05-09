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
static struct fid_cq **txcqs, **rxcqs;
static struct fid_av **avs;
static fi_addr_t *remote_fiaddr;
static bool shared_cq = false;
static bool shared_av = false;
int num_eps = 3;
static int start_idx = 0;

enum {
	LONG_OPT_SHARED_AV,
	LONG_OPT_SHARED_CQ,
};

struct thread_context {
	int idx;
	pthread_t thread;
	int num_cqes;
};

struct thread_context *contexts_ep;
struct thread_context *contexts_cq;

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
		FT_CLOSE_FID(txcqs[i]);
		FT_CLOSE_FID(rxcqs[i]);
		FT_CLOSE_FID(avs[i]);
	}

	free(txcqs);
	free(rxcqs);
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

	txcqs = calloc(num_eps, sizeof(*txcqs));
	rxcqs = calloc(num_eps, sizeof(*rxcqs));
	avs = calloc(num_eps, sizeof(*avs));

	if (!eps || !remote_fiaddr || !send_bufs || !recv_bufs ||
	    !send_ctx || !recv_ctx || !send_bufs || !recv_bufs ||
	    !send_mrs || !recv_mrs || !send_descs || !recv_descs ||
	    !txcqs || !rxcqs || !peer_iovs)
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
	int ret, cq_read_idx = idx;

	if (shared_cq)
		cq_read_idx = 0;

	do {
		ret = fi_recv(eps[idx], recv_bufs[idx], opts.transfer_size,
			      recv_descs[idx], FI_ADDR_UNSPEC,
			      &recv_ctx[idx]);
		if (ret == -FI_EAGAIN)
			(void) fi_cq_read(rxcqs[cq_read_idx], NULL, 0);

	} while (ret == -FI_EAGAIN);

	return ret;
}

static int ep_post_tx(int idx, size_t len)
{
	int ret, cq_read_idx = idx;

	if (shared_cq)
		cq_read_idx = 0;

	do {
		ret = fi_send(eps[idx], send_bufs[idx], len,
			      send_descs[idx], remote_fiaddr[idx],
			      &send_ctx[idx]);
		if (ret == -FI_EAGAIN)
			(void) fi_cq_read(txcqs[cq_read_idx], NULL, 0);

	} while (ret == -FI_EAGAIN);

	return ret;
}

static int ep_post_write(int idx)
{
	int ret, cq_read_idx = idx;

	if (shared_cq)
		cq_read_idx = 0;

	do {
		ret = fi_write(eps[idx], send_bufs[idx], opts.transfer_size,
			       send_descs[idx], remote_fiaddr[idx],
			       peer_iovs[idx].addr, peer_iovs[idx].key,
			       &send_ctx[idx]);
		if (ret == -FI_EAGAIN)
			(void) fi_cq_read(txcqs[cq_read_idx], NULL, 0);

	} while (ret == -FI_EAGAIN);

	return ret;
}

static int get_one_comp(struct fid_cq *cq)
{
	struct fi_cq_err_entry comp;
	int ret, i;

	do {
		ret = fi_cq_read(cq, &comp, 1);
		if (ret > 0)
			break;

		if (ret < 0 && ret != -FI_EAGAIN) {
			printf("fi_cq_read returns error %d\n", ret);
			return ret;
		}

		if (!shared_cq) {
			/* Drive progress on all EPs in case peer is waiting on
			 * different EP pair
			 */
			for (i = 0; i < num_eps; i++)
				(void) fi_cq_read(rxcqs[i], NULL, 0);
		}
	} while (1);

	return FI_SUCCESS;
}

static int sync_all(void)
{
	int i, ret, cq_read_idx;

	for (i = start_idx; i < num_eps; i++) {
		ret = ep_post_rx(i);
		if (ret) {
			FT_PRINTERR("fi_recv", ret);
			return ret;
		}

		ret = ep_post_tx(i, 0);
		if (ret) {
			FT_PRINTERR("fi_send", ret);
			return ret;
		}

		cq_read_idx = shared_cq ? 0 : i;

		ret = get_one_comp(txcqs[cq_read_idx]);
		if (ret)
			return ret;

		ret = get_one_comp(rxcqs[cq_read_idx]);
		if (ret)
			return ret;
	}
	return FI_SUCCESS;
}

static void *post_sends(void *context)
{
	int idx, ret;
	size_t len;

	idx = ((struct thread_context *) context)->idx;

	//printf("Thread %d: Send RMA info to remote EPs\n", i);
	
	len = opts.transfer_size;

	printf("Thread %d: post send for ep %d \n", idx, idx);
	ret = ep_post_tx(idx, len);
	if (ret) {
		FT_PRINTERR("fi_send", ret);
		return NULL;
	}

	return NULL;
}

static void *close_first_av(void *context)
{
	/* Now close the first ep and destroy the av */
	int idx = ((struct thread_context *) context)->idx;

	printf("Thread %d: Close the first ep and destroy av\n", idx);
	FT_CLOSE_FID(eps[0]);
	printf("ep close finishes\n");
	if (!shared_av)
		FT_CLOSE_FID(avs[0]);

	return NULL;
}

static void *poll_tx_cq(void *context)
{
	int i, ret;
	int num_cqes = 0;

	i = ((struct thread_context *) context)->idx;

	printf("Client: thread %d polling tx cq for %d cqes\n", i, ((struct thread_context *) context)->num_cqes);

	while (num_cqes < ((struct thread_context *) context)->num_cqes) {
		
		ret = get_one_comp(txcqs[i]);
		if (ret)
			return NULL;
		num_cqes++;
		printf("Client: thread %d get %d completion from tx cq \n", i, num_cqes);
	}

	return NULL;
}

static int run_server(void)
{
	int i, ret, cq_read_idx;

	for (i = 0; i < num_eps; i++) {
		printf("Server: posting recv to ep %d\n", i);
		ret = ep_post_rx(i);
		if (ret) {
			FT_PRINTERR("fi_recv", ret);
			return ret;
		}
	}

	printf("Server: wait for completions\n");
	for (i = 0; i < num_eps; i++) {
		cq_read_idx = shared_cq ? 0 : i;
		ret = get_one_comp(rxcqs[cq_read_idx]);
		if (ret)
			return ret;
		printf("Server: Get %d completions from rx cq\n", i);
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
	contexts_cq = calloc(num_eps,  sizeof(struct thread_context));

	for (i=0; i< num_eps; i++) {
		contexts_ep[i].idx = i;
		contexts_cq[i].idx = i;
		contexts_cq[i].num_cqes = 1;
	}

	if (shared_cq)
		contexts_cq[0].num_cqes = num_eps;


	if (!shared_cq) {
		for (i = 0; i < num_eps; i++) {
			ret = pthread_create(&contexts_cq[i].thread, NULL, poll_tx_cq,  &contexts_cq[i]);
			if (ret)
				printf("Client: thread %d poll_tx_cq create failed: %d\n", i, ret);
		}
	} else {
		pthread_create(&contexts_cq[0].thread, NULL, poll_tx_cq,  &contexts_cq[0]);
	}

	for (i = 0; i < num_eps; i++) {
		ret = pthread_create(&contexts_ep[i].thread, NULL, post_sends,  &contexts_ep[i]);
		if (ret)
			printf("Client: thread %d post_sends create failed: %d\n", i, ret);
	}

	//ret = pthread_create(&contexts_ep[0].thread, NULL, close_first_av, &contexts_ep[0]);
	//if (ret)
	//	printf("Client: thread 0 close_first_av create failed: %d\n", ret);

	

	if (!shared_cq) {
		for (i = 0; i < num_eps; i++)
			pthread_join(contexts_cq[i].thread, NULL);
	} else {
		pthread_join(contexts_cq[0].thread, NULL);
	}

	for (i=0; i<num_eps; i++)
		pthread_join(contexts_ep[i].thread, NULL);

	printf("Client: PASSED multi ep sends\n");
	return 0;
}

static int setup_av_ep(int idx)
{
	int ret;

	ret = fi_getinfo(FT_FIVERSION, opts.src_addr, NULL, 0, hints, &fi);
	if (ret) {
		FT_PRINTERR("fi_getinfo", ret);
		return ret;
	}

	ret = fi_endpoint(domain, fi, &eps[idx], NULL);
	if (ret) {
		FT_PRINTERR("fi_endpoint", ret);
		return ret;
	}

	ret = ft_alloc_ep_res(fi, &txcqs[idx], &rxcqs[idx], NULL, NULL, NULL, &avs[idx]);
	if (ret)
		return ret;

	return 0;
}

static int enable_ep(int idx)
{
	int ret, av_bind_idx = idx, cq_bind_idx = idx;

	if (shared_cq)
		cq_bind_idx = 0;

	if (shared_av)
		av_bind_idx = 0;

	ret = ft_enable_ep(eps[idx], eq, avs[av_bind_idx], txcqs[cq_bind_idx], rxcqs[cq_bind_idx],
			   NULL, NULL, NULL);
	if (ret)
		return ret;

	ret = ft_init_av_addr(avs[av_bind_idx], eps[idx], &remote_fiaddr[idx]);
	if (ret)
		return ret;

	return 0;
}

static int set_up_client(int i) {
	int ret;

	ret = setup_av_ep(i);
	if (ret)
		return ret;

	ret = enable_ep(i);
	if (ret)
		return ret;
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

	/* Create additional endpoints. */
	printf("Creating %d EPs\n", num_eps);
	for (i = 0; i < num_eps; i++) {
		ret = setup_av_ep(i);
		if (ret)
			goto out;
	}

	ret = reg_mrs();
	if (ret)
		goto out;

	for (i = 0; i < num_eps; i++) {
		ret = enable_ep(i);
		if (ret)
			goto out;
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
		case 'A':
			shared_av = true;
			break;
		case 'Q':
			shared_cq = true;
			break;
		case '?':
		case 'h':
			ft_usage(argv[0], "Multi endpoint test");
			FT_PRINT_OPTS_USAGE("-c <int>",
				"number of endpoints to create and test (def 3)");
			FT_PRINT_OPTS_USAGE("-v", "Enable data verification");
			FT_PRINT_OPTS_USAGE("-Q",
				"Share tx/rx cq among endpoints. \n"
				"By default each ep has its own tx/rx cq");
			FT_PRINT_OPTS_USAGE("-A",
				"Share the av among endpoints. \n"
				"By default each ep has its own av");
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
