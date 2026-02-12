/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/* SPDX-FileCopyrightText: Copyright Amazon.com, Inc. or its affiliates. All rights reserved. */

/**
 * FI_MORE test with separate send and CQ threads
 * Client has 2 threads:
 * - Send thread: Posts batches of sends with FI_MORE flag
 * - CQ thread: Polls TX completions and prints context pointers
 */

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

#include <rdma/fabric.h>
#include <rdma/fi_endpoint.h>
#include <rdma/fi_errno.h>

#include "shared.h"

#define BATCH_SIZE 64
#define CQ_BATCH_SIZE 64

static pthread_t send_thread, cq_thread;
static struct fi_context2 *send_contexts;
static void **received_contexts;  // Track received contexts
static int total_sends;
static volatile int sends_posted = 0;
static volatile int sends_completed = 0;

static void *send_thread_func(void *arg)
{
	int ret, i, batch_idx;
	struct fi_msg msg;
	struct iovec iov;
	uint64_t flags;
	
	printf("Send thread: Starting to post %d sends in batches of %d\n", 
	       total_sends, BATCH_SIZE);
	
	iov.iov_base = tx_buf;
	iov.iov_len = opts.transfer_size;
	
	msg.msg_iov = &iov;
	msg.desc = &mr_desc;
	msg.iov_count = 1;
	msg.addr = remote_fi_addr;
	msg.data = 0;
	
	for (i = 0; i < total_sends; i++) {
		batch_idx = i % BATCH_SIZE;
		
		// Set FI_MORE for first 63 sends in batch, clear for last send
		flags = (batch_idx < BATCH_SIZE - 1) ? FI_MORE : 0;
		
		msg.context = &send_contexts[i];
		
		//printf("Send thread: Posting send %d, context=%p, flags=0x%lx\n", 
		  //     i, msg.context, flags);
		
		ret = fi_sendmsg(ep, &msg, flags);
		if (ret) {
			FT_PRINTERR("fi_sendmsg", ret);
			return NULL;
		}
		
		sends_posted++;
	}
	
	printf("Send thread: Posted all %d sends\n", total_sends);
	return NULL;
}

static void *cq_thread_func(void *arg)
{
	int ret, i, j, num_comps;
	struct fi_cq_entry comps[CQ_BATCH_SIZE];
	bool error_found = false;
	
	printf("CQ thread: Starting to poll completions in batches of %d\n", CQ_BATCH_SIZE);
	
	while (sends_completed < total_sends) {
		ret = fi_cq_read(txcq, comps, CQ_BATCH_SIZE);
		if (ret > 0) {
			num_comps = ret;
			for (j = 0; j < num_comps; j++) {
				// Check for NULL context
				if (comps[j].op_context == NULL) {
					printf("ERROR: NULL context found at completion %d!\n", 
					       sends_completed + 1);
					error_found = true;
				}

				// Check for duplicate context
				for (i = 0; i < sends_completed; i++) {
					if (received_contexts[i] == comps[j].op_context) {
						printf("ERROR: Duplicate context %p found at completion %d!\n", 
						       comps[j].op_context, sends_completed + 1);
						error_found = true;
						break;
					}
				}

				received_contexts[sends_completed] = comps[j].op_context;
				//printf("CQ thread: Got completion %d, context=%p\n", 
				//       sends_completed + 1, comps[j].op_context);
				sends_completed++;
			}
		} else if (ret < 0 && ret != -FI_EAGAIN) {
			FT_PRINTERR("fi_cq_read", ret);
			return NULL;
		}
	}
	
	if (error_found) {
		printf("CQ thread: FAILED - NULL or duplicate contexts detected!\n");
	} else {
		printf("CQ thread: PASSED - got all %d unique non-NULL completions\n", total_sends);
	}
	return NULL;
}

static int run_client(void)
{
	int ret;
	
	total_sends = opts.iterations;
	
	// Allocate contexts for all sends (each context is unique)
	send_contexts = calloc(total_sends, sizeof(*send_contexts));
	if (!send_contexts) {
		FT_ERR("Failed to allocate send contexts");
		return -FI_ENOMEM;
	}
	
	// Allocate array to track received contexts
	received_contexts = calloc(total_sends, sizeof(*received_contexts));
	if (!received_contexts) {
		FT_ERR("Failed to allocate received contexts array");
		free(send_contexts);
		return -FI_ENOMEM;
	}
	
	// Create threads
	ret = pthread_create(&send_thread, NULL, send_thread_func, NULL);
	if (ret) {
		FT_ERR("Failed to create send thread");
		goto cleanup;
	}
	
	ret = pthread_create(&cq_thread, NULL, cq_thread_func, NULL);
	if (ret) {
		FT_ERR("Failed to create CQ thread");
		goto cleanup;
	}
	
	// Wait for threads to complete
	pthread_join(send_thread, NULL);
	pthread_join(cq_thread, NULL);
	
	printf("Client: PASSED FI_MORE test - posted %d, completed %d\n", 
	       sends_posted, sends_completed);
	
cleanup:
	free(send_contexts);
	free(received_contexts);
	return ret;
}

static int run_server(void)
{
	int ret, i;
	struct fi_cq_data_entry comp;
	int num_recvs = 0;
	
	// Post receive buffers
	printf("Server: Posting %d receive buffers\n", opts.iterations);
	for (i = 0; i < opts.iterations; i++) {
		ret = ft_post_rx(ep, opts.transfer_size, &rx_ctx);
		if (ret) {
			FT_PRINTERR("ft_post_rx", ret);
			return ret;
		}
	}
	
	// Wait for completions
	printf("Server: Waiting for completions\n");
	while (num_recvs < opts.iterations) {
		ret = fi_cq_read(rxcq, &comp, 1);
		if (ret > 0) {
			num_recvs++;
			if (num_recvs % 100 == 0 || num_recvs == opts.iterations) {
				printf("Server: Received %d messages\n", num_recvs);
			}
		} else if (ret < 0 && ret != -FI_EAGAIN) {
			FT_PRINTERR("fi_cq_read", ret);
			return ret;
		}
	}
	
	printf("Server: PASSED - received all %d messages\n", opts.iterations);
	return 0;
}

int main(int argc, char **argv)
{
	int op, ret;
	
	opts = INIT_OPTS;
	opts.iterations = 1024;  // Default iterations
	opts.transfer_size = 64;
	
	hints = fi_allocinfo();
	if (!hints)
		return EXIT_FAILURE;
	
	hints->caps = FI_MSG;
	hints->mode = FI_CONTEXT | FI_CONTEXT2;
	hints->ep_attr->type = FI_EP_RDM;
	hints->domain_attr->mr_mode = FI_MR_VIRT_ADDR | FI_MR_ALLOCATED | FI_MR_PROV_KEY | FI_MR_LOCAL;
	
	// Parse command line options
	while ((op = getopt_long(argc, argv, "h" ADDR_OPTS INFO_OPTS CS_OPTS,
				 long_opts, &lopt_idx)) != -1) {
		switch (op) {
		default:
			if (!ft_parse_long_opts(op, optarg))
				continue;
			ft_parse_addr_opts(op, optarg, &opts);
			ft_parseinfo(op, optarg, hints, &opts);
			ft_parsecsopts(op, optarg, &opts);
			break;
		case '?':
		case 'h':
			ft_usage(argv[0], "FI_MORE test with separate send and CQ threads");
			return EXIT_FAILURE;
		}
	}
	
	if (optind < argc)
		opts.dst_addr = argv[optind];
	
	// Initialize fabric
	ret = ft_init_fabric();
	if (ret)
		return ret;
	
	if (opts.dst_addr) {
		ret = run_client();
	} else {
		ret = run_server();
	}
	
	ft_free_res();
	return ft_exit_code(ret);
}