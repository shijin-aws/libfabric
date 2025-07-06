#include <arpa/inet.h>
#include <getopt.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <rdma/fabric.h>
#include <rdma/fi_cm.h>
#include <rdma/fi_domain.h>
#include <rdma/fi_endpoint.h>
#include <rdma/fi_errno.h>
#include <rdma/fi_rma.h>
#include <rdma/fi_tagged.h>

#include "hmem.h"
#include "shared.h"
#include <pthread.h>

#define MAX_WORKERS	64
#define MAX_PEERS	MAX_WORKERS
#define MAX_EP_ADDR_LEN 256
#define MAX_MESSAGES	1000
#define NOTIFY_PORT	8000

// Message types
#define MSG_TYPE_EP_UP	     1
#define MSG_TYPE_EP_DOWN     2
#define MSG_TYPE_EP_UPDATE   3
#define MSG_TYPE_EP_TEARDOWN 4

#define TEST_CQDATA 0xAAAA // Hardcoded CQ data for fi_writedata

// Configuration structure
struct test_opts {
	int num_sender_workers;
	int num_receiver_workers;
	int msgs_per_endpoint;
	int sender_ep_recycling; // Number of times for sender to recycle
				 // endpoints
	int receiver_ep_recycling; // Number of times for receiver to recycle
				   // endpoints
    bool shared_av;        // New: use shared AV
    bool shared_cq;        // New: use shared CQ
    enum {
        OP_MSG_UNTAGGED = 0,
        OP_MSG_TAGGED,
        OP_RMA_WRITEDATA
    } op_type;
    bool verbose;
};

// Global variables
static struct test_opts topts = {
	.num_sender_workers = 1,
	.num_receiver_workers = 1,
	.msgs_per_endpoint = 1000,
	.sender_ep_recycling = 1, // Default to 1 recycling for sender
	.receiver_ep_recycling = 1, // Default to 1 recycling for receiver
    .shared_av = false,    // Default: per-worker AV
    .shared_cq = false,    // Default: per-worker CQ
    .op_type = OP_MSG_UNTAGGED,
    .verbose = true
};

enum {
    OPT_SENDER_WORKERS = 256,
    OPT_RECEIVER_WORKERS,
    OPT_MSGS_PER_EP,
    OPT_SENDER_EP_CYCLES,
    OPT_RECEIVER_EP_CYCLES,
    OPT_SHARED_AV,
    OPT_SHARED_CQ,
    OPT_OP_TYPE
};

static struct option test_long_opts[] = {
    {"sender-workers", required_argument, NULL, OPT_SENDER_WORKERS},
    {"receiver-workers", required_argument, NULL, OPT_RECEIVER_WORKERS},
    {"msgs-per-ep", required_argument, NULL, OPT_MSGS_PER_EP},
    {"sender-ep-cycles", required_argument, NULL, OPT_SENDER_EP_CYCLES},
    {"receiver-ep-cycles", required_argument, NULL, OPT_RECEIVER_EP_CYCLES},
    {"shared-av", no_argument, NULL, OPT_SHARED_AV},
    {"shared-cq", no_argument, NULL, OPT_SHARED_CQ},
    {"op-type", required_argument, NULL, OPT_OP_TYPE},
    {0, 0, 0, 0}
};

// Endpoint status
enum ep_status {
    EP_INIT,
    EP_READY,
    EP_SENDING,
    EP_RECEIVING,
    EP_TEARDOWN
};

// RMA information
struct rma_info {
	uint64_t remote_addr;
	uint64_t rkey;
	size_t length;
};

// Endpoint metadata
struct ep_info {
	uint32_t worker_id;
	char ep_addr[MAX_EP_ADDR_LEN];
	size_t addr_len;
	struct rma_info rma;
};

// Message structure for endpoint updates
struct ep_message {
	int msg_type;
	struct ep_info info;
};

// Worker status tracking
struct worker_status {
	pthread_mutex_t mutex;
	bool active;
	enum ep_status ep_status;
	uint64_t ep_generation;
};

// Common context structure
struct common_context {
	struct fid_ep *ep;
	struct fid_cq *cq;
	struct fid_av *av;
};

// Sender context
struct sender_context {
    struct common_context common;
    int worker_id;
    void *tx_buf;
    struct fid_mr *mr;
    struct fi_context2 *tx_ctx;
    fi_addr_t *peer_addrs;
    struct rma_info *peer_rma_info;  // Array of RMA info for each peer
    int num_peers;
    int control_sock;
    struct worker_status status;
    pthread_t notification_thread;
    int epoll_fd;
    uint64_t total_sent;
};


// Receiver context
struct receiver_context {
	struct common_context common;
	int worker_id;
	void *rx_buf;
	struct fid_mr *mr;
	struct fi_context2 *rx_ctx;
	struct worker_status status;
	uint64_t total_received;
	int *control_socks; // Array of control sockets for multiple
					// senders
	int num_senders; // Number of connected senders
};

// Setup endpoint for a worker
static int setup_endpoint(struct common_context *ctx)
{
	int ret;

	ret = fi_endpoint(domain, fi, &ctx->ep, NULL);
	if (ret) {
		FT_PRINTERR("fi_endpoint", ret);
		return ret;
	}

	struct fi_cq_attr cq_attr = {.format = FI_CQ_FORMAT_CONTEXT,
				     .wait_obj = FI_WAIT_NONE,
				     .size = topts.msgs_per_endpoint};

	ret = fi_cq_open(domain, &cq_attr, &ctx->cq, NULL);
	if (ret) {
		FT_PRINTERR("fi_cq_open", ret);
		goto cleanup_ep;
	}

	ret = fi_ep_bind(ctx->ep, &ctx->cq->fid, FI_SEND | FI_RECV);
	if (ret) {
		FT_PRINTERR("fi_ep_bind", ret);
		goto cleanup_cq;
	}

	ret = fi_enable(ctx->ep);
	if (ret) {
		FT_PRINTERR("fi_enable", ret);
		goto cleanup_cq;
	}

	return 0;

cleanup_cq:
	fi_close(&ctx->cq->fid);
	ctx->cq = NULL;
cleanup_ep:
	fi_close(&ctx->ep->fid);
	ctx->ep = NULL;
	return ret;
}

static void cleanup_endpoint(struct common_context *ctx)
{
	if (ctx->ep) {
		fi_close(&ctx->ep->fid);
		ctx->ep = NULL;
	}
	if (ctx->cq) {
		fi_close(&ctx->cq->fid);
		ctx->cq = NULL;
	}
}

// Notification handler thread for sender
void* notification_handler(void *arg)
{
    struct sender_context *ctx = (struct sender_context *)arg;
    struct epoll_event events[10];
    
    while (ctx->status.active) {
        int n = epoll_wait(ctx->epoll_fd, events, 10, 100);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            fprintf(stderr, "Sender %d: epoll_wait failed: %s\n", 
                    ctx->worker_id, strerror(errno));
            break;
        }
        
        for (int i = 0; i < n; i++) {
            if (events[i].data.fd == ctx->control_sock) {
                // Read all available messages
                while (1) {
                    struct ep_message msg;
                    size_t bytes_received = 0;
                    
                    // Read complete message
                    while (bytes_received < sizeof(msg)) {
                        int ret = recv(ctx->control_sock, 
                                     (char*)&msg + bytes_received,
                                     sizeof(msg) - bytes_received, 
                                     0);
                        if (ret <= 0) {
                            if (ret == 0) {
                                fprintf(stderr, "Sender %d: control connection closed\n", 
                                        ctx->worker_id);
                                goto connection_closed;
                            } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
                                if (bytes_received > 0) {
                                    // Partial message received, keep trying
                                    if (topts.verbose) {
                                        fprintf(stderr, "Sender %d: partial message received (%zu/%zu bytes), retrying\n",
                                                ctx->worker_id, bytes_received, sizeof(msg));
                                    }
                                    usleep(1000);  // Short delay before retry
                                    continue;  // Continue the inner while loop for more recv
                                } else {
                                    // No data at all, go back to epoll_wait
                                    goto wait_more_data;
                                }
                            } else if (errno == EINTR) {
                                // Interrupted, try again
                                continue;
                            } else {
                                fprintf(stderr, "Sender %d: recv failed: %s\n", 
                                        ctx->worker_id, strerror(errno));
                                goto connection_closed;
                            }
                        }
                        bytes_received += ret;
                    }

                    // Process complete message
                    pthread_mutex_lock(&ctx->status.mutex);
                    
                    int worker_idx = msg.info.worker_id / ctx->num_peers;
                    if (worker_idx < ctx->num_peers) {
                        fi_addr_t fi_addr;
                        int ret = fi_av_insert(ctx->common.av, msg.info.ep_addr, 1, 
                                             &fi_addr, 0, NULL);
                        if (ret == 1) {
                            ctx->peer_addrs[worker_idx] = fi_addr;
                            memcpy(&ctx->peer_rma_info[worker_idx], &msg.info.rma, 
                                   sizeof(struct rma_info));
                            if (topts.verbose) {
                                printf("Sender %d: Updated EP for receiver %d\n", 
                                       ctx->worker_id, msg.info.worker_id);
                            }
                        }
                    }
                    
                    pthread_mutex_unlock(&ctx->status.mutex);
                }
            }
        }
        continue;

wait_more_data:
        // Only reached when no data was received at all
        continue;

connection_closed:
        break;
    }
    return NULL;
}

/*
 * Setup control socket server for endpoint notifications.
 * @param port_str: Port number as string
 * @param sock: Pointer to store the created socket
 * @return 0 on success, negative error code on failure
 */
static int control_setup_server(const char *port_str, int *sock)
{
	int ret, optval = 1;
	struct addrinfo *ai, hints = {.ai_flags = AI_PASSIVE,
				      .ai_family = AF_UNSPEC,
				      .ai_socktype = SOCK_STREAM};

	ret = getaddrinfo(NULL, port_str, &hints, &ai);
	if (ret) {
		fprintf(stderr, "getaddrinfo() failed: %s\n",
			gai_strerror(ret));
		return -FI_EINVAL;
	}

	*sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
	if (*sock < 0) {
		ret = -errno;
		fprintf(stderr, "socket() failed: %s\n", strerror(errno));
		goto free_ai;
	}

	ret = setsockopt(*sock, SOL_SOCKET, SO_REUSEADDR, &optval,
			 sizeof(optval));
	if (ret) {
		ret = -errno;
		fprintf(stderr, "setsockopt(SO_REUSEADDR) failed: %s\n",
			strerror(errno));
		goto close_sock;
	}

	ret = bind(*sock, ai->ai_addr, ai->ai_addrlen);
	if (ret) {
		ret = -errno;
		fprintf(stderr, "bind() failed: %s\n", strerror(errno));
		goto close_sock;
	}

	ret = listen(*sock, topts.num_receiver_workers);
	if (ret) {
		ret = -errno;
		fprintf(stderr, "listen() failed: %s\n", strerror(errno));
		goto close_sock;
	}

	freeaddrinfo(ai);
	return 0;

close_sock:
	close(*sock);
	*sock = -1;
free_ai:
	freeaddrinfo(ai);
	return ret;
}

/*
 * Setup control socket client for endpoint notifications.
 * @param server_addr: Server address
 * @param port_str: Port number as string
 * @param sock: Pointer to store the created socket
 * @return 0 on success, negative error code on failure
 */
static int control_setup_client(const char *server_addr, const char *port_str,
				int *sock)
{
	int ret;
	struct addrinfo *ai,
		hints = {.ai_family = AF_UNSPEC, .ai_socktype = SOCK_STREAM};

	ret = getaddrinfo(server_addr, port_str, &hints, &ai);
	if (ret) {
		fprintf(stderr, "getaddrinfo() failed: %s\n",
			gai_strerror(ret));
		return -FI_EINVAL;
	}

	*sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
	if (*sock < 0) {
		ret = -errno;
		fprintf(stderr, "socket() failed: %s\n", strerror(errno));
		goto free_ai;
	}

	ret = connect(*sock, ai->ai_addr, ai->ai_addrlen);
	if (ret) {
		ret = -errno;
		fprintf(stderr, "connect() failed: %s\n", strerror(errno));
		goto close_sock;
	}

	freeaddrinfo(ai);
	return 0;

close_sock:
	close(*sock);
	*sock = -1;
free_ai:
	freeaddrinfo(ai);
	return ret;
}

static int calculate_worker_distribution(int sender_id, int *num_peers,
					 int *peer_ids)
{
	if (topts.num_sender_workers <= topts.num_receiver_workers) {
		// Original round-robin distribution
		*num_peers =
			topts.num_receiver_workers / topts.num_sender_workers;
		for (int i = 0; i < *num_peers; i++) {
			peer_ids[i] = sender_id + i * topts.num_sender_workers;
		}
	} else {
		// Multiple senders share the same receiver
		*num_peers = 1;
		peer_ids[0] = sender_id % topts.num_receiver_workers;
	}
	return 0;
}

static int wait_for_comp(struct fid_cq *cq, int num_completions)
{
	struct fi_cq_data_entry comp;
	int ret;
	int completed = 0;
	struct timespec a, b;

	if (timeout >= 0)
		clock_gettime(CLOCK_MONOTONIC, &a);

	while (completed < num_completions) {
		ret = fi_cq_read(cq, &comp, 1);
		if (ret > 0) {
			completed++;
			continue;
		} else if (ret < 0 && ret != -FI_EAGAIN) {
			struct fi_cq_err_entry err_entry;
			fi_cq_readerr(cq, &err_entry, 0);
			fprintf(stderr, "CQ read error: %s\n",
				fi_cq_strerror(cq, err_entry.prov_errno,
					       err_entry.err_data, NULL, 0));
		} else if (timeout >= 0) {
			clock_gettime(CLOCK_MONOTONIC, &b);
			if ((b.tv_sec - a.tv_sec) > timeout) {
				fprintf(stderr, "%ds timeout expired\n",
					timeout);
				return -FI_ENODATA;
			}
		}
	}

	return 0;
}

// Modified sender worker function
static int run_sender_worker(struct sender_context *ctx)
{
	int ret;
    uint64_t total_ops = 0;

	ctx->epoll_fd = epoll_create1(0);
	struct epoll_event ev = {.events = EPOLLIN,
				 .data.fd = ctx->control_sock};
	epoll_ctl(ctx->epoll_fd, EPOLL_CTL_ADD, ctx->control_sock, &ev);

	ctx->status.active = true;
	pthread_create(&ctx->notification_thread, NULL, notification_handler,
		       ctx);

    // Wait for initial peer addresses (only at startup)
    if (topts.verbose) {
        printf("Sender %d: Waiting for initial peer addresses\n", ctx->worker_id);
    }
    bool peers_ready = false;
    while (!peers_ready && ctx->status.active) {
        pthread_mutex_lock(&ctx->status.mutex);
        peers_ready = true;
        for (int i = 0; i < ctx->num_peers; i++) {
            if (ctx->peer_addrs[i] == FI_ADDR_UNSPEC) {
                peers_ready = false;
                break;
            }
        }
        pthread_mutex_unlock(&ctx->status.mutex);
        if (!peers_ready) {
            usleep(100000);  // 100ms sleep before checking again
        }
    }

    if (!ctx->status.active) {
        return -FI_EOTHER;
    }

    if (topts.verbose) {
        printf("Sender %d: All initial peer addresses received\n", ctx->worker_id);
    }

	for (int cycle = 0; cycle < topts.sender_ep_recycling; cycle++) {
        printf("Sender %d: Starting EP cycle %d/%d\n", 
                ctx->worker_id, cycle + 1, topts.sender_ep_recycling);

        // Setup new endpoint for this cycle
        ret = setup_endpoint(&ctx->common);
        if (ret) {
            fprintf(stderr, "Sender %d: endpoint setup failed\n", ctx->worker_id);
            goto out;
        }

        // Post all sends for this endpoint cycle
        int pending_ops = 0;
        for (int i = 0; i < ctx->num_peers; i++) {
            pthread_mutex_lock(&ctx->status.mutex);
            fi_addr_t current_addr = ctx->peer_addrs[i];
            pthread_mutex_unlock(&ctx->status.mutex);

            for (int j = 0; j < topts.msgs_per_endpoint; j++) {
                switch (topts.op_type) {
                case OP_MSG_UNTAGGED:
                    ret = fi_send(ctx->common.ep, ctx->tx_buf, opts.transfer_size,
                                fi_mr_desc(ctx->mr), current_addr, 
                                &ctx->tx_ctx[pending_ops]);
                    break;
                case OP_MSG_TAGGED:
                    ret = fi_tsend(ctx->common.ep, ctx->tx_buf, opts.transfer_size,
                                 fi_mr_desc(ctx->mr), current_addr, 
                                 0x123, // tag
                                 &ctx->tx_ctx[pending_ops]);
                    break;
                case OP_RMA_WRITEDATA:
                    pthread_mutex_lock(&ctx->status.mutex);
                    struct rma_info *peer_rma = &ctx->peer_rma_info[i];
                    pthread_mutex_unlock(&ctx->status.mutex);

                    ret = fi_writedata(ctx->common.ep, ctx->tx_buf, 
                                     opts.transfer_size,
                                     fi_mr_desc(ctx->mr), 0xCAFE, // immediate data
                                     current_addr,
                                     peer_rma->remote_addr + (j * opts.transfer_size),
                                     peer_rma->rkey,
                                     &ctx->tx_ctx[pending_ops]);
                    break;
                }

                if (ret) {
                    fprintf(stderr, "Sender %d: operation failed: %s\n", 
                            ctx->worker_id, fi_strerror(-ret));
                    goto cleanup;
                }
                pending_ops++;
            }
        }

        // Wait for all operations to complete
        ret = wait_for_comp(ctx->common.cq, pending_ops);
        if (ret) {
            fprintf(stderr, "Sender %d: completion failed: %s\n", 
                    ctx->worker_id, fi_strerror(-ret));
            goto cleanup;
        }

        total_ops += pending_ops;

        if (topts.verbose) {
            printf("Sender %d: Completed cycle %d, ops=%d\n", 
                   ctx->worker_id, cycle + 1, pending_ops);
        }

cleanup:
        // Cleanup endpoint before next cycle
        cleanup_endpoint(&ctx->common);
        
        if (ret) {
            goto out;
        }

        // Small delay between cycles
        if (cycle < topts.sender_ep_recycling - 1) {
            usleep(1000);
        }
    }

    printf("Sender %d: All cycles completed, total ops=%lu\n", 
            ctx->worker_id, total_ops);


out:
    ctx->status.active = false;
    return ret;
}

static int notify_endpoint_update(struct receiver_context *ctx)
{
    struct ep_message msg;
    msg.msg_type = MSG_TYPE_EP_UPDATE;
    msg.info.worker_id = ctx->worker_id;
    
    // Get endpoint address
    msg.info.addr_len = MAX_EP_ADDR_LEN;
    int ret = fi_getname(&ctx->common.ep->fid, msg.info.ep_addr, 
                        &msg.info.addr_len);
    if (ret) return ret;
    
    // Fill RMA info
    msg.info.rma.remote_addr = (uint64_t)ctx->rx_buf;
    msg.info.rma.rkey = fi_mr_key(ctx->mr);
    msg.info.rma.length = opts.transfer_size * topts.msgs_per_endpoint;
    
    // Send to all connected senders
    for (int i = 0; i < ctx->num_senders; i++) {
        if (ctx->control_socks[i] < 0)
            continue;

        size_t sent = 0;
        while (sent < sizeof(msg)) {
            ret = send(ctx->control_socks[i], 
                      (char*)&msg + sent, 
                      sizeof(msg) - sent, 
                      0);
            
            if (ret < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    // Would block, try again after small delay
                    usleep(1000);  // 1ms delay
                    continue;
                } else if (errno == EINTR) {
                    // Interrupted by signal, retry immediately
                    continue;
                } else {
                    // Real error
                    fprintf(stderr, "Receiver %d: Failed to notify sender %d: %s\n", 
                            ctx->worker_id, i, strerror(errno));
                    return -errno;
                }
            }
            sent += ret;
        }

        if (topts.verbose) {
            printf("Receiver %d: Notified sender %d of new endpoint\n", 
                   ctx->worker_id, i);
        }
    }
    
    return 0;
}

// Modified receiver worker function
static int run_receiver_worker(struct receiver_context *ctx)
{
	int ret;
	int ep_cycles = 0;

	ctx->status.active = true;

	while (ep_cycles < topts.receiver_ep_recycling) {
		ret = setup_endpoint(&ctx->common);
		if (ret)
			break;

		ctx->status.ep_generation++;
		ctx->status.ep_status = EP_RECEIVING;

		// Notify sender of new endpoint
		ret = notify_endpoint_update(ctx);
		if (ret < 0) {
			cleanup_endpoint(&ctx->common);
			continue;
		}

		int completed = 0;
		while (ctx->status.ep_status == EP_RECEIVING) {
			int total_posts = 0;

			// Post a batch of receives
			for (int i = 0; i < topts.msgs_per_endpoint; i++) {
				ret = fi_recv(ctx->common.ep, ctx->rx_buf,
					      opts.transfer_size,
					      fi_mr_desc(ctx->mr), 0,
					      &ctx->rx_ctx[total_posts]);
				if (ret) {
					FT_PRINTERR("fi_recv", ret);
					continue;
				}
				total_posts++;
			}

			// Wait for all completions if any receives were posted
			if (total_posts > 0) {
				ret = wait_for_comp(ctx->common.cq,
						    total_posts);
				if (ret == -FI_ETIMEDOUT) {
					fprintf(stderr,
						"Receive completion timeout, "
						"recycling endpoint\n");
					break;
				}
				completed += total_posts;
				ctx->total_received += total_posts;
			}
		}

		cleanup_endpoint(&ctx->common);
		ep_cycles++;
		usleep(1000);
	}

	printf("Receiver %d: Completed %d EP cycles\n", ctx->worker_id,
	       ep_cycles);

	return 0;
}

// Common function for buffer and MR setup
static int setup_worker_resources(void **buf, struct fi_context2 **ctx,
				  struct fid_mr **mr, uint64_t access)
{
	int ret;

	// Allocate buffer
	*buf = calloc(1, opts.transfer_size * topts.msgs_per_endpoint);
	if (!*buf) {
		return -FI_ENOMEM;
	}

	// Allocate context array
	*ctx = calloc(topts.msgs_per_endpoint, sizeof(struct fi_context));
	if (!*ctx) {
		free(*buf);
		*buf = NULL;
		return -FI_ENOMEM;
	}

	// Register memory region
	ret = fi_mr_reg(domain, *buf, opts.transfer_size, access, 0, 0, 0, mr,
			NULL);
	if (ret) {
		FT_PRINTERR("fi_mr_reg", ret);
		free(*ctx);
		free(*buf);
		*buf = NULL;
		*ctx = NULL;
		return ret;
	}

	return 0;
}

// Common function for AV setup
static int setup_av(struct fid_av **av, int av_size)
{
	struct fi_av_attr av_attr = {.type = FI_AV_MAP, .count = av_size};

	int ret = fi_av_open(domain, &av_attr, av, NULL);
	if (ret) {
		FT_PRINTERR("fi_av_open", ret);
	}
	return ret;
}

static int run_sender(void)
{
	int ret;
	struct sender_context *workers;
	pthread_t *threads;

	workers = calloc(topts.num_sender_workers, sizeof(*workers));
	threads = calloc(topts.num_sender_workers, sizeof(*threads));
	if (!workers || !threads) {
		ret = -FI_ENOMEM;
		goto out;
	}

	printf("\nSender Worker Distribution:\n");
	printf("-------------------------\n");
	printf("Total: %d senders, %d receivers\n", topts.num_sender_workers,
	       topts.num_receiver_workers);

	// Initialize workers
	for (int i = 0; i < topts.num_sender_workers; i++) {
		workers[i].worker_id = i;
		pthread_mutex_init(&workers[i].status.mutex, NULL);

		int num_peers;
		int *peer_ids = calloc(MAX_PEERS, sizeof(int));
		if (!peer_ids) {
			ret = -FI_ENOMEM;
			goto out;
		}

		calculate_worker_distribution(i, &num_peers, peer_ids);
		workers[i].num_peers = num_peers;

		// Setup common resources
		ret = setup_worker_resources(&workers[i].tx_buf,
					     &workers[i].tx_ctx, &workers[i].mr,
					     FI_SEND);
		if (ret) {
			free(peer_ids);
			goto out;
		}

		workers[i].peer_addrs = calloc(num_peers, sizeof(fi_addr_t));
		if (!workers[i].peer_addrs) {
			free(peer_ids);
			ret = -FI_ENOMEM;
			goto out;
		}

        // Initialize all addresses to FI_ADDR_UNSPEC
        for (int i = 0; i < num_peers; i++) {
            workers[i].peer_addrs[i] = FI_ADDR_UNSPEC;
        }

        workers[i].peer_rma_info = calloc(num_peers, sizeof(fi_addr_t));
		if (!workers[i].peer_rma_info) {
			free(peer_ids);
			ret = -FI_ENOMEM;
			goto out;
		}

		ret = setup_av(&workers[i].common.av, num_peers);
		if (ret) {
			free(peer_ids);
			goto out;
		}

		char port_str[16];
		snprintf(port_str, sizeof(port_str), "%d", NOTIFY_PORT + i);

		printf("\nSender Worker %d:\n", i);
		printf("  - Port: %s\n", port_str);
		printf("  - Number of receivers: %d\n", num_peers);
		printf("  - Assigned receivers: ");
		for (int j = 0; j < num_peers; j++) {
			printf("%d ", peer_ids[j]);
		}
		printf("\n");

		ret = control_setup_server(port_str, &workers[i].control_sock);
		if (ret) {
			fprintf(stderr,
				"control_setup_server failed for worker %d: "
				"%d\n",
				i, ret);
			free(peer_ids);
			goto out;
		}

		free(peer_ids);
	}

	// Create worker threads
	for (int i = 0; i < topts.num_sender_workers; i++) {
		ret = pthread_create(&threads[i], NULL,
				     (void *(*) (void *) ) run_sender_worker,
				     &workers[i]);
		if (ret) {
			printf("Failed to create sender thread: %d\n", ret);
			goto out;
		}
	}

	// Wait for completion
	for (int i = 0; i < topts.num_sender_workers; i++) {
		pthread_join(threads[i], NULL);
	}

out:
	if (workers) {
		for (int i = 0; i < topts.num_sender_workers; i++) {
			if (workers[i].control_sock >= 0)
				close(workers[i].control_sock);
			if (workers[i].mr)
				fi_close(&workers[i].mr->fid);
			if (workers[i].common.av)
				fi_close(&workers[i].common.av->fid);
			free(workers[i].tx_buf);
			free(workers[i].tx_ctx);
			free(workers[i].peer_addrs);
            free(workers[i].peer_rma_info);
			pthread_mutex_destroy(&workers[i].status.mutex);
		}
	}
	free(workers);
	free(threads);
	return ret;
}

static int run_receiver(void)
{
	int ret;
	struct receiver_context *workers;
	pthread_t *threads;

	workers = calloc(topts.num_receiver_workers, sizeof(*workers));
	threads = calloc(topts.num_receiver_workers, sizeof(*threads));
	if (!workers || !threads) {
		ret = -FI_ENOMEM;
		goto out;
	}

	printf("\nReceiver Worker Distribution:\n");
	printf("-------------------------\n");
	printf("Total: %d receivers, %d senders\n", topts.num_receiver_workers,
	       topts.num_sender_workers);

	// Initialize workers
	for (int i = 0; i < topts.num_receiver_workers; i++) {
		workers[i].worker_id = i;
		pthread_mutex_init(&workers[i].status.mutex, NULL);

		// Setup common resources
		ret = setup_worker_resources(&workers[i].rx_buf,
					     &workers[i].rx_ctx, &workers[i].mr,
					     FI_RECV);
		if (ret) {
			goto out;
		}

        // Calculate number of senders this receiver talks to
        workers[i].num_senders = (topts.num_sender_workers + topts.num_receiver_workers - 1) 
                                / topts.num_receiver_workers;

        // Allocate control socket array
        workers[i].control_socks = calloc(workers[i].num_senders, sizeof(int));
        if (!workers[i].control_socks) {
            ret = -FI_ENOMEM;
            goto out;
        }

        // Setup AV
		ret = setup_av(&workers[i].common.av,
			       1); // Only need one entry for the sender
		if (ret) {
			goto out;
		}

        if (topts.verbose) {
		    printf("\nReceiver Worker %d:\n", i);
		    printf("  - Connected by senders: ");
		    for (int j = i; j < topts.num_sender_workers;
			    j += topts.num_receiver_workers) {
			    printf("%d ", j);
		    }
		    printf("\n");
        }

		// Each receiver needs to connect to multiple senders
		for (int j = i; j < topts.num_sender_workers;
		     j += topts.num_receiver_workers) {
			char port_str[16];
            int sock_idx = j / topts.num_receiver_workers;
			snprintf(port_str, sizeof(port_str), "%d",
				 NOTIFY_PORT + j);

			if (topts.verbose) {
                printf("Receiver %d connecting to sender %d on port %s\n",
                       i, j, port_str);
            }

			int *control_sock = &workers[i].control_socks[sock_idx];
			ret = control_setup_client(opts.dst_addr, port_str,
						   control_sock);
			if (ret) {
				fprintf(stderr,
					"control_setup_client failed for "
					"worker %d->%d: %d\n",
					i, j, ret);
				goto out;
			}
		}
	}

	// Create worker threads
	for (int i = 0; i < topts.num_receiver_workers; i++) {
		ret = pthread_create(&threads[i], NULL,
				     (void *(*) (void *) ) run_receiver_worker,
				     &workers[i]);
		if (ret) {
			printf("Failed to create receiver thread: %d\n", ret);
			goto out;
		}
	}

	// Wait for completion
	for (int i = 0; i < topts.num_receiver_workers; i++) {
		pthread_join(threads[i], NULL);
	}

out:
	if (workers) {
		for (int i = 0; i < topts.num_receiver_workers; i++) {
			if (workers[i].control_socks) {
                // Close all control sockets
                for (int j = 0; j < workers[i].num_senders; j++) {
                    if (workers[i].control_socks[j] >= 0)
                        close(workers[i].control_socks[j]);
                }
                free(workers[i].control_socks);
            }
			if (workers[i].mr)
				fi_close(&workers[i].mr->fid);
			if (workers[i].common.av)
				fi_close(&workers[i].common.av->fid);
			free(workers[i].rx_buf);
			free(workers[i].rx_ctx);
			pthread_mutex_destroy(&workers[i].status.mutex);
		}
	}
	free(workers);
	free(threads);
	return ret;
}

static int run_test(void)
{
	int ret;

	ret = ft_init_fabric();
	if (ret)
		return ret;

	// Run as sender or receiver based on dst_addr
	if (opts.dst_addr) {
		ret = run_sender();
	} else {
		ret = run_receiver();
	}

	return ret;
}

static void print_test_usage(void)
{
    FT_PRINT_OPTS_USAGE("--sender-workers <N>", "number of sender workers (default: 1)");
    FT_PRINT_OPTS_USAGE("--receiver-workers <N>", "number of receiver workers (default: 1)");
    FT_PRINT_OPTS_USAGE("--msgs-per-ep <N>", "messages per endpoint (default: 1000)");
    FT_PRINT_OPTS_USAGE("--sender-ep-cycles <N>", "number of sender endpoint recycling iterations (default: 1)");
    FT_PRINT_OPTS_USAGE("--receiver-ep-cycles <N>", "number of receiver endpoint recycling iterations (default: 1)");
    FT_PRINT_OPTS_USAGE("--shared-av", "use shared AV among workers (default: off)");
    FT_PRINT_OPTS_USAGE("--shared-cq", "use shared CQ among workers (default: off)");
    FT_PRINT_OPTS_USAGE("--op-type <type>", "operation type: untagged|tagged|writedata (default: untagged)");
}

static int parse_test_opts(int argc, char **argv)
{
    int op;

    while ((op = getopt_long(argc, argv, "hAQ" ADDR_OPTS INFO_OPTS CS_OPTS,
                          test_long_opts, NULL)) != -1) {
        switch (op) {
        case OPT_SENDER_WORKERS:
            topts.num_sender_workers = atoi(optarg);
            if (topts.num_sender_workers < 1) {
                fprintf(stderr, "number of sender workers must be at least 1\n");
                return -1;
            }
            break;
        case OPT_RECEIVER_WORKERS:
            topts.num_receiver_workers = atoi(optarg);
            if (topts.num_receiver_workers < 1) {
                fprintf(stderr, "number of receiver workers must be at least 1\n");
                return -1;
            }
            break;
        case OPT_MSGS_PER_EP:
            topts.msgs_per_endpoint = atoi(optarg);
            if (topts.msgs_per_endpoint < 1) {
                fprintf(stderr, "messages per endpoint must be at least 1\n");
                return -1;
            }
            break;
        case OPT_SENDER_EP_CYCLES:
            topts.sender_ep_recycling = atoi(optarg);
            if (topts.sender_ep_recycling < 1) {
                fprintf(stderr, "sender EP recycling must be at least 1\n");
                return -1;
            }
            break;
        case OPT_RECEIVER_EP_CYCLES:
            topts.receiver_ep_recycling = atoi(optarg);
            if (topts.receiver_ep_recycling < 1) {
                fprintf(stderr, "receiver EP recycling must be at least 1\n");
                return -1;
            }
            break;
        case OPT_SHARED_AV:
            topts.shared_av = true;
            break;
        case OPT_SHARED_CQ:
            topts.shared_cq = true;
            break;
        case OPT_OP_TYPE:
            if (strcmp(optarg, "untagged") == 0) {
                topts.op_type = OP_MSG_UNTAGGED;
            } else if (strcmp(optarg, "tagged") == 0) {
                topts.op_type = OP_MSG_TAGGED;
            } else if (strcmp(optarg, "writedata") == 0) {
                topts.op_type = OP_RMA_WRITEDATA;
            } else {
                fprintf(stderr, "invalid operation type: %s\n", optarg);
                return -1;
            }
            break;
        case '?':
        case 'h':
            ft_usage(argv[0], "Endpoint recycling test");
            print_test_usage();
            return -2;
        default:
            ft_parse_addr_opts(op, optarg, &opts);
			ft_parseinfo(op, optarg, hints, &opts);
			ft_parsecsopts(op, optarg, &opts);
            break;
        }
    }

    return 0;
}

// Main function
int main(int argc, char **argv)
{
	int ret;

	opts.options |= FT_OPT_SIZE;

	hints = fi_allocinfo();
	if (!hints)
		return EXIT_FAILURE;

	// Set up hints
	hints->caps = FI_MSG;
	hints->mode = FI_CONTEXT | FI_CONTEXT2;
	hints->domain_attr->mr_mode = FI_MR_LOCAL | FI_MR_ALLOCATED;
	hints->ep_attr->type = FI_EP_RDM;

	ret = parse_test_opts(argc, argv);
	if (ret)
		goto out;

	ret = run_test();

out:
	ft_free_res();
	return ft_exit_code(ret);
}

