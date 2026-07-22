/*
 * Copyright (c) 2026, Amazon.com, Inc.  All rights reserved.
 *
 * GPU kernels using the OFI Accelerator high-level device API.
 * Consumer never touches WQE formats, ring buffers, or doorbells.
 * All operations go through fi_acc_write/send/cq_poll/cntr_read.
 */

#include <rdma/providers/fi_acc_efa_device.cuh>
#include "fi_acc_kernels.h"

/*
 * Latency: send/recv ping-pong (single thread)
 */
__global__ void fi_acc_lat_send_kernel(
	void *ep, void *send_cq, void *recv_cq,
	void *send_cntr, void *recv_cntr,
	void *desc, void *peer,
	uint64_t recv_addr, uint32_t recv_length,
	uint64_t send_addr, uint32_t send_length,
	int iters, int rx_depth, int is_client)
{
	if (threadIdx.x != 0 || blockIdx.x != 0) return;

	int scnt = 0, rcnt = 0;
	uint64_t send_cntr_start = send_cntr ? fi_acc_cntr_read(send_cntr) : 0;
	uint64_t recv_cntr_start = recv_cntr ? fi_acc_cntr_read(recv_cntr) : 0;

	/* Post initial receives */
	for (int i = 0; i < rx_depth; i++)
		fi_acc_post_recv(ep, (void *)recv_addr, recv_length, desc);
	fi_acc_flush_recv(ep);

	while (scnt < iters || rcnt < iters) {
		/* Wait for receive (except first client send) */
		if (rcnt < iters && !(scnt < 1 && is_client)) {
			if (recv_cntr) {
				fi_acc_cntr_wait(recv_cntr, recv_cntr_start + rcnt + 1);
			} else {
				while (!fi_acc_cq_poll(recv_cq, 0)) ;
			}
			rcnt++;
			fi_acc_cq_pop(recv_cq, 1);

			if (rcnt + rx_depth <= iters) {
				fi_acc_post_recv(ep, (void *)recv_addr, recv_length, desc);
				fi_acc_flush_recv(ep);
			}
		}

		/* Send */
		if (scnt < iters) {
			scnt++;
			fi_acc_send(ep, (void *)send_addr, send_length, desc, peer, 0);

			if (send_cntr) {
				fi_acc_cntr_wait(send_cntr, send_cntr_start + scnt);
			} else {
				while (!fi_acc_cq_poll(send_cq, 0)) ;
			}
			fi_acc_cq_pop(send_cq, 1);
		}
	}
}

/*
 * Bandwidth: RDMA write/read/send (single thread)
 */
__global__ void fi_acc_bw_kernel(
	void *ep, void *send_cq, void *send_cntr,
	void *desc, void *peer, int opcode,
	uint64_t send_addr, uint32_t send_length,
	uint64_t remote_addr, uint32_t remote_rkey,
	int iters, int tx_depth)
{
	if (threadIdx.x != 0 || blockIdx.x != 0) return;

	int scnt = 0, ccnt = 0;
	uint64_t cntr_start = send_cntr ? fi_acc_cntr_read(send_cntr) : 0;

	while (scnt < iters || ccnt < iters) {
		while (scnt < iters && (scnt - ccnt) < tx_depth) {
			if (opcode == 1 || opcode == 3) {
				/* write or read */
				fi_acc_write(ep, (void *)send_addr, send_length, desc,
					     remote_addr, remote_rkey, peer, 0);
			} else {
				/* send */
				fi_acc_send(ep, (void *)send_addr, send_length, desc, peer, 0);
			}
			scnt++;
		}

		while (ccnt < scnt && (scnt == iters || (scnt - ccnt) >= tx_depth)) {
			if (send_cntr) {
				fi_acc_cntr_wait(send_cntr, cntr_start + ccnt + 1);
				fi_acc_cq_pop(send_cq, 1);
				ccnt++;
			} else {
				if (fi_acc_cq_poll(send_cq, 0)) {
					fi_acc_cq_pop(send_cq, 1);
					ccnt++;
				}
			}
		}
	}
}

/*
 * BW recv side: post receives and poll
 */
__global__ void fi_acc_bw_recv_kernel(
	void *ep, void *recv_cq, void *recv_cntr, void *desc,
	uint64_t recv_addr, uint32_t recv_length,
	int iters, int rx_depth)
{
	if (threadIdx.x != 0 || blockIdx.x != 0) return;

	int rcnt = 0;
	uint64_t cntr_start = recv_cntr ? fi_acc_cntr_read(recv_cntr) : 0;

	for (int i = 0; i < rx_depth; i++)
		fi_acc_post_recv(ep, (void *)recv_addr, recv_length, desc);
	fi_acc_flush_recv(ep);

	while (rcnt < iters) {
		if (recv_cntr) {
			fi_acc_cntr_wait(recv_cntr, cntr_start + rcnt + 1);
		} else {
			while (!fi_acc_cq_poll(recv_cq, 0)) ;
		}
		rcnt++;
		fi_acc_cq_pop(recv_cq, 1);

		if (rcnt + rx_depth <= iters) {
			fi_acc_post_recv(ep, (void *)recv_addr, recv_length, desc);
			fi_acc_flush_recv(ep);
		}
	}
}

/* Host launch wrappers */

int fi_acc_run_lat_send(
	void *d_ep, void *d_send_cq, void *d_recv_cq,
	void *d_send_cntr, void *d_recv_cntr,
	void *d_desc, void *d_peer,
	uint64_t recv_addr, uint32_t recv_length,
	uint64_t send_addr, uint32_t send_length,
	int iters, int rx_depth, int is_client, cudaStream_t stream)
{
	fi_acc_lat_send_kernel<<<1, 1, 0, stream>>>(
		d_ep, d_send_cq, d_recv_cq, d_send_cntr, d_recv_cntr,
		d_desc, d_peer,
		recv_addr, recv_length, send_addr, send_length,
		iters, rx_depth, is_client);
	cudaError_t err = cudaStreamSynchronize(stream);
	return (err == cudaSuccess) ? 0 : -1;
}

int fi_acc_run_bw(
	void *d_ep, void *d_send_cq, void *d_send_cntr,
	void *d_desc, void *d_peer, int opcode,
	uint64_t send_addr, uint32_t send_length,
	uint64_t remote_addr, uint32_t remote_rkey,
	int iters, int tx_depth, cudaStream_t stream)
{
	fi_acc_bw_kernel<<<1, 1, 0, stream>>>(
		d_ep, d_send_cq, d_send_cntr, d_desc, d_peer, opcode,
		send_addr, send_length, remote_addr, remote_rkey,
		iters, tx_depth);
	cudaError_t err = cudaStreamSynchronize(stream);
	return (err == cudaSuccess) ? 0 : -1;
}

int fi_acc_run_bw_recv(
	void *d_ep, void *d_recv_cq, void *d_recv_cntr, void *d_desc,
	uint64_t recv_addr, uint32_t recv_length,
	int iters, int rx_depth, cudaStream_t stream)
{
	fi_acc_bw_recv_kernel<<<1, 1, 0, stream>>>(
		d_ep, d_recv_cq, d_recv_cntr, d_desc,
		recv_addr, recv_length, iters, rx_depth);
	cudaError_t err = cudaStreamSynchronize(stream);
	return (err == cudaSuccess) ? 0 : -1;
}
