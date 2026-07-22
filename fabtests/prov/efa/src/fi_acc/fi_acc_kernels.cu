/*
 * Copyright (c) 2026, Amazon.com, Inc.  All rights reserved.
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
 * GPU kernels for the OFI Accelerator API fabtest.
 *
 * These replace the efa-dp-direct-based kernels in efagda/efa_gda_kernels.cu
 * with the portable fi_acc_dev_* functions from <rdma/fi_acc_device.h>.
 *
 * The kernels are functionally identical to the GDA versions but use
 * the provider-neutral API throughout.
 */

#include <rdma/fi_acc_device.h>
#include "fi_acc_kernels.h"
#include <assert.h>

#define CNTR_POLL_MAX_ITER 100000000

enum fi_acc_opcode {
	FI_ACC_OP_SEND = 0,
	FI_ACC_OP_WRITE = 1,
	FI_ACC_OP_WRITE_IMM = 2,
	FI_ACC_OP_READ = 3,
};

/*
 * =============================================================================
 * Latency kernel: send/recv ping-pong
 * =============================================================================
 */
__global__ void fi_acc_lat_send_kernel(
	struct fi_acc_dev_qp *qp,
	struct fi_acc_dev_cq *send_cq,
	struct fi_acc_dev_cq *recv_cq,
	volatile uint64_t *send_cntr_ptr,
	volatile uint64_t *recv_cntr_ptr,
	uint16_t ah, uint16_t remote_qpn, uint32_t remote_qkey,
	uint64_t recv_addr, uint32_t recv_length, uint32_t recv_lkey,
	uint64_t send_addr, uint32_t send_length, uint32_t send_lkey,
	int iters, int rx_depth, int machine_type)
{
	int scnt = 0;
	int rcnt = 0;
	void *cqe;
	struct fi_acc_dev_wqe wr;
	struct fi_acc_dev_peer target;

	__shared__ struct fi_acc_dev_qp local_qp;
	__shared__ struct fi_acc_dev_cq local_send_cq;
	__shared__ struct fi_acc_dev_cq local_recv_cq;

	uint64_t send_cntr_start = 0;
	uint64_t recv_cntr_start = 0;

	local_qp = *qp;
	local_send_cq = *send_cq;
	local_recv_cq = *recv_cq;

	if (send_cntr_ptr)
		send_cntr_start = *send_cntr_ptr;
	if (recv_cntr_ptr)
		recv_cntr_start = *recv_cntr_ptr;

	target.ahn = ah;
	target.remote_qpn = remote_qpn;
	target.remote_qkey = remote_qkey;

	/* Post initial receives */
	for (int i = 0; i < rx_depth; i++) {
		fi_acc_dev_post_recv(&local_qp, (uint32_t)i,
				     recv_addr, recv_length, recv_lkey);
	}
	fi_acc_dev_rq_flush(&local_qp, (uint32_t)rx_depth);

	while (scnt < iters || rcnt < iters) {
		/* Wait for receive (except first client send) */
		if (rcnt < iters && !(scnt < 1 && machine_type == 1)) {
			if (recv_cntr_ptr) {
				/* Poll HW counter */
				for (int i = 0; i < CNTR_POLL_MAX_ITER; i++) {
					if (*recv_cntr_ptr >= recv_cntr_start + rcnt + 1)
						break;
				}
			} else {
				do {
					cqe = fi_acc_dev_cq_poll(&local_recv_cq, 0);
				} while (!cqe);
			}
			rcnt++;
			fi_acc_dev_cq_pop(&local_recv_cq, 1);

			/* Repost receive */
			if (rcnt + rx_depth <= iters) {
				fi_acc_dev_post_recv(&local_qp, 0,
						     recv_addr, recv_length,
						     recv_lkey);
				fi_acc_dev_rq_flush(&local_qp, 1);
			}
		}

		/* Send */
		if (scnt < iters) {
			scnt++;

			/* Prepare Send WQE (opcode 0x00 for EFA send) */
			uint64_t *w = (uint64_t *)wr.data;
			for (int i = 0; i < 8; i++) w[i] = 0;
			uint32_t *meta = (uint32_t *)&w[0];
			meta[0] = 0x00; /* opcode: SEND */
			meta[1] = 1;    /* num_sge */
			meta[2] = (uint32_t)scnt; /* wr_id */

			/* SGE at offset [32..47] */
			uint32_t *sge = (uint32_t *)&w[4];
			sge[0] = send_lkey;
			uint64_t *sge_va = (uint64_t *)&sge[2];
			*sge_va = send_addr;
			sge[4] = send_length;

			/* Remote target */
			fi_acc_dev_wr_set_peer(&wr, &target);

			/* Submit */
			fi_acc_dev_sq_start_batch(&local_qp, 1);
			fi_acc_dev_sq_place(&local_qp, 0, &wr);
			fi_acc_dev_sq_flush(&local_qp);

			/* Wait for send completion */
			if (send_cntr_ptr) {
				for (int i = 0; i < CNTR_POLL_MAX_ITER; i++) {
					if (*send_cntr_ptr >= send_cntr_start + scnt)
						break;
				}
			} else {
				do {
					cqe = fi_acc_dev_cq_poll(&local_send_cq, 0);
				} while (!cqe);
			}
			fi_acc_dev_cq_pop(&local_send_cq, 1);
		}
	}

	*qp = local_qp;
	*send_cq = local_send_cq;
	*recv_cq = local_recv_cq;
}

/*
 * =============================================================================
 * Bandwidth kernel: RDMA write / send
 * =============================================================================
 */
__global__ void fi_acc_bw_kernel(
	struct fi_acc_dev_qp *qp,
	struct fi_acc_dev_cq *send_cq,
	volatile uint64_t *send_cntr_ptr,
	int opcode,
	uint64_t send_addr, uint32_t send_length, uint32_t send_lkey,
	uint16_t ah, uint32_t remote_qpn, uint32_t remote_qkey,
	uint64_t remote_addr, uint32_t remote_rkey,
	int iters, int tx_depth)
{
	int scnt = 0;
	int ccnt = 0;
	void *cqe;
	struct fi_acc_dev_wqe wr;
	struct fi_acc_dev_peer target;

	__shared__ struct fi_acc_dev_qp local_qp;
	__shared__ struct fi_acc_dev_cq local_send_cq;
	uint64_t send_cntr_start = 0;

	local_qp = *qp;
	local_send_cq = *send_cq;

	if (send_cntr_ptr)
		send_cntr_start = *send_cntr_ptr;

	target.ahn = ah;
	target.remote_qpn = (uint16_t)remote_qpn;
	target.remote_qkey = remote_qkey;

	while (scnt < iters || ccnt < iters) {
		/* Post operations up to tx_depth */
		while (scnt < iters && (scnt - ccnt) < tx_depth) {
			/* Build WQE based on opcode */
			if (opcode == FI_ACC_OP_WRITE ||
			    opcode == FI_ACC_OP_WRITE_IMM ||
			    opcode == FI_ACC_OP_READ) {
				fi_acc_dev_write_prep(&wr, (uint32_t)scnt,
						     remote_rkey, remote_addr,
						     send_lkey, send_addr,
						     send_length);
				/* Fixup opcode for read/write_imm */
				uint32_t *meta = (uint32_t *)wr.data;
				if (opcode == FI_ACC_OP_READ)
					meta[0] = 0x05; /* RDMA_READ */
				else if (opcode == FI_ACC_OP_WRITE_IMM)
					meta[0] = 0x06; /* RDMA_WRITE_IMM */
			} else {
				/* Send */
				uint64_t *w = (uint64_t *)wr.data;
				for (int i = 0; i < 8; i++) w[i] = 0;
				uint32_t *meta = (uint32_t *)&w[0];
				meta[0] = 0x00; /* SEND */
				meta[1] = 1;
				meta[2] = (uint32_t)scnt;
				uint32_t *sge = (uint32_t *)&w[4];
				sge[0] = send_lkey;
				uint64_t *sge_va = (uint64_t *)&sge[2];
				*sge_va = send_addr;
				sge[4] = send_length;
			}

			fi_acc_dev_wr_set_peer(&wr, &target);
			fi_acc_dev_sq_start_batch(&local_qp, 1);
			fi_acc_dev_sq_place(&local_qp, 0, &wr);
			fi_acc_dev_sq_flush(&local_qp);
			scnt++;
		}

		/* Poll completions */
		while (ccnt < scnt &&
		       (scnt == iters || (scnt - ccnt) >= tx_depth)) {
			if (send_cntr_ptr) {
				for (int i = 0; i < CNTR_POLL_MAX_ITER; i++) {
					if (*send_cntr_ptr >= send_cntr_start + ccnt + 1)
						break;
				}
				fi_acc_dev_cq_pop(&local_send_cq, 1);
				ccnt++;
			} else {
				cqe = fi_acc_dev_cq_poll(&local_send_cq, 0);
				if (cqe) {
					fi_acc_dev_cq_pop(&local_send_cq, 1);
					ccnt++;
				}
			}
		}
	}

	*qp = local_qp;
	*send_cq = local_send_cq;
}

/*
 * =============================================================================
 * BW recv kernel: post receives and poll recv CQ
 * =============================================================================
 */
__global__ void fi_acc_bw_recv_kernel(
	struct fi_acc_dev_qp *qp,
	struct fi_acc_dev_cq *recv_cq,
	volatile uint64_t *recv_cntr_ptr,
	uint64_t recv_addr, uint32_t recv_length, uint32_t recv_lkey,
	int iters, int rx_depth)
{
	int rcnt = 0;
	void *cqe;

	__shared__ struct fi_acc_dev_qp local_qp;
	__shared__ struct fi_acc_dev_cq local_recv_cq;
	uint64_t recv_cntr_start = 0;

	local_qp = *qp;
	local_recv_cq = *recv_cq;

	if (recv_cntr_ptr)
		recv_cntr_start = *recv_cntr_ptr;

	/* Post initial receives */
	for (int i = 0; i < rx_depth; i++) {
		fi_acc_dev_post_recv(&local_qp, (uint32_t)i,
				     recv_addr, recv_length, recv_lkey);
	}
	fi_acc_dev_rq_flush(&local_qp, (uint32_t)rx_depth);

	while (rcnt < iters) {
		if (recv_cntr_ptr) {
			for (int i = 0; i < CNTR_POLL_MAX_ITER; i++) {
				if (*recv_cntr_ptr >= recv_cntr_start + rcnt + 1)
					break;
			}
		} else {
			do {
				cqe = fi_acc_dev_cq_poll(&local_recv_cq, 0);
			} while (!cqe);
		}
		rcnt++;
		fi_acc_dev_cq_pop(&local_recv_cq, 1);

		/* Repost receive */
		if (rcnt + rx_depth <= iters) {
			fi_acc_dev_post_recv(&local_qp, 0,
					     recv_addr, recv_length,
					     recv_lkey);
			fi_acc_dev_rq_flush(&local_qp, 1);
		}
	}

	*qp = local_qp;
	*recv_cq = local_recv_cq;
}

/*
 * =============================================================================
 * Host-side launch wrappers
 * =============================================================================
 */

int fi_acc_run_lat_send(
	void *d_qp, void *d_send_cq, void *d_recv_cq,
	volatile uint64_t *send_cntr_ptr, volatile uint64_t *recv_cntr_ptr,
	uint16_t ah, uint16_t remote_qpn, uint32_t remote_qkey,
	uint64_t recv_addr, uint32_t recv_length, uint32_t recv_lkey,
	uint64_t send_addr, uint32_t send_length, uint32_t send_lkey,
	int iters, int rx_depth, int is_client,
	cudaStream_t stream)
{
	fi_acc_lat_send_kernel<<<1, 1, 0, stream>>>(
		(struct fi_acc_dev_qp *)d_qp,
		(struct fi_acc_dev_cq *)d_send_cq,
		(struct fi_acc_dev_cq *)d_recv_cq,
		send_cntr_ptr, recv_cntr_ptr,
		ah, remote_qpn, remote_qkey,
		recv_addr, recv_length, recv_lkey,
		send_addr, send_length, send_lkey,
		iters, rx_depth, is_client);

	cudaError_t err = cudaGetLastError();
	if (err != cudaSuccess) return -1;
	err = cudaStreamSynchronize(stream);
	return (err == cudaSuccess) ? 0 : -1;
}

int fi_acc_run_bw(
	void *d_qp, void *d_send_cq,
	volatile uint64_t *send_cntr_ptr,
	int opcode,
	uint64_t send_addr, uint32_t send_length, uint32_t send_lkey,
	uint16_t ah, uint32_t remote_qpn, uint32_t remote_qkey,
	uint64_t remote_addr, uint32_t remote_rkey,
	int iters, int tx_depth,
	cudaStream_t stream)
{
	fi_acc_bw_kernel<<<1, 1, 0, stream>>>(
		(struct fi_acc_dev_qp *)d_qp,
		(struct fi_acc_dev_cq *)d_send_cq,
		send_cntr_ptr, opcode,
		send_addr, send_length, send_lkey,
		ah, remote_qpn, remote_qkey,
		remote_addr, remote_rkey,
		iters, tx_depth);

	cudaError_t err = cudaGetLastError();
	if (err != cudaSuccess) return -1;
	err = cudaStreamSynchronize(stream);
	return (err == cudaSuccess) ? 0 : -1;
}

int fi_acc_run_bw_recv(
	void *d_qp, void *d_recv_cq,
	volatile uint64_t *recv_cntr_ptr,
	uint64_t recv_addr, uint32_t recv_length, uint32_t recv_lkey,
	int iters, int rx_depth,
	cudaStream_t stream)
{
	fi_acc_bw_recv_kernel<<<1, 1, 0, stream>>>(
		(struct fi_acc_dev_qp *)d_qp,
		(struct fi_acc_dev_cq *)d_recv_cq,
		recv_cntr_ptr,
		recv_addr, recv_length, recv_lkey,
		iters, rx_depth);

	cudaError_t err = cudaGetLastError();
	if (err != cudaSuccess) return -1;
	err = cudaStreamSynchronize(stream);
	return (err == cudaSuccess) ? 0 : -1;
}
