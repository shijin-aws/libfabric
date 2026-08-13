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

#include <rdma/fi_xpu_device.h>
#include "fi_xpu_kernels.h"
#include <assert.h>

#define CNTR_TIMEOUT -1 /* infinite wait */

__global__ void fi_xpu_lat_send_kernel(
	void *xpu_ep,
	void *xpu_send_cq,
	void *xpu_recv_cq,
	void *xpu_send_cntr,
	void *xpu_recv_cntr,
	void *dest_addr, size_t dest_addr_size,
	void *recv_buf, size_t recv_len,
	void *recv_desc, size_t recv_desc_size,
	void *send_buf, size_t send_len,
	void *send_desc, size_t send_desc_size,
	int iters, int rx_depth, int is_client)
{
	int scnt = 0;
	int rcnt = 0;
	int ret;
	uint64_t send_cntr_base = 0;
	uint64_t recv_cntr_base = 0;

	if (xpu_send_cntr)
		send_cntr_base = fi_xpu_cntr_read(xpu_send_cntr,
						   FI_XPU_WORK_ITEM);
	if (xpu_recv_cntr)
		recv_cntr_base = fi_xpu_cntr_read(xpu_recv_cntr,
						   FI_XPU_WORK_ITEM);

	/* Post initial receives */
	for (int i = 0; i < rx_depth; i++) {
		ret = fi_xpu_recv(xpu_ep, recv_buf, recv_len, recv_desc,
				  NULL, NULL, 0, FI_XPU_WORK_ITEM);
		if (ret) {
			printf("fi_xpu_recv post failed: %d\n", ret);
			return;
		}
	}

	while (scnt < iters || rcnt < iters) {
		/* Poll for receive completion (except for first client send) */
		if (rcnt < iters && !(scnt < 1 && is_client == 1)) {
			if (xpu_recv_cntr) {
				fi_xpu_cntr_wait(xpu_recv_cntr,
						 recv_cntr_base + rcnt + 1,
						 CNTR_TIMEOUT,
						 FI_XPU_WORK_ITEM);
			} else {
				int64_t cq_ret;
				do {
					cq_ret = fi_xpu_cq_read(xpu_recv_cq,
								NULL, 1,
								FI_XPU_WORK_ITEM);
				} while (cq_ret == -FI_EAGAIN);
			}

			rcnt++;

			/* Repost receive */
			if (rcnt + rx_depth <= iters) {
				ret = fi_xpu_recv(xpu_ep, recv_buf, recv_len,
						  recv_desc, NULL, NULL, 0,
						  FI_XPU_WORK_ITEM);
				if (ret) {
					printf("fi_xpu_recv repost failed: %d\n", ret);
					return;
				}
			}
		}

		/* Send */
		if (scnt < iters) {
			ret = fi_xpu_send(xpu_ep, send_buf, send_len,
					  send_desc, 0, dest_addr, NULL, 0,
					  FI_XPU_WORK_ITEM);
			if (ret) {
				printf("fi_xpu_send failed: %d\n", ret);
				return;
			}
			scnt++;

			/* Wait for send completion */
			if (xpu_send_cntr) {
				fi_xpu_cntr_wait(xpu_send_cntr,
						 send_cntr_base + scnt,
						 CNTR_TIMEOUT,
						 FI_XPU_WORK_ITEM);
			} else {
				int64_t cq_ret;
				do {
					cq_ret = fi_xpu_cq_read(xpu_send_cq,
								NULL, 1,
								FI_XPU_WORK_ITEM);
				} while (cq_ret == -FI_EAGAIN);
			}
		}
	}
}

int fi_xpu_run_lat_send(void *xpu_ep,
			void *xpu_send_cq,
			void *xpu_recv_cq,
			void *xpu_send_cntr,
			void *xpu_recv_cntr,
			void *dest_addr, size_t dest_addr_size,
			void *recv_buf, size_t recv_len,
			void *recv_desc, size_t recv_desc_size,
			void *send_buf, size_t send_len,
			void *send_desc, size_t send_desc_size,
			int iters, int rx_depth, int is_client,
			cudaStream_t stream)
{
	cudaError_t err;

	fi_xpu_lat_send_kernel<<<1, 1, 0, stream>>>(
		xpu_ep, xpu_send_cq, xpu_recv_cq,
		xpu_send_cntr, xpu_recv_cntr,
		dest_addr, dest_addr_size,
		recv_buf, recv_len, recv_desc, recv_desc_size,
		send_buf, send_len, send_desc, send_desc_size,
		iters, rx_depth, is_client);

	err = cudaGetLastError();
	if (err != cudaSuccess) {
		fprintf(stderr, "fi_xpu_run_lat_send: launch failed: %s\n",
			cudaGetErrorString(err));
		return -1;
	}

	err = cudaStreamSynchronize(stream);
	if (err != cudaSuccess) {
		fprintf(stderr, "fi_xpu_run_lat_send: kernel failed: %s\n",
			cudaGetErrorString(err));
		return -1;
	}

	return 0;
}

__global__ void fi_xpu_bw_kernel(
	void *xpu_ep,
	void *xpu_send_cq,
	void *xpu_send_cntr,
	int is_write,
	void *send_buf, size_t send_len,
	void *send_desc, size_t send_desc_size,
	void *dest_addr, size_t dest_addr_size,
	uint64_t remote_addr, uint64_t remote_key,
	int iters, int tx_depth)
{
	int scnt = 0;
	int ccnt = 0;
	int ret;
	uint64_t send_cntr_base = 0;

	if (xpu_send_cntr)
		send_cntr_base = fi_xpu_cntr_read(xpu_send_cntr,
						   FI_XPU_WORK_ITEM);

	while (scnt < iters || ccnt < iters) {
		/* Post operations up to tx_depth */
		while (scnt < iters && (scnt - ccnt) < tx_depth) {
			if (is_write) {
				ret = fi_xpu_write(xpu_ep, send_buf, send_len,
						   send_desc, 0, dest_addr,
						   remote_addr, remote_key,
						   NULL, 0, FI_XPU_WORK_ITEM);
			} else {
				ret = fi_xpu_send(xpu_ep, send_buf, send_len,
						  send_desc, 0, dest_addr,
						  NULL, 0, FI_XPU_WORK_ITEM);
			}
			if (ret) {
				printf("fi_xpu_bw: post failed: %d at scnt=%d\n",
				       ret, scnt);
				return;
			}
			scnt++;
		}

		/* Poll completions */
		while (ccnt < scnt && (scnt == iters ||
		       (scnt - ccnt) >= tx_depth)) {
			if (xpu_send_cntr) {
				fi_xpu_cntr_wait(xpu_send_cntr,
						 send_cntr_base + ccnt + 1,
						 CNTR_TIMEOUT,
						 FI_XPU_WORK_ITEM);
				ccnt++;
			} else {
				int64_t cq_ret;
				cq_ret = fi_xpu_cq_read(xpu_send_cq, NULL, 1,
							FI_XPU_WORK_ITEM);
				if (cq_ret > 0)
					ccnt++;
			}
		}
	}
}

int fi_xpu_run_bw(void *xpu_ep,
		  void *xpu_send_cq,
		  void *xpu_send_cntr,
		  int is_write,
		  void *send_buf, size_t send_len,
		  void *send_desc, size_t send_desc_size,
		  void *dest_addr, size_t dest_addr_size,
		  uint64_t remote_addr, uint64_t remote_key,
		  int iters, int tx_depth,
		  cudaStream_t stream)
{
	cudaError_t err;

	fi_xpu_bw_kernel<<<1, 1, 0, stream>>>(
		xpu_ep, xpu_send_cq, xpu_send_cntr, is_write,
		send_buf, send_len, send_desc, send_desc_size,
		dest_addr, dest_addr_size,
		remote_addr, remote_key,
		iters, tx_depth);

	err = cudaGetLastError();
	if (err != cudaSuccess) {
		fprintf(stderr, "fi_xpu_run_bw: launch failed: %s\n",
			cudaGetErrorString(err));
		return -1;
	}

	err = cudaStreamSynchronize(stream);
	if (err != cudaSuccess) {
		fprintf(stderr, "fi_xpu_run_bw: kernel failed: %s\n",
			cudaGetErrorString(err));
		return -1;
	}

	return 0;
}

__global__ void fi_xpu_bw_recv_kernel(
	void *xpu_ep,
	void *xpu_recv_cq,
	void *xpu_recv_cntr,
	void *recv_buf, size_t recv_len,
	void *recv_desc, size_t recv_desc_size,
	int iters, int rx_depth)
{
	int rcnt = 0;
	int ret;
	uint64_t recv_cntr_base = 0;

	if (xpu_recv_cntr)
		recv_cntr_base = fi_xpu_cntr_read(xpu_recv_cntr,
						   FI_XPU_WORK_ITEM);

	/* Post initial receives */
	for (int i = 0; i < rx_depth; i++) {
		ret = fi_xpu_recv(xpu_ep, recv_buf, recv_len, recv_desc,
				  NULL, NULL, 0, FI_XPU_WORK_ITEM);
		if (ret) {
			printf("fi_xpu_bw_recv: post failed: %d\n", ret);
			return;
		}
	}

	while (rcnt < iters) {
		if (xpu_recv_cntr) {
			fi_xpu_cntr_wait(xpu_recv_cntr,
					 recv_cntr_base + rcnt + 1,
					 CNTR_TIMEOUT, FI_XPU_WORK_ITEM);
		} else {
			int64_t cq_ret;
			do {
				cq_ret = fi_xpu_cq_read(xpu_recv_cq, NULL, 1,
							FI_XPU_WORK_ITEM);
			} while (cq_ret == -FI_EAGAIN);
		}

		rcnt++;

		/* Repost receive */
		if (rcnt + rx_depth <= iters) {
			ret = fi_xpu_recv(xpu_ep, recv_buf, recv_len,
					  recv_desc, NULL, NULL, 0,
					  FI_XPU_WORK_ITEM);
			if (ret) {
				printf("fi_xpu_bw_recv: repost failed: %d\n", ret);
				return;
			}
		}
	}
}

int fi_xpu_run_bw_recv(void *xpu_ep,
		       void *xpu_recv_cq,
		       void *xpu_recv_cntr,
		       void *recv_buf, size_t recv_len,
		       void *recv_desc, size_t recv_desc_size,
		       int iters, int rx_depth,
		       cudaStream_t stream)
{
	cudaError_t err;

	fi_xpu_bw_recv_kernel<<<1, 1, 0, stream>>>(
		xpu_ep, xpu_recv_cq, xpu_recv_cntr,
		recv_buf, recv_len, recv_desc, recv_desc_size,
		iters, rx_depth);

	err = cudaGetLastError();
	if (err != cudaSuccess) {
		fprintf(stderr, "fi_xpu_run_bw_recv: launch failed: %s\n",
			cudaGetErrorString(err));
		return -1;
	}

	err = cudaStreamSynchronize(stream);
	if (err != cudaSuccess) {
		fprintf(stderr, "fi_xpu_run_bw_recv: kernel failed: %s\n",
			cudaGetErrorString(err));
		return -1;
	}

	return 0;
}
