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

#ifndef FI_XPU_KERNELS_H
#define FI_XPU_KERNELS_H

#include <stdint.h>
#include <stddef.h>
#include <cuda_runtime.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * fi_xpu_run_lat_send - Run a latency (ping-pong) send test on GPU.
 *
 * @xpu_ep:       Device-side XPU endpoint handle
 * @xpu_send_cq:  Device-side XPU send completion queue handle
 * @xpu_recv_cq:  Device-side XPU recv completion queue handle
 * @xpu_send_cntr: Device-side XPU send counter (or NULL to use CQ)
 * @xpu_recv_cntr: Device-side XPU recv counter (or NULL to use CQ)
 * @dest_addr:    Device-side AV address of remote peer
 * @dest_addr_size: Size of dest_addr buffer
 * @recv_buf:     Receive buffer address (device memory)
 * @recv_len:     Receive buffer length
 * @recv_desc:    Receive MR descriptor (device-side)
 * @recv_desc_size: Size of recv_desc
 * @send_buf:     Send buffer address (device memory)
 * @send_len:     Send buffer length
 * @send_desc:    Send MR descriptor (device-side)
 * @send_desc_size: Size of send_desc
 * @iters:        Number of iterations
 * @rx_depth:     Receive queue depth (pre-posted receives)
 * @is_client:    1 if this side sends first, 0 otherwise
 * @stream:       CUDA stream for kernel launch
 *
 * Returns 0 on success, negative on failure.
 */
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
			cudaStream_t stream);

/**
 * fi_xpu_run_bw - Run a bandwidth (one-directional) test on GPU.
 *
 * @xpu_ep:       Device-side XPU endpoint handle
 * @xpu_send_cq:  Device-side XPU send CQ handle
 * @xpu_send_cntr: Device-side XPU send counter (or NULL to use CQ)
 * @is_write:     1 for RDMA write, 0 for send
 * @send_buf:     Send buffer address (device memory)
 * @send_len:     Send buffer length
 * @send_desc:    Send MR descriptor (device-side)
 * @send_desc_size: Size of send_desc
 * @dest_addr:    Device-side AV address of remote peer
 * @dest_addr_size: Size of dest_addr
 * @remote_addr:  Remote memory address (for RDMA write/read)
 * @remote_key:   Remote memory key (for RDMA write/read)
 * @iters:        Number of iterations
 * @tx_depth:     Transmit queue depth
 * @stream:       CUDA stream for kernel launch
 *
 * Returns 0 on success, negative on failure.
 */
int fi_xpu_run_bw(void *xpu_ep,
		  void *xpu_send_cq,
		  void *xpu_send_cntr,
		  int is_write,
		  void *send_buf, size_t send_len,
		  void *send_desc, size_t send_desc_size,
		  void *dest_addr, size_t dest_addr_size,
		  uint64_t remote_addr, uint64_t remote_key,
		  int iters, int tx_depth,
		  cudaStream_t stream);

/**
 * fi_xpu_run_bw_recv - Run receiver side of bandwidth test on GPU.
 *
 * @xpu_ep:       Device-side XPU endpoint handle
 * @xpu_recv_cq:  Device-side XPU recv CQ handle
 * @xpu_recv_cntr: Device-side XPU recv counter (or NULL to use CQ)
 * @recv_buf:     Receive buffer address (device memory)
 * @recv_len:     Receive buffer length
 * @recv_desc:    Receive MR descriptor (device-side)
 * @recv_desc_size: Size of recv_desc
 * @iters:        Number of iterations
 * @rx_depth:     Receive queue depth
 * @stream:       CUDA stream for kernel launch
 *
 * Returns 0 on success, negative on failure.
 */
int fi_xpu_run_bw_recv(void *xpu_ep,
		       void *xpu_recv_cq,
		       void *xpu_recv_cntr,
		       void *recv_buf, size_t recv_len,
		       void *recv_desc, size_t recv_desc_size,
		       int iters, int rx_depth,
		       cudaStream_t stream);

#ifdef __cplusplus
}
#endif

#endif /* FI_XPU_KERNELS_H */
