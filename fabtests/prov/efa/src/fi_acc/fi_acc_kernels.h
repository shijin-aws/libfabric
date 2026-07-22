/*
 * Copyright (c) 2026, Amazon.com, Inc.  All rights reserved.
 */

#ifndef FI_ACC_KERNELS_H
#define FI_ACC_KERNELS_H

#include <stdint.h>
#include <cuda_runtime.h>

#ifdef __cplusplus
extern "C" {
#endif

int fi_acc_run_lat_send(
	void *d_ep, void *d_send_cq, void *d_recv_cq,
	void *d_send_cntr, void *d_recv_cntr,
	void *d_desc, void *d_peer,
	uint64_t recv_addr, uint32_t recv_length,
	uint64_t send_addr, uint32_t send_length,
	int iters, int rx_depth, int is_client,
	cudaStream_t stream);

int fi_acc_run_bw(
	void *d_ep, void *d_send_cq, void *d_send_cntr,
	void *d_desc, void *d_peer, int opcode,
	uint64_t send_addr, uint32_t send_length,
	uint64_t remote_addr, uint32_t remote_rkey,
	int iters, int tx_depth,
	cudaStream_t stream);

int fi_acc_run_bw_recv(
	void *d_ep, void *d_recv_cq, void *d_recv_cntr,
	void *d_desc,
	uint64_t recv_addr, uint32_t recv_length,
	int iters, int rx_depth,
	cudaStream_t stream);

#ifdef __cplusplus
}
#endif

#endif
