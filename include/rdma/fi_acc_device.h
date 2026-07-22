/*
 * Copyright (c) 2026 Amazon.com, Inc. or its affiliates. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
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

#ifndef FI_ACC_DEVICE_H
#define FI_ACC_DEVICE_H

/*
 * =============================================================================
 * OFI Accelerator API — Device-Side
 *
 * High-level functions callable from accelerator compute kernels.
 * The consumer passes opaque handles obtained from fi_acc_*_export() and
 * never touches ring buffers, doorbells, WQE formats, or phase bits.
 *
 * All provider-internal details (struct layouts, HW protocol) are defined
 * below for the compiler to inline, but consumers MUST NOT access struct
 * fields directly — only call the fi_acc_* functions.
 *
 * This file replaces efa-dp-direct (efa_cuda_dp_impl.cuh) with a
 * provider-neutral API shipped as part of libfabric.
 * =============================================================================
 */

#include <stdint.h>

/* Device function qualifier */
#if defined(__CUDACC__) || defined(__HIP_DEVICE_COMPILE__)
  #define FI_ACC_DEV __device__ static inline
  #define FI_ACC_DEV_FENCE_SYSTEM() __threadfence_system()
  #define FI_ACC_DEV_FENCE_BLOCK()  __threadfence_block()
  #define FI_ACC_DEV_ATOMIC_CAS(ptr, expected, desired) \
	atomicCAS((unsigned int *)(ptr), (expected), (desired))
  #define FI_ACC_DEV_ATOMIC_EXCH(ptr, val) \
	atomicExch((unsigned int *)(ptr), (val))
#elif defined(__SYCL_DEVICE_ONLY__)
  #define FI_ACC_DEV static inline
  #define FI_ACC_DEV_FENCE_SYSTEM()
  #define FI_ACC_DEV_FENCE_BLOCK()
  #define FI_ACC_DEV_ATOMIC_CAS(ptr, expected, desired) (*(ptr))
  #define FI_ACC_DEV_ATOMIC_EXCH(ptr, val) (*(ptr) = (val))
#else
  #define FI_ACC_DEV static inline
  #define FI_ACC_DEV_FENCE_SYSTEM()
  #define FI_ACC_DEV_FENCE_BLOCK()
  #define FI_ACC_DEV_ATOMIC_CAS(ptr, expected, desired) (*(ptr))
  #define FI_ACC_DEV_ATOMIC_EXCH(ptr, val) (*(ptr) = (val))
#endif

#ifdef __cplusplus
extern "C" {
#endif

/*
 * =============================================================================
 * Internal struct definitions — VISIBLE FOR COMPILER INLINING ONLY
 *
 * DO NOT ACCESS THESE FIELDS DIRECTLY FROM CONSUMER CODE.
 * They are provider-internal and may change without notice.
 * =============================================================================
 */

/* WQE size constant (EFA: 64 bytes) */
#define FI_ACC_WQE_SIZE 64

struct fi_acc_dev_wq {
	uint32_t  pc;
	int32_t   phase;
	uint32_t  queue_mask;
	uint32_t  queue_size_shift;
	uint32_t  max_batch;
	uint32_t  wqes_pending;
	uint32_t  entry_size;
	uint8_t  *buf;
	uint32_t *db;
};

struct fi_acc_dev_ep {
	struct fi_acc_dev_wq sq;
	struct fi_acc_dev_wq rq;
	uint32_t  sq_lock;
	uint64_t  submitted_count;
	uint32_t  sq_size;
	volatile uint64_t *local_cntr;
};

struct fi_acc_dev_cq {
	uint32_t  cc;
	int32_t   phase;
	uint32_t  queue_mask;
	uint32_t  queue_size_shift;
	uint32_t  entry_size;
	uint8_t  *buf;
};

struct fi_acc_dev_cntr {
	volatile uint64_t *value;
};

struct fi_acc_dev_peer {
	uint16_t ahn;
	uint16_t remote_qpn;
	uint32_t remote_qkey;
};

struct fi_acc_dev_desc {
	uint32_t lkey;
};

/*
 * =============================================================================
 * PUBLIC DEVICE API — Consumer calls only these functions
 * =============================================================================
 */

/**
 * fi_acc_write - Post an RDMA write from the accelerator.
 * @acc_ep:   Opaque EP handle from fi_acc_ep_export()
 * @buf:      Local source buffer address (GPU memory)
 * @len:      Transfer length in bytes
 * @desc:     Opaque MR descriptor from fi_acc_mr_export()
 * @raddr:    Remote destination virtual address
 * @rkey:     Remote key
 * @acc_peer: Opaque peer handle from fi_acc_av_export()
 * @flags:    Reserved, must be 0
 *
 * Internally handles: backpressure check, WQE construction, phase-bit
 * stamping, ring buffer write, memory fence, doorbell write, and
 * submitted_count update.
 *
 * For multi-CTA: caller must hold fi_acc_ep_lock() around this call
 * if multiple CTAs may target the same EP concurrently.
 */
FI_ACC_DEV int
fi_acc_write(void *acc_ep, const void *buf, uint64_t len, void *desc,
	     uint64_t raddr, uint32_t rkey, void *acc_peer, uint64_t flags)
{
	struct fi_acc_dev_ep *ep = (struct fi_acc_dev_ep *)acc_ep;
	struct fi_acc_dev_desc *d = (struct fi_acc_dev_desc *)desc;
	struct fi_acc_dev_peer *peer = (struct fi_acc_dev_peer *)acc_peer;
	uint8_t wqe[FI_ACC_WQE_SIZE];
	uint64_t *w = (uint64_t *)wqe;
	uint32_t *meta, *raddr_seg, *sge_seg;
	uint16_t *target;
	int wqe_phase;
	uint32_t sq_offset;
	uint64_t *src, *dst;
	int i;

	/* Backpressure: wait until SQ has room */
	if (ep->local_cntr) {
		while ((ep->submitted_count - *ep->local_cntr + 1) > ep->sq_size)
			;
	}

	/* Build WQE */
	for (i = 0; i < 8; i++) w[i] = 0;

	meta = (uint32_t *)&w[0];
	meta[0] = 0x04; /* RDMA_WRITE */
	meta[1] = 1;    /* num_sge */
	meta[2] = (uint32_t)(ep->submitted_count & 0xFFFFFFFF); /* wr_id */

	raddr_seg = (uint32_t *)&w[2];
	raddr_seg[0] = rkey;
	*((uint64_t *)&raddr_seg[2]) = raddr;

	sge_seg = (uint32_t *)&w[4];
	sge_seg[0] = d->lkey;
	*((uint64_t *)&sge_seg[2]) = (uint64_t)(uintptr_t)buf;
	sge_seg[4] = (uint32_t)len;

	target = (uint16_t *)&wqe[48];
	target[0] = peer->ahn;
	target[1] = peer->remote_qpn;
	*((uint32_t *)&wqe[52]) = peer->remote_qkey;

	/* Stamp phase bit */
	wqe_phase = ep->sq.phase ^
		(int)(((ep->sq.pc & ep->sq.queue_mask)) >> ep->sq.queue_size_shift);
	*((uint32_t *)&wqe[12]) = (uint32_t)(wqe_phase & 1);

	/* Write WQE to SQ ring (BAR MMIO) */
	sq_offset = (ep->sq.pc & ep->sq.queue_mask) * FI_ACC_WQE_SIZE;
	src = (uint64_t *)wqe;
	dst = (uint64_t *)(ep->sq.buf + sq_offset);
	for (i = 0; i < 8; i++) dst[i] = src[i];

	/* Advance phase */
	ep->sq.phase = ep->sq.phase ^
		(int)(((ep->sq.pc & ep->sq.queue_mask) + 1) >> ep->sq.queue_size_shift);
	ep->sq.pc += 1;

	/* Fence + doorbell */
	FI_ACC_DEV_FENCE_SYSTEM();
	*ep->sq.db = ep->sq.pc;
	FI_ACC_DEV_FENCE_SYSTEM();

	ep->submitted_count++;
	return 0;
}

/**
 * fi_acc_send - Post a send from the accelerator.
 * Same as fi_acc_write but uses send opcode (no remote addr/rkey).
 */
FI_ACC_DEV int
fi_acc_send(void *acc_ep, const void *buf, uint64_t len, void *desc,
	    void *acc_peer, uint64_t flags)
{
	struct fi_acc_dev_ep *ep = (struct fi_acc_dev_ep *)acc_ep;
	struct fi_acc_dev_desc *d = (struct fi_acc_dev_desc *)desc;
	struct fi_acc_dev_peer *peer = (struct fi_acc_dev_peer *)acc_peer;
	uint8_t wqe[FI_ACC_WQE_SIZE];
	uint64_t *w = (uint64_t *)wqe;
	uint32_t *meta, *sge_seg;
	uint16_t *target;
	int wqe_phase;
	uint32_t sq_offset;
	uint64_t *src, *dst;
	int i;

	if (ep->local_cntr) {
		while ((ep->submitted_count - *ep->local_cntr + 1) > ep->sq_size)
			;
	}

	for (i = 0; i < 8; i++) w[i] = 0;

	meta = (uint32_t *)&w[0];
	meta[0] = 0x00; /* SEND */
	meta[1] = 1;
	meta[2] = (uint32_t)(ep->submitted_count & 0xFFFFFFFF);

	sge_seg = (uint32_t *)&w[4];
	sge_seg[0] = d->lkey;
	*((uint64_t *)&sge_seg[2]) = (uint64_t)(uintptr_t)buf;
	sge_seg[4] = (uint32_t)len;

	target = (uint16_t *)&wqe[48];
	target[0] = peer->ahn;
	target[1] = peer->remote_qpn;
	*((uint32_t *)&wqe[52]) = peer->remote_qkey;

	wqe_phase = ep->sq.phase ^
		(int)(((ep->sq.pc & ep->sq.queue_mask)) >> ep->sq.queue_size_shift);
	*((uint32_t *)&wqe[12]) = (uint32_t)(wqe_phase & 1);

	sq_offset = (ep->sq.pc & ep->sq.queue_mask) * FI_ACC_WQE_SIZE;
	src = (uint64_t *)wqe;
	dst = (uint64_t *)(ep->sq.buf + sq_offset);
	for (i = 0; i < 8; i++) dst[i] = src[i];

	ep->sq.phase = ep->sq.phase ^
		(int)(((ep->sq.pc & ep->sq.queue_mask) + 1) >> ep->sq.queue_size_shift);
	ep->sq.pc += 1;

	FI_ACC_DEV_FENCE_SYSTEM();
	*ep->sq.db = ep->sq.pc;
	FI_ACC_DEV_FENCE_SYSTEM();

	ep->submitted_count++;
	return 0;
}

/**
 * fi_acc_cq_poll - Poll for a completion at the given position.
 * @acc_cq:   Opaque CQ handle from fi_acc_cq_export()
 * @position: Position to check (0 for single-thread, tid for cooperative)
 *
 * Returns non-NULL pointer to CQE if ready, NULL otherwise.
 */
FI_ACC_DEV void *
fi_acc_cq_poll(void *acc_cq, uint32_t position)
{
	struct fi_acc_dev_cq *cq = (struct fi_acc_dev_cq *)acc_cq;
	uint32_t cq_offset = ((cq->cc + position) & cq->queue_mask) * cq->entry_size;
	uint8_t *cqe = cq->buf + cq_offset;

	int expected = cq->phase ^
		(int)(((cq->cc & cq->queue_mask) + position) >> cq->queue_size_shift);
	int actual = cqe[3] & 1;

	if (actual == expected) {
		FI_ACC_DEV_FENCE_BLOCK();
		return (void *)cqe;
	}
	return (void *)0;
}

/**
 * fi_acc_cq_pop - Advance CQ consumer pointer after consuming entries.
 * @acc_cq: Opaque CQ handle
 * @amount: Number of CQEs consumed
 */
FI_ACC_DEV void
fi_acc_cq_pop(void *acc_cq, uint32_t amount)
{
	struct fi_acc_dev_cq *cq = (struct fi_acc_dev_cq *)acc_cq;
	cq->phase = cq->phase ^
		(int)(((cq->cc & cq->queue_mask) + amount) >> cq->queue_size_shift);
	cq->cc += amount;
}

/**
 * fi_acc_cntr_read - Read counter value from accelerator memory.
 * @acc_cntr: Opaque counter handle from fi_acc_cntr_export()
 *
 * Inlines to a single volatile load — zero overhead.
 */
FI_ACC_DEV uint64_t
fi_acc_cntr_read(void *acc_cntr)
{
	struct fi_acc_dev_cntr *c = (struct fi_acc_dev_cntr *)acc_cntr;
	return *c->value;
}

/**
 * fi_acc_cntr_wait - Spin until counter reaches target value.
 * @acc_cntr: Opaque counter handle
 * @target:   Value to wait for (inclusive)
 */
FI_ACC_DEV void
fi_acc_cntr_wait(void *acc_cntr, uint64_t target)
{
	struct fi_acc_dev_cntr *c = (struct fi_acc_dev_cntr *)acc_cntr;
	while (*c->value < target)
		;
}

/**
 * fi_acc_post_recv - Post a receive buffer from the accelerator.
 * @acc_ep: Opaque EP handle
 * @buf:    Local receive buffer address
 * @len:    Buffer length
 * @desc:   Opaque MR descriptor
 */
FI_ACC_DEV int
fi_acc_post_recv(void *acc_ep, void *buf, uint64_t len, void *desc)
{
	struct fi_acc_dev_ep *ep = (struct fi_acc_dev_ep *)acc_ep;
	struct fi_acc_dev_desc *d = (struct fi_acc_dev_desc *)desc;
	uint32_t rq_offset = (ep->rq.pc & ep->rq.queue_mask) * ep->rq.entry_size;
	uint8_t *rqe = ep->rq.buf + rq_offset;

	uint32_t *rqe32 = (uint32_t *)rqe;
	rqe32[0] = d->lkey;
	*((uint64_t *)&rqe32[1]) = (uint64_t)(uintptr_t)buf;
	rqe32[3] = (uint32_t)len;

	ep->rq.pc += 1;
	return 0;
}

/**
 * fi_acc_flush_recv - Commit posted receives (fence + RQ doorbell).
 * @acc_ep: Opaque EP handle
 */
FI_ACC_DEV void
fi_acc_flush_recv(void *acc_ep)
{
	struct fi_acc_dev_ep *ep = (struct fi_acc_dev_ep *)acc_ep;
	FI_ACC_DEV_FENCE_SYSTEM();
	*ep->rq.db = ep->rq.pc;
	FI_ACC_DEV_FENCE_SYSTEM();
}

/**
 * fi_acc_ep_lock - Acquire per-EP spinlock for multi-CTA serialization.
 * @acc_ep: Opaque EP handle
 */
FI_ACC_DEV void
fi_acc_ep_lock(void *acc_ep)
{
	struct fi_acc_dev_ep *ep = (struct fi_acc_dev_ep *)acc_ep;
	while (FI_ACC_DEV_ATOMIC_CAS(&ep->sq_lock, 0u, 1u) != 0u)
		;
}

/**
 * fi_acc_ep_unlock - Release per-EP spinlock.
 * @acc_ep: Opaque EP handle
 */
FI_ACC_DEV void
fi_acc_ep_unlock(void *acc_ep)
{
	struct fi_acc_dev_ep *ep = (struct fi_acc_dev_ep *)acc_ep;
	FI_ACC_DEV_ATOMIC_EXCH(&ep->sq_lock, 0u);
}

#ifdef __cplusplus
}
#endif

#endif /* FI_ACC_DEVICE_H */
