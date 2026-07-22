/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/* SPDX-FileCopyrightText: Copyright Amazon.com, Inc. or its affiliates. All
 * rights reserved. */

#ifndef FI_ACC_EFA_DEVICE_H
#define FI_ACC_EFA_DEVICE_H

/*
 * =============================================================================
 * EFA Provider — Accelerator Device-Side Implementation
 *
 * This header provides the inlined device functions for EFA hardware.
 * It is the replacement for efa-dp-direct (efa_cuda_dp_impl.cuh).
 *
 * Consumers include THIS file (not fi_acc_device.h directly) to get the
 * full inlined implementation. This file is mirrored into NCCL's tree.
 *
 * Location: prov/efa/src/acc_cuda/fi_acc_efa_device.h
 * =============================================================================
 */

#define FI_ACC_DEVICE_IMPL  /* Suppress declarations in fi_acc_device.h */
#include <rdma/fi_acc_device.h>

/* Device intrinsics */
#if defined(__CUDACC__) || defined(__HIP_DEVICE_COMPILE__)
  #define FI_ACC_EFA_FENCE_SYSTEM() __threadfence_system()
  #define FI_ACC_EFA_FENCE_BLOCK()  __threadfence_block()
  #define FI_ACC_EFA_ATOMIC_CAS(ptr, exp, des) \
	atomicCAS((unsigned int *)(ptr), (exp), (des))
  #define FI_ACC_EFA_ATOMIC_EXCH(ptr, val) \
	atomicExch((unsigned int *)(ptr), (val))
#else
  #define FI_ACC_EFA_FENCE_SYSTEM()
  #define FI_ACC_EFA_FENCE_BLOCK()
  #define FI_ACC_EFA_ATOMIC_CAS(ptr, exp, des) (*(ptr))
  #define FI_ACC_EFA_ATOMIC_EXCH(ptr, val) (*(ptr) = (val))
#endif

#ifdef __cplusplus
extern "C" {
#endif

/*
 * =============================================================================
 * EFA Internal Struct Definitions
 *
 * These are layout-compatible with efa-dp-direct's efa_cuda_qp / efa_cuda_cq.
 * Defined here for the compiler to inline functions. Consumers MUST NOT
 * access fields directly — only call fi_acc_* functions.
 * =============================================================================
 */

#define FI_ACC_EFA_WQE_SIZE 64

struct fi_acc_efa_wq {
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

struct fi_acc_efa_ep {
	struct fi_acc_efa_wq sq;
	struct fi_acc_efa_wq rq;
	uint32_t  sq_lock;
	uint64_t  submitted_count;
	uint32_t  sq_size;
	volatile uint64_t *local_cntr;
};

struct fi_acc_efa_cq {
	uint32_t  cc;
	int32_t   phase;
	uint32_t  queue_mask;
	uint32_t  queue_size_shift;
	uint32_t  entry_size;
	uint8_t  *buf;
};

struct fi_acc_efa_cntr {
	volatile uint64_t *value;
};

struct fi_acc_efa_peer {
	uint16_t ahn;
	uint16_t remote_qpn;
	uint32_t remote_qkey;
};

struct fi_acc_efa_desc {
	uint32_t lkey;
};

/*
 * =============================================================================
 * EFA Device Function Implementations
 * =============================================================================
 */

FI_ACC_DEV int
fi_acc_write(void *acc_ep, const void *buf, uint64_t len, void *desc,
	     uint64_t raddr, uint32_t rkey, void *acc_peer, uint64_t flags)
{
	struct fi_acc_efa_ep *ep = (struct fi_acc_efa_ep *)acc_ep;
	struct fi_acc_efa_desc *d = (struct fi_acc_efa_desc *)desc;
	struct fi_acc_efa_peer *peer = (struct fi_acc_efa_peer *)acc_peer;
	uint8_t wqe[FI_ACC_EFA_WQE_SIZE];
	uint64_t *w = (uint64_t *)wqe;
	uint32_t *meta, *raddr_seg, *sge_seg;
	uint16_t *target;
	int wqe_phase, i;
	uint32_t sq_offset;
	uint64_t *src, *dst;

	(void)flags;

	/* Backpressure */
	if (ep->local_cntr) {
		while ((ep->submitted_count - *ep->local_cntr + 1) > ep->sq_size)
			;
	}

	/* Build WQE */
	for (i = 0; i < 8; i++) w[i] = 0;

	meta = (uint32_t *)&w[0];
	meta[0] = 0x04; /* RDMA_WRITE */
	meta[1] = 1;    /* num_sge */
	meta[2] = (uint32_t)(ep->submitted_count & 0xFFFFFFFF);

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

	/* Phase bit */
	wqe_phase = ep->sq.phase ^
		(int)((ep->sq.pc & ep->sq.queue_mask) >> ep->sq.queue_size_shift);
	*((uint32_t *)&wqe[12]) = (uint32_t)(wqe_phase & 1);

	/* Write WQE to SQ ring (BAR MMIO) */
	sq_offset = (ep->sq.pc & ep->sq.queue_mask) * FI_ACC_EFA_WQE_SIZE;
	src = (uint64_t *)wqe;
	dst = (uint64_t *)(ep->sq.buf + sq_offset);
	for (i = 0; i < 8; i++) dst[i] = src[i];

	/* Advance state */
	ep->sq.phase = ep->sq.phase ^
		(int)(((ep->sq.pc & ep->sq.queue_mask) + 1) >> ep->sq.queue_size_shift);
	ep->sq.pc += 1;

	/* Fence + doorbell */
	FI_ACC_EFA_FENCE_SYSTEM();
	*ep->sq.db = ep->sq.pc;
	FI_ACC_EFA_FENCE_SYSTEM();

	ep->submitted_count++;
	return 0;
}

FI_ACC_DEV int
fi_acc_send(void *acc_ep, const void *buf, uint64_t len, void *desc,
	    void *acc_peer, uint64_t flags)
{
	struct fi_acc_efa_ep *ep = (struct fi_acc_efa_ep *)acc_ep;
	struct fi_acc_efa_desc *d = (struct fi_acc_efa_desc *)desc;
	struct fi_acc_efa_peer *peer = (struct fi_acc_efa_peer *)acc_peer;
	uint8_t wqe[FI_ACC_EFA_WQE_SIZE];
	uint64_t *w = (uint64_t *)wqe;
	uint32_t *meta, *sge_seg;
	uint16_t *target;
	int wqe_phase, i;
	uint32_t sq_offset;
	uint64_t *src, *dst;

	(void)flags;

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
		(int)((ep->sq.pc & ep->sq.queue_mask) >> ep->sq.queue_size_shift);
	*((uint32_t *)&wqe[12]) = (uint32_t)(wqe_phase & 1);

	sq_offset = (ep->sq.pc & ep->sq.queue_mask) * FI_ACC_EFA_WQE_SIZE;
	src = (uint64_t *)wqe;
	dst = (uint64_t *)(ep->sq.buf + sq_offset);
	for (i = 0; i < 8; i++) dst[i] = src[i];

	ep->sq.phase = ep->sq.phase ^
		(int)(((ep->sq.pc & ep->sq.queue_mask) + 1) >> ep->sq.queue_size_shift);
	ep->sq.pc += 1;

	FI_ACC_EFA_FENCE_SYSTEM();
	*ep->sq.db = ep->sq.pc;
	FI_ACC_EFA_FENCE_SYSTEM();

	ep->submitted_count++;
	return 0;
}

FI_ACC_DEV void *
fi_acc_cq_poll(void *acc_cq, uint32_t position)
{
	struct fi_acc_efa_cq *cq = (struct fi_acc_efa_cq *)acc_cq;
	uint32_t cq_offset = ((cq->cc + position) & cq->queue_mask) * cq->entry_size;
	uint8_t *cqe = cq->buf + cq_offset;

	int expected = cq->phase ^
		(int)(((cq->cc & cq->queue_mask) + position) >> cq->queue_size_shift);
	int actual = cqe[3] & 1;

	if (actual == expected) {
		FI_ACC_EFA_FENCE_BLOCK();
		return (void *)cqe;
	}
	return (void *)0;
}

FI_ACC_DEV void
fi_acc_cq_pop(void *acc_cq, uint32_t amount)
{
	struct fi_acc_efa_cq *cq = (struct fi_acc_efa_cq *)acc_cq;
	cq->phase = cq->phase ^
		(int)(((cq->cc & cq->queue_mask) + amount) >> cq->queue_size_shift);
	cq->cc += amount;
}

FI_ACC_DEV uint64_t
fi_acc_cntr_read(void *acc_cntr)
{
	struct fi_acc_efa_cntr *c = (struct fi_acc_efa_cntr *)acc_cntr;
	return *c->value;
}

FI_ACC_DEV void
fi_acc_cntr_wait(void *acc_cntr, uint64_t target)
{
	struct fi_acc_efa_cntr *c = (struct fi_acc_efa_cntr *)acc_cntr;
	while (*c->value < target)
		;
}

FI_ACC_DEV int
fi_acc_post_recv(void *acc_ep, void *buf, uint64_t len, void *desc)
{
	struct fi_acc_efa_ep *ep = (struct fi_acc_efa_ep *)acc_ep;
	struct fi_acc_efa_desc *d = (struct fi_acc_efa_desc *)desc;
	uint32_t rq_offset = (ep->rq.pc & ep->rq.queue_mask) * ep->rq.entry_size;
	uint8_t *rqe = ep->rq.buf + rq_offset;
	uint32_t *rqe32 = (uint32_t *)rqe;

	rqe32[0] = d->lkey;
	*((uint64_t *)&rqe32[1]) = (uint64_t)(uintptr_t)buf;
	rqe32[3] = (uint32_t)len;

	ep->rq.pc += 1;
	return 0;
}

FI_ACC_DEV void
fi_acc_flush_recv(void *acc_ep)
{
	struct fi_acc_efa_ep *ep = (struct fi_acc_efa_ep *)acc_ep;
	FI_ACC_EFA_FENCE_SYSTEM();
	*ep->rq.db = ep->rq.pc;
	FI_ACC_EFA_FENCE_SYSTEM();
}

FI_ACC_DEV void
fi_acc_ep_lock(void *acc_ep)
{
	struct fi_acc_efa_ep *ep = (struct fi_acc_efa_ep *)acc_ep;
	while (FI_ACC_EFA_ATOMIC_CAS(&ep->sq_lock, 0u, 1u) != 0u)
		;
}

FI_ACC_DEV void
fi_acc_ep_unlock(void *acc_ep)
{
	struct fi_acc_efa_ep *ep = (struct fi_acc_efa_ep *)acc_ep;
	FI_ACC_EFA_ATOMIC_EXCH(&ep->sq_lock, 0u);
}

#ifdef __cplusplus
}
#endif

#endif /* FI_ACC_EFA_DEVICE_H */
