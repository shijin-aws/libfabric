/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/* SPDX-FileCopyrightText: Copyright Amazon.com, Inc. or its affiliates. All
 * rights reserved. */

#ifndef FI_ACC_EFA_DEVICE_H
#define FI_ACC_EFA_DEVICE_H

/*
 * =============================================================================
 * EFA Provider — Accelerator Device-Side Implementation (CUDA)
 *
 * Provider-specific inlined device functions for EFA hardware.
 * All public functions use the _efa suffix (e.g., fi_acc_write_efa).
 * Included by the unified rdma/fi_acc_cuda.cuh dispatch header.
 *
 * Consumers MUST NOT include this file directly — include
 * <rdma/fi_acc_cuda.cuh> instead.
 * =============================================================================
 */

/* Uses FI_ACC_DEV and fi_acc_scope from the parent fi_acc_cuda.cuh */

/*
 * Operation flags (subset used on the device path). Values match
 * <rdma/fabric.h>; defined here so device kernels need no host headers.
 */
#ifndef FI_REMOTE_CQ_DATA
#define FI_REMOTE_CQ_DATA	(1ULL << 17)
#endif
#ifndef FI_MORE
#define FI_MORE			(1ULL << 18)
#endif

/* Device intrinsics.
 * Note: test __HIP_DEVICE_COMPILE__'s value, not definedness — HIP host
 * builds define it to 0. */
#if defined(__CUDACC__) || (defined(__HIP_DEVICE_COMPILE__) && __HIP_DEVICE_COMPILE__)
  #define FI_ACC_EFA_FENCE_SYSTEM() __threadfence_system()
  #define FI_ACC_EFA_FENCE_BLOCK()  __threadfence_block()
  #define FI_ACC_EFA_ATOMIC_CAS(ptr, exp, des) \
	atomicCAS((unsigned int *)(ptr), (exp), (des))
  #define FI_ACC_EFA_ATOMIC_EXCH(ptr, val) \
	atomicExch((unsigned int *)(ptr), (val))
#else
  /* Host-side type checking only — never executed */
  #define FI_ACC_EFA_FENCE_SYSTEM()
  #define FI_ACC_EFA_FENCE_BLOCK()
  #define FI_ACC_EFA_ATOMIC_CAS(ptr, exp, des) \
	(*(unsigned int *)(ptr) == (exp) ? \
		(*(unsigned int *)(ptr) = (des), (exp)) : *(unsigned int *)(ptr))
  #define FI_ACC_EFA_ATOMIC_EXCH(ptr, val) \
	({ unsigned int _o = *(unsigned int *)(ptr); \
	   *(unsigned int *)(ptr) = (val); _o; })
#endif

#ifdef __cplusplus
extern "C" {
#endif

/*
 * =============================================================================
 * EFA hardware WQE/CQE formats (mirrors prov/efa/src/efa_io_defs.h)
 * =============================================================================
 */

#define FI_ACC_EFA_WQE_SIZE	64
#define FI_ACC_EFA_RX_DESC_SIZE	16

/* efa_io_send_op_type */
#define FI_ACC_EFA_OP_SEND	 0
#define FI_ACC_EFA_OP_RDMA_READ	 1
#define FI_ACC_EFA_OP_RDMA_WRITE 2

/* ctrl1 bits */
#define FI_ACC_EFA_CTRL1_OP_TYPE_MASK	0x0F	/* bits 3:0 */
#define FI_ACC_EFA_CTRL1_HAS_IMM	(1u << 4)
#define FI_ACC_EFA_CTRL1_META_DESC	(1u << 7)

/* ctrl2 bits */
#define FI_ACC_EFA_CTRL2_PHASE		(1u << 0)
#define FI_ACC_EFA_CTRL2_FIRST		(1u << 2)
#define FI_ACC_EFA_CTRL2_LAST		(1u << 3)
#define FI_ACC_EFA_CTRL2_COMP_REQ	(1u << 4)

/* rx desc lkey_ctrl bits */
#define FI_ACC_EFA_RX_LKEY_MASK		0x00FFFFFFu
#define FI_ACC_EFA_RX_FIRST		(1u << 30)
#define FI_ACC_EFA_RX_LAST		(1u << 31)

/* cqe flags bits (byte 3 of common cdesc) */
#define FI_ACC_EFA_CQE_PHASE		(1u << 0)

struct fi_acc_efa_tx_meta_desc {
	uint16_t req_id;
	uint8_t  ctrl1;
	uint8_t  ctrl2;
	uint16_t dest_qp_num;
	uint16_t length;	/* SGL count (or inline length) */
	uint32_t immediate_data;
	uint16_t ah;
	uint8_t  ctrl3;
	uint8_t  reserved;
	uint32_t qkey;
	uint8_t  reserved2[12];
};

struct fi_acc_efa_tx_buf_desc {
	uint32_t length;
	uint32_t lkey;		/* bits 23:0 */
	uint32_t buf_addr_lo;
	uint32_t buf_addr_hi;
};

struct fi_acc_efa_tx_wqe {
	struct fi_acc_efa_tx_meta_desc meta;
	union {
		struct fi_acc_efa_tx_buf_desc sgl[2];
		struct {
			struct fi_acc_efa_tx_buf_desc remote_mem; /* length,rkey,lo,hi */
			struct fi_acc_efa_tx_buf_desc local_mem;  /* length,lkey,lo,hi */
		} rdma_req;
	} data;
};

struct fi_acc_efa_rx_desc {
	uint32_t buf_addr_lo;
	uint32_t buf_addr_hi;
	uint16_t req_id;
	uint16_t length;
	uint32_t lkey_ctrl;
};

/*
 * =============================================================================
 * Opaque device handle layouts
 *
 * All exported structs carry a comp_mask as the first field for
 * forward-compatible extension (append-only; new fields guarded by
 * new comp_mask bits).
 * =============================================================================
 */

struct fi_acc_efa_wq {
	uint32_t  pc;		/* producer counter (monotonic) */
	int32_t   phase;
	uint32_t  queue_mask;
	uint32_t  queue_size_shift;
	uint32_t  max_batch;
	uint32_t  wqes_pending;	/* written but doorbell not rung */
	uint32_t  entry_size;
	uint8_t  *buf;
	uint32_t *db;
};

struct fi_acc_efa_ep {
	struct fi_acc_hdr hdr;	/* must be first */
	struct fi_acc_efa_wq sq;
	struct fi_acc_efa_wq rq;
	uint32_t  sq_lock;
	uint32_t  pad;
	uint64_t  submitted_count;
	uint32_t  sq_size;
	uint32_t  pad2;
	volatile uint64_t *local_cntr;
};

struct fi_acc_efa_cq {
	struct fi_acc_hdr hdr;	/* must be first */
	uint32_t  cc;		/* consumer counter */
	int32_t   phase;
	uint32_t  queue_mask;
	uint32_t  queue_size_shift;
	uint32_t  entry_size;
	uint32_t  pad;
	uint8_t  *buf;
};

struct fi_acc_efa_cntr {
	struct fi_acc_hdr hdr;	/* must be first */
	volatile uint64_t *value;	/* completion counter (NIC-written) */
	volatile uint64_t *err_value;	/* error counter (may be NULL) */
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
 * Internal helpers
 * =============================================================================
 */

/*
 * Scope-based serialization. FI_ACC_WORK_ITEM means a single thread owns
 * the EP — no synchronization needed. All other scopes serialize posts
 * through the EP spinlock. (Warp-cooperative slot reservation with
 * parallel WQE writes is a planned optimization; the lock preserves
 * correctness for all scopes.)
 */
FI_ACC_DEV void fi_acc_efa_lock(struct fi_acc_efa_ep *ep, int scope)
{
	if (scope == FI_ACC_WORK_ITEM)
		return;
	while (FI_ACC_EFA_ATOMIC_CAS(&ep->sq_lock, 0u, 1u) != 0u)
		;
}

FI_ACC_DEV void fi_acc_efa_unlock(struct fi_acc_efa_ep *ep, int scope)
{
	if (scope == FI_ACC_WORK_ITEM)
		return;
	FI_ACC_EFA_FENCE_SYSTEM();
	FI_ACC_EFA_ATOMIC_EXCH(&ep->sq_lock, 0u);
}

FI_ACC_DEV int fi_acc_efa_wq_phase(struct fi_acc_efa_wq *wq, uint32_t idx)
{
	return wq->phase ^
	       (int)(((wq->pc & wq->queue_mask) + idx) >> wq->queue_size_shift);
}

/* Ring the SQ doorbell for all written-but-pending WQEs */
FI_ACC_DEV void fi_acc_efa_sq_ring(struct fi_acc_efa_ep *ep)
{
	if (!ep->sq.wqes_pending)
		return;

	ep->sq.phase = fi_acc_efa_wq_phase(&ep->sq, ep->sq.wqes_pending);
	ep->sq.pc += ep->sq.wqes_pending;
	ep->sq.wqes_pending = 0;

	FI_ACC_EFA_FENCE_SYSTEM();
	*ep->sq.db = ep->sq.pc;
	FI_ACC_EFA_FENCE_SYSTEM();
}

/*
 * Post one WQE. Handles backpressure, phase stamping, the 64-byte ring
 * write, and doorbell (deferred when FI_MORE is set).
 */
FI_ACC_DEV int fi_acc_efa_post_wqe(struct fi_acc_efa_ep *ep,
				   struct fi_acc_efa_tx_wqe *wqe,
				   uint64_t flags)
{
	uint32_t slot, sq_offset;
	uint64_t *src, *dst;
	int i;

	/* Backpressure: bound in-flight WQEs by SQ size via HW counter */
	if (ep->local_cntr) {
		while ((ep->submitted_count + ep->sq.wqes_pending + 1 -
			*ep->local_cntr) > ep->sq_size)
			;
	}

	/* Respect the HW staging limit for un-rung WQEs */
	if (ep->sq.wqes_pending + 1 > ep->sq.max_batch)
		fi_acc_efa_sq_ring(ep);

	slot = ep->sq.pc + ep->sq.wqes_pending;

	/* Phase bit */
	if (fi_acc_efa_wq_phase(&ep->sq, ep->sq.wqes_pending) & 1)
		wqe->meta.ctrl2 |= FI_ACC_EFA_CTRL2_PHASE;

	/* 64-byte write to SQ ring slot (BAR MMIO) */
	sq_offset = (slot & ep->sq.queue_mask) * FI_ACC_EFA_WQE_SIZE;
	src = (uint64_t *)wqe;
	dst = (uint64_t *)(ep->sq.buf + sq_offset);
	for (i = 0; i < 8; i++)
		dst[i] = src[i];

	ep->sq.wqes_pending++;
	ep->submitted_count++;

	if (!(flags & FI_MORE))
		fi_acc_efa_sq_ring(ep);

	return 0;
}

/* Initialize common WQE fields */
FI_ACC_DEV void fi_acc_efa_init_wqe(struct fi_acc_efa_tx_wqe *wqe,
				    uint32_t op_type, uint16_t req_id,
				    struct fi_acc_efa_peer *peer)
{
	uint64_t *w = (uint64_t *)wqe;
	int i;

	for (i = 0; i < 8; i++)
		w[i] = 0;

	wqe->meta.req_id = req_id;
	wqe->meta.ctrl1 = (uint8_t)(FI_ACC_EFA_CTRL1_META_DESC |
				    (op_type & FI_ACC_EFA_CTRL1_OP_TYPE_MASK));
	wqe->meta.ctrl2 = (uint8_t)(FI_ACC_EFA_CTRL2_FIRST |
				    FI_ACC_EFA_CTRL2_LAST |
				    FI_ACC_EFA_CTRL2_COMP_REQ);
	wqe->meta.ah = peer->ahn;
	wqe->meta.dest_qp_num = peer->remote_qpn;
	wqe->meta.qkey = peer->remote_qkey;
}

FI_ACC_DEV void fi_acc_efa_set_buf(struct fi_acc_efa_tx_buf_desc *d,
				   uint32_t key, uint64_t addr, uint32_t len)
{
	d->length = len;
	d->lkey = key & FI_ACC_EFA_RX_LKEY_MASK;
	d->buf_addr_lo = (uint32_t)(addr & 0xFFFFFFFF);
	d->buf_addr_hi = (uint32_t)(addr >> 32);
}

/*
 * =============================================================================
 * Device-side post operations (OFI Accelerator API)
 * =============================================================================
 */

/**
 * fi_acc_write - RDMA write from a device kernel.
 * @acc_ep: opaque EP handle from fi_ep_export_acc()
 * @buf:    local source buffer
 * @desc:   opaque MR descriptor entry from fi_mr_export_acc()
 * @size:   bytes to write
 * @data:   immediate data; delivered when FI_REMOTE_CQ_DATA is set in flags
 * @peer:   opaque peer entry from fi_av_export_acc()
 * @raddr:  remote virtual address
 * @rkey:   remote key
 * @ctxt:   per-op context (CQ-based consumers; counter-only pass NULL)
 * @scope:  contention level on this EP (FI_ACC_WORK_ITEM..FI_ACC_DEVICE)
 * @flags:  FI_MORE (defer doorbell), FI_REMOTE_CQ_DATA (write with imm)
 */
FI_ACC_DEV int
fi_acc_write_efa(void *acc_ep, const void *buf, void *desc, uint64_t size,
	     uint64_t data, void *peer, uint64_t raddr, uint64_t rkey,
	     void *ctxt, int scope, uint64_t flags)
{
	struct fi_acc_efa_ep *ep = (struct fi_acc_efa_ep *)acc_ep;
	struct fi_acc_efa_desc *d = (struct fi_acc_efa_desc *)desc;
	struct fi_acc_efa_peer *p = (struct fi_acc_efa_peer *)peer;
	struct fi_acc_efa_tx_wqe wqe;
	int ret;

	(void)ctxt;

	fi_acc_efa_lock(ep, scope);

	fi_acc_efa_init_wqe(&wqe, FI_ACC_EFA_OP_RDMA_WRITE,
			    (uint16_t)(ep->submitted_count +
				       ep->sq.wqes_pending), p);
	if (flags & FI_REMOTE_CQ_DATA) {
		wqe.meta.ctrl1 |= FI_ACC_EFA_CTRL1_HAS_IMM;
		wqe.meta.immediate_data = (uint32_t)data;
	}
	fi_acc_efa_set_buf(&wqe.data.rdma_req.remote_mem, (uint32_t)rkey,
			   raddr, (uint32_t)size);
	fi_acc_efa_set_buf(&wqe.data.rdma_req.local_mem, d->lkey,
			   (uint64_t)(uintptr_t)buf, (uint32_t)size);
	wqe.meta.length = 1;

	ret = fi_acc_efa_post_wqe(ep, &wqe, flags);

	fi_acc_efa_unlock(ep, scope);
	return ret;
}

/**
 * fi_acc_read - RDMA read from a device kernel.
 */
FI_ACC_DEV int
fi_acc_read_efa(void *acc_ep, void *buf, void *desc, uint64_t size,
	    void *peer, uint64_t raddr, uint64_t rkey,
	    void *ctxt, int scope, uint64_t flags)
{
	struct fi_acc_efa_ep *ep = (struct fi_acc_efa_ep *)acc_ep;
	struct fi_acc_efa_desc *d = (struct fi_acc_efa_desc *)desc;
	struct fi_acc_efa_peer *p = (struct fi_acc_efa_peer *)peer;
	struct fi_acc_efa_tx_wqe wqe;
	int ret;

	(void)ctxt;

	fi_acc_efa_lock(ep, scope);

	fi_acc_efa_init_wqe(&wqe, FI_ACC_EFA_OP_RDMA_READ,
			    (uint16_t)(ep->submitted_count +
				       ep->sq.wqes_pending), p);
	fi_acc_efa_set_buf(&wqe.data.rdma_req.remote_mem, (uint32_t)rkey,
			   raddr, (uint32_t)size);
	fi_acc_efa_set_buf(&wqe.data.rdma_req.local_mem, d->lkey,
			   (uint64_t)(uintptr_t)buf, (uint32_t)size);
	wqe.meta.length = 1;

	ret = fi_acc_efa_post_wqe(ep, &wqe, flags);

	fi_acc_efa_unlock(ep, scope);
	return ret;
}

/**
 * fi_acc_send - message send from a device kernel.
 */
FI_ACC_DEV int
fi_acc_send_efa(void *acc_ep, const void *buf, uint64_t size, void *desc,
	    uint64_t data, void *peer, void *ctxt, int scope, uint64_t flags)
{
	struct fi_acc_efa_ep *ep = (struct fi_acc_efa_ep *)acc_ep;
	struct fi_acc_efa_desc *d = (struct fi_acc_efa_desc *)desc;
	struct fi_acc_efa_peer *p = (struct fi_acc_efa_peer *)peer;
	struct fi_acc_efa_tx_wqe wqe;
	int ret;

	(void)ctxt;

	fi_acc_efa_lock(ep, scope);

	fi_acc_efa_init_wqe(&wqe, FI_ACC_EFA_OP_SEND,
			    (uint16_t)(ep->submitted_count +
				       ep->sq.wqes_pending), p);
	if (flags & FI_REMOTE_CQ_DATA) {
		wqe.meta.ctrl1 |= FI_ACC_EFA_CTRL1_HAS_IMM;
		wqe.meta.immediate_data = (uint32_t)data;
	}
	fi_acc_efa_set_buf(&wqe.data.sgl[0], d->lkey,
			   (uint64_t)(uintptr_t)buf, (uint32_t)size);
	wqe.meta.length = 1;

	ret = fi_acc_efa_post_wqe(ep, &wqe, flags);

	fi_acc_efa_unlock(ep, scope);
	return ret;
}

/**
 * fi_acc_recv - post a receive buffer from a device kernel.
 * @flags: FI_MORE defers the RQ doorbell until fi_acc_flush(FI_RECV)
 *         or a subsequent post without FI_MORE.
 */
FI_ACC_DEV int
fi_acc_recv_efa(void *acc_ep, void *buf, void *desc, uint64_t size,
	    void *peer, void *ctxt, int scope, uint64_t flags)
{
	struct fi_acc_efa_ep *ep = (struct fi_acc_efa_ep *)acc_ep;
	struct fi_acc_efa_desc *d = (struct fi_acc_efa_desc *)desc;
	struct fi_acc_efa_rx_desc rqe;
	uint32_t rq_offset;
	uint32_t *dst, *src;
	int i;

	(void)peer; (void)ctxt;

	fi_acc_efa_lock(ep, scope);

	rqe.buf_addr_lo = (uint32_t)((uint64_t)(uintptr_t)buf & 0xFFFFFFFF);
	rqe.buf_addr_hi = (uint32_t)((uint64_t)(uintptr_t)buf >> 32);
	rqe.req_id = (uint16_t)ep->rq.pc;
	rqe.length = (uint16_t)size;
	rqe.lkey_ctrl = (d->lkey & FI_ACC_EFA_RX_LKEY_MASK) |
			FI_ACC_EFA_RX_FIRST | FI_ACC_EFA_RX_LAST;

	rq_offset = (ep->rq.pc & ep->rq.queue_mask) * FI_ACC_EFA_RX_DESC_SIZE;
	dst = (uint32_t *)(ep->rq.buf + rq_offset);
	src = (uint32_t *)&rqe;
	for (i = 0; i < 4; i++)
		dst[i] = src[i];

	ep->rq.pc++;
	if (!(ep->rq.pc & ep->rq.queue_mask))
		ep->rq.phase++;

	ep->rq.wqes_pending++;
	if (!(flags & FI_MORE) || ep->rq.wqes_pending >= ep->rq.max_batch) {
		FI_ACC_EFA_FENCE_SYSTEM();
		*ep->rq.db = ep->rq.pc;
		ep->rq.wqes_pending = 0;
	}

	fi_acc_efa_unlock(ep, scope);
	return 0;
}

/**
 * fi_acc_flush - ring the doorbell for FI_MORE-deferred WQEs.
 * @flags: FI_TRANSMIT/FI_SEND flushes the SQ, FI_RECV flushes the RQ.
 *         0 flushes both. Does NOT wait for completion — use the
 *         counter drain pattern (fi_acc_cntr_wait) for that.
 */
#ifndef FI_SEND
#define FI_SEND			(1ULL << 11)
#endif
#ifndef FI_RECV
#define FI_RECV			(1ULL << 10)
#endif
#ifndef FI_TRANSMIT
#define FI_TRANSMIT		FI_SEND
#endif

FI_ACC_DEV void
fi_acc_flush_efa(void *acc_ep, uint64_t flags)
{
	struct fi_acc_efa_ep *ep = (struct fi_acc_efa_ep *)acc_ep;

	if (!flags || (flags & FI_TRANSMIT))
		fi_acc_efa_sq_ring(ep);

	if (!flags || (flags & FI_RECV)) {
		if (ep->rq.wqes_pending) {
			FI_ACC_EFA_FENCE_SYSTEM();
			*ep->rq.db = ep->rq.pc;
			ep->rq.wqes_pending = 0;
		}
	}
}

/*
 * =============================================================================
 * Completion — counters (primary) and CQ polling (secondary)
 * =============================================================================
 */

FI_ACC_DEV uint64_t
fi_acc_cntr_read_efa(void *acc_cntr)
{
	struct fi_acc_efa_cntr *c = (struct fi_acc_efa_cntr *)acc_cntr;
	return *c->value;
}

FI_ACC_DEV uint64_t
fi_acc_cntr_readerr_efa(void *acc_cntr)
{
	struct fi_acc_efa_cntr *c = (struct fi_acc_efa_cntr *)acc_cntr;
	if (!c->err_value)
		return 0;
	return *c->err_value;
}

FI_ACC_DEV void
fi_acc_cntr_wait_efa(void *acc_cntr, uint64_t target)
{
	struct fi_acc_efa_cntr *c = (struct fi_acc_efa_cntr *)acc_cntr;
	while (*c->value < target)
		;
}

/**
 * fi_acc_cq_poll - poll one CQ entry at a position offset.
 * Position-based so N threads can poll positions 0..N-1 in parallel.
 * Returns the raw CQE pointer when ready, NULL otherwise.
 */
FI_ACC_DEV void *
fi_acc_cq_poll_efa(void *acc_cq, uint32_t position)
{
	struct fi_acc_efa_cq *cq = (struct fi_acc_efa_cq *)acc_cq;
	uint32_t cq_offset = ((cq->cc + position) & cq->queue_mask) *
			     cq->entry_size;
	uint8_t *cqe = cq->buf + cq_offset;
	int expected = (cq->phase ^
		(int)(((cq->cc & cq->queue_mask) + position) >>
		      cq->queue_size_shift)) & 1;
	int actual = cqe[3] & FI_ACC_EFA_CQE_PHASE;

	if (actual == expected) {
		FI_ACC_EFA_FENCE_BLOCK();
		return (void *)cqe;
	}
	return (void *)0;
}

FI_ACC_DEV void
fi_acc_cq_pop_efa(void *acc_cq, uint32_t amount)
{
	struct fi_acc_efa_cq *cq = (struct fi_acc_efa_cq *)acc_cq;
	cq->phase = cq->phase ^
		(int)(((cq->cc & cq->queue_mask) + amount) >>
		      cq->queue_size_shift);
	cq->cc += amount;
}

/**
 * fi_acc_wc_read_vendor_err - vendor error code from a CQE
 * (byte 2 = status in the EFA common completion descriptor).
 */
FI_ACC_DEV uint32_t
fi_acc_wc_read_vendor_err_efa(void *cqe)
{
	return ((uint8_t *)cqe)[2];
}

#ifdef __cplusplus
}
#endif

#endif /* FI_ACC_EFA_DEVICE_H */
