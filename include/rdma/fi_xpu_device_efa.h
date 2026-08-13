/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/* SPDX-FileCopyrightText: Copyright Amazon.com, Inc. or its affiliates. */

#ifndef FI_XPU_DEVICE_EFA_H
#define FI_XPU_DEVICE_EFA_H

/*
 * EFA Provider — XPU Device-Side Implementation
 *
 * Inlined device functions for EFA hardware, implementing the OFI XPU
 * device API surface. Consumers include fi_xpu_device.h which pulls in
 * this header and dispatches based on prov_id.
 *
 * The struct definitions below exist so the compiler can inline the
 * functions. Consumers MUST NOT access struct fields directly — treat
 * all handles as opaque and only call fi_xpu_* dispatch functions.
 */

#include <stdint.h>
#include <stddef.h>
#include <rdma/fi_xpu.h>

/*
 * This header is included by fi_xpu_device.h which defines FI_XPU_FUNC
 * and the scope enum. Provide fallbacks for standalone compilation.
 */
#ifndef FI_XPU_FUNC
#define FI_XPU_FUNC static inline
#endif
#ifndef FI_XPU_WORK_ITEM
#define FI_XPU_WORK_ITEM  0
#define FI_XPU_SUBGROUP   1
#define FI_XPU_WORK_GROUP 2
#define FI_XPU_DEVICE     3
#endif

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
#ifndef FI_SEND
#define FI_SEND			(1ULL << 11)
#endif
#ifndef FI_RECV
#define FI_RECV			(1ULL << 10)
#endif
#ifndef FI_TRANSMIT
#define FI_TRANSMIT		FI_SEND
#endif

/* Device intrinsics */
#if defined(__CUDACC__) || \
    (defined(__HIP_DEVICE_COMPILE__) && __HIP_DEVICE_COMPILE__)
  #define FI_XPU_EFA_FENCE_SYSTEM() __threadfence_system()
  #define FI_XPU_EFA_FENCE_BLOCK()  __threadfence_block()
  #define FI_XPU_EFA_ATOMIC_CAS(ptr, exp, des) \
	atomicCAS((unsigned int *)(ptr), (exp), (des))
  #define FI_XPU_EFA_ATOMIC_EXCH(ptr, val) \
	atomicExch((unsigned int *)(ptr), (val))
#else
  /* Host-side type checking only — never executed */
  #define FI_XPU_EFA_FENCE_SYSTEM()
  #define FI_XPU_EFA_FENCE_BLOCK()
  #define FI_XPU_EFA_ATOMIC_CAS(ptr, exp, des) \
	(*(unsigned int *)(ptr) == (exp) ? \
		(*(unsigned int *)(ptr) = (des), (exp)) : \
		*(unsigned int *)(ptr))
  #define FI_XPU_EFA_ATOMIC_EXCH(ptr, val) \
	({ unsigned int _o = *(unsigned int *)(ptr); \
	   *(unsigned int *)(ptr) = (val); _o; })
#endif

/*
 * EFA hardware WQE/CQE constants
 */
#define FI_XPU_EFA_WQE_SIZE		64
#define FI_XPU_EFA_RX_DESC_SIZE		16

/* efa_io_send_op_type */
#define FI_XPU_EFA_OP_SEND		0
#define FI_XPU_EFA_OP_RDMA_READ		1
#define FI_XPU_EFA_OP_RDMA_WRITE	2

/* ctrl1 bits */
#define FI_XPU_EFA_CTRL1_OP_TYPE_MASK	0x0F
#define FI_XPU_EFA_CTRL1_HAS_IMM	(1u << 4)
#define FI_XPU_EFA_CTRL1_META_DESC	(1u << 7)

/* ctrl2 bits */
#define FI_XPU_EFA_CTRL2_PHASE		(1u << 0)
#define FI_XPU_EFA_CTRL2_FIRST		(1u << 2)
#define FI_XPU_EFA_CTRL2_LAST		(1u << 3)
#define FI_XPU_EFA_CTRL2_COMP_REQ	(1u << 4)

/* rx desc lkey_ctrl bits */
#define FI_XPU_EFA_RX_LKEY_MASK		0x00FFFFFFu
#define FI_XPU_EFA_RX_FIRST		(1u << 30)
#define FI_XPU_EFA_RX_LAST		(1u << 31)

/* cqe phase bit */
#define FI_XPU_EFA_CQE_PHASE		(1u << 0)

/*
 * EFA hardware descriptor formats
 */
struct fi_xpu_efa_tx_meta_desc {
	uint16_t req_id;
	uint8_t  ctrl1;
	uint8_t  ctrl2;
	uint16_t dest_qp_num;
	uint16_t length;
	uint32_t immediate_data;
	uint16_t ah;
	uint8_t  ctrl3;
	uint8_t  reserved;
	uint32_t qkey;
	uint8_t  reserved2[12];
};

struct fi_xpu_efa_tx_buf_desc {
	uint32_t length;
	uint32_t lkey;
	uint32_t buf_addr_lo;
	uint32_t buf_addr_hi;
};

struct fi_xpu_efa_tx_wqe {
	struct fi_xpu_efa_tx_meta_desc meta;
	union {
		struct fi_xpu_efa_tx_buf_desc sgl[2];
		struct {
			struct fi_xpu_efa_tx_buf_desc remote_mem;
			struct fi_xpu_efa_tx_buf_desc local_mem;
		} rdma_req;
	} data;
};

struct fi_xpu_efa_rx_desc {
	uint32_t buf_addr_lo;
	uint32_t buf_addr_hi;
	uint16_t req_id;
	uint16_t length;
	uint32_t lkey_ctrl;
};

/*
 * Opaque device handle layouts — exported by the host-side functions
 */
struct fi_xpu_efa_wq {
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

struct fi_xpu_efa_ep {
	struct fid_xpu_ep	xpu_ep;		/* must be first */
	struct fi_xpu_efa_wq	sq;
	struct fi_xpu_efa_wq	rq;
	uint32_t		sq_lock;
	uint32_t		pad;
	uint64_t		submitted_count;
	uint32_t		sq_size;
	uint32_t		pad2;
	volatile uint64_t	*local_cntr;
};

struct fi_xpu_efa_cq {
	struct fid_xpu_cq	xpu_cq;		/* must be first */
	uint32_t		cc;
	int32_t			phase;
	uint32_t		queue_mask;
	uint32_t		queue_size_shift;
	uint32_t		entry_size;
	uint32_t		pad;
	uint8_t			*buf;
};

struct fi_xpu_efa_cntr {
	struct fid_xpu_cntr	xpu_cntr;	/* must be first */
	volatile uint64_t	*value;
	volatile uint64_t	*err_value;
};

struct fi_xpu_efa_peer {
	uint16_t ahn;
	uint16_t remote_qpn;
	uint32_t remote_qkey;
};

struct fi_xpu_efa_desc {
	uint32_t lkey;
};

/*
 * Internal helpers
 */
FI_XPU_FUNC void
fi_xpu_efa_lock(struct fi_xpu_efa_ep *ep, int scope)
{
	if (scope == FI_XPU_WORK_ITEM)
		return;
	while (FI_XPU_EFA_ATOMIC_CAS(&ep->sq_lock, 0u, 1u) != 0u)
		;
}

FI_XPU_FUNC void
fi_xpu_efa_unlock(struct fi_xpu_efa_ep *ep, int scope)
{
	if (scope == FI_XPU_WORK_ITEM)
		return;
	FI_XPU_EFA_FENCE_SYSTEM();
	FI_XPU_EFA_ATOMIC_EXCH(&ep->sq_lock, 0u);
}

FI_XPU_FUNC int
fi_xpu_efa_wq_phase(struct fi_xpu_efa_wq *wq, uint32_t idx)
{
	return wq->phase ^
	       (int)(((wq->pc & wq->queue_mask) + idx) >>
		     wq->queue_size_shift);
}

FI_XPU_FUNC void
fi_xpu_efa_sq_ring(struct fi_xpu_efa_ep *ep)
{
	if (!ep->sq.wqes_pending)
		return;

	ep->sq.phase = fi_xpu_efa_wq_phase(&ep->sq,
					    ep->sq.wqes_pending);
	ep->sq.pc += ep->sq.wqes_pending;
	ep->sq.wqes_pending = 0;

	FI_XPU_EFA_FENCE_SYSTEM();
	*ep->sq.db = ep->sq.pc;
	FI_XPU_EFA_FENCE_SYSTEM();
}

FI_XPU_FUNC int
fi_xpu_efa_post_wqe(struct fi_xpu_efa_ep *ep,
		    struct fi_xpu_efa_tx_wqe *wqe,
		    uint64_t flags)
{
	uint32_t slot, sq_offset;
	uint64_t *src, *dst;
	int i;

	/* Backpressure: bound in-flight WQEs by SQ size */
	if (ep->local_cntr) {
		while ((ep->submitted_count + ep->sq.wqes_pending + 1 -
			*ep->local_cntr) > ep->sq_size)
			;
	}

	/* Respect the HW staging limit */
	if (ep->sq.wqes_pending + 1 > ep->sq.max_batch)
		fi_xpu_efa_sq_ring(ep);

	slot = ep->sq.pc + ep->sq.wqes_pending;

	/* Phase bit */
	if (fi_xpu_efa_wq_phase(&ep->sq, ep->sq.wqes_pending) & 1)
		wqe->meta.ctrl2 |= FI_XPU_EFA_CTRL2_PHASE;

	/* 64-byte write to SQ ring slot (BAR MMIO) */
	sq_offset = (slot & ep->sq.queue_mask) * FI_XPU_EFA_WQE_SIZE;
	src = (uint64_t *)wqe;
	dst = (uint64_t *)(ep->sq.buf + sq_offset);
	for (i = 0; i < 8; i++)
		dst[i] = src[i];

	ep->sq.wqes_pending++;
	ep->submitted_count++;

	if (!(flags & FI_MORE))
		fi_xpu_efa_sq_ring(ep);

	return 0;
}

FI_XPU_FUNC void
fi_xpu_efa_init_wqe(struct fi_xpu_efa_tx_wqe *wqe,
		    uint32_t op_type, uint16_t req_id,
		    struct fi_xpu_efa_peer *peer)
{
	uint64_t *w = (uint64_t *)wqe;
	int i;

	for (i = 0; i < 8; i++)
		w[i] = 0;

	wqe->meta.req_id = req_id;
	wqe->meta.ctrl1 = (uint8_t)(FI_XPU_EFA_CTRL1_META_DESC |
				    (op_type &
				     FI_XPU_EFA_CTRL1_OP_TYPE_MASK));
	wqe->meta.ctrl2 = (uint8_t)(FI_XPU_EFA_CTRL2_FIRST |
				    FI_XPU_EFA_CTRL2_LAST |
				    FI_XPU_EFA_CTRL2_COMP_REQ);
	wqe->meta.ah = peer->ahn;
	wqe->meta.dest_qp_num = peer->remote_qpn;
	wqe->meta.qkey = peer->remote_qkey;
}

FI_XPU_FUNC void
fi_xpu_efa_set_buf(struct fi_xpu_efa_tx_buf_desc *d,
		   uint32_t key, uint64_t addr, uint32_t len)
{
	d->length = len;
	d->lkey = key & FI_XPU_EFA_RX_LKEY_MASK;
	d->buf_addr_lo = (uint32_t)(addr & 0xFFFFFFFF);
	d->buf_addr_hi = (uint32_t)(addr >> 32);
}

/*
 * Device-side data transfer operations
 */
FI_XPU_FUNC int
fi_xpu_write_efa(void *ep, const void *buf, size_t len, void *desc,
		 uint64_t data, void *dest_addr, uint64_t addr,
		 uint64_t key, void *context, uint64_t flags, int scope)
{
	struct fi_xpu_efa_ep *e = (struct fi_xpu_efa_ep *)ep;
	struct fi_xpu_efa_desc *d = (struct fi_xpu_efa_desc *)desc;
	struct fi_xpu_efa_peer *p = (struct fi_xpu_efa_peer *)dest_addr;
	struct fi_xpu_efa_tx_wqe wqe;
	int ret;

	(void)context;
	fi_xpu_efa_lock(e, scope);

	fi_xpu_efa_init_wqe(&wqe, FI_XPU_EFA_OP_RDMA_WRITE,
			    (uint16_t)(e->submitted_count +
				       e->sq.wqes_pending), p);
	if (flags & FI_REMOTE_CQ_DATA) {
		wqe.meta.ctrl1 |= FI_XPU_EFA_CTRL1_HAS_IMM;
		wqe.meta.immediate_data = (uint32_t)data;
	}
	fi_xpu_efa_set_buf(&wqe.data.rdma_req.remote_mem,
			   (uint32_t)key, addr, (uint32_t)len);
	fi_xpu_efa_set_buf(&wqe.data.rdma_req.local_mem, d->lkey,
			   (uint64_t)(uintptr_t)buf, (uint32_t)len);
	wqe.meta.length = 1;

	ret = fi_xpu_efa_post_wqe(e, &wqe, flags);
	fi_xpu_efa_unlock(e, scope);
	return ret;
}

FI_XPU_FUNC int
fi_xpu_read_efa(void *ep, void *buf, size_t len, void *desc,
		void *src_addr, uint64_t addr, uint64_t key,
		void *context, uint64_t flags, int scope)
{
	struct fi_xpu_efa_ep *e = (struct fi_xpu_efa_ep *)ep;
	struct fi_xpu_efa_desc *d = (struct fi_xpu_efa_desc *)desc;
	struct fi_xpu_efa_peer *p = (struct fi_xpu_efa_peer *)src_addr;
	struct fi_xpu_efa_tx_wqe wqe;
	int ret;

	(void)context;
	fi_xpu_efa_lock(e, scope);

	fi_xpu_efa_init_wqe(&wqe, FI_XPU_EFA_OP_RDMA_READ,
			    (uint16_t)(e->submitted_count +
				       e->sq.wqes_pending), p);
	fi_xpu_efa_set_buf(&wqe.data.rdma_req.remote_mem,
			   (uint32_t)key, addr, (uint32_t)len);
	fi_xpu_efa_set_buf(&wqe.data.rdma_req.local_mem, d->lkey,
			   (uint64_t)(uintptr_t)buf, (uint32_t)len);
	wqe.meta.length = 1;

	ret = fi_xpu_efa_post_wqe(e, &wqe, flags);
	fi_xpu_efa_unlock(e, scope);
	return ret;
}

FI_XPU_FUNC int
fi_xpu_send_efa(void *ep, const void *buf, size_t len, void *desc,
		uint64_t data, void *dest_addr, void *context,
		uint64_t flags, int scope)
{
	struct fi_xpu_efa_ep *e = (struct fi_xpu_efa_ep *)ep;
	struct fi_xpu_efa_desc *d = (struct fi_xpu_efa_desc *)desc;
	struct fi_xpu_efa_peer *p = (struct fi_xpu_efa_peer *)dest_addr;
	struct fi_xpu_efa_tx_wqe wqe;
	int ret;

	(void)context;
	fi_xpu_efa_lock(e, scope);

	fi_xpu_efa_init_wqe(&wqe, FI_XPU_EFA_OP_SEND,
			    (uint16_t)(e->submitted_count +
				       e->sq.wqes_pending), p);
	if (flags & FI_REMOTE_CQ_DATA) {
		wqe.meta.ctrl1 |= FI_XPU_EFA_CTRL1_HAS_IMM;
		wqe.meta.immediate_data = (uint32_t)data;
	}
	fi_xpu_efa_set_buf(&wqe.data.sgl[0], d->lkey,
			   (uint64_t)(uintptr_t)buf, (uint32_t)len);
	wqe.meta.length = 1;

	ret = fi_xpu_efa_post_wqe(e, &wqe, flags);
	fi_xpu_efa_unlock(e, scope);
	return ret;
}

FI_XPU_FUNC int
fi_xpu_recv_efa(void *ep, void *buf, size_t len, void *desc,
		void *src_addr, void *context, uint64_t flags, int scope)
{
	struct fi_xpu_efa_ep *e = (struct fi_xpu_efa_ep *)ep;
	struct fi_xpu_efa_desc *d = (struct fi_xpu_efa_desc *)desc;
	struct fi_xpu_efa_rx_desc rqe;
	uint32_t rq_offset;
	uint32_t *dst, *src_p;
	int i;

	(void)src_addr;
	(void)context;
	fi_xpu_efa_lock(e, scope);

	rqe.buf_addr_lo = (uint32_t)((uint64_t)(uintptr_t)buf &
				     0xFFFFFFFF);
	rqe.buf_addr_hi = (uint32_t)((uint64_t)(uintptr_t)buf >> 32);
	rqe.req_id = (uint16_t)e->rq.pc;
	rqe.length = (uint16_t)len;
	rqe.lkey_ctrl = (d->lkey & FI_XPU_EFA_RX_LKEY_MASK) |
			FI_XPU_EFA_RX_FIRST | FI_XPU_EFA_RX_LAST;

	rq_offset = (e->rq.pc & e->rq.queue_mask) *
		    FI_XPU_EFA_RX_DESC_SIZE;
	dst = (uint32_t *)(e->rq.buf + rq_offset);
	src_p = (uint32_t *)&rqe;
	for (i = 0; i < 4; i++)
		dst[i] = src_p[i];

	e->rq.pc++;
	if (!(e->rq.pc & e->rq.queue_mask))
		e->rq.phase++;

	e->rq.wqes_pending++;
	if (!(flags & FI_MORE) ||
	    e->rq.wqes_pending >= e->rq.max_batch) {
		FI_XPU_EFA_FENCE_SYSTEM();
		*e->rq.db = e->rq.pc;
		e->rq.wqes_pending = 0;
	}

	fi_xpu_efa_unlock(e, scope);
	return 0;
}

/*
 * Counter operations
 */
FI_XPU_FUNC uint64_t
fi_xpu_cntr_read_efa(void *cntr, int scope)
{
	struct fi_xpu_efa_cntr *c = (struct fi_xpu_efa_cntr *)cntr;
	(void)scope;
	return *c->value;
}

FI_XPU_FUNC uint64_t
fi_xpu_cntr_readerr_efa(void *cntr, int scope)
{
	struct fi_xpu_efa_cntr *c = (struct fi_xpu_efa_cntr *)cntr;
	(void)scope;
	if (!c->err_value)
		return 0;
	return *c->err_value;
}

FI_XPU_FUNC void
fi_xpu_cntr_wait_efa(void *cntr, uint64_t threshold,
		     int timeout, int scope)
{
	struct fi_xpu_efa_cntr *c = (struct fi_xpu_efa_cntr *)cntr;
	(void)timeout;
	(void)scope;
	while (*c->value < threshold)
		;
}

/*
 * CQ operations
 */
FI_XPU_FUNC int64_t
fi_xpu_cq_read_efa(void *cq, void *buf, size_t count, int scope)
{
	struct fi_xpu_efa_cq *c = (struct fi_xpu_efa_cq *)cq;
	uint32_t cq_offset;
	uint8_t *cqe;
	int expected, actual;

	(void)buf;
	(void)scope;

	/* Poll one entry at current consumer position */
	cq_offset = (c->cc & c->queue_mask) * c->entry_size;
	cqe = c->buf + cq_offset;
	expected = (c->phase ^
		(int)((c->cc & c->queue_mask) >> c->queue_size_shift)) & 1;
	actual = cqe[3] & FI_XPU_EFA_CQE_PHASE;

	if (actual != expected)
		return 0;  /* no completion ready */

	FI_XPU_EFA_FENCE_BLOCK();

	/* Advance consumer counter */
	c->phase = c->phase ^
		(int)(((c->cc & c->queue_mask) + 1) >> c->queue_size_shift);
	c->cc++;

	return 1;
}

#endif /* FI_XPU_DEVICE_EFA_H */
