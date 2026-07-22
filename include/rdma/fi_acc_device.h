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
 * OFI Accelerator API — Device-Side Header
 *
 * Functions callable from accelerator compute kernels (CUDA, SYCL, etc.)
 * for GPU-initiated RDMA operations.
 *
 * This header is compiled by the device compiler (nvcc, dpcpp, etc.) and
 * provides inline device functions for:
 *   - Work Queue Entry (WQE) preparation
 *   - SQ batch submission (reserve → place → flush)
 *   - CQ polling (phase-bit protocol)
 *   - Counter reading (NIC-written, device-resident)
 *   - SQ backpressure management
 *   - Per-QP spinlock (multi-CTA serialization)
 *
 * Device-side types are provider-neutral. The host-side fi_acc_*_export()
 * functions fill these structures with provider-specific values.
 * =============================================================================
 */

#include <stdint.h>

/*
 * Compiler-specific device function qualifier.
 * CUDA: __device__, SYCL: inline (device code), HIP: __device__
 */
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
  #define FI_ACC_DEV_FENCE_SYSTEM() /* SYCL: atomic_fence(memory_order_release, memory_scope_system) */
  #define FI_ACC_DEV_FENCE_BLOCK()  /* SYCL: atomic_fence(memory_order_acquire, memory_scope_work_group) */
  #define FI_ACC_DEV_ATOMIC_CAS(ptr, expected, desired) /* SYCL atomic */
  #define FI_ACC_DEV_ATOMIC_EXCH(ptr, val) /* SYCL atomic */
#else
  /* Host-side compilation: stubs for type checking */
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
 * Device-side descriptor types (GPU-resident, populated by host export)
 * =============================================================================
 */

/** Work Queue descriptor (SQ or RQ) — tracks ring buffer state */
struct fi_acc_dev_wq {
	uint32_t  pc;               /* Producer counter (total posted) */
	int32_t   phase;            /* Current phase bit for new entries */
	uint32_t  queue_mask;       /* num_entries - 1 (power-of-2 mask) */
	uint32_t  queue_size_shift; /* log2(num_entries) — phase flip calc */
	uint32_t  max_batch;        /* Max entries per flush (HW property) */
	uint32_t  wqes_pending;     /* Staged in current batch */
	uint32_t  entry_size;       /* Bytes per WQE/RQE */
	uint8_t  *buf;              /* Device ptr → ring buffer (BAR MMIO) */
	uint32_t *db;               /* Device ptr → doorbell register */
};

/** QP descriptor (SQ + RQ) */
struct fi_acc_dev_qp {
	struct fi_acc_dev_wq sq;
	struct fi_acc_dev_wq rq;
	uint32_t max_inline_data;
	uint32_t max_rdma_sges;
};

/** CQ descriptor — tracks completion ring buffer state */
struct fi_acc_dev_cq {
	uint32_t  cc;               /* Consumer counter (total consumed) */
	int32_t   phase;            /* Expected phase bit for next CQE */
	uint32_t  queue_mask;       /* num_entries - 1 */
	uint32_t  queue_size_shift; /* log2(num_entries) */
	uint32_t  entry_size;       /* Bytes per CQE */
	uint8_t  *buf;              /* Ptr to CQ ring buffer */
};

/** Counter descriptor — NIC-written value in device memory */
struct fi_acc_dev_cntr {
	volatile uint64_t *value;   /* Device ptr to counter (GPU HBM) */
};

/** Peer address — raw HW addressing for WQE destination fields */
struct fi_acc_dev_peer {
	uint16_t ahn;               /* Address handle number */
	uint16_t remote_qpn;        /* Remote QPN */
	uint32_t remote_qkey;       /* Queue key */
};

/** WQE buffer — opaque 64-byte work queue entry */
#define FI_ACC_WQE_SIZE 64

struct fi_acc_dev_wqe {
	uint8_t data[FI_ACC_WQE_SIZE];
};

/*
 * =============================================================================
 * Phase-bit calculation
 *
 * The NIC uses phase bits to distinguish "new WQE" from "old data from
 * previous ring wrap." The phase flips each time the ring wraps.
 * =============================================================================
 */

FI_ACC_DEV int
fi_acc_dev_get_wqe_phase(struct fi_acc_dev_wq *wq, uint32_t index)
{
	return wq->phase ^ (int)(((wq->pc & wq->queue_mask) + index)
				 >> wq->queue_size_shift);
}

FI_ACC_DEV int
fi_acc_dev_get_cqe_phase(struct fi_acc_dev_cq *cq, uint32_t position)
{
	return cq->phase ^ (int)(((cq->cc & cq->queue_mask) + position)
				 >> cq->queue_size_shift);
}

/*
 * =============================================================================
 * WQE Preparation
 * =============================================================================
 */

/**
 * fi_acc_dev_write_prep - Prepare an RDMA Write WQE.
 * @wr:        [out] 64-byte WQE buffer (on stack/registers)
 * @wr_id:     Work request ID (for CQ matching)
 * @dst_rkey:  Remote key for destination buffer
 * @dst_addr:  Remote virtual address
 * @src_lkey:  Local key for source buffer
 * @src_addr:  Local source virtual address
 * @length:    Transfer length in bytes
 *
 * Fills the WQE with RDMA Write opcode, remote address, and local SGE.
 * Caller must also call fi_acc_dev_wr_set_peer() to set destination.
 */
FI_ACC_DEV void
fi_acc_dev_write_prep(struct fi_acc_dev_wqe *wr,
		      uint32_t wr_id,
		      uint32_t dst_rkey, uint64_t dst_addr,
		      uint32_t src_lkey, uint64_t src_addr,
		      uint32_t length)
{
	uint64_t *w = (uint64_t *)wr->data;
	int i;

	/* Zero the 64-byte WQE */
	for (i = 0; i < 8; i++)
		w[i] = 0;

	/*
	 * WQE layout (EFA efa_io_tx_wqe compatible):
	 *   [0..15]:  meta/ctrl — opcode, num_sge, wr_id, ctrl2 (phase)
	 *   [16..31]: raddr segment — rkey, remote VA
	 *   [32..47]: SGE — lkey, local VA, length
	 *   [48..63]: remote target — ahn, qpn, qkey (set by set_peer)
	 */
	uint32_t *meta = (uint32_t *)&w[0];
	meta[0] = 0x04;      /* opcode: RDMA_WRITE */
	meta[1] = 1;         /* num_sge = 1 */
	meta[2] = wr_id;     /* wr_id */
	/* meta[3] = ctrl2: phase bit stamped during sq_place */

	uint32_t *raddr_seg = (uint32_t *)&w[2];
	raddr_seg[0] = dst_rkey;
	uint64_t *raddr_va = (uint64_t *)&raddr_seg[2];
	*raddr_va = dst_addr;

	uint32_t *sge = (uint32_t *)&w[4];
	sge[0] = src_lkey;
	uint64_t *sge_va = (uint64_t *)&sge[2];
	*sge_va = src_addr;
	sge[4] = length;
}

/**
 * fi_acc_dev_wr_set_peer - Set remote destination in a prepared WQE.
 * @wr:   Prepared WQE
 * @peer: Device-resident peer address
 */
FI_ACC_DEV void
fi_acc_dev_wr_set_peer(struct fi_acc_dev_wqe *wr,
		       const struct fi_acc_dev_peer *peer)
{
	uint16_t *target = (uint16_t *)&wr->data[48];
	target[0] = peer->ahn;
	target[1] = peer->remote_qpn;
	uint32_t *qkey = (uint32_t *)&wr->data[52];
	*qkey = peer->remote_qkey;
}

/*
 * =============================================================================
 * Batch Submission: start → place → flush
 *
 * Mirrors efa-dp-direct: efa_cuda_start_sq_batch → sq_batch_place_wr → flush
 * =============================================================================
 */

/**
 * fi_acc_dev_sq_start_batch - Reserve SQ slots for a batch of WQEs.
 * @qp:         Device-resident QP descriptor
 * @batch_size: Number of WQEs in this batch
 *
 * Must be called by a single thread. Auto-flushes if pending would
 * exceed max_batch. Other threads wait (syncthreads) before place.
 */
FI_ACC_DEV int
fi_acc_dev_sq_start_batch(struct fi_acc_dev_qp *qp, int batch_size)
{
	if (qp->sq.wqes_pending + (uint32_t)batch_size > qp->sq.max_batch) {
		/* Auto-flush pending WQEs */
		if (qp->sq.wqes_pending > 0) {
			qp->sq.phase = fi_acc_dev_get_wqe_phase(
				&qp->sq, qp->sq.wqes_pending);
			qp->sq.pc += qp->sq.wqes_pending;
			qp->sq.wqes_pending = 0;
			FI_ACC_DEV_FENCE_SYSTEM();
			*qp->sq.db = qp->sq.pc;
			FI_ACC_DEV_FENCE_SYSTEM();
		}
	}
	qp->sq.wqes_pending += (uint32_t)batch_size;
	return 0;
}

/**
 * fi_acc_dev_sq_place - Write a prepared WQE into the SQ ring buffer.
 * @qp:             Device-resident QP descriptor
 * @index_in_batch: Slot within current batch (0-based)
 * @wr:             Prepared 64-byte WQE
 *
 * Thread-safe: different threads can call with different index_in_batch
 * values concurrently (they write to different ring slots).
 * Writes 64 bytes to BAR MMIO (8 × 8-byte stores).
 */
FI_ACC_DEV int
fi_acc_dev_sq_place(struct fi_acc_dev_qp *qp, int index_in_batch,
		    struct fi_acc_dev_wqe *wr)
{
	int i;
	/* Compute and stamp phase bit into ctrl2 (byte 12, bit 0) */
	int wqe_phase = fi_acc_dev_get_wqe_phase(&qp->sq, (uint32_t)index_in_batch);
	uint32_t *ctrl2 = (uint32_t *)&wr->data[12];
	*ctrl2 = (*ctrl2 & ~1u) | ((uint32_t)wqe_phase & 1u);

	/* Compute byte offset into SQ ring */
	uint32_t sq_offset =
		((qp->sq.pc + (uint32_t)index_in_batch) & qp->sq.queue_mask)
		* FI_ACC_WQE_SIZE;

	/* Copy 64 bytes to ring buffer (8 × 8-byte stores to BAR MMIO) */
	uint64_t *src = (uint64_t *)wr->data;
	uint64_t *dst = (uint64_t *)(qp->sq.buf + sq_offset);

	for (i = 0; i < 8; i++)
		dst[i] = src[i];

	return 0;
}

/**
 * fi_acc_dev_sq_flush - Commit batch: memory fence + ring doorbell.
 * @qp: Device-resident QP descriptor
 *
 * After this call the NIC fetches WQEs and begins DMA.
 * Must be called by a single thread after all sq_place complete.
 */
FI_ACC_DEV void
fi_acc_dev_sq_flush(struct fi_acc_dev_qp *qp)
{
	if (!qp->sq.wqes_pending)
		return;

	/* Advance phase to value after this batch */
	qp->sq.phase = fi_acc_dev_get_wqe_phase(&qp->sq, qp->sq.wqes_pending);

	/* Advance producer counter */
	qp->sq.pc += qp->sq.wqes_pending;
	qp->sq.wqes_pending = 0;

	/* System fence: ensure WQE MMIO stores visible to NIC */
	FI_ACC_DEV_FENCE_SYSTEM();

	/* Ring doorbell: write new pc to BAR MMIO register */
	*qp->sq.db = qp->sq.pc;

	/* Fence: ensure doorbell committed before proceeding */
	FI_ACC_DEV_FENCE_SYSTEM();
}

/*
 * =============================================================================
 * CQ Polling — phase-bit protocol
 * =============================================================================
 */

/**
 * fi_acc_dev_cq_poll - Check if a CQE is ready at a given position.
 * @cq:       Device-resident CQ descriptor
 * @position: Position to check (0 for single-thread, tid for cooperative)
 *
 * Returns pointer to CQE if ready, NULL otherwise.
 * NIC flips the phase bit each ring wrap — matches indicate "new CQE."
 */
FI_ACC_DEV void *
fi_acc_dev_cq_poll(struct fi_acc_dev_cq *cq, uint32_t position)
{
	uint32_t cq_offset =
		((cq->cc + position) & cq->queue_mask) * cq->entry_size;
	uint8_t *cqe = cq->buf + cq_offset;

	int expected_phase = fi_acc_dev_get_cqe_phase(cq, position);
	/* Phase bit at byte 3, bit 0 (EFA efa_io_cdesc_common.flags) */
	int actual_phase = cqe[3] & 1;

	if (actual_phase == expected_phase) {
		FI_ACC_DEV_FENCE_BLOCK();
		return (void *)cqe;
	}
	return (void *)0;
}

/**
 * fi_acc_dev_cq_pop - Advance CQ consumer pointer after consuming CQEs.
 * @cq:     Device-resident CQ descriptor
 * @amount: Number of CQEs consumed
 *
 * No doorbell needed — CQ consumer pointer is software-only.
 */
FI_ACC_DEV void
fi_acc_dev_cq_pop(struct fi_acc_dev_cq *cq, uint32_t amount)
{
	cq->phase = fi_acc_dev_get_cqe_phase(cq, amount);
	cq->cc += amount;
}

/*
 * =============================================================================
 * Counter Operations
 * =============================================================================
 */

/**
 * fi_acc_dev_cntr_read - Read NIC-written counter value from device memory.
 * @cntr: Device-resident counter descriptor
 */
FI_ACC_DEV uint64_t
fi_acc_dev_cntr_read(struct fi_acc_dev_cntr *cntr)
{
	return *cntr->value;
}

/**
 * fi_acc_dev_cntr_wait - Spin until counter reaches target.
 * @cntr:   Device-resident counter
 * @target: Value to wait for (inclusive)
 */
FI_ACC_DEV void
fi_acc_dev_cntr_wait(struct fi_acc_dev_cntr *cntr, uint64_t target)
{
	while (*cntr->value < target)
		;
}

/*
 * =============================================================================
 * SQ Backpressure — prevent SQ overflow
 * =============================================================================
 */

/**
 * fi_acc_dev_sq_check - Wait until SQ has room for batch_size more WQEs.
 * @submitted: Total WQEs submitted so far (caller-maintained)
 * @cntr:      Device-resident completion counter
 * @sq_size:   Total SQ depth (num_entries)
 * @batch:     Number of WQEs about to submit
 *
 * Spins: (submitted - completed + batch) <= sq_size
 */
FI_ACC_DEV void
fi_acc_dev_sq_check(uint64_t submitted, struct fi_acc_dev_cntr *cntr,
		    uint32_t sq_size, uint32_t batch)
{
	while ((submitted - *cntr->value + batch) > sq_size)
		;
}

/*
 * =============================================================================
 * Spinlock — per-QP multi-CTA serialization
 * =============================================================================
 */

/** fi_acc_dev_lock - Acquire per-QP spinlock. */
FI_ACC_DEV void
fi_acc_dev_lock(uint32_t *lock)
{
	while (FI_ACC_DEV_ATOMIC_CAS(lock, 0u, 1u) != 0u)
		;
}

/** fi_acc_dev_unlock - Release per-QP spinlock. */
FI_ACC_DEV void
fi_acc_dev_unlock(uint32_t *lock)
{
	FI_ACC_DEV_ATOMIC_EXCH(lock, 0u);
}

/*
 * =============================================================================
 * Receive Queue Posting (from device)
 * =============================================================================
 */

/**
 * fi_acc_dev_post_recv - Post a receive buffer to the RQ from device.
 * @qp:     Device-resident QP descriptor
 * @index:  RQ slot index within current batch
 * @addr:   Local buffer address
 * @length: Buffer length in bytes
 * @lkey:   Local memory key
 */
FI_ACC_DEV void
fi_acc_dev_post_recv(struct fi_acc_dev_qp *qp, uint32_t index,
		     uint64_t addr, uint32_t length, uint32_t lkey)
{
	uint32_t rq_offset =
		((qp->rq.pc + index) & qp->rq.queue_mask) * qp->rq.entry_size;
	uint8_t *rqe = qp->rq.buf + rq_offset;

	uint32_t *rqe32 = (uint32_t *)rqe;
	rqe32[0] = lkey;
	uint64_t *rqe64 = (uint64_t *)&rqe32[1];
	*rqe64 = addr;
	rqe32[3] = length;
}

/**
 * fi_acc_dev_rq_flush - Commit posted receives: fence + ring RQ doorbell.
 * @qp:    Device-resident QP
 * @count: Number of receives posted
 */
FI_ACC_DEV void
fi_acc_dev_rq_flush(struct fi_acc_dev_qp *qp, uint32_t count)
{
	qp->rq.pc += count;
	FI_ACC_DEV_FENCE_SYSTEM();
	*qp->rq.db = qp->rq.pc;
	FI_ACC_DEV_FENCE_SYSTEM();
}

#ifdef __cplusplus
}
#endif

#endif /* FI_ACC_DEVICE_H */
