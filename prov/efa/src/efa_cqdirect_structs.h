/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/* SPDX-FileCopyrightText: Copyright Amazon.com, Inc. or its affiliates. All rights reserved. */

#ifndef _EFA_CQDIRECT_STRUCTS_H
#define _EFA_CQDIRECT_STRUCTS_H

#include "config.h"
#include <asm/types.h>
#include "efa_cqdirect_efa_io_defs.h"
// #include <infiniband/efadv.h>

/*
 * The contents of this file only make sense if we can query rdma-core for QP
 * and CQ information.
 */

#define HAVE_CQDIRECT (HAVE_EFADV_QUERY_QP_WQS && HAVE_EFADV_QUERY_CQ)

// TODO: remove.  This is only for testing the timing
#include <x86intrin.h>
struct cqdirect_timer {
	uint64_t count;
	uint64_t cycles;
	uint64_t tic;
};
static inline void efa_cqdirect_timer_init(struct cqdirect_timer *tt) {
	tt->count = 0;
	tt->cycles = 0;
	tt->tic = 0;
}
static inline void efa_cqdirect_timer_start(struct cqdirect_timer *tt) {
	tt->tic = __rdtsc();
	asm volatile("" ::: "memory");
}
static inline void efa_cqdirect_timer_stop(struct cqdirect_timer *tt) {
	asm volatile("" ::: "memory");
	tt->cycles += __rdtsc() - tt->tic;
	tt->count++;
}
static inline void efa_cqdirect_timer_report(const char* prefix, struct cqdirect_timer *tt) {
	if (tt->count) {
		uint64_t avg_cycles = tt->cycles / tt->count;
		printf("Timer Report: %s: Count: %ld, Avg Cycles: %ld\n", prefix, tt->count, avg_cycles);
	}
}


struct efa_cqdirect_wq {
	/* see `struct efa_wq` in rdma-core/providers/efa/efa.h */

	uint64_t *wrid;
	/* wrid_idx_pool: Pool of free indexes in the wrid array, used to select the
	 * wrid entry to be used to hold the next tx packet's context.
	 * At init time, entry N will hold value N, as OOO tx-completions arrive,
	 * the value stored in a given entry might not equal the entry's index.
	 */
	uint32_t *wrid_idx_pool;
	uint32_t wqe_cnt;
	uint32_t wqe_size;
	uint32_t wqe_posted;
	uint32_t wqe_completed;
	uint16_t pc; /* Producer counter */
	uint16_t desc_mask;
	/* wrid_idx_pool_next: Index of the next entry to use in wrid_idx_pool. */
	uint16_t wrid_idx_pool_next;
	int max_sge;
	int phase;
	pthread_spinlock_t wqlock;

	uint32_t *db;
	uint16_t sub_cq_idx;
};

struct efa_cqdirect_cq {
	/* combines fi_efa_cq_attr (public) with rdma-core's private efa_sub_cq */

	uint8_t *buffer;
    uint32_t entry_size;
    uint32_t num_entries;

	struct efa_io_cdesc_common *cur_cqe;
	struct efa_qp *cur_qp;
	struct efa_cqdirect_wq *cur_wq;
	int phase;
	int qmask;
	uint16_t consumed_cnt;

	struct cqdirect_timer timing;
};

struct efa_cqdirect_rq {
	/* see efa_rq in rdma-core/providers/efa/efa.h */
	struct efa_cqdirect_wq wq;
	uint8_t *buf;
	// size_t buf_size;
};

#define EFA_CQDIRECT_TX_WQE_MAX_CACHE 1
struct efa_cqdirect_sq {
	/* see efa_sq in rdma-core/providers/efa/efa.h */
	struct efa_cqdirect_wq wq;
	uint8_t *desc; // this is the "buf" for the sq.
	// uint32_t desc_offset;
	// size_t desc_ring_mmap_size;
	size_t max_inline_data;
	size_t max_wr_rdma_sge;
	uint16_t max_batch_wr; //TODO: how?

	/* Buffer for pending WR entries in the current session */
	// uint8_t *local_queue;
	/* cqdirect change:  Number of WR entries we have accepted without ringing doorbell,
	   however we copy each wqe as soon as we finish building it. */
	uint32_t num_wqe_pending;
	/* Phase before current session */
	// int phase_rb;
	
	/* Current wqe being built. */
	struct efa_io_tx_wqe curr_tx_wqe;

};

struct efa_cqdirect_qp {
	// struct efadv_wq_attr sq_attr;
	// struct efadv_wq_attr rq_attr;

	// struct verbs_qp verbs_qp;
	struct efa_cqdirect_sq sq;
	struct efa_cqdirect_rq rq;
	// int page_size;
	// int sq_sig_all;
	int wr_session_err;
	// struct ibv_device *dev;

	struct cqdirect_timer send_timing;
	struct cqdirect_timer recv_timing;
};

#endif