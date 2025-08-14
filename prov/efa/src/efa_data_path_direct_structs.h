/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/* SPDX-FileCopyrightText: Copyright Amazon.com, Inc. or its affiliates. All
 * rights reserved. */

/**
 * @file efa_data_path_direct_structs.h
 * @brief EFA Direct Data Path Data Structures
 *
 * This header file defines the core data structures used by EFA's direct
 * data path operations. These structures provide direct access to
 * hardware queue pairs and completion queues, enabling high-performance
 * completion processing by bypassing standard libfabric abstractions.
 *
 * Key Components:
 * - Work queue structures that mirror rdma-core's internal representations
 * - Completion queue structures for direct hardware access
 * - Performance timing utilities for profiling and optimization
 * - Queue pair structures combining send and receive queues
 *
 * The structures in this file are designed to be binary-compatible with
 * rdma-core's internal structures while providing the additional metadata
 * needed for direct completion queue operations.
 *
 * @note This file is only compiled when HAVE_EFA_DATA_PATH_DIRECT is defined,
 *       indicating that the system supports direct completion queue operations
 */

#ifndef _EFA_DATA_PATH_DIRECT_STRUCTS_H
#define _EFA_DATA_PATH_DIRECT_STRUCTS_H

#include "config.h"

#if HAVE_EFA_DATA_PATH_DIRECT

#include "efa_io_defs.h"

/**
 * The contents of this file only make sense if we can query rdma-core for QP
 * and CQ information. These structures provide direct access to hardware
 * resources and must be kept in sync with rdma-core's internal representations.
 */


/**
 * @struct efa_data_path_direct_wq
 * @brief Direct work queue structure mirroring rdma-core's efa_wq
 *
 * This structure provides direct access to work queue state and is designed
 * to be binary-compatible with rdma-core's internal efa_wq structure.
 * It manages work request IDs, queue indices, and synchronization for
 * both send and receive operations.
 */
struct efa_data_path_direct_wq {
	/* Mirror of `struct efa_wq` in rdma-core/providers/efa/efa.h */

	/** Array of work request IDs indexed by queue position */
	uint64_t *wrid;

	/**
	 * Pool of free indexes in the wrid array, used to select the wrid entry
	 * to be used to hold the next work request's context. At initialization,
	 * entry N holds value N. As out-of-order completions arrive, the value
	 * stored in a given entry might not equal the entry's index.
	 */
	uint32_t *wrid_idx_pool;

	uint32_t wqe_cnt;       /**< Total number of work queue entries */
	uint32_t wqe_size;      /**< Size of each work queue entry in bytes */
	uint32_t wqe_posted;    /**< Number of work requests posted */
	uint32_t wqe_completed; /**< Number of work requests completed */
	uint16_t pc;            /**< Producer counter for device queue indexing */
	uint16_t desc_mask;     /**< Mask for wrapping queue indices */

	/**
	 * Index of the next entry to use in wrid_idx_pool. This tracks the
	 * next available slot for assigning work request IDs.
	 */
	uint16_t wrid_idx_pool_next;

	int phase;                    /**< Current phase bit for queue wrapping */
	struct ofi_genlock *wqlock;   /**< Lock for thread-safe queue operations */
	uint32_t *db;                 /**< Hardware doorbell register pointer */
};

/**
 * @struct efa_data_path_direct_cq
 * @brief Direct completion queue structure
 *
 * Combines libfabric's public completion queue attributes with rdma-core's
 * private completion queue state. Provides direct access to hardware
 * completion queue buffer and maintains state for efficient completion
 * processing.
 */
struct efa_data_path_direct_cq {
	/* Combines fi_efa_cq_attr (public) with rdma-core's private efa_device_cq */

	uint8_t *buffer;        /**< Hardware completion queue buffer */
	uint32_t entry_size;    /**< Size of each completion queue entry */
	uint32_t num_entries;   /**< Total number of completion queue entries */

	/** Current completion queue entry being processed */
	struct efa_io_cdesc_common *cur_cqe;
	struct efa_qp *cur_qp;                    /**< Current queue pair being processed */
	struct efa_data_path_direct_wq *cur_wq;   /**< Current work queue being processed */
	int phase;                                /**< Current phase bit for queue wrapping */
	int qmask;                                /**< Mask for queue index wrapping */
	uint16_t consumed_cnt;                    /**< Number of completions consumed */
};

/**
 * @struct efa_data_path_direct_rq
 * @brief Direct receive queue structure
 *
 * Mirrors rdma-core's efa_rq structure and provides direct access to
 * the receive queue buffer and work queue state.
 */
struct efa_data_path_direct_rq {
	/* Mirror of efa_rq in rdma-core/providers/efa/efa.h */
	struct efa_data_path_direct_wq wq;  /**< Work queue management structure */
	uint8_t *buf;                       /**< Hardware receive queue buffer */
};

/**
 * @struct efa_data_path_direct_sq
 * @brief Direct send queue structure
 *
 * Mirrors rdma-core's efa_sq structure and provides direct access to
 * the send queue buffer and work queue state. Includes optimizations
 * for batching work queue entries before ringing the doorbell.
 */
struct efa_data_path_direct_sq {
	/* Mirror of efa_sq in rdma-core/providers/efa/efa.h */
	struct efa_data_path_direct_wq wq;  /**< Work queue management structure */
	uint8_t *desc;                      /**< Hardware send queue buffer ("buf" for SQ) */

	/**
	 * Number of work request entries we have accepted without ringing
	 * the doorbell. Each WQE is copied to hardware as soon as it's
	 * built, but doorbell is deferred for batching efficiency.
	 */
	uint32_t num_wqe_pending;

	/** Current work queue entry being constructed */
	struct efa_io_tx_wqe curr_tx_wqe;
};

/**
 * @struct efa_data_path_direct_qp
 * @brief Direct queue pair structure
 *
 * Combines send and receive queues with error tracking and performance
 * timing. This structure provides the complete direct access interface
 * to an EFA queue pair's hardware resources.
 */
struct efa_data_path_direct_qp {
	struct efa_data_path_direct_sq sq;        /**< Send queue structure */
	struct efa_data_path_direct_rq rq;        /**< Receive queue structure */
	int wr_session_err;                       /**< Error state for current WR session */
};


#endif /* HAVE_EFA_DATA_PATH_DIRECT */

#ifdef PRINT_EFA_TIMING
#include <x86intrin.h>

/**
 * @struct efa_data_path_timer
 * @brief High-resolution performance timing utility
 *
 * Provides cycle-accurate timing measurements for profiling direct completion
 * queue operations. Uses x86 RDTSC instruction for minimal overhead timing.
 */
struct efa_data_path_timer {
	uint64_t count;  /**< Number of timing measurements taken */
	uint64_t cycles; /**< Total CPU cycles accumulated across all measurements */
	uint64_t tic;    /**< Timestamp of current measurement start */
};

/**
 * @brief Initialize a performance timer
 * @param tt Pointer to timer structure to initialize
 */
static inline void efa_data_path_timer_init(struct efa_data_path_timer *tt) {
	tt->count = 0;
	tt->cycles = 0;
	tt->tic = 0;
}

/**
 * @brief Start a timing measurement
 * @param tt Pointer to timer structure
 */
static inline void efa_data_path_timer_start(struct efa_data_path_timer *tt) {
	tt->tic = __rdtsc();
	asm volatile("" ::: "memory"); /* Compiler barrier */
}

/**
 * @brief Stop a timing measurement and accumulate results
 * @param tt Pointer to timer structure
 */
static inline void efa_data_path_timer_stop(struct efa_data_path_timer *tt) {
	asm volatile("" ::: "memory"); /* Compiler barrier */
	tt->cycles += __rdtsc() - tt->tic;
	tt->count++;
}

/**
 * @brief Print timing statistics
 * @param prefix String prefix for the report
 * @param tt Pointer to timer structure
 */
static inline void efa_data_path_timer_report(const char* prefix, struct efa_data_path_timer *tt) {
	if (tt->count) {
		uint64_t avg_cycles = tt->cycles / tt->count;
		printf("Timer Report: %s: Count: %ld, Avg Cycles: %ld\n", prefix, tt->count, avg_cycles);
	}
}
#else
/* Empty struct and no-op functions when timing is disabled */
struct efa_data_path_timer {
	/* Empty struct */
};

static inline void efa_data_path_timer_init(struct efa_data_path_timer *tt) {
	(void)tt;
}

static inline void efa_data_path_timer_start(struct efa_data_path_timer *tt) {
	(void)tt;
}

static inline void efa_data_path_timer_stop(struct efa_data_path_timer *tt) {
	(void)tt;
}

static inline void efa_data_path_timer_report(const char* prefix, struct efa_data_path_timer *tt) {
	(void)prefix;
	(void)tt;
}
#endif /* PRINT_EFA_TIMING */

#endif /* _EFA_DATA_PATH_DIRECT_STRUCTS_H */