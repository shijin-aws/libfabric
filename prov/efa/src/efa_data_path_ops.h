/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/* SPDX-FileCopyrightText: Copyright Amazon.com, Inc. or its affiliates. All rights reserved. */

/*
 * EFA Data Path Operations
 *
 * This file contains wrapper functions for EFA device operations that are used
 * in the data transfer path. These operations provide a unified interface for
 * both regular IBV operations and direct CQ operations, allowing the EFA provider
 * to seamlessly switch between different hardware acceleration modes based on
 * device capabilities and configuration.
 *
 * The wrapper functions handle:
 * - Queue Pair (QP) operations: post_recv, work request operations (send, RDMA read/write)
 * - Completion Queue (CQ) operations: polling, reading completion data
 * - Automatic selection between IBV and direct CQ implementations
 */

#ifndef EFA_DATA_PATH_OPS_H
#define EFA_DATA_PATH_OPS_H

#include <infiniband/verbs.h>
#include <infiniband/efadv.h>

/* Forward declarations to avoid cyclic dependencies */
#include "efa_base_ep.h"
#include "efa_cq.h"

#if HAVE_EFA_DATA_PATH_DIRECT
#include "efa_data_path_direct_entry.h"
#include "efa_data_path_direct_internal.h"
#include "efa_perf_timer.h"
#include "efa_mmio.h"

/**
 * @brief Consolidated send operation - builds WQE as stack variable and posts directly
 * @param base_ep EFA base endpoint
 * @param sge_list Pre-prepared SGE list (used when use_inline=false)
 * @param inline_data_list Pre-prepared inline data list (used when use_inline=true)
 * @param data_count Number of SGE entries or inline data buffers
 * @param use_inline True to use inline data, false to use SGE list
 * @param wr_id Work request ID (pre-prepared by caller)
 * @param data Immediate data (used when FI_REMOTE_CQ_DATA flag is set)
 * @param flags Operation flags
 * @param conn Connection information
 */
static inline int
efa_post_send_direct(struct efa_base_ep *base_ep,
                     const struct ibv_sge *sge_list,
                     const struct ibv_data_buf *inline_data_list,
                     size_t data_count,
                     bool use_inline,
                     uintptr_t wr_id,
                     uint64_t data,
                     uint64_t flags,
                     struct efa_conn *conn)
{
    struct efa_qp *qp = base_ep->qp;
    struct efa_data_path_direct_sq *sq = &qp->data_path_direct_qp.sq;
    struct efa_io_tx_wqe local_wqe = {0}; /* Stack variable - can be in registers */
    struct efa_io_tx_meta_desc *meta_desc = &local_wqe.meta;
    uint32_t sq_desc_idx;
    struct efa_io_tx_wqe *wc_wqe;
    uint32_t total_length = 0;
    size_t i;
    int err;

    /* Validate queue space */
    err = efa_post_send_validate(qp);
    if (OFI_UNLIKELY(err))
        return err;

    /* Set work request ID */
    qp->ibv_qp_ex->wr_id = wr_id;

    /* Build metadata in local stack variable */
    meta_desc->dest_qp_num = conn->ep_addr->qpn;
    meta_desc->ah = conn->ah->ahn;
    meta_desc->qkey = conn->ep_addr->qkey;
    meta_desc->req_id = efa_wq_get_next_wrid_idx(&sq->wq, qp->ibv_qp_ex->wr_id);

    /* Set common control flags */
    efa_set_common_ctrl_flags(meta_desc, sq, EFA_IO_SEND);
    if (flags & FI_REMOTE_CQ_DATA) {
        EFA_SET(&meta_desc->ctrl1, EFA_IO_TX_META_DESC_HAS_IMM, 1);
        meta_desc->immediate_data = data;
    }

    /* Handle inline data or SGE list */
    if (use_inline) {
        /* Inline data path - caller has prepared inline_data_list */
        EFA_SET(&meta_desc->ctrl1, EFA_IO_TX_META_DESC_INLINE_MSG, 1);
        for (i = 0; i < data_count; i++) {
            memcpy(local_wqe.data.inline_data + total_length, 
                   inline_data_list[i].addr, inline_data_list[i].length);
            total_length += inline_data_list[i].length;
        }
        meta_desc->length = total_length;
    } else {
        /* SGE list path - caller has prepared sge_list */
        efa_post_send_sgl(local_wqe.data.sgl, sge_list, data_count);
        meta_desc->length = data_count;
    }

    /* Calculate target address in write-combined memory */
    sq_desc_idx = sq->wq.pc & sq->wq.desc_mask;
    wc_wqe = (struct efa_io_tx_wqe *)sq->desc + sq_desc_idx;

    /* Copy complete WQE to write-combined memory in one operation */
    mmio_memcpy_x64(wc_wqe, &local_wqe, sizeof(struct efa_io_tx_wqe));

    /* Update queue state */
    efa_sq_advance_post_idx(sq);

    /* Ring doorbell if required */
    if (!(flags & FI_MORE)) {
        mmio_flush_writes();
        efa_sq_ring_doorbell(sq, sq->wq.pc);
        mmio_wc_start();
    }

    return 0;
}

/**
 * @brief Consolidated RDMA read operation - builds WQE as stack variable and posts directly
 * @param base_ep EFA base endpoint
 * @param sge_list Pre-prepared SGE list for local buffers
 * @param sge_count Number of SGE entries
 * @param remote_key Remote memory key
 * @param remote_addr Remote memory address
 * @param wr_id Work request ID (pre-prepared by caller)
 * @param flags Operation flags
 * @param conn Connection information
 */
static inline int
efa_post_rdma_read_direct(struct efa_base_ep *base_ep,
                          const struct ibv_sge *sge_list,
                          size_t sge_count,
                          uint32_t remote_key,
                          uint64_t remote_addr,
                          uintptr_t wr_id,
                          uint64_t flags,
                          struct efa_conn *conn)
{
    struct efa_qp *qp = base_ep->qp;
    struct efa_data_path_direct_sq *sq = &qp->data_path_direct_qp.sq;
    struct efa_io_tx_wqe local_wqe = {0}; /* Stack variable - can be in registers */
    struct efa_io_tx_meta_desc *meta_desc = &local_wqe.meta;
    struct efa_io_remote_mem_addr *remote_mem = &local_wqe.data.rdma_req.remote_mem;
    uint32_t sq_desc_idx;
    struct efa_io_tx_wqe *wc_wqe;
    int err;

    /* Validate queue space */
    err = efa_post_send_validate(qp);
    if (OFI_UNLIKELY(err))
        return err;

    /* Set work request ID */
    qp->ibv_qp_ex->wr_id = wr_id;

    /* Build metadata in local stack variable */
    meta_desc->dest_qp_num = conn->ep_addr->qpn;
    meta_desc->ah = conn->ah->ahn;
    meta_desc->qkey = conn->ep_addr->qkey;
    meta_desc->req_id = efa_wq_get_next_wrid_idx(&sq->wq, qp->ibv_qp_ex->wr_id);

    /* Set common control flags for RDMA READ */
    efa_set_common_ctrl_flags(meta_desc, sq, EFA_IO_RDMA_READ);

    /* Set remote memory information */
    remote_mem->rkey = remote_key;
    remote_mem->buf_addr_lo = remote_addr & 0xFFFFFFFF;
    remote_mem->buf_addr_hi = remote_addr >> 32;

    /* Set local SGE list - caller has prepared sge_list */
    efa_post_send_sgl(local_wqe.data.sgl, sge_list, sge_count);
    meta_desc->length = sge_count;

    /* Calculate target address in write-combined memory */
    sq_desc_idx = sq->wq.pc & sq->wq.desc_mask;
    wc_wqe = (struct efa_io_tx_wqe *)sq->desc + sq_desc_idx;

    /* Copy complete WQE to write-combined memory in one operation */
    mmio_memcpy_x64(wc_wqe, &local_wqe, sizeof(struct efa_io_tx_wqe));

    /* Update queue state */
    efa_sq_advance_post_idx(sq);

    /* Ring doorbell if required */
    if (!(flags & FI_MORE)) {
        mmio_flush_writes();
        efa_sq_ring_doorbell(sq, sq->wq.pc);
        mmio_wc_start();
    }

    return 0;
}

/**
 * @brief Consolidated RDMA write operation - builds WQE as stack variable and posts directly
 * @param base_ep EFA base endpoint
 * @param sge_list Pre-prepared SGE list for local buffers
 * @param sge_count Number of SGE entries
 * @param remote_key Remote memory key
 * @param remote_addr Remote memory address
 * @param wr_id Work request ID (pre-prepared by caller)
 * @param data Immediate data (used when FI_REMOTE_CQ_DATA flag is set)
 * @param flags Operation flags
 * @param conn Connection information
 */
static inline int
efa_post_rdma_write_direct(struct efa_base_ep *base_ep,
                           const struct ibv_sge *sge_list,
                           size_t sge_count,
                           uint32_t remote_key,
                           uint64_t remote_addr,
                           uintptr_t wr_id,
                           uint64_t data,
                           uint64_t flags,
                           struct efa_conn *conn)
{
    struct efa_qp *qp = base_ep->qp;
    struct efa_data_path_direct_sq *sq = &qp->data_path_direct_qp.sq;
    struct efa_io_tx_wqe local_wqe = {0}; /* Stack variable - can be in registers */
    struct efa_io_tx_meta_desc *meta_desc = &local_wqe.meta;
    struct efa_io_remote_mem_addr *remote_mem = &local_wqe.data.rdma_req.remote_mem;
    uint32_t sq_desc_idx;
    struct efa_io_tx_wqe *wc_wqe;
    int err;

    /* Validate queue space */
    err = efa_post_send_validate(qp);
    if (OFI_UNLIKELY(err))
        return err;

    /* Set work request ID */
    qp->ibv_qp_ex->wr_id = wr_id;

    /* Build metadata in local stack variable */
    meta_desc->dest_qp_num = conn->ep_addr->qpn;
    meta_desc->ah = conn->ah->ahn;
    meta_desc->qkey = conn->ep_addr->qkey;
    meta_desc->req_id = efa_wq_get_next_wrid_idx(&sq->wq, qp->ibv_qp_ex->wr_id);

    /* Set common control flags for RDMA WRITE */
    efa_set_common_ctrl_flags(meta_desc, sq, EFA_IO_RDMA_WRITE);
    if (flags & FI_REMOTE_CQ_DATA) {
        EFA_SET(&meta_desc->ctrl1, EFA_IO_TX_META_DESC_HAS_IMM, 1);
        meta_desc->immediate_data = data;
    }

    /* Set remote memory information */
    remote_mem->rkey = remote_key;
    remote_mem->buf_addr_lo = remote_addr & 0xFFFFFFFF;
    remote_mem->buf_addr_hi = remote_addr >> 32;

    /* Set local SGE list - caller has prepared sge_list */
    efa_post_send_sgl(local_wqe.data.sgl, sge_list, sge_count);
    meta_desc->length = sge_count;

    /* Calculate target address in write-combined memory */
    sq_desc_idx = sq->wq.pc & sq->wq.desc_mask;
    wc_wqe = (struct efa_io_tx_wqe *)sq->desc + sq_desc_idx;

    /* Copy complete WQE to write-combined memory in one operation */
    mmio_memcpy_x64(wc_wqe, &local_wqe, sizeof(struct efa_io_tx_wqe));

    /* Update queue state */
    efa_sq_advance_post_idx(sq);

    /* Ring doorbell if required */
    if (!(flags & FI_MORE)) {
        mmio_flush_writes();
        efa_sq_ring_doorbell(sq, sq->wq.pc);
        mmio_wc_start();
    }

    return 0;
}

/**
 * @brief RDMA-core version of send operation using ibv_* APIs
 */
static inline int
efa_post_send_ibv(struct efa_base_ep *base_ep,
                  const struct ibv_sge *sge_list,
                  const struct ibv_data_buf *inline_data_list,
                  size_t data_count,
                  bool use_inline,
                  uintptr_t wr_id,
                  uint64_t data,
                  uint64_t flags,
                  struct efa_conn *conn)
{
    struct efa_qp *qp = base_ep->qp;
    int ret;

    if (!base_ep->is_wr_started) {
        ibv_wr_start(qp->ibv_qp_ex);
        base_ep->is_wr_started = true;
    }

    qp->ibv_qp_ex->wr_id = wr_id;

    if (flags & FI_REMOTE_CQ_DATA) {
        ibv_wr_send_imm(qp->ibv_qp_ex, data);
    } else {
        ibv_wr_send(qp->ibv_qp_ex);
    }

    if (use_inline) {
        ibv_wr_set_inline_data_list(qp->ibv_qp_ex, data_count, inline_data_list);
    } else {
        ibv_wr_set_sge_list(qp->ibv_qp_ex, data_count, sge_list);
    }

    ibv_wr_set_ud_addr(qp->ibv_qp_ex, conn->ah->ibv_ah, conn->ep_addr->qpn, conn->ep_addr->qkey);

    if (!(flags & FI_MORE)) {
        ret = ibv_wr_complete(qp->ibv_qp_ex);
        base_ep->is_wr_started = false;
        return ret;
    }

    return 0;
}

/**
 * @brief RDMA-core version of RDMA read operation using ibv_* APIs
 */
static inline int
efa_post_rdma_read_ibv(struct efa_base_ep *base_ep,
                       const struct ibv_sge *sge_list,
                       size_t sge_count,
                       uint32_t remote_key,
                       uint64_t remote_addr,
                       uintptr_t wr_id,
                       uint64_t flags,
                       struct efa_conn *conn)
{
    struct efa_qp *qp = base_ep->qp;
    int ret;

    if (!base_ep->is_wr_started) {
        ibv_wr_start(qp->ibv_qp_ex);
        base_ep->is_wr_started = true;
    }

    qp->ibv_qp_ex->wr_id = wr_id;
    ibv_wr_rdma_read(qp->ibv_qp_ex, remote_key, remote_addr);
    ibv_wr_set_sge_list(qp->ibv_qp_ex, sge_count, sge_list);
    ibv_wr_set_ud_addr(qp->ibv_qp_ex, conn->ah->ibv_ah, conn->ep_addr->qpn, conn->ep_addr->qkey);

    if (!(flags & FI_MORE)) {
        ret = ibv_wr_complete(qp->ibv_qp_ex);
        base_ep->is_wr_started = false;
        return ret;
    }

    return 0;
}

/**
 * @brief RDMA-core version of RDMA write operation using ibv_* APIs
 */
static inline int
efa_post_rdma_write_ibv(struct efa_base_ep *base_ep,
                        const struct ibv_sge *sge_list,
                        size_t sge_count,
                        uint32_t remote_key,
                        uint64_t remote_addr,
                        uintptr_t wr_id,
                        uint64_t data,
                        uint64_t flags,
                        struct efa_conn *conn)
{
    struct efa_qp *qp = base_ep->qp;
    int ret;

    if (!base_ep->is_wr_started) {
        ibv_wr_start(qp->ibv_qp_ex);
        base_ep->is_wr_started = true;
    }

    qp->ibv_qp_ex->wr_id = wr_id;

    if (flags & FI_REMOTE_CQ_DATA) {
        ibv_wr_rdma_write_imm(qp->ibv_qp_ex, remote_key, remote_addr, data);
    } else {
        ibv_wr_rdma_write(qp->ibv_qp_ex, remote_key, remote_addr);
    }

    ibv_wr_set_sge_list(qp->ibv_qp_ex, sge_count, sge_list);
    ibv_wr_set_ud_addr(qp->ibv_qp_ex, conn->ah->ibv_ah, conn->ep_addr->qpn, conn->ep_addr->qkey);

    if (!(flags & FI_MORE)) {
        ret = ibv_wr_complete(qp->ibv_qp_ex);
        base_ep->is_wr_started = false;
        return ret;
    }

    return 0;
}

/**
 * @brief Wrapper for send operations - chooses between direct and IBV paths
 */
static inline int
efa_qp_post_send(struct efa_base_ep *base_ep,
                 const struct ibv_sge *sge_list,
                 const struct ibv_data_buf *inline_data_list,
                 size_t data_count,
                 bool use_inline,
                 uintptr_t wr_id,
                 uint64_t data,
                 uint64_t flags,
                 struct efa_ah *ah,
                 uint32_t qpn,
                 uint32_t qkey)
{
    struct efa_conn conn = {.ah = ah, .ep_addr = &(struct efa_ep_addr){.qpn = qpn, .qkey = qkey}};
#if HAVE_EFA_DATA_PATH_DIRECT
    if (base_ep->qp->data_path_direct_enabled)
        return efa_post_send_direct(base_ep, sge_list, inline_data_list, data_count,
                                   use_inline, wr_id, data, flags, &conn);
#endif
    return efa_post_send_ibv(base_ep, sge_list, inline_data_list, data_count,
                            use_inline, wr_id, data, flags, &conn);
}

/**
 * @brief Wrapper for RDMA read operations - chooses between direct and IBV paths
 */
static inline int
efa_qp_post_read(struct efa_base_ep *base_ep,
                 const struct ibv_sge *sge_list,
                 size_t sge_count,
                 uint32_t remote_key,
                 uint64_t remote_addr,
                 uintptr_t wr_id,
                 uint64_t flags,
                 struct efa_ah *ah,
                 uint32_t qpn,
                 uint32_t qkey)
{
    struct efa_conn conn = {.ah = ah, .ep_addr = &(struct efa_ep_addr){.qpn = qpn, .qkey = qkey}};
#if HAVE_EFA_DATA_PATH_DIRECT
    if (base_ep->qp->data_path_direct_enabled)
        return efa_post_rdma_read_direct(base_ep, sge_list, sge_count,
                                        remote_key, remote_addr, wr_id, flags, &conn);
#endif
    return efa_post_rdma_read_ibv(base_ep, sge_list, sge_count,
                                 remote_key, remote_addr, wr_id, flags, &conn);
}

/**
 * @brief Wrapper for RDMA write operations - chooses between direct and IBV paths
 */
static inline int
efa_qp_post_write(struct efa_base_ep *base_ep,
                  const struct ibv_sge *sge_list,
                  size_t sge_count,
                  uint32_t remote_key,
                  uint64_t remote_addr,
                  uintptr_t wr_id,
                  uint64_t data,
                  uint64_t flags,
                  struct efa_ah *ah,
                  uint32_t qpn,
                  uint32_t qkey)
{
    struct efa_conn conn = {.ah = ah, .ep_addr = &(struct efa_ep_addr){.qpn = qpn, .qkey = qkey}};
#if HAVE_EFA_DATA_PATH_DIRECT
    if (base_ep->qp->data_path_direct_enabled)
        return efa_post_rdma_write_direct(base_ep, sge_list, sge_count,
                                         remote_key, remote_addr, wr_id, data, flags, &conn);
#endif
    return efa_post_rdma_write_ibv(base_ep, sge_list, sge_count,
                                  remote_key, remote_addr, wr_id, data, flags, &conn);
}

#endif

#if EFA_UNIT_TEST
/* For unit tests, declare functions that are defined in efa_unit_test_data_path_ops.c */
int efa_qp_post_recv(struct efa_qp *qp, struct ibv_recv_wr *wr, struct ibv_recv_wr **bad);
int efa_qp_wr_complete(struct efa_qp *efaqp);
void efa_qp_wr_rdma_read(struct efa_qp *efaqp, uint32_t rkey, uint64_t remote_addr);
void efa_qp_wr_rdma_write(struct efa_qp *efaqp, uint32_t rkey, uint64_t remote_addr);
void efa_qp_wr_rdma_write_imm(struct efa_qp *efaqp, uint32_t rkey, uint64_t remote_addr, __be32 imm_data);
void efa_qp_wr_send(struct efa_qp *efaqp);
void efa_qp_wr_send_imm(struct efa_qp *efaqp, __be32 imm_data);
void efa_qp_wr_set_inline_data_list(struct efa_qp *efaqp, size_t num_buf, const struct ibv_data_buf *buf_list);
void efa_qp_wr_set_sge_list(struct efa_qp *efaqp, size_t num_sge, const struct ibv_sge *sg_list);
void efa_qp_wr_set_ud_addr(struct efa_qp *efaqp, struct efa_ah *ah, uint32_t remote_qpn, uint32_t remote_qkey);
void efa_qp_wr_start(struct efa_qp *efaqp);
int efa_ibv_cq_start_poll(struct efa_ibv_cq *ibv_cq, struct ibv_poll_cq_attr *attr);
int efa_ibv_cq_next_poll(struct efa_ibv_cq *ibv_cq);
enum ibv_wc_opcode efa_ibv_cq_wc_read_opcode(struct efa_ibv_cq *ibv_cq);
void efa_ibv_cq_end_poll(struct efa_ibv_cq *ibv_cq);
uint32_t efa_ibv_cq_wc_read_qp_num(struct efa_ibv_cq *ibv_cq);
uint32_t efa_ibv_cq_wc_read_vendor_err(struct efa_ibv_cq *ibv_cq);
uint32_t efa_ibv_cq_wc_read_src_qp(struct efa_ibv_cq *ibv_cq);
uint32_t efa_ibv_cq_wc_read_slid(struct efa_ibv_cq *ibv_cq);
uint32_t efa_ibv_cq_wc_read_byte_len(struct efa_ibv_cq *ibv_cq);
unsigned int efa_ibv_cq_wc_read_wc_flags(struct efa_ibv_cq *ibv_cq);
__be32 efa_ibv_cq_wc_read_imm_data(struct efa_ibv_cq *ibv_cq);
bool efa_ibv_cq_wc_is_unsolicited(struct efa_ibv_cq *ibv_cq);

int efa_ibv_cq_wc_read_sgid(struct efa_ibv_cq *ibv_cq, union ibv_gid *sgid);

int efa_ibv_get_cq_event(struct efa_ibv_cq *ibv_cq, void **cq_context);
int efa_ibv_req_notify_cq(struct efa_ibv_cq *ibv_cq, int solicited_only);

#else
/* For production, define static inline functions */

/* QP wrapper functions */
static inline int efa_qp_post_recv(struct efa_qp *qp, struct ibv_recv_wr *wr, struct ibv_recv_wr **bad)
{
#if HAVE_EFA_DATA_PATH_DIRECT
	if (qp->data_path_direct_enabled)
		return efa_data_path_direct_post_recv(qp, wr, bad);
#endif
	return ibv_post_recv(qp->ibv_qp, wr, bad);
}

static inline int efa_qp_wr_complete(struct efa_qp *efaqp)
{
#if HAVE_EFA_DATA_PATH_DIRECT
	if (efaqp->data_path_direct_enabled)
		return efa_data_path_direct_wr_complete(efaqp);
#endif
	return ibv_wr_complete(efaqp->ibv_qp_ex);
}

static inline void efa_qp_wr_rdma_read(struct efa_qp *efaqp, uint32_t rkey, uint64_t remote_addr)
{
#if HAVE_EFA_DATA_PATH_DIRECT
	if (efaqp->data_path_direct_enabled) {
		efa_data_path_direct_wr_rdma_read(efaqp, rkey, remote_addr);
		return;
	}
#endif
	ibv_wr_rdma_read(efaqp->ibv_qp_ex, rkey, remote_addr);
}

static inline void efa_qp_wr_rdma_write(struct efa_qp *efaqp, uint32_t rkey, uint64_t remote_addr)
{
#if HAVE_EFA_DATA_PATH_DIRECT
	if (efaqp->data_path_direct_enabled) {
		efa_data_path_direct_wr_rdma_write(efaqp, rkey, remote_addr);
		return;
	}
#endif
	ibv_wr_rdma_write(efaqp->ibv_qp_ex, rkey, remote_addr);
}

static inline void efa_qp_wr_rdma_write_imm(struct efa_qp *efaqp, uint32_t rkey, uint64_t remote_addr, __be32 imm_data)
{
#if HAVE_EFA_DATA_PATH_DIRECT
	if (efaqp->data_path_direct_enabled) {
		efa_data_path_direct_wr_rdma_write_imm(efaqp, rkey, remote_addr, imm_data);
		return;
	}
#endif
	ibv_wr_rdma_write_imm(efaqp->ibv_qp_ex, rkey, remote_addr, imm_data);
}

static inline void efa_qp_wr_send(struct efa_qp *efaqp)
{
#if HAVE_EFA_DATA_PATH_DIRECT
	if (efaqp->data_path_direct_enabled) {
		efa_data_path_direct_wr_send(efaqp);
		return;
	}
#endif
	ibv_wr_send(efaqp->ibv_qp_ex);
}

static inline void efa_qp_wr_send_imm(struct efa_qp *efaqp, __be32 imm_data)
{
#if HAVE_EFA_DATA_PATH_DIRECT
	if (efaqp->data_path_direct_enabled) {
		efa_data_path_direct_wr_send_imm(efaqp, imm_data);
		return;
	}
#endif
	ibv_wr_send_imm(efaqp->ibv_qp_ex, imm_data);
}

static inline void efa_qp_wr_set_inline_data_list(struct efa_qp *efaqp, size_t num_buf, const struct ibv_data_buf *buf_list)
{
#if HAVE_EFA_DATA_PATH_DIRECT
	if (efaqp->data_path_direct_enabled) {
		efa_data_path_direct_wr_set_inline_data_list(efaqp, num_buf, buf_list);
		return;
	}
#endif
	ibv_wr_set_inline_data_list(efaqp->ibv_qp_ex, num_buf, buf_list);
}

static inline void efa_qp_wr_set_sge_list(struct efa_qp *efaqp, size_t num_sge, const struct ibv_sge *sg_list)
{
#if HAVE_EFA_DATA_PATH_DIRECT
	if (efaqp->data_path_direct_enabled) {
		efa_data_path_direct_wr_set_sge_list(efaqp, num_sge, sg_list);
		return;
	}
#endif
	ibv_wr_set_sge_list(efaqp->ibv_qp_ex, num_sge, sg_list);
}

static inline void efa_qp_wr_set_ud_addr(struct efa_qp *efaqp, struct efa_ah *ah, uint32_t remote_qpn, uint32_t remote_qkey)
{
#if HAVE_EFA_DATA_PATH_DIRECT
	if (efaqp->data_path_direct_enabled) {
		efa_data_path_direct_wr_set_ud_addr(efaqp, ah, remote_qpn, remote_qkey);
		return;
	}
#endif
	ibv_wr_set_ud_addr(efaqp->ibv_qp_ex, ah->ibv_ah, remote_qpn, remote_qkey);
}

static inline void efa_qp_wr_start(struct efa_qp *efaqp)
{
#if HAVE_EFA_DATA_PATH_DIRECT
	if (efaqp->data_path_direct_enabled) {
		efa_data_path_direct_wr_start(efaqp);
		return;
	}
#endif
	ibv_wr_start(efaqp->ibv_qp_ex);
}

/* CQ wrapper functions */
static inline int efa_ibv_cq_start_poll(struct efa_ibv_cq *ibv_cq, struct ibv_poll_cq_attr *attr)
{
#if HAVE_EFA_DATA_PATH_DIRECT
	if (ibv_cq->data_path_direct_enabled)
		return efa_data_path_direct_start_poll(ibv_cq, attr);
#endif
	return ibv_start_poll(ibv_cq->ibv_cq_ex, attr);
}

static inline int efa_ibv_cq_next_poll(struct efa_ibv_cq *ibv_cq)
{
#if HAVE_EFA_DATA_PATH_DIRECT
	if (ibv_cq->data_path_direct_enabled)
		return efa_data_path_direct_next_poll(ibv_cq);
#endif
	return ibv_next_poll(ibv_cq->ibv_cq_ex);
}

static inline enum ibv_wc_opcode efa_ibv_cq_wc_read_opcode(struct efa_ibv_cq *ibv_cq)
{
#if HAVE_EFA_DATA_PATH_DIRECT
	if (ibv_cq->data_path_direct_enabled)
		return efa_data_path_direct_wc_read_opcode(ibv_cq);
#endif
	return ibv_wc_read_opcode(ibv_cq->ibv_cq_ex);
}

static inline void efa_ibv_cq_end_poll(struct efa_ibv_cq *ibv_cq)
{
#if HAVE_EFA_DATA_PATH_DIRECT
	if (ibv_cq->data_path_direct_enabled) {
		efa_data_path_direct_end_poll(ibv_cq);
		return;
	}
#endif
	ibv_end_poll(ibv_cq->ibv_cq_ex);
}

static inline uint32_t efa_ibv_cq_wc_read_qp_num(struct efa_ibv_cq *ibv_cq)
{
#if HAVE_EFA_DATA_PATH_DIRECT
	if (ibv_cq->data_path_direct_enabled)
		return efa_data_path_direct_wc_read_qp_num(ibv_cq);
#endif
	return ibv_wc_read_qp_num(ibv_cq->ibv_cq_ex);
}

static inline uint32_t efa_ibv_cq_wc_read_vendor_err(struct efa_ibv_cq *ibv_cq)
{
#if HAVE_EFA_DATA_PATH_DIRECT
	if (ibv_cq->data_path_direct_enabled)
		return efa_data_path_direct_wc_read_vendor_err(ibv_cq);
#endif
	return ibv_wc_read_vendor_err(ibv_cq->ibv_cq_ex);
}

static inline uint32_t efa_ibv_cq_wc_read_src_qp(struct efa_ibv_cq *ibv_cq)
{
#if HAVE_EFA_DATA_PATH_DIRECT
	if (ibv_cq->data_path_direct_enabled)
		return efa_data_path_direct_wc_read_src_qp(ibv_cq);
#endif
	return ibv_wc_read_src_qp(ibv_cq->ibv_cq_ex);
}

static inline uint32_t efa_ibv_cq_wc_read_slid(struct efa_ibv_cq *ibv_cq)
{
#if HAVE_EFA_DATA_PATH_DIRECT
	if (ibv_cq->data_path_direct_enabled)
		return efa_data_path_direct_wc_read_slid(ibv_cq);
#endif
	return ibv_wc_read_slid(ibv_cq->ibv_cq_ex);
}

static inline uint32_t efa_ibv_cq_wc_read_byte_len(struct efa_ibv_cq *ibv_cq)
{
#if HAVE_EFA_DATA_PATH_DIRECT
	if (ibv_cq->data_path_direct_enabled)
		return efa_data_path_direct_wc_read_byte_len(ibv_cq);
#endif
	return ibv_wc_read_byte_len(ibv_cq->ibv_cq_ex);
}

static inline unsigned int efa_ibv_cq_wc_read_wc_flags(struct efa_ibv_cq *ibv_cq)
{
#if HAVE_EFA_DATA_PATH_DIRECT
	if (ibv_cq->data_path_direct_enabled)
		return efa_data_path_direct_wc_read_wc_flags(ibv_cq);
#endif
	return ibv_wc_read_wc_flags(ibv_cq->ibv_cq_ex);
}

static inline __be32 efa_ibv_cq_wc_read_imm_data(struct efa_ibv_cq *ibv_cq)
{
#if HAVE_EFA_DATA_PATH_DIRECT
	if (ibv_cq->data_path_direct_enabled)
		return efa_data_path_direct_wc_read_imm_data(ibv_cq);
#endif
	return ibv_wc_read_imm_data(ibv_cq->ibv_cq_ex);
}


static inline bool efa_ibv_cq_wc_is_unsolicited(struct efa_ibv_cq *ibv_cq)
{
#if HAVE_EFA_DATA_PATH_DIRECT
	if (ibv_cq->data_path_direct_enabled)
		return efa_data_path_direct_wc_is_unsolicited(ibv_cq);
#endif
#if HAVE_CAPS_UNSOLICITED_WRITE_RECV
	return efadv_wc_is_unsolicited(efadv_cq_from_ibv_cq_ex(ibv_cq->ibv_cq_ex));
#else
	return false;
#endif
}

static inline int efa_ibv_cq_wc_read_sgid(struct efa_ibv_cq *ibv_cq, union ibv_gid *sgid)
{
#if HAVE_EFA_DATA_PATH_DIRECT
	if (ibv_cq->data_path_direct_enabled)
		return efa_data_path_direct_wc_read_sgid(ibv_cq, sgid);
#endif

#if HAVE_EFADV_CQ_EX
	return efadv_wc_read_sgid(efadv_cq_from_ibv_cq_ex(ibv_cq->ibv_cq_ex), sgid);
#else
	return false;
#endif
}

static inline int efa_ibv_get_cq_event(struct efa_ibv_cq *ibv_cq, void **cq_context)
{
	struct ibv_cq *cq = ibv_cq_ex_to_cq(ibv_cq->ibv_cq_ex);
#if HAVE_EFA_DATA_PATH_DIRECT && HAVE_EFADV_CQ_ATTR_DB
	if (ibv_cq->data_path_direct_enabled)
		return efa_data_path_direct_get_cq_event(ibv_cq, &cq, cq_context);
#endif
#if HAVE_EFA_CQ_NOTIFICATION
	return ibv_get_cq_event(ibv_cq->channel, &cq, cq_context);
#else
	return -FI_ENOSYS;
#endif
}

static inline int efa_ibv_req_notify_cq(struct efa_ibv_cq *ibv_cq, int solicited_only)
{
#if HAVE_EFA_DATA_PATH_DIRECT && HAVE_EFADV_CQ_ATTR_DB
	if (ibv_cq->data_path_direct_enabled)
		return efa_data_path_direct_req_notify_cq(ibv_cq, solicited_only);
#endif
#if HAVE_EFA_CQ_NOTIFICATION
	return ibv_req_notify_cq(ibv_cq_ex_to_cq(ibv_cq->ibv_cq_ex), solicited_only);
#else
	return -FI_ENOSYS;
#endif
}


#endif /* EFA_UNIT_TEST */

/**
 * @brief Check whether a completion consumes recv buffer
 *
 * @param ibv_cq efa ibv cq
 * @return true the wc consumes a recv buffer
 * @return false the wc doesn't consume a recv buffer
 */
static inline bool efa_cq_wc_is_unsolicited(struct efa_ibv_cq *ibv_cq)
{
	return ibv_cq->unsolicited_write_recv_enabled && efa_ibv_cq_wc_is_unsolicited(ibv_cq);
}

static inline bool efa_cq_wc_available(struct efa_ibv_cq *cq)
{
	return cq->poll_active && !cq->poll_err;
}

static inline void efa_cq_report_poll_err(struct efa_ibv_cq *cq)
{
	int err = cq->poll_err;

	if (err && err != ENOENT)
		EFA_INFO(FI_LOG_CQ, "Ignoring CQ entries from destroyed queue pair");
}

static inline void efa_cq_start_poll(struct efa_ibv_cq *cq)
{
	/**
	 * It is possible that the last efa_cq_readfrom
	 * is leaving the device cq in a poll active status
	 * when polling a failed cqe and leave it for the efa_cq_readfrom, efa_cq_readerr
	 * or efa_cq_poll_ibv_cq to consume it. And efa_cq_poll_ibv_cq
	 * will call this wrapper at the beginning.
	 * We shouldn't start poll in this stuation as it will make the
	 * cqe index shifted and the entry lost.
	 */
	if (cq->poll_active)
		return;

	/* Pass an empty ibv_poll_cq_attr struct (zero-initialized) for
	 * ibv_start_poll. EFA expects .comp_mask = 0, or otherwise returns EINVAL.
	 */
	cq->poll_err = efa_ibv_cq_start_poll(cq, &(struct ibv_poll_cq_attr){0});
	if (!cq->poll_err)
		cq->poll_active = true;
	else
		efa_cq_report_poll_err(cq);
}

static inline void efa_cq_next_poll(struct efa_ibv_cq *cq)
{
	assert(cq->poll_active);
	cq->poll_err = efa_ibv_cq_next_poll(cq);
	if (cq->poll_err)
		efa_cq_report_poll_err(cq);
}

static inline void efa_cq_end_poll(struct efa_ibv_cq *cq)
{
	if (cq->poll_active)
		efa_ibv_cq_end_poll(cq);
	cq->poll_active = false;
	cq->poll_err = 0;
}

#endif /* EFA_DATA_PATH_OPS_H */
