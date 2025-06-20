/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/* SPDX-FileCopyrightText: Copyright Amazon.com, Inc. or its affiliates. All rights reserved. */

#include <infiniband/efadv.h>

#define SIZEOF_LONG 8 // TODO: :ahhh: rdma-core's config.h is leaking into mmio.h!
#include <util/mmio.h>

#include "efa.h"
#include "efa_cqdirect.h"
#include "efa_cqdirect_structs.h"
#include "efa_cqdirect_efa_io_defs.h"
#include "efa_av.h"


static inline void efa_cqdirect_rq_ring_doorbell(struct efa_cqdirect_rq *rq, uint16_t pc)
{
	udma_to_device_barrier();
	mmio_write32(rq->wq.db, pc);
}

static inline void efa_sq_ring_doorbell(struct efa_cqdirect_sq *sq, uint16_t pc)
{
	// int32_t old_db, new_db; //DEBUG ONLY:
	// old_db = mmio_read32(sq->wq.db); //DEBUG ONLY:
	mmio_write32(sq->wq.db, pc);
	// new_db = mmio_read32(sq->wq.db); //DEBUG ONLY:
	
}

static uint32_t efa_wq_get_next_wrid_idx(struct efa_cqdirect_wq *wq, uint64_t wr_id)
{
	uint32_t wrid_idx;

	/* Get the next wrid to be used from the index pool */
	wrid_idx = wq->wrid_idx_pool[wq->wrid_idx_pool_next];
	wq->wrid[wrid_idx] = wr_id;

	/* Will never overlap, as validate function succeeded */
	wq->wrid_idx_pool_next++;
	assert(wq->wrid_idx_pool_next <= wq->wqe_cnt);

	return wrid_idx;
}

static enum ibv_wc_status to_ibv_status(enum efa_errno status)
{
	/* note: enum efa_errno status are precisely enum efa_io_comp_status. */
	switch (status) {
	case EFA_IO_COMP_STATUS_OK:
		return IBV_WC_SUCCESS;
	case EFA_IO_COMP_STATUS_FLUSHED:
		return IBV_WC_WR_FLUSH_ERR;
	case EFA_IO_COMP_STATUS_LOCAL_ERROR_QP_INTERNAL_ERROR:
	case EFA_IO_COMP_STATUS_LOCAL_ERROR_UNSUPPORTED_OP:
	case EFA_IO_COMP_STATUS_LOCAL_ERROR_INVALID_AH:
		return IBV_WC_LOC_QP_OP_ERR;
	case EFA_IO_COMP_STATUS_LOCAL_ERROR_INVALID_LKEY:
		return IBV_WC_LOC_PROT_ERR;
	case EFA_IO_COMP_STATUS_LOCAL_ERROR_BAD_LENGTH:
		return IBV_WC_LOC_LEN_ERR;
	case EFA_IO_COMP_STATUS_REMOTE_ERROR_ABORT:
		return IBV_WC_REM_ABORT_ERR;
	case EFA_IO_COMP_STATUS_REMOTE_ERROR_RNR:
		return IBV_WC_RNR_RETRY_EXC_ERR;
	case EFA_IO_COMP_STATUS_REMOTE_ERROR_BAD_DEST_QPN:
		return IBV_WC_REM_INV_RD_REQ_ERR;
	case EFA_IO_COMP_STATUS_REMOTE_ERROR_BAD_STATUS:
		return IBV_WC_BAD_RESP_ERR;
	case EFA_IO_COMP_STATUS_REMOTE_ERROR_BAD_LENGTH:
		return IBV_WC_REM_INV_REQ_ERR;
	case EFA_IO_COMP_STATUS_LOCAL_ERROR_UNRESP_REMOTE:
	case EFA_IO_COMP_STATUS_LOCAL_ERROR_UNREACH_REMOTE:
		return IBV_WC_RESP_TIMEOUT_ERR;
	case EFA_IO_COMP_STATUS_REMOTE_ERROR_BAD_ADDRESS:
		return IBV_WC_REM_ACCESS_ERR;
	case EFA_IO_COMP_STATUS_REMOTE_ERROR_UNKNOWN_PEER:
		return IBV_WC_REM_OP_ERR;
	default:
		return IBV_WC_GENERAL_ERR;
	}
}

enum ibv_wc_opcode efa_cqdirect_wc_read_opcode(struct efa_cq *efacq)
{
	enum efa_io_send_op_type op_type;
	struct efa_io_cdesc_common *cqe;

	cqe = efacq->cqdirect.cur_cqe;
	op_type = EFA_GET(&cqe->flags, EFA_IO_CDESC_COMMON_OP_TYPE);

	if (EFA_GET(&cqe->flags, EFA_IO_CDESC_COMMON_Q_TYPE) ==
		    EFA_IO_SEND_QUEUE) {
		if (op_type == EFA_IO_RDMA_WRITE)
			return IBV_WC_RDMA_WRITE;

		return IBV_WC_SEND;
	}

	if (op_type == EFA_IO_RDMA_WRITE)
		return IBV_WC_RECV_RDMA_WITH_IMM;

	return IBV_WC_RECV;
}


static int efa_cqe_is_pending(struct efa_io_cdesc_common *cqe_common,
			      int phase)
{
	return EFA_GET(&cqe_common->flags, EFA_IO_CDESC_COMMON_PHASE) == phase;
}

static inline struct efa_io_cdesc_common *
efa_sub_cq_get_cqe(struct efa_cqdirect_cq *cqd, int entry)
{
	return (struct efa_io_cdesc_common *)(cqd->buffer +
					      (entry * cqd->entry_size));
}

static inline uint32_t efa_cqdirect_get_current_index(struct efa_cqdirect_cq *cqdirect)
{
	return cqdirect->consumed_cnt & cqdirect->qmask;
}

static struct efa_io_cdesc_common *
efa_cqdirect_next_sub_cqe_get(struct efa_cqdirect_cq *cqdirect)
{
	/* See: cq_next_sub_cqe_get */
	struct efa_io_cdesc_common *cqe;
	uint32_t current_index;

	current_index = efa_cqdirect_get_current_index(cqdirect);
	cqe = efa_sub_cq_get_cqe(cqdirect, current_index);
	if (efa_cqe_is_pending(cqe, cqdirect->phase)) {
		/* Do not read the rest of the completion entry before the
		 * phase bit has been validated.
		 */
		udma_from_device_barrier();
		cqdirect->consumed_cnt++;
		if (!efa_cqdirect_get_current_index(cqdirect))
			cqdirect->phase = 1 - cqdirect->phase;
		return cqe;
	}

	return NULL;
}

static void efa_cqdirect_process_ex_cqe(struct efa_cq *efa_cq, struct efa_qp *qp)
{
	struct ibv_cq_ex *ibvcqx = efa_cq->ibv_cq.ibv_cq_ex;
	struct efa_io_cdesc_common *cqe = efa_cq->cqdirect.cur_cqe;
	uint32_t wrid_idx;

	wrid_idx = cqe->req_id;

	if (EFA_GET(&cqe->flags, EFA_IO_CDESC_COMMON_Q_TYPE) == EFA_IO_SEND_QUEUE) {
		efa_cq->cqdirect.cur_wq = &qp->cqdirect_qp.sq.wq;
		ibvcqx->wr_id = efa_cq->cqdirect.cur_wq->wrid[wrid_idx];
		ibvcqx->status = to_ibv_status(cqe->status);

		// rdma_tracepoint(rdma_core_efa, process_completion, cq->dev->name, ibvcqx->wr_id,
		// 		ibvcqx->status, efa_wc_read_opcode(ibvcqx), cqe->qp_num,
		// 		UINT32_MAX, UINT16_MAX, efa_wc_read_byte_len(ibvcqx));
	} else {
		efa_cq->cqdirect.cur_wq = &qp->cqdirect_qp.rq.wq;
		ibvcqx->wr_id = !EFA_GET(&cqe->flags, EFA_IO_CDESC_COMMON_UNSOLICITED) ?
			efa_cq->cqdirect.cur_wq->wrid[wrid_idx] : 0;
		ibvcqx->status = to_ibv_status(cqe->status);

		// rdma_tracepoint(rdma_core_efa, process_completion, cq->dev->name, ibvcqx->wr_id,
		// 		ibvcqx->status, efa_wc_read_opcode(ibvcqx),
		// 		efa_wc_read_src_qp(ibvcqx), cqe->qp_num, efa_wc_read_slid(ibvcqx),
		// 		efa_wc_read_byte_len(ibvcqx));
	}
}

uint32_t efa_cqdirect_wc_read_qp_num(struct efa_cq *efa_cq) {
	return efa_cq->cqdirect.cur_cqe->qp_num;
}

uint32_t efa_cqdirect_wc_read_byte_len(struct efa_cq *efa_cq)
{
	struct efa_io_cdesc_common *cqe;
	struct efa_io_rx_cdesc_ex *rcqe;
	uint32_t length;

	cqe = efa_cq->cqdirect.cur_cqe;

	if (EFA_GET(&cqe->flags, EFA_IO_CDESC_COMMON_Q_TYPE) != EFA_IO_RECV_QUEUE)
		return 0;

	rcqe = container_of(cqe, struct efa_io_rx_cdesc_ex, base.common);

	length = rcqe->base.length;
	if (EFA_GET(&cqe->flags, EFA_IO_CDESC_COMMON_OP_TYPE) == EFA_IO_RDMA_WRITE)
		length |= ((uint32_t)rcqe->u.rdma_write.length_hi << 16);

	return length;
}

unsigned int efa_cqdirect_wc_read_wc_flags(struct efa_cq *efa_cq)
{
	unsigned int wc_flags = 0;

	if (EFA_GET(&efa_cq->cqdirect.cur_cqe->flags, EFA_IO_CDESC_COMMON_HAS_IMM))
		wc_flags |= IBV_WC_WITH_IMM;

	return wc_flags;
}

__be32 efa_cqdirect_wc_read_imm_data(struct efa_cq *efa_cq)
{
	struct efa_io_rx_cdesc *rcqe;
	
	rcqe = container_of(efa_cq->cqdirect.cur_cqe, struct efa_io_rx_cdesc, common);

	return htobe32(rcqe->imm);
}


int efa_cqdirect_start_poll( struct efa_cq *efa_cq, struct ibv_poll_cq_attr *attr)
{
	uint32_t qpn;
	struct efa_domain *efa_domain;
	efa_cq->cqdirect.cur_cqe = efa_cqdirect_next_sub_cqe_get(&efa_cq->cqdirect);
	if (!efa_cq->cqdirect.cur_cqe)
		return ENOENT;
	qpn = efa_cq->cqdirect.cur_cqe->qp_num;
	efa_domain = container_of(efa_cq->util_cq.domain, struct efa_domain, util_domain);
	efa_cq->cqdirect.cur_qp = efa_domain->qp_table[qpn & efa_domain->qp_table_sz_m1];
	


	efa_cqdirect_process_ex_cqe(efa_cq, efa_cq->cqdirect.cur_qp);
	return 0;
}

static void efa_wq_put_wrid_idx(struct efa_cqdirect_wq *wq, uint32_t wrid_idx)
{
	// pthread_spin_lock(&wq->wqlock);
	wq->wrid_idx_pool_next--;
	wq->wrid_idx_pool[wq->wrid_idx_pool_next] = wrid_idx;
	wq->wqe_completed++;
	// pthread_spin_unlock(&wq->wqlock);
}

int efa_cqdirect_next_poll(struct efa_cq *efa_cq)
{
	struct efa_io_cdesc_common *cqe = efa_cq->cqdirect.cur_cqe;

	if (!EFA_GET(&cqe->flags, EFA_IO_CDESC_COMMON_UNSOLICITED))
		efa_wq_put_wrid_idx(efa_cq->cqdirect.cur_wq, cqe->req_id);
	return efa_cqdirect_start_poll(efa_cq, NULL);
}

void efa_cqdirect_end_poll(struct efa_cq *efa_cq)
{
	struct efa_io_cdesc_common *cqe = efa_cq->cqdirect.cur_cqe;

	if (cqe) {
		if (!EFA_GET(&cqe->flags, EFA_IO_CDESC_COMMON_UNSOLICITED))
			efa_wq_put_wrid_idx(efa_cq->cqdirect.cur_wq, cqe->req_id);
		// if (efa_cq->cqdirect.db)
		// 	efa_update_cq_doorbell(efa_cq, false);
	}

	// pthread_spin_unlock(&cq->lock);
}

static int efa_cqdirect_wq_initialize(struct efa_cqdirect_wq *wq, uint32_t wqe_cnt )
{
	int i;

	wq->wqe_cnt = wqe_cnt;
	wq->desc_mask = wqe_cnt - 1;
	wq->pc = 0;

	wq->wrid = malloc(wq->wqe_cnt * sizeof(*wq->wrid));
	if (!wq->wrid)
		return ENOMEM;

	wq->wrid_idx_pool = malloc(wqe_cnt * sizeof(uint32_t));
	if (!wq->wrid_idx_pool) {
		free(wq->wrid);
		return ENOMEM;
	}
	

	/* Initialize the wrid free indexes pool. */
	for (i = 0; i < wqe_cnt; i++)
		wq->wrid_idx_pool[i] = i;

	wq->sub_cq_idx = 0; // TODO: sub CQ idx?

	return 0;
}


int efa_cqdirect_qp_initialize( struct efa_qp *efa_qp) {
	/* Called during efa_base_ep_create_qp.
	 * See also rdma-core/providers/efa/verbs.c: efa_setup_qp
	 */
	struct efa_cqdirect_qp *direct_qp = &efa_qp->cqdirect_qp;

	struct efadv_wq_attr sq_attr;
	struct efadv_wq_attr rq_attr;

	efa_qp->cqdirect_enabled = 0;
	if (!efa_env.efa_direct_cq_ops) {
		// TODO: probably need to make sure CQ and QP both have visibility to efa_qp->cqdirect_enabled
		/* nothing to do.  Not using directcq.*/
		return FI_SUCCESS;
	}

	int ret = efadv_query_qp_wqs(efa_qp->ibv_qp,
								&sq_attr,
								&rq_attr,
								sizeof(rq_attr));
	if (ret != FI_SUCCESS)
		return ret;

	direct_qp->rq.buf = rq_attr.buffer;
	direct_qp->rq.wq.db = rq_attr.doorbell;
	direct_qp->rq.wq.wqe_size = rq_attr.entry_size;
	direct_qp->rq.wq.max_sge = 3;
	efa_cqdirect_wq_initialize(&direct_qp->rq.wq, rq_attr.num_entries);
	

	direct_qp->sq.desc = sq_attr.buffer;
	direct_qp->sq.wq.phase = 0;
	direct_qp->sq.wq.db = sq_attr.doorbell;
	direct_qp->sq.num_wqe_pending = 0;
	direct_qp->sq.max_batch_wr = 16; //TODO how do we get this number?
	direct_qp->sq.max_wr_rdma_sge = 1; // TODO how do we get this number?
	direct_qp->sq.wq.max_sge = 2; // TODO how do we get this number?
	direct_qp->sq.max_inline_data = 32; // TODO how do we get this number?

	direct_qp->sq.wq.wqe_size = sq_attr.entry_size;
	efa_cqdirect_wq_initialize(&direct_qp->sq.wq, sq_attr.num_entries);
	
	// TODO: max_batch!

// 	struct efadv_wq_attr {
// 	uint64_t comp_mask;
// 	uint8_t *buffer;
// 	uint32_t entry_size;
// 	uint32_t num_entries;
// 	uint32_t *doorbell;
// 	uint32_t max_batch;
// 	uint8_t reserved[4];
// };


	/* see efa_qp_init_indices */

	efa_qp->cqdirect_enabled = 1;
	return ret;
	
}


static size_t efa_sge_total_bytes(const struct ibv_sge *sg_list, int num_sge)
{
	size_t bytes = 0;
	size_t i;

	for (i = 0; i < num_sge; i++)
		bytes += sg_list[i].length;

	return bytes;
}

static void efa_set_tx_buf(struct efa_io_tx_buf_desc *tx_buf,
			   uint64_t addr, uint32_t lkey,
			   uint32_t length)
{
	tx_buf->length = length;
	EFA_SET(&tx_buf->lkey, EFA_IO_TX_BUF_DESC_LKEY, lkey);
	tx_buf->buf_addr_lo = addr & 0xffffffff;
	tx_buf->buf_addr_hi = addr >> 32;
}

static void efa_post_send_sgl(struct efa_io_tx_buf_desc *tx_bufs,
			      const struct ibv_sge *sg_list,
			      int num_sge)
{
	const struct ibv_sge *sge;
	size_t i;

	for (i = 0; i < num_sge; i++) {
		sge = &sg_list[i];
		efa_set_tx_buf(&tx_bufs[i], sge->addr, sge->lkey, sge->length);
	}
}


int efa_cqdirect_cq_initialize( struct efa_cq *efa_cq) {
	struct efadv_cq_attr attr = {0};
	int ret;

	efa_cq->cqdirect_enabled = 0;

	memset(&efa_cq->cqdirect, 0, sizeof(efa_cq->cqdirect));
	if (!efa_env.efa_direct_cq_ops) {
		/* nothing to do.  Not using directcq.*/

		return FI_SUCCESS;
	}

	ret = efadv_query_cq(ibv_cq_ex_to_cq(efa_cq->ibv_cq.ibv_cq_ex), &attr, sizeof(attr));
	if (ret != FI_SUCCESS) {
		return ret;
	}
	efa_cq->cqdirect_enabled = 1;
	efa_cq->cqdirect.buffer = attr.buffer;
	efa_cq->cqdirect.entry_size = attr.entry_size;
	efa_cq->cqdirect.num_entries = attr.num_entries;

	efa_cq->cqdirect.phase = 1;
	efa_cq->cqdirect.consumed_cnt = 0;
	efa_cq->cqdirect.qmask = efa_cq->cqdirect.num_entries - 1;

	return FI_SUCCESS;

}


int efa_cqdirect_post_recv(struct efa_qp *qp, struct ibv_recv_wr *wr, struct ibv_recv_wr **bad) {
	/* see rdma-core/providers/efa/verbs.c: efa_post_recv */
	uintptr_t addr;
	struct efa_io_rx_desc *rx_buf;
	struct efa_cqdirect_wq *wq = &qp->cqdirect_qp.rq.wq;
	uint32_t rq_desc_offset;
	uint32_t i;

	while (wr) {

		rq_desc_offset = (wq->pc & wq->desc_mask) *
					 sizeof(*rx_buf);
		rx_buf = (struct efa_io_rx_desc *)(qp->cqdirect_qp.rq.buf + rq_desc_offset);
		memset(rx_buf, 0, sizeof(*rx_buf));

		/* Wrap rx descriptor index */
		wq->pc++;
		if (!(wq->pc & wq->desc_mask))
			wq->phase++;

		// err = efa_post_recv_validate(qp, wr); // TODO: validate?

		rx_buf->req_id = efa_wq_get_next_wrid_idx(wq, wr->wr_id);
		wq->wqe_posted++;

		/* Default init of the rx buffer */
		EFA_SET(&rx_buf->lkey_ctrl, EFA_IO_RX_DESC_FIRST, 1);
		EFA_SET(&rx_buf->lkey_ctrl, EFA_IO_RX_DESC_LAST, 0);

		for (i = 0; i < wr->num_sge; i++) {
			/* Set last indication if need) */
			if (i == wr->num_sge - 1)
				EFA_SET(&rx_buf->lkey_ctrl, EFA_IO_RX_DESC_LAST, 1);

			addr = wr->sg_list[i].addr;

			/* Set RX buffer desc from SGE */
			rx_buf->length = min(wr->sg_list[i].length, UINT16_MAX);
			EFA_SET(&rx_buf->lkey_ctrl, EFA_IO_RX_DESC_LKEY,
				wr->sg_list[i].lkey);
			rx_buf->buf_addr_lo = addr;
			rx_buf->buf_addr_hi = (uint64_t)addr >> 32;

			/* reset descriptor for next iov */
		}
		wr = wr->next;
	}

	efa_cqdirect_rq_ring_doorbell(&qp->cqdirect_qp.rq, wq->pc);
	return FI_SUCCESS;
}

static int efa_post_send_validate(struct efa_qp *qp,
				  unsigned int wr_flags)
{
	// if (unlikely(qp->verbs_qp.qp.state != IBV_QPS_RTS &&
	// 	     qp->verbs_qp.qp.state != IBV_QPS_SQD)) {
	// 	verbs_err(verbs_get_ctx(qp->verbs_qp.qp.context),
	// 		  "SQ[%u] is in invalid state\n",
	// 		  qp->verbs_qp.qp.qp_num);
	// 	return EINVAL;
	// }

	// if (unlikely(!(wr_flags & IBV_SEND_SIGNALED) && !qp->sq_sig_all)) {
	// 	verbs_err(verbs_get_ctx(qp->verbs_qp.qp.context),
	// 		  "SQ[%u] Non signaled WRs not supported\n",
	// 		  qp->verbs_qp.qp.qp_num);
	// 	return EINVAL;
	// }

	// if (unlikely(wr_flags & ~(IBV_SEND_SIGNALED | IBV_SEND_INLINE))) {
	// 	verbs_err(verbs_get_ctx(qp->verbs_qp.qp.context),
	// 		  "SQ[%u] Unsupported wr_flags[%#x] supported[%#x]\n",
	// 		  qp->verbs_qp.qp.qp_num, wr_flags,
	// 		  ~(IBV_SEND_SIGNALED | IBV_SEND_INLINE));
	// 	return EINVAL;
	// }

	if (unlikely(qp->cqdirect_qp.sq.wq.wqe_posted - qp->cqdirect_qp.sq.wq.wqe_completed ==
		     qp->cqdirect_qp.sq.wq.wqe_cnt)) {
		EFA_DBG(FI_LOG_EP_DATA,
			  "SQ[%u] is full wqe_posted[%u] wqe_completed[%u] wqe_cnt[%u]\n",
			  qp->qp_num, qp->cqdirect_qp.sq.wq.wqe_posted,
			  qp->cqdirect_qp.sq.wq.wqe_completed, qp->cqdirect_qp.sq.wq.wqe_cnt);
		return ENOMEM;
	}

	return 0;
}

static void efa_set_common_ctrl_flags(struct efa_io_tx_meta_desc *desc,
				      struct efa_cqdirect_sq *sq,
				      enum efa_io_send_op_type op_type)
{
	EFA_SET(&desc->ctrl1, EFA_IO_TX_META_DESC_META_DESC, 1);
	EFA_SET(&desc->ctrl1, EFA_IO_TX_META_DESC_OP_TYPE, op_type);
	EFA_SET(&desc->ctrl2, EFA_IO_TX_META_DESC_PHASE, sq->wq.phase);
	EFA_SET(&desc->ctrl2, EFA_IO_TX_META_DESC_FIRST, 1);
	EFA_SET(&desc->ctrl2, EFA_IO_TX_META_DESC_LAST, 1);
	EFA_SET(&desc->ctrl2, EFA_IO_TX_META_DESC_COMP_REQ, 1);
}

static void efa_sq_advance_post_idx(struct efa_cqdirect_sq *sq)
{
	struct efa_cqdirect_wq *wq = &sq->wq;

	wq->wqe_posted++;
	wq->pc++;

	if (!(wq->pc & wq->desc_mask))
		wq->phase++;
}

void efa_cqdirect_send_wr_set_imm_data(struct efa_io_tx_wqe *tx_wqe, __be32 imm_data)
{
	struct efa_io_tx_meta_desc *meta_desc;

	meta_desc = &tx_wqe->meta;
	meta_desc->immediate_data = be32toh(imm_data);
	EFA_SET(&meta_desc->ctrl1, EFA_IO_TX_META_DESC_HAS_IMM, 1);
}

static size_t efa_buf_list_total_bytes(const struct ibv_data_buf *buf_list,
				       size_t num_buf)
{
	size_t bytes = 0;
	size_t i;

	for (i = 0; i < num_buf; i++)
		bytes += buf_list[i].length;

	return bytes;
}

void
efa_cqdirect_wr_set_inline_data_list(struct efa_qp *efa_qp,
				 size_t num_buf,
				 const struct ibv_data_buf *buf_list)
{
	struct efa_cqdirect_qp *qp = &efa_qp->cqdirect_qp;
	struct efa_io_tx_wqe *tx_wqe = qp->sq.curr_tx_wqe;
	uint32_t total_length = 0;
	uint32_t length;
	size_t i;

	if (unlikely(qp->wr_session_err))
		return;

	// TODO: list_total_bytes needs implementation
	if (unlikely(efa_buf_list_total_bytes(buf_list, num_buf) >
		     qp->sq.max_inline_data)) {
		// verbs_err(verbs_get_ctx(qp->verbs_qp.qp.context),
		// 	  "SQ[%u] WR inline length %zu > %zu\n",
		// 	  ibvqpx->qp_base.qp_num,
		// 	  efa_buf_list_total_bytes(buf_list, num_buf),
		// 	  qp->sq.max_inline_data);
		qp->wr_session_err = EINVAL;
		return;
	}

	for (i = 0; i < num_buf; i++) {
		length = buf_list[i].length;

		memcpy(tx_wqe->data.inline_data + total_length,
		       buf_list[i].addr, length);
		total_length += length;
	}

	EFA_SET(&tx_wqe->meta.ctrl1, EFA_IO_TX_META_DESC_INLINE_MSG, 1);
	tx_wqe->meta.length = total_length;
}


void efa_cqdirect_wr_set_sge_list(struct efa_qp *efa_qp, size_t num_sge,
				     const struct ibv_sge *sg_list)
{
	struct efa_cqdirect_qp *qp = &efa_qp->cqdirect_qp;
	struct efa_io_rdma_req *rdma_req;
	struct efa_io_tx_wqe *tx_wqe;
	struct efa_cqdirect_sq *sq = &qp->sq;
	uint8_t op_type;

	if (unlikely(qp->wr_session_err))
		return;

	tx_wqe = sq->curr_tx_wqe;
	op_type = EFA_GET(&tx_wqe->meta.ctrl1, EFA_IO_TX_META_DESC_OP_TYPE);
	switch (op_type) {
	case EFA_IO_SEND:
		if (unlikely(num_sge > sq->wq.max_sge)) {
			// verbs_err(verbs_get_ctx(qp->verbs_qp.qp.context),
			// 	  "SQ[%u] num_sge[%zu] > max_sge[%u]\n",
			// 	  ibvqpx->qp_base.qp_num, num_sge,
			// 	  sq->wq.max_sge);
			qp->wr_session_err = EINVAL;
			return;
		}
		efa_post_send_sgl(tx_wqe->data.sgl, sg_list, num_sge);
		break;
	case EFA_IO_RDMA_READ:
	case EFA_IO_RDMA_WRITE:
		if (unlikely(num_sge > sq->max_wr_rdma_sge)) {
			// verbs_err(verbs_get_ctx(qp->verbs_qp.qp.context),
			// 	  "SQ[%u] num_sge[%zu] > max_rdma_sge[%zu]\n",
			// 	  ibvqpx->qp_base.qp_num, num_sge,
			// 	  sq->max_wr_rdma_sge);
			qp->wr_session_err = EINVAL;
			return;
		}
		rdma_req = &tx_wqe->data.rdma_req;
		rdma_req->remote_mem.length = efa_sge_total_bytes(sg_list,
								  num_sge);
		efa_post_send_sgl(rdma_req->local_mem, sg_list, num_sge);
		break;
	default:
		return;
	}

	tx_wqe->meta.length = num_sge;
}

static void efa_send_wr_set_imm_data(struct efa_io_tx_wqe *tx_wqe, __be32 imm_data)
{
	struct efa_io_tx_meta_desc *meta_desc;

	meta_desc = &tx_wqe->meta;
	meta_desc->immediate_data = be32toh(imm_data);
	EFA_SET(&meta_desc->ctrl1, EFA_IO_TX_META_DESC_HAS_IMM, 1);
}

static void efa_send_wr_set_rdma_addr(struct efa_io_tx_wqe *tx_wqe, uint32_t rkey,
				      uint64_t remote_addr)
{
	struct efa_io_remote_mem_addr *remote_mem;

	remote_mem = &tx_wqe->data.rdma_req.remote_mem;
	remote_mem->rkey = rkey;
	remote_mem->buf_addr_lo = remote_addr & 0xFFFFFFFF;
	remote_mem->buf_addr_hi = remote_addr >> 32;
}

void efa_cqdirect_wr_set_ud_addr(struct efa_qp *efaqp, struct ibv_ah *ibvah, uint32_t remote_qpn, uint32_t remote_qkey)
{
	/* TODO: This is terrible abstraction breakage to get efa_ah using container_of!!!!*/
	struct efa_ah {
		struct ibv_ah ibvah;
		uint16_t efa_ah;
	} *ah = container_of(ibvah, struct efa_ah, ibvah);
	struct efa_io_tx_wqe *tx_wqe;

	if (unlikely(efaqp->cqdirect_qp.wr_session_err))
		return;

	tx_wqe = efaqp->cqdirect_qp.sq.curr_tx_wqe;

	tx_wqe->meta.dest_qp_num = remote_qpn;
	tx_wqe->meta.ah = ah->efa_ah;
	tx_wqe->meta.qkey = remote_qkey;

	// rdma_tracepoint(rdma_core_efa, post_send, qp->dev->name, ibvqpx->wr_id,
	// 		EFA_GET(&tx_wqe->meta.ctrl1, EFA_IO_TX_META_DESC_OP_TYPE),
	// 		ibvqpx->qp_base.qp_num, remote_qpn, ah->efa_ah, efa_get_wqe_length(tx_wqe));
}


void efa_cqdirect_wr_start(struct efa_qp *qp)
{

	// mmio_wc_spinlock(&qp->sq.wq.wqlock);
	qp->cqdirect_qp.wr_session_err = 0;
	qp->cqdirect_qp.sq.num_wqe_pending = 0;
	// sq->phase_rb = qp->sq.wq.phase;
}

int efa_cqdirect_wr_complete(struct efa_qp *qp) {
	/* See: efa_send_wr_complete. */
	
	struct efa_cqdirect_sq *sq = &qp->cqdirect_qp.sq;

	uint32_t max_txbatch = sq->max_batch_wr;
	uint32_t pc, sq_desc_idx, curbatch, num_wqe_to_copy, local_idx;

	/*
	 * Copy local queue to device in chunks, handling wraparound and max
	 * doorbell batch.
	 */
	pc = sq->wq.pc - sq->num_wqe_pending;
	sq_desc_idx = pc & sq->wq.desc_mask;
	local_idx=0;

	/* mmio_wc_start() comes from efa_send_wr_start() */
	while (sq->num_wqe_pending) {
		num_wqe_to_copy = MIN(MIN(
				sq->num_wqe_pending, sq->wq.wqe_cnt - sq_desc_idx),
				max_txbatch - curbatch);
		mmio_memcpy_x64(
				(struct efa_io_tx_wqe *)sq->desc + sq_desc_idx,
				sq->wqe_batch + local_idx,
				num_wqe_to_copy * sizeof(struct efa_io_tx_wqe));

		sq->num_wqe_pending -= num_wqe_to_copy;
		local_idx += num_wqe_to_copy;
		curbatch += num_wqe_to_copy;
		pc += num_wqe_to_copy;
		sq_desc_idx = (sq_desc_idx + num_wqe_to_copy) &
			      sq->wq.desc_mask;

		if (curbatch == max_txbatch) {
			mmio_flush_writes();
			efa_sq_ring_doorbell(sq, pc);
			curbatch = 0;
			mmio_wc_start();
		}
	}

	if (curbatch) {
		mmio_flush_writes();
		efa_sq_ring_doorbell(sq, sq->wq.pc);
	}

	return qp->cqdirect_qp.wr_session_err;
}


static struct efa_io_tx_wqe* efa_cqdirect_send_wr_common(struct efa_qp *qp,
						enum efa_io_send_op_type op_type)
{
	struct ibv_qp_ex *ibvqpx = qp->ibv_qp_ex;
	struct efa_cqdirect_qp *cqd_qp = &qp->cqdirect_qp;
	struct efa_cqdirect_sq *sq = &qp->cqdirect_qp.sq;
	struct efa_io_tx_meta_desc *meta_desc;
	int wqe_idx;
	int err;

	if (unlikely(cqd_qp->wr_session_err))
		return NULL;

	// TODO: how is ibvqpx->wr_flags ever set?
	err = efa_post_send_validate(qp, ibvqpx->wr_flags);
	if (unlikely(err)) {
		cqd_qp->wr_session_err = err;
		return NULL;
	}

	/* MODIFIED: since we don't have the local_queue, just grab an entry
	directly on the CQ. */
	// wqe_idx = (sq->wq.pc) & sq->wq.desc_mask;
	wqe_idx = sq->num_wqe_pending;

	sq->curr_tx_wqe = &sq->wqe_batch[wqe_idx];
	memset(sq->curr_tx_wqe, 0, sizeof(*sq->curr_tx_wqe));

	meta_desc = &sq->curr_tx_wqe->meta;
	efa_set_common_ctrl_flags(meta_desc, sq, op_type);
	meta_desc->req_id = efa_wq_get_next_wrid_idx(&sq->wq,
							    ibvqpx->wr_id);

	/* advance index and change phase */
	efa_sq_advance_post_idx(sq);
	sq->num_wqe_pending++;
	return sq->curr_tx_wqe;
}

void efa_cqdirect_wr_rdma_read(struct efa_qp *efaqp, uint32_t rkey, uint64_t remote_addr) {
	struct efa_io_tx_wqe *tx_wqe;

	tx_wqe = efa_cqdirect_send_wr_common(efaqp, EFA_IO_RDMA_READ);
	if (unlikely(!tx_wqe))
		return;

	efa_send_wr_set_rdma_addr(tx_wqe, rkey, remote_addr);
}

void efa_cqdirect_wr_rdma_write(struct efa_qp *efaqp, uint32_t rkey,
				   uint64_t remote_addr)
{
	struct efa_io_tx_wqe *tx_wqe;

	tx_wqe = efa_cqdirect_send_wr_common(efaqp, EFA_IO_RDMA_WRITE);
	if (unlikely(!tx_wqe))
		return;

	efa_send_wr_set_rdma_addr(tx_wqe, rkey, remote_addr);
}

void efa_cqdirect_wr_rdma_write_imm(struct efa_qp *efaqp, uint32_t rkey,
				       uint64_t remote_addr, __be32 imm_data)
{
	struct efa_io_tx_wqe *tx_wqe;

	tx_wqe = efa_cqdirect_send_wr_common(efaqp, EFA_IO_RDMA_WRITE);
	if (unlikely(!tx_wqe))
		return;

	efa_send_wr_set_rdma_addr(tx_wqe, rkey, remote_addr);
	efa_send_wr_set_imm_data(tx_wqe, imm_data);
}

void efa_cqdirect_wr_send(struct efa_qp *efaqp) {
		efa_cqdirect_send_wr_common(efaqp, EFA_IO_SEND);
}

void efa_cqdirect_wr_send_imm(struct efa_qp *efaqp, __be32 imm_data) {
	struct efa_io_tx_wqe *tx_wqe;

	tx_wqe = efa_cqdirect_send_wr_common(efaqp, EFA_IO_SEND);
	if (unlikely(!tx_wqe))
		return;

	efa_send_wr_set_imm_data(tx_wqe, imm_data);
}

