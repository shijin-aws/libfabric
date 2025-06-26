#ifndef _EFA_CQDIRECT_INTERNAL_H
#define _EFA_CQDIRECT_INTERNAL_H

// #include "efa.h"
// #include "efa_cqdirect.h"
// #include "efa_cqdirect_structs.h"
// #include "efa_cqdirect_efa_io_defs.h"
// #include "efa_av.h"

#define SIZEOF_LONG 8 // TODO: :ahhh: rdma-core's config.h is leaking into mmio.h!
#include <util/mmio.h>

#define PRINT_TRACE 0


MAYBE_INLINE void efa_cqdirect_rq_ring_doorbell(struct efa_cqdirect_rq *rq, uint16_t pc)
{
	udma_to_device_barrier();
	mmio_write32(rq->wq.db, pc);
#if PRINT_TRACE
	printf("[cqdirect] RQ Doorbell: %d\n",pc);
#endif
}


MAYBE_INLINE void efa_sq_ring_doorbell(struct efa_cqdirect_sq *sq, uint16_t pc)
{
	// int32_t old_db, new_db; //DEBUG ONLY:
	// old_db = mmio_read32(sq->wq.db); //DEBUG ONLY:
	mmio_write32(sq->wq.db, pc);
	// new_db = mmio_read32(sq->wq.db); //DEBUG ONLY:
#if PRINT_TRACE
	printf("[cqdirect] SQ Doorbell: %d\n",pc);
#endif
	
}


MAYBE_INLINE uint32_t efa_wq_get_next_wrid_idx(struct efa_cqdirect_wq *wq, uint64_t wr_id)
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

MAYBE_INLINE enum ibv_wc_status to_ibv_status(enum efa_errno status)
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


MAYBE_INLINE enum ibv_wc_opcode efa_cqdirect_wc_read_opcode(struct efa_cq *efacq)
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


MAYBE_INLINE int efa_cqe_is_pending(struct efa_io_cdesc_common *cqe_common,
			      int phase)
{
	return EFA_GET(&cqe_common->flags, EFA_IO_CDESC_COMMON_PHASE) == phase;
}

MAYBE_INLINE struct efa_io_cdesc_common *
efa_sub_cq_get_cqe(struct efa_cqdirect_cq *cqd, int entry)
{
	return (struct efa_io_cdesc_common *)(cqd->buffer +
					      (entry * cqd->entry_size));
}

MAYBE_INLINE uint32_t efa_cqdirect_get_current_index(struct efa_cqdirect_cq *cqdirect)
{
	return cqdirect->consumed_cnt & cqdirect->qmask;
}

MAYBE_INLINE struct efa_io_cdesc_common *
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

MAYBE_INLINE void efa_cqdirect_process_ex_cqe(struct efa_cq *efa_cq, struct efa_qp *qp)
{
	struct ibv_cq_ex *ibvcqx = efa_cq->ibv_cq.ibv_cq_ex;
	struct efa_io_cdesc_common *cqe = efa_cq->cqdirect.cur_cqe;
	uint32_t wrid_idx;

	wrid_idx = cqe->req_id;

	if (EFA_GET(&cqe->flags, EFA_IO_CDESC_COMMON_Q_TYPE) == EFA_IO_SEND_QUEUE) {
		efa_cq->cqdirect.cur_wq = &qp->cqdirect_qp.sq.wq;
		ibvcqx->wr_id = efa_cq->cqdirect.cur_wq->wrid[wrid_idx];
		ibvcqx->status = to_ibv_status(cqe->status);

#if PRINT_TRACE
		printf("[cqdirect] Got completion for wrid_idx at %d (SQ).  status=%d\n", wrid_idx, ibvcqx->status);
#endif
		// rdma_tracepoint(rdma_core_efa, process_completion, cq->dev->name, ibvcqx->wr_id,
		// 		ibvcqx->status, efa_wc_read_opcode(ibvcqx), cqe->qp_num,
		// 		UINT32_MAX, UINT16_MAX, efa_wc_read_byte_len(ibvcqx));
	} else {
		efa_cq->cqdirect.cur_wq = &qp->cqdirect_qp.rq.wq;
		ibvcqx->wr_id = !EFA_GET(&cqe->flags, EFA_IO_CDESC_COMMON_UNSOLICITED) ?
			efa_cq->cqdirect.cur_wq->wrid[wrid_idx] : 0;
		ibvcqx->status = to_ibv_status(cqe->status);

#if PRINT_TRACE
		printf("[cqdirect] Got completion for wrid_idx at %d (RQ).  status=%d\n", wrid_idx, ibvcqx->status);
#endif
		// rdma_tracepoint(rdma_core_efa, process_completion, cq->dev->name, ibvcqx->wr_id,
		// 		ibvcqx->status, efa_wc_read_opcode(ibvcqx),
		// 		efa_wc_read_src_qp(ibvcqx), cqe->qp_num, efa_wc_read_slid(ibvcqx),
		// 		efa_wc_read_byte_len(ibvcqx));
	}

}

MAYBE_INLINE uint32_t efa_cqdirect_wc_read_qp_num(struct efa_cq *efa_cq) {
	return efa_cq->cqdirect.cur_cqe->qp_num;
}



MAYBE_INLINE int efa_cqdirect_start_poll( struct efa_cq *efa_cq, struct ibv_poll_cq_attr *attr)
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


MAYBE_INLINE void efa_wq_put_wrid_idx(struct efa_cqdirect_wq *wq, uint32_t wrid_idx)
{
	// pthread_spin_lock(&wq->wqlock);
	wq->wrid_idx_pool_next--;
	wq->wrid_idx_pool[wq->wrid_idx_pool_next] = wrid_idx;
	wq->wqe_completed++;
	// pthread_spin_unlock(&wq->wqlock);
}

MAYBE_INLINE int efa_cqdirect_next_poll(struct efa_cq *efa_cq)
{
	struct efa_io_cdesc_common *cqe = efa_cq->cqdirect.cur_cqe;

	if (!EFA_GET(&cqe->flags, EFA_IO_CDESC_COMMON_UNSOLICITED))
		efa_wq_put_wrid_idx(efa_cq->cqdirect.cur_wq, cqe->req_id);
	return efa_cqdirect_start_poll(efa_cq, NULL);
}

MAYBE_INLINE void efa_cqdirect_end_poll(struct efa_cq *efa_cq)
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

MAYBE_INLINE int efa_cqdirect_wq_initialize(struct efa_cqdirect_wq *wq, uint32_t wqe_cnt )
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


MAYBE_INLINE size_t efa_sge_total_bytes(const struct ibv_sge *sg_list, int num_sge)
{
	size_t bytes = 0;
	size_t i;

	for (i = 0; i < num_sge; i++)
		bytes += sg_list[i].length;

	return bytes;
}

MAYBE_INLINE void efa_set_tx_buf(struct efa_io_tx_buf_desc *tx_buf,
			   uint64_t addr, uint32_t lkey,
			   uint32_t length)
{
	tx_buf->length = length;
	EFA_SET(&tx_buf->lkey, EFA_IO_TX_BUF_DESC_LKEY, lkey);
	tx_buf->buf_addr_lo = addr & 0xffffffff;
	tx_buf->buf_addr_hi = addr >> 32;
}

MAYBE_INLINE void efa_post_send_sgl(struct efa_io_tx_buf_desc *tx_bufs,
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


MAYBE_INLINE int efa_post_send_validate(struct efa_qp *qp,
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

MAYBE_INLINE void efa_set_common_ctrl_flags(struct efa_io_tx_meta_desc *desc,
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

MAYBE_INLINE void efa_sq_advance_post_idx(struct efa_cqdirect_sq *sq)
{
	struct efa_cqdirect_wq *wq = &sq->wq;

	wq->wqe_posted++;
	wq->pc++;

	if (!(wq->pc & wq->desc_mask))
		wq->phase++;
}

MAYBE_INLINE void efa_cqdirect_send_wr_set_imm_data(struct efa_io_tx_wqe *tx_wqe, __be32 imm_data)
{
	struct efa_io_tx_meta_desc *meta_desc;

	meta_desc = &tx_wqe->meta;
	meta_desc->immediate_data = be32toh(imm_data);
	EFA_SET(&meta_desc->ctrl1, EFA_IO_TX_META_DESC_HAS_IMM, 1);
}

MAYBE_INLINE size_t efa_buf_list_total_bytes(const struct ibv_data_buf *buf_list,
				       size_t num_buf)
{
	size_t bytes = 0;
	size_t i;

	for (i = 0; i < num_buf; i++)
		bytes += buf_list[i].length;

	return bytes;
}

MAYBE_INLINE void efa_send_wr_set_imm_data(struct efa_io_tx_wqe *tx_wqe, __be32 imm_data)
{
	struct efa_io_tx_meta_desc *meta_desc;

	meta_desc = &tx_wqe->meta;
	meta_desc->immediate_data = be32toh(imm_data);
	EFA_SET(&meta_desc->ctrl1, EFA_IO_TX_META_DESC_HAS_IMM, 1);
}

MAYBE_INLINE void efa_send_wr_set_rdma_addr(struct efa_io_tx_wqe *tx_wqe, uint32_t rkey,
				      uint64_t remote_addr)
{
	struct efa_io_remote_mem_addr *remote_mem;

	remote_mem = &tx_wqe->data.rdma_req.remote_mem;
	remote_mem->rkey = rkey;
	remote_mem->buf_addr_lo = remote_addr & 0xFFFFFFFF;
	remote_mem->buf_addr_hi = remote_addr >> 32;
}


#if PRINT_TRACE
static inline void dump_sqe(struct efa_io_tx_wqe *sqe, int count) {

	for (int jcount=0;jcount < count; jcount++) {
		printf("SQE[%d].META: req_id=%d, ctrl1=%x, ctrl2=%x, desp_qp=%d, len=%d, imm=%d, ah=%d, qkey=0x%x\n",
			jcount,
			sqe->meta.req_id,
			sqe->meta.ctrl1,
			sqe->meta.ctrl2,
			sqe->meta.dest_qp_num,
			sqe->meta.length,
			sqe->meta.immediate_data,
			sqe->meta.ah,
			sqe->meta.qkey);
	
		if (EFA_GET(&sqe->meta.ctrl1, EFA_IO_TX_META_DESC_INLINE_MSG)) {
			printf("[cqdirect] SQE[%d].INLINE (%d bytes): ",jcount, sqe->meta.length);
			for (int jbyte=0; jbyte<sqe->meta.length; jbyte++) {
				printf("%02hhX ",sqe->data.inline_data[jbyte]);
			}
			printf("\n");
		} else {
			for (int jsge=0; jsge<sqe->meta.length; jsge++) {
				printf("[cqdirect] SQE[%d].SGE[%d] (%d bytes): lkey=0x%x, addr_lo=0x%x, addr_hi=0x%x\n",jcount,jsge,
					sqe->data.sgl[jsge].length,
					sqe->data.sgl[jsge].lkey,
					sqe->data.sgl[jsge].buf_addr_lo,
					sqe->data.sgl[jsge].buf_addr_hi );
			}
		}

		sqe++;
	}
}
#endif


MAYBE_INLINE struct efa_io_tx_wqe* efa_cqdirect_send_wr_common(struct efa_qp *qp,
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


#endif
