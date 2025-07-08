/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/* SPDX-FileCopyrightText: Copyright Amazon.com, Inc. or its affiliates. All rights reserved. */

#ifndef _EFA_CQDIRECT_ENTRY_H
#define _EFA_CQDIRECT_ENTRY_H

#include "efa_cqdirect.h"

ENTRY_FUN int efa_cqdirect_post_recv(struct efa_qp *qp, struct ibv_recv_wr *wr, struct ibv_recv_wr **bad) {
	/* see rdma-core/providers/efa/verbs.c: efa_post_recv */
	uintptr_t addr;
	struct efa_io_rx_desc *rx_buf;
	struct efa_cqdirect_wq *wq = &qp->cqdirect_qp.rq.wq;
	uint32_t rq_desc_offset;
	uint32_t i;

	// TODO: unlike rdma-core, this method directly writes to the
	// TODO: write-combining memory of the RQ.  This might be sub-optimal.

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

ENTRY_FUN int efa_cqdirect_wr_complete(struct efa_qp *qp) {
	/* See: efa_send_wr_complete. */
	
	struct efa_cqdirect_sq *sq = &qp->cqdirect_qp.sq;


	/* it should not be possible to get here with sq->num_wqe_pending==0 */
	assert(sq->num_wqe_pending);

	efa_cqdirect_send_wr_post_working(sq, true);

	return qp->cqdirect_qp.wr_session_err;
}

ENTRY_FUN void efa_cqdirect_wr_rdma_read(struct efa_qp *efaqp, uint32_t rkey, uint64_t remote_addr) {
	struct efa_io_tx_wqe *tx_wqe;

	tx_wqe = efa_cqdirect_send_wr_common(efaqp, EFA_IO_RDMA_READ);
	if (unlikely(!tx_wqe))
		return;

	efa_send_wr_set_rdma_addr(tx_wqe, rkey, remote_addr);
}

ENTRY_FUN void efa_cqdirect_wr_rdma_write(struct efa_qp *efaqp, uint32_t rkey,
				   uint64_t remote_addr)
{
	struct efa_io_tx_wqe *tx_wqe;

	tx_wqe = efa_cqdirect_send_wr_common(efaqp, EFA_IO_RDMA_WRITE);
	if (unlikely(!tx_wqe))
		return;

	efa_send_wr_set_rdma_addr(tx_wqe, rkey, remote_addr);
}

ENTRY_FUN void efa_cqdirect_wr_rdma_write_imm(struct efa_qp *efaqp, uint32_t rkey,
				       uint64_t remote_addr, __be32 imm_data)
{
	struct efa_io_tx_wqe *tx_wqe;

	tx_wqe = efa_cqdirect_send_wr_common(efaqp, EFA_IO_RDMA_WRITE);
	if (unlikely(!tx_wqe))
		return;

	efa_send_wr_set_rdma_addr(tx_wqe, rkey, remote_addr);
	efa_send_wr_set_imm_data(tx_wqe, imm_data);
}

ENTRY_FUN void efa_cqdirect_wr_send(struct efa_qp *efaqp) {
		efa_cqdirect_send_wr_common(efaqp, EFA_IO_SEND);
}

ENTRY_FUN void efa_cqdirect_wr_send_imm(struct efa_qp *efaqp, __be32 imm_data) {
	struct efa_io_tx_wqe *tx_wqe;

	tx_wqe = efa_cqdirect_send_wr_common(efaqp, EFA_IO_SEND);
	if (unlikely(!tx_wqe))
		return;

	efa_send_wr_set_imm_data(tx_wqe, imm_data);
}

ENTRY_FUN void efa_cqdirect_wr_set_inline_data_list(struct efa_qp *efa_qp,
				 size_t num_buf,
				 const struct ibv_data_buf *buf_list)
{
	struct efa_cqdirect_qp *qp = &efa_qp->cqdirect_qp;
	struct efa_io_tx_wqe *tx_wqe = &qp->sq.curr_tx_wqe;
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

ENTRY_FUN void efa_cqdirect_wr_set_sge_list(struct efa_qp *efa_qp, size_t num_sge,
				     const struct ibv_sge *sg_list)
{
	struct efa_cqdirect_qp *qp = &efa_qp->cqdirect_qp;
	struct efa_io_rdma_req *rdma_req;
	struct efa_io_tx_wqe *tx_wqe;
	struct efa_cqdirect_sq *sq = &qp->sq;
	uint8_t op_type;

	if (unlikely(qp->wr_session_err))
		return;

	tx_wqe = &sq->curr_tx_wqe;
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

ENTRY_FUN void efa_cqdirect_wr_set_ud_addr(struct efa_qp *efaqp, struct ibv_ah *ibvah, uint32_t remote_qpn, uint32_t remote_qkey)
{
	/* TODO: This is terrible abstraction breakage to get efa_ah using container_of!!!!*/
	struct efa_ah {
		struct ibv_ah ibvah;
		uint16_t efa_ah;
	} *ah = container_of(ibvah, struct efa_ah, ibvah);
	struct efa_io_tx_wqe *tx_wqe;

	if (unlikely(efaqp->cqdirect_qp.wr_session_err))
		return;

	tx_wqe = &efaqp->cqdirect_qp.sq.curr_tx_wqe;

	tx_wqe->meta.dest_qp_num = remote_qpn;
	tx_wqe->meta.ah = ah->efa_ah;
	tx_wqe->meta.qkey = remote_qkey;

	// rdma_tracepoint(rdma_core_efa, post_send, qp->dev->name, ibvqpx->wr_id,
	// 		EFA_GET(&tx_wqe->meta.ctrl1, EFA_IO_TX_META_DESC_OP_TYPE),
	// 		ibvqpx->qp_base.qp_num, remote_qpn, ah->efa_ah, efa_get_wqe_length(tx_wqe));
}

ENTRY_FUN void efa_cqdirect_wr_start(struct efa_qp *qp)
{

	// mmio_wc_spinlock(&qp->sq.wq.wqlock);
	qp->cqdirect_qp.wr_session_err = 0;
	qp->cqdirect_qp.sq.num_wqe_pending = 0;
	mmio_wc_start();
	// sq->phase_rb = qp->sq.wq.phase;
}

ENTRY_FUN uint32_t efa_cqdirect_wc_read_byte_len(struct efa_cq *efa_cq)
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

ENTRY_FUN unsigned int efa_cqdirect_wc_read_wc_flags(struct efa_cq *efa_cq)
{
	unsigned int wc_flags = 0;

	if (EFA_GET(&efa_cq->cqdirect.cur_cqe->flags, EFA_IO_CDESC_COMMON_HAS_IMM))
		wc_flags |= IBV_WC_WITH_IMM;

	return wc_flags;
}

ENTRY_FUN __be32 efa_cqdirect_wc_read_imm_data(struct efa_cq *efa_cq)
{
	struct efa_io_rx_cdesc *rcqe;
	
	rcqe = container_of(efa_cq->cqdirect.cur_cqe, struct efa_io_rx_cdesc, common);

	return htobe32(rcqe->imm);
}

#endif