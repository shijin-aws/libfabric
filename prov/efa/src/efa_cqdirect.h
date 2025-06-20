/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/* SPDX-FileCopyrightText: Copyright Amazon.com, Inc. or its affiliates. All rights reserved. */

#ifndef _EFA_CQDIRECT_H
#define _EFA_CQDIRECT_H

#include "efa.h"
#include "efa_base_ep.h"
#include "efa_cq.h"
#include <infiniband/verbs.h>



int efa_cqdirect_qp_initialize( struct efa_qp *efa_qp);
int efa_cqdirect_cq_initialize( struct efa_cq *efa_cq);


int efa_cqdirect_post_recv(struct efa_qp *efaqp, struct ibv_recv_wr *wr, struct ibv_recv_wr **bad_wr);
static inline int efaibv_post_recv(struct efa_qp *efaqp, struct ibv_qp *qp, struct ibv_recv_wr *wr, struct ibv_recv_wr **bad_wr) {
	if (efaqp->cqdirect_enabled)
		return efa_cqdirect_post_recv(efaqp, wr, bad_wr);
	else
		return ibv_post_recv(qp, wr, bad_wr);
}

#define EFADIRECT_SWITCH(fun, ...) \
   if(efaqp->cqdirect_enabled) { efa_cqdirect_##fun(efaqp, ##__VA_ARGS__); } else { ibv_##fun(ibvqpx, ##__VA_ARGS__ ); }
#define EFADIRECT_SWITCH_RETURNING(fun, ...) \
   if(efaqp->cqdirect_enabled) { return efa_cqdirect_##fun(efaqp, ##__VA_ARGS__); } else { return ibv_##fun(ibvqpx, ##__VA_ARGS__ ); }
#define EFADIRECT_SWITCH_CQ(fun, ...) \
   if(efacq->cqdirect_enabled) { efa_cqdirect_##fun(efacq, ##__VA_ARGS__); } else { ibv_##fun(efacq->ibv_cq.ibv_cq_ex, ##__VA_ARGS__); }
#define EFADIRECT_SWITCH_CQ_RETURNING(fun, ...) \
   if(efacq->cqdirect_enabled) { return efa_cqdirect_##fun(efacq, ##__VA_ARGS__); } else { return ibv_##fun(efacq->ibv_cq.ibv_cq_ex, ##__VA_ARGS__); }


int efa_cqdirect_wr_complete(struct efa_qp *efaqp);
static inline int efaibv_wr_complete(struct efa_qp *efaqp, struct ibv_qp_ex *ibvqpx) {
	EFADIRECT_SWITCH_RETURNING(wr_complete)
}

void efa_cqdirect_wr_rdma_read(struct efa_qp *efaqp, uint32_t rkey, uint64_t remote_addr);
static inline void efaibv_wr_rdma_read(struct efa_qp *efaqp, struct ibv_qp_ex *ibvqpx, uint32_t rkey, uint64_t remote_addr) {
	EFADIRECT_SWITCH(wr_rdma_read, rkey, remote_addr)
}

void efa_cqdirect_wr_rdma_write(struct efa_qp *efaqp, uint32_t rkey, uint64_t remote_addr);
static inline void efaibv_wr_rdma_write(struct efa_qp *efaqp, struct ibv_qp_ex *ibvqpx, uint32_t rkey, uint64_t remote_addr) {
	EFADIRECT_SWITCH(wr_rdma_write, rkey, remote_addr)
}

void efa_cqdirect_wr_rdma_write_imm(struct efa_qp *efaqp, uint32_t rkey, uint64_t remote_addr, __be32 imm_data);
static inline void efaibv_wr_rdma_write_imm(struct efa_qp *efaqp, struct ibv_qp_ex *ibvqpx, uint32_t rkey, uint64_t remote_addr, __be32 imm_data) {
	EFADIRECT_SWITCH(wr_rdma_write_imm, rkey, remote_addr, imm_data)
}

void efa_cqdirect_wr_send(struct efa_qp *efaqp);
static inline void efaibv_wr_send(struct efa_qp *efaqp, struct ibv_qp_ex *ibvqpx) {
	EFADIRECT_SWITCH(wr_send)
}

void efa_cqdirect_wr_send_imm(struct efa_qp *efaqp, __be32 imm_data);
static inline void efaibv_wr_send_imm(struct efa_qp *efaqp, struct ibv_qp_ex *ibvqpx, __be32 imm_data) {
	EFADIRECT_SWITCH(wr_send_imm, imm_data)
}

void efa_cqdirect_wr_set_inline_data_list(struct efa_qp *efaqp, size_t num_buf, const struct ibv_data_buf *buf_list);
static inline void efaibv_wr_set_inline_data_list(struct efa_qp *efaqp, struct ibv_qp_ex *ibvqpx, size_t num_buf, const struct ibv_data_buf *buf_list) {
	EFADIRECT_SWITCH(wr_set_inline_data_list, num_buf, buf_list)
}

void efa_cqdirect_wr_set_sge_list(struct efa_qp *efaqp, size_t num_sge, const struct ibv_sge *sg_list);
static inline void efaibv_wr_set_sge_list(struct efa_qp *efaqp, struct ibv_qp_ex *ibvqpx, size_t num_sge, const struct ibv_sge *sg_list) {
	EFADIRECT_SWITCH(wr_set_sge_list, num_sge, sg_list)
}

void efa_cqdirect_wr_set_ud_addr(struct efa_qp *efaqp, struct ibv_ah *ah, uint32_t remote_qpn, uint32_t remote_qkey);
static inline void efaibv_wr_set_ud_addr(struct efa_qp *efaqp, struct ibv_qp_ex *ibvqpx, struct ibv_ah *ah, uint32_t remote_qpn, uint32_t remote_qkey) {
	EFADIRECT_SWITCH(wr_set_ud_addr, ah, remote_qpn, remote_qkey)
}
 
void efa_cqdirect_wr_start(struct efa_qp *efaqp);
static inline void efaibv_wr_start(struct efa_qp *efaqp, struct ibv_qp_ex *ibvqpx) {
	EFADIRECT_SWITCH(wr_start)
}

int efa_cqdirect_start_poll(struct efa_cq *efacq, struct ibv_poll_cq_attr *attr);
static inline int efaibv_start_poll(struct efa_cq *efacq, struct ibv_poll_cq_attr *attr) {
	EFADIRECT_SWITCH_CQ_RETURNING(start_poll, attr)
}

// enum ibv_wc_opcode efa_cqdirect_wc_read_opcode(struct efa_cq *efacq);
// static inline enum ibv_wc_opcode efaibv_wc_read_opcode(struct efa_cq *efacq) {
// 	if(1) {
// 		return efa_cqdirect_wc_read_opcode(efacq);
// 	} else {
// 		return ibv_wc_read_opcode(efacq->ibv_cq.ibv_cq_ex);
// 	}
// }
enum ibv_wc_opcode efa_cqdirect_wc_read_opcode(struct efa_cq *efacq );
static inline enum ibv_wc_opcode efaibv_wc_read_opcode(struct efa_cq *efacq) {
	EFADIRECT_SWITCH_CQ_RETURNING(wc_read_opcode)
}

int efa_cqdirect_next_poll(struct efa_cq *efacq);
static inline int efaibv_next_poll(struct efa_cq *efacq) {
	EFADIRECT_SWITCH_CQ_RETURNING(next_poll)
}

void efa_cqdirect_end_poll(struct efa_cq *efacq);
static inline void efaibv_end_poll(struct efa_cq *efacq) {
	EFADIRECT_SWITCH_CQ(end_poll)
}

uint32_t efa_cqdirect_wc_read_qp_num(struct efa_cq *efacq);
static inline uint32_t efaibv_wc_read_qp_num(struct efa_cq *efacq) {
	EFADIRECT_SWITCH_CQ_RETURNING(wc_read_qp_num)
}

uint32_t efa_cqdirect_wc_read_byte_len(struct efa_cq *efacq);
static inline uint32_t efaibv_wc_read_byte_len(struct efa_cq *efacq) {
	EFADIRECT_SWITCH_CQ_RETURNING(wc_read_byte_len)
}

unsigned int efa_cqdirect_wc_read_wc_flags(struct efa_cq *efacq);
static inline unsigned int efaibv_wc_read_wc_flags(struct efa_cq *efacq) {
	EFADIRECT_SWITCH_CQ_RETURNING(wc_read_wc_flags)
}

__be32 efa_cqdirect_wc_read_imm_data(struct efa_cq *efacq);
static inline __be32 efaibv_wc_read_imm_data(struct efa_cq *efacq) {
	EFADIRECT_SWITCH_CQ_RETURNING(wc_read_imm_data)
}


#if HAVE_CAPS_UNSOLICITED_WRITE_RECV
/**
 * @brief Check whether a completion consumes recv buffer
 *
 * @param ibv_cq_ex extended ibv cq
 * @return true the wc consumes a recv buffer
 * @return false the wc doesn't consume a recv buffer
 */
static inline
bool efaibv_wc_is_unsolicited(struct efa_cq *efa_cq)
{
	struct ibv_cq_ex *ibv_cq_ex;
	
	if (!efa_use_unsolicited_write_recv())
		return false;
	ibv_cq_ex = efa_cq->ibv_cq.ibv_cq_ex;
	if (efa_cq->cqdirect_enabled) {
		return EFA_GET(&efa_cq->cqdirect.cur_cqe->flags, EFA_IO_CDESC_COMMON_UNSOLICITED);
	} else {
		return efadv_wc_is_unsolicited(efadv_cq_from_ibv_cq_ex(ibv_cq_ex));
	}
}

#else

static inline
bool efaibv_wc_is_unsolicited(struct efa_cq *efa_cq)
{
	return false;
}

#endif




/*
Called by efa_post_send:
ibv_wr_start
ibv_wr_send_imm
ibv_wr_send
ibv_wr_set_inline_data_list
ibv_wr_set_sge_list
ibv_wr_set_ud_addr
ibv_wr_complete

Called by efa_post_recv:
ibv_post_recv

Called by RMA Write:
ibv_wr_start
ibv_wr_rdma_write_imm
ibv_wr_rdma_write
ibv_wr_set_sge_list
ibv_wr_set_ud_addr
ibv_wr_complete

Called by RMA Read:
ibv_wr_start
ibv_wr_rdma_read
ibv_wr_set_sge_list
ibv_wr_set_ud_addr
ibv_wr_complete

Called during CQ Polling:
ibv_start_poll
ibv_wc_read_opcode
ibv_next_poll
ibv_end_poll

ibv_wc_read_byte_len
ibv_wc_read_wc_flags
ibv_wc_read_imm_data
ibv_wc_read_slid
ibv_wc_read_src_qp

Complete set:
1.  ibv_post_recv
2.  ibv_wr_complete
3.  ibv_wr_rdma_read
4.  ibv_wr_rdma_write
5.  ibv_wr_rdma_write_imm
6.  ibv_wr_send
7.  ibv_wr_send_imm
8.  ibv_wr_set_inline_data_list
9.  ibv_wr_set_sge_list
10. ibv_wr_set_ud_addr
11. ibv_wr_start
*/

#endif