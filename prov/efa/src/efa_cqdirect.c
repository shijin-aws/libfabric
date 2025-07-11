/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/* SPDX-FileCopyrightText: Copyright Amazon.com, Inc. or its affiliates. All rights reserved. */

#include <infiniband/efadv.h>


#include "efa.h"
#include "efa_cqdirect.h"
#include "efa_cqdirect_structs.h"
#include "efa_cqdirect_efa_io_defs.h"
#include "efa_av.h"

#if HAVE_CQDIRECT

#include "efa_cqdirect_entry.h"

struct efa_ibv_cq_ops cqdirect_cq_ops = {
    .start_poll = efa_cqdirect_start_poll,
    .next_poll = efa_cqdirect_next_poll,
    .wc_read_opcode = efa_cqdirect_wc_read_opcode,
    .end_poll = efa_cqdirect_end_poll,
    .wc_read_qp_num = efa_cqdirect_wc_read_qp_num,
    .wc_read_vendor_err = efa_cqdirect_wc_read_vendor_err,
	.wc_read_slid = efa_cqdirect_wc_read_slid,
	.wc_read_src_qp = efa_cqdirect_wc_read_src_qp,
    .wc_read_byte_len = efa_cqdirect_wc_read_byte_len,
    .wc_read_wc_flags = efa_cqdirect_wc_read_wc_flags,
    .wc_read_imm_data = efa_cqdirect_wc_read_imm_data,
    .wc_is_unsolicited = efa_cqdirect_wc_is_unsolicited
};

struct efa_qp_ops cqdirect_qp_ops = {
    .post_recv = efa_cqdirect_post_recv,
    .wr_complete = efa_cqdirect_wr_complete,
    .wr_rdma_read = efa_cqdirect_wr_rdma_read,
    .wr_rdma_write = efa_cqdirect_wr_rdma_write,
    .wr_rdma_write_imm = efa_cqdirect_wr_rdma_write_imm,
    .wr_send = efa_cqdirect_wr_send,
    .wr_send_imm = efa_cqdirect_wr_send_imm,
    .wr_set_inline_data_list = efa_cqdirect_wr_set_inline_data_list,
    .wr_set_sge_list = efa_cqdirect_wr_set_sge_list,
    .wr_set_ud_addr = efa_cqdirect_wr_set_ud_addr,
    .wr_start = efa_cqdirect_wr_start,
};

int efa_cqdirect_qp_initialize( struct efa_qp *efa_qp) {
	/* Called during efa_base_ep_create_qp.
	 * See also rdma-core/providers/efa/verbs.c: efa_setup_qp
	 */
	struct efa_cqdirect_qp *direct_qp = &efa_qp->cqdirect_qp;

	struct efadv_wq_attr sq_attr;
	struct efadv_wq_attr rq_attr;
	int ret = 0;

	memset(&efa_qp->cqdirect_qp, 0, sizeof(efa_qp->cqdirect_qp));
		
	//efa_cqdirect_timer_init(&efa_qp->cqdirect_qp.send_timing);
	//efa_cqdirect_timer_init(&efa_qp->cqdirect_qp.recv_timing);

	ret = efadv_query_qp_wqs(efa_qp->ibv_qp,
								&sq_attr,
								&rq_attr,
								sizeof(rq_attr));
	if (ret != FI_SUCCESS)
		return ret;

	direct_qp->rq.buf = rq_attr.buffer;
	direct_qp->rq.wq.db = rq_attr.doorbell;
	direct_qp->rq.wq.wqe_size = rq_attr.entry_size;
	// TODO: in rdma-core, the wqe_cnt is set to rq_desc_cnt / qp->rq.wq.max_sge,
	// TODO: while the desc_mask is just rq_desc_cnt - 1.  In practice only the mask matters.
	rq_attr.num_entries = 32768; // TODO fix this hard-coded number!
	efa_cqdirect_wq_initialize(&direct_qp->rq.wq, rq_attr.num_entries);

	direct_qp->sq.desc = sq_attr.buffer;
	direct_qp->sq.wq.phase = 0;
	direct_qp->sq.wq.db = sq_attr.doorbell;
	direct_qp->sq.num_wqe_pending = 0;

	direct_qp->sq.wq.wqe_size = sq_attr.entry_size;
	efa_cqdirect_wq_initialize(&direct_qp->sq.wq, sq_attr.num_entries);

	/* see efa_qp_init_indices */

	efa_qp->cqdirect_enabled = 1;
	efa_qp->ops = &cqdirect_qp_ops;
	return ret;
	
}

int efa_cqdirect_cq_initialize(struct efa_cq *efa_cq) {
    struct efadv_cq_attr attr = {0};
    struct efa_cqdirect_cq *cqdirect = &efa_cq->ibv_cq.cqdirect;
    int ret;

    memset(cqdirect, 0, sizeof(*cqdirect));

    //efa_cqdirect_timer_init(&cqdirect->timing);

    /**
     * We cannot use direct cq when hardware is still using sub cq.
     * Also disable direct cq when it's specified by environment
     */
    if (!efa_env.efa_direct_cq_ops || efa_device_use_sub_cq()) {
        /* nothing to do.  Not using directcq.*/
        return FI_SUCCESS;
    }

    ret = efadv_query_cq(ibv_cq_ex_to_cq(efa_cq->ibv_cq.ibv_cq_ex), &attr, sizeof(attr));
    if (ret != FI_SUCCESS) {
        return ret;
    }

    efa_cq->ibv_cq.cqdirect_enabled = 1;
	efa_cq->ibv_cq.ops = &cqdirect_cq_ops;
    cqdirect->buffer = attr.buffer;
    cqdirect->entry_size = attr.entry_size;
    cqdirect->num_entries = attr.num_entries;

    cqdirect->phase = 1;
    cqdirect->consumed_cnt = 0;
    cqdirect->qmask = cqdirect->num_entries - 1;

    return FI_SUCCESS;
}

#endif /* end of HAVE_CQDIRECT */
