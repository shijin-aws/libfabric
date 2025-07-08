/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/* SPDX-FileCopyrightText: Copyright Amazon.com, Inc. or its affiliates. All rights reserved. */

#include <infiniband/efadv.h>


#include "efa.h"
#include "efa_cqdirect.h"
#include "efa_cqdirect_structs.h"
#include "efa_cqdirect_efa_io_defs.h"
#include "efa_av.h"

#if CQ_INLINE_MODE == 1
#include "efa_cqdirect_entry.h"
#endif

#if CQ_INLINE_MODE == 0
#include "efa_cqdirect_entry.h"
#endif



int efa_cqdirect_qp_initialize( struct efa_qp *efa_qp) {
	/* Called during efa_base_ep_create_qp.
	 * See also rdma-core/providers/efa/verbs.c: efa_setup_qp
	 */
	struct efa_cqdirect_qp *direct_qp = &efa_qp->cqdirect_qp;

	struct efadv_wq_attr sq_attr;
	struct efadv_wq_attr rq_attr;

	memset(&efa_qp->cqdirect_qp, 0, sizeof(efa_qp->cqdirect_qp));
		
	efa_cqdirect_timer_init(&efa_qp->cqdirect_qp.send_timing);
	efa_cqdirect_timer_init(&efa_qp->cqdirect_qp.recv_timing);

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
	// TODO: in rdma-core, the wqe_cnt is set to rq_desc_cnt / qp->rq.wq.max_sge,
	// TODO: while the desc_mask is just rq_desc_cnt - 1.  In practice only the mask matters.
	rq_attr.num_entries = 32768; // TODO fix this hard-coded number!
	efa_cqdirect_wq_initialize(&direct_qp->rq.wq, rq_attr.num_entries);
	

	direct_qp->sq.desc = sq_attr.buffer;
	direct_qp->sq.wq.phase = 0;
	direct_qp->sq.wq.db = sq_attr.doorbell;
	direct_qp->sq.num_wqe_pending = 0;
	direct_qp->sq.max_batch_wr = 16; //TODO how do we get this number?
	direct_qp->sq.max_batch_wr = MIN(direct_qp->sq.max_batch_wr, EFA_CQDIRECT_TX_WQE_MAX_CACHE);
	direct_qp->sq.max_wr_rdma_sge = 1; // TODO how do we get this number?
	direct_qp->sq.wq.max_sge = 2; // TODO how do we get this number?
	direct_qp->sq.max_inline_data = 32; // TODO how do we get this number?

	direct_qp->sq.wq.wqe_size = sq_attr.entry_size;
	efa_cqdirect_wq_initialize(&direct_qp->sq.wq, sq_attr.num_entries);
	
	// TODO: max_batch!

	/* see efa_qp_init_indices */

	efa_qp->cqdirect_enabled = 1;
	return ret;
	
}

int efa_cqdirect_cq_initialize( struct efa_cq *efa_cq) {
	struct efadv_cq_attr attr = {0};
	int ret;

	
	memset(&efa_cq->cqdirect, 0, sizeof(efa_cq->cqdirect));
	efa_cq->cqdirect_enabled = 0;

	efa_cqdirect_timer_init(&efa_cq->cqdirect.timing);

	if (!efa_env.efa_direct_cq_ops) {
		/* nothing to do.  Not using directcq.*/

		return FI_SUCCESS;
	}

	// TODO: check for new enough hardware.

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