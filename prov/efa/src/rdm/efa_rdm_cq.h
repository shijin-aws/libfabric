/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/* SPDX-FileCopyrightText: Copyright Amazon.com, Inc. or its affiliates. All rights reserved. */

#ifndef EFA_RDM_CQ_H
#define EFA_RDM_CQ_H

#include "efa_cq.h"
#include <ofi_util.h>

struct efa_rdm_cq {
	struct util_cq util_cq;
	struct fid_cq *shm_cq;
	struct ibv_cq_ex *ibv_cq_ex;
	enum ibv_cq_ex_type ibv_cq_ex_type;
	struct dlist_entry  poll_list;
	struct ofi_genlock	poll_list_lock;
};

/*
 * Control header with completion data. CQ data length is static.
 */
#define EFA_RDM_CQ_DATA_SIZE (4)

int efa_rdm_cq_open(struct fid_domain *domain, struct fi_cq_attr *attr,
		    struct fid_cq **cq_fid, void *context);

struct efa_rdm_cq_poll_list_entry {
	struct dlist_entry	entry;
	struct efa_rdm_cq	*cq;
};

int efa_rdm_cq_poll_list_insert(struct dlist_entry *poll_list, struct ofi_genlock *lock, struct efa_rdm_cq *cq);
void efa_rdm_cq_poll_list_remove(struct dlist_entry *poll_list, struct ofi_genlock *lock,
		      struct efa_rdm_cq *cq);

void efa_rdm_cq_poll_ibv_cq(ssize_t cqe_to_process, struct efa_rdm_cq *efa_rdm_cq);
#endif