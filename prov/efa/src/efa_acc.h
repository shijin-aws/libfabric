/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/* SPDX-FileCopyrightText: Copyright Amazon.com, Inc. or its affiliates. All
 * rights reserved. */

#ifndef EFA_ACC_H
#define EFA_ACC_H

#include <rdma/fi_acc.h>

struct efa_acc_state {
	struct fi_acc_info acc_info;
};

struct efa_acc_ep_state {
	struct efa_acc_state base;
	void *sq_buf_dev;
	void *sq_db_dev;
	void *rq_buf_dev;
	void *rq_db_dev;
};

struct efa_acc_cq_state {
	struct efa_acc_state base;
	void *cq_buf_dev;
};

struct efa_acc_cntr_state {
	struct efa_acc_state base;
	void *cntr_value_dev;       /* completion counter in GPU HBM */
	void *cntr_err_dev;         /* error counter in GPU HBM */
	void *cntr_alloc_addr;      /* base alloc for cleanup (comp) */
	void *cntr_err_alloc_addr;  /* base alloc for cleanup (err) */
};

/* Opaque export implementations */
int efa_acc_ep_export(struct fid_ep *ep, uint64_t flags,
		      void **acc_ep, size_t *size);
int efa_acc_cq_export(struct fid_cq *cq, uint64_t flags,
		      void **acc_cq, size_t *size);
int efa_acc_cntr_export(struct fid_cntr *cntr, uint64_t flags,
			void **acc_cntr, size_t *size);
int efa_acc_mr_export(struct fid_mr **mrs, size_t count, uint64_t flags,
		      void **acc_descs, size_t *size);
int efa_acc_av_export(struct fid_av *av, const fi_addr_t *fi_addrs,
		      size_t count, uint64_t flags,
		      void **acc_peers, size_t *size);
int efa_acc_mr_get_info(struct fid_mr *mr, uint64_t flags,
			uint32_t *lkey, uint64_t *addr, uint64_t *rkey);

/* State lifecycle */
struct efa_acc_ep_state *efa_acc_ep_state_create(const struct fi_acc_info *acc_info);
struct efa_acc_cq_state *efa_acc_cq_state_create(const struct fi_acc_info *acc_info);
struct efa_acc_cntr_state *efa_acc_cntr_state_create(const struct fi_acc_info *acc_info);
void efa_acc_ep_state_destroy(struct efa_acc_ep_state *acc);
void efa_acc_cq_state_destroy(struct efa_acc_cq_state *acc);
void efa_acc_cntr_state_destroy(struct efa_acc_cntr_state *acc);

#endif /* EFA_ACC_H */
