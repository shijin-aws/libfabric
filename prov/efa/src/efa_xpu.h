/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/* SPDX-FileCopyrightText: Copyright Amazon.com, Inc. or its affiliates. */

#ifndef EFA_XPU_H
#define EFA_XPU_H

#include <rdma/fi_xpu.h>

/* Per-EP XPU state */
struct efa_xpu_ep_state {
	struct fid_xpu_ctx *xpu_ctx;
	void *sq_buf_dev;
	void *sq_db_dev;
	void *rq_buf_dev;
	void *rq_db_dev;
};

/* Per-CQ XPU state */
struct efa_xpu_cq_state {
	struct fid_xpu_ctx *xpu_ctx;
	void *cq_buf_dev;
};

/* Per-counter XPU state */
struct efa_xpu_cntr_state {
	struct fid_xpu_ctx *xpu_ctx;
	void *cntr_value_dev;
	void *cntr_err_dev;
	void *cntr_alloc_addr;
	void *cntr_err_alloc_addr;
};

/* XPU context provider-private data (stored in fid_xpu_ctx) */
struct efa_xpu_ctx {
	struct fid_xpu_ctx ctx;        /* must be first */
	struct fi_xpu_attr attr;       /* copy of user's attr */
	struct fid_domain *domain;
};

/* Export implementations */
int efa_ep_export_xpu(struct fid_ep *ep, uint64_t flags,
                      struct fid_xpu_ep **xpu_ep, size_t *size);
int efa_cq_export_xpu(struct fid_cq *cq, uint64_t flags,
                      struct fid_xpu_cq **xpu_cq, size_t *size);
int efa_cntr_export_xpu(struct fid_cntr *cntr, uint64_t flags,
                        struct fid_xpu_cntr **xpu_cntr, size_t *size);

/* AV and MR ops */
int efa_av_lookup2(struct fid_av *av, fi_addr_t fi_addr,
                   void *buf, size_t *len, uint64_t flags,
                   struct fid_xpu_ctx *ctx);
int efa_mr_get_desc(struct fid_mr *mr, void *buf, size_t *len,
                    uint64_t flags, struct fid_xpu_ctx *ctx);

/* Domain op: create XPU context */
int efa_xpu_ctx_open(struct fid_domain *domain, struct fi_xpu_attr *attr,
                     struct fid_xpu_ctx **ctx, void *context);

/* State lifecycle */
struct efa_xpu_ep_state *efa_xpu_ep_state_create(struct fid_xpu_ctx *ctx);
struct efa_xpu_cq_state *efa_xpu_cq_state_create(struct fid_xpu_ctx *ctx);
struct efa_xpu_cntr_state *efa_xpu_cntr_state_create(struct fid_xpu_ctx *ctx);
void efa_xpu_ep_state_destroy(struct efa_xpu_ep_state *state);
void efa_xpu_cq_state_destroy(struct efa_xpu_cq_state *state);
void efa_xpu_cntr_state_destroy(struct efa_xpu_cntr_state *state);

#endif /* EFA_XPU_H */
