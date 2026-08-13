/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/* SPDX-FileCopyrightText: Copyright Amazon.com, Inc. or its affiliates. */

#if HAVE_CONFIG_H
#include <config.h>
#endif

#include "efa.h"
#include "efa_base_ep.h"
#include "efa_cq.h"
#include "efa_cntr.h"
#include "efa_av.h"
#include "efa_mr.h"
#include "efa_conn.h"
#include "efa_xpu.h"

#include <rdma/fi_xpu_device_efa.h>

/*
 * efadv.h is already pulled in by efa_base_ep.h -> infiniband/efadv.h.
 * No additional include needed here.
 */

/*
 * FI_CLASS values for exported XPU objects.
 * These are local definitions used to tag the fid_xpu.fclass field
 * so device-side dispatch can identify the object type.
 */
#define FI_CLASS_XPU_EP		0x58455000	/* 'XEP\0' */
#define FI_CLASS_XPU_CQ		0x58435100	/* 'XCQ\0' */
#define FI_CLASS_XPU_CNTR	0x58434E00	/* 'XCN\0' */
#define FI_CLASS_XPU_CTX	0x58435800	/* 'XCX\0' */

/* ----------------------------------------------------------------
 * Memory allocation / import helpers
 * ---------------------------------------------------------------- */

/**
 * xpu_alloc - allocate device memory via user-provided ops or HMEM.
 *
 * If the XPU attr has ops->alloc, use that (user-managed allocation).
 * Otherwise fall through to provider-side HMEM infrastructure (stub).
 */
static int xpu_alloc(struct efa_xpu_ctx *xctx, uint64_t size,
		     uint64_t alignment, uint64_t flags,
		     void **addr, int *fd, uint64_t *offset)
{
	struct fi_xpu_attr *attr = &xctx->attr;

	if (attr->ops && attr->ops->alloc)
		return attr->ops->alloc(attr->device, size, alignment,
					flags, addr, fd, offset);

	/* Provider-managed: use HMEM infrastructure (not yet wired) */
	return -FI_ENOSYS;
}

/**
 * xpu_import - map host address into device address space.
 */
static int xpu_import(struct efa_xpu_ctx *xctx, void *host_addr,
		      uint64_t size, uint64_t flags, void **dev_addr)
{
	struct fi_xpu_attr *attr = &xctx->attr;

	if (attr->ops && attr->ops->import)
		return attr->ops->import(attr->device, host_addr,
					 size, flags, dev_addr);

	/* No import callback — cannot proceed */
	return -FI_ENOSYS;
}

/**
 * xpu_free - free device memory via user-provided ops or HMEM.
 */
static void xpu_free(struct efa_xpu_ctx *xctx, void *addr)
{
	struct fi_xpu_attr *attr = &xctx->attr;

	if (attr->ops && attr->ops->free) {
		attr->ops->free(attr->device, addr);
		return;
	}

	/* Provider-managed: HMEM free path (not yet wired) */
}

/* ----------------------------------------------------------------
 * XPU Context (fid_xpu_ctx) management
 * ---------------------------------------------------------------- */

static int efa_xpu_ctx_query(struct fid_xpu_ctx *ctx,
			     struct fi_xpu_ctx_attr *attr)
{
	attr->caps = FI_XPU_CAP_EP | FI_XPU_CAP_CQ | FI_XPU_CAP_CNTR;
	attr->av_addr_size = sizeof(struct fi_xpu_efa_peer);
	attr->mr_desc_size = sizeof(struct fi_xpu_efa_desc);
	return 0;
}

static struct fi_ops_xpu_ctx efa_xpu_ctx_ops = {
	.size = sizeof(struct fi_ops_xpu_ctx),
	.query = efa_xpu_ctx_query,
};

static int efa_xpu_ctx_close(struct fid *fid)
{
	struct efa_xpu_ctx *ctx;

	ctx = container_of(fid, struct efa_xpu_ctx, ctx.fid);
	free(ctx);
	return 0;
}

static struct fi_ops efa_xpu_ctx_fi_ops = {
	.size = sizeof(struct fi_ops),
	.close = efa_xpu_ctx_close,
	.bind = fi_no_bind,
	.control = fi_no_control,
	.ops_open = fi_no_ops_open,
};

int efa_xpu_ctx_open(struct fid_domain *domain, struct fi_xpu_attr *attr,
		     struct fid_xpu_ctx **ctx_out, void *context)
{
	struct efa_xpu_ctx *ctx;

	if (!domain || !attr || !ctx_out)
		return -FI_EINVAL;

	ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
		return -FI_ENOMEM;

	ctx->ctx.fid.fclass = FI_CLASS_XPU_CTX;
	ctx->ctx.fid.context = context;
	ctx->ctx.fid.ops = &efa_xpu_ctx_fi_ops;
	ctx->ctx.ops = &efa_xpu_ctx_ops;
	ctx->attr = *attr;
	ctx->domain = domain;

	*ctx_out = &ctx->ctx;
	return 0;
}

/* ----------------------------------------------------------------
 * State lifecycle
 * ---------------------------------------------------------------- */

struct efa_xpu_ep_state *efa_xpu_ep_state_create(struct fid_xpu_ctx *ctx)
{
	struct efa_xpu_ep_state *state;

	state = calloc(1, sizeof(*state));
	if (!state)
		return NULL;

	state->xpu_ctx = ctx;
	return state;
}

struct efa_xpu_cq_state *efa_xpu_cq_state_create(struct fid_xpu_ctx *ctx)
{
	struct efa_xpu_cq_state *state;

	state = calloc(1, sizeof(*state));
	if (!state)
		return NULL;

	state->xpu_ctx = ctx;
	return state;
}

struct efa_xpu_cntr_state *efa_xpu_cntr_state_create(struct fid_xpu_ctx *ctx)
{
	struct efa_xpu_cntr_state *state;

	state = calloc(1, sizeof(*state));
	if (!state)
		return NULL;

	state->xpu_ctx = ctx;
	return state;
}

void efa_xpu_ep_state_destroy(struct efa_xpu_ep_state *state)
{
	struct efa_xpu_ctx *xctx;

	if (!state)
		return;

	xctx = container_of(state->xpu_ctx, struct efa_xpu_ctx, ctx);

	if (state->sq_buf_dev)
		xpu_free(xctx, state->sq_buf_dev);
	if (state->sq_db_dev)
		xpu_free(xctx, state->sq_db_dev);
	if (state->rq_buf_dev)
		xpu_free(xctx, state->rq_buf_dev);
	if (state->rq_db_dev)
		xpu_free(xctx, state->rq_db_dev);

	free(state);
}

void efa_xpu_cq_state_destroy(struct efa_xpu_cq_state *state)
{
	struct efa_xpu_ctx *xctx;

	if (!state)
		return;

	xctx = container_of(state->xpu_ctx, struct efa_xpu_ctx, ctx);

	if (state->cq_buf_dev)
		xpu_free(xctx, state->cq_buf_dev);

	free(state);
}

void efa_xpu_cntr_state_destroy(struct efa_xpu_cntr_state *state)
{
	struct efa_xpu_ctx *xctx;

	if (!state)
		return;

	xctx = container_of(state->xpu_ctx, struct efa_xpu_ctx, ctx);

	if (state->cntr_alloc_addr)
		xpu_free(xctx, state->cntr_alloc_addr);
	if (state->cntr_err_alloc_addr)
		xpu_free(xctx, state->cntr_err_alloc_addr);

	free(state);
}

/* ----------------------------------------------------------------
 * EP export
 * ---------------------------------------------------------------- */

int efa_ep_export_xpu(struct fid_ep *ep, uint64_t flags,
		      struct fid_xpu_ep **xpu_ep, size_t *size)
{
	struct efa_base_ep *base_ep;
	struct efa_xpu_ctx *xctx;
	struct fi_xpu_efa_ep *dev_ep;
	struct fid_xpu_ctx *fid_ctx;
	void *dev_buf = NULL;
	int ret;
	int dmabuf_fd = -1;
	uint64_t dmabuf_offset = 0;

	if (!ep || !xpu_ep || !size)
		return -FI_EINVAL;

	base_ep = container_of(ep, struct efa_base_ep, util_ep.ep_fid);

	/*
	 * The XPU context should have been associated with the EP's domain.
	 * Retrieve it from the domain's info or via the ep's bind path.
	 * For now we expect the caller to pass the xpu_ctx via the
	 * ep_fid.fid.context (set during bind), or we look it up from
	 * the domain fid.
	 */
	fid_ctx = (struct fid_xpu_ctx *)ep->fid.context;
	if (!fid_ctx)
		return -FI_EINVAL;

	xctx = container_of(fid_ctx, struct efa_xpu_ctx, ctx);

	/* Allocate the device-side EP struct on the XPU */
	ret = xpu_alloc(xctx, sizeof(struct fi_xpu_efa_ep),
			64, /* alignment */
			(flags & FI_XPU_ALLOC_DMABUF) ? FI_XPU_ALLOC_DMABUF : 0,
			&dev_buf, &dmabuf_fd, &dmabuf_offset);
	if (ret)
		return ret;

	/* Build the host-side copy and transfer to device */
	dev_ep = (struct fi_xpu_efa_ep *)dev_buf;

	/* Populate the XPU header */
	dev_ep->fid.fid.fclass = FI_CLASS_XPU_EP;
	dev_ep->fid.fid.prov_id = FI_XPU_PROV_EFA;

	/* Populate EP-specific fields from hardware state */
	if (base_ep->qp) {
		dev_ep->qp_num = base_ep->qp->qp_num;
		dev_ep->qkey = base_ep->qp->qkey;
	}

	/*
	 * Map SQ/RQ ring buffers into device memory if import is available.
	 * The actual BAR addresses depend on hardware specifics; for now
	 * we set placeholders that the import callback will resolve.
	 */
	if (base_ep->qp && base_ep->qp->ibv_qp) {
		void *sq_db_addr = NULL;
		void *rq_db_addr = NULL;

		/*
		 * Import doorbell addresses into device-accessible memory.
		 * These are MMIO addresses, so use FI_XPU_IMPORT_IOMEMORY.
		 */
		ret = xpu_import(xctx, (void *)(uintptr_t)base_ep->qp->ibv_qp,
				 sizeof(uint32_t), FI_XPU_IMPORT_IOMEMORY,
				 &sq_db_addr);
		if (ret == 0)
			dev_ep->sq_db = sq_db_addr;

		ret = xpu_import(xctx, (void *)(uintptr_t)base_ep->qp->ibv_qp,
				 sizeof(uint32_t), FI_XPU_IMPORT_IOMEMORY,
				 &rq_db_addr);
		if (ret == 0)
			dev_ep->rq_db = rq_db_addr;
	}

	*xpu_ep = &dev_ep->fid;
	*size = sizeof(struct fi_xpu_efa_ep);

	return 0;
}

/* ----------------------------------------------------------------
 * CQ export
 * ---------------------------------------------------------------- */

int efa_cq_export_xpu(struct fid_cq *cq, uint64_t flags,
		      struct fid_xpu_cq **xpu_cq, size_t *size)
{
	struct efa_cq *efa_cq;
	struct efa_xpu_ctx *xctx;
	struct fi_xpu_efa_cq *dev_cq;
	struct fid_xpu_ctx *fid_ctx;
	void *dev_buf = NULL;
	int ret;
	int dmabuf_fd = -1;
	uint64_t dmabuf_offset = 0;

	if (!cq || !xpu_cq || !size)
		return -FI_EINVAL;

	efa_cq = container_of(cq, struct efa_cq, util_cq.cq_fid);

	fid_ctx = (struct fid_xpu_ctx *)cq->fid.context;
	if (!fid_ctx)
		return -FI_EINVAL;

	xctx = container_of(fid_ctx, struct efa_xpu_ctx, ctx);

	/* Allocate device-side CQ struct */
	ret = xpu_alloc(xctx, sizeof(struct fi_xpu_efa_cq),
			64, /* alignment */
			(flags & FI_XPU_ALLOC_DMABUF) ? FI_XPU_ALLOC_DMABUF : 0,
			&dev_buf, &dmabuf_fd, &dmabuf_offset);
	if (ret)
		return ret;

	dev_cq = (struct fi_xpu_efa_cq *)dev_buf;

	/* Populate the XPU header */
	dev_cq->fid.fid.fclass = FI_CLASS_XPU_CQ;
	dev_cq->fid.fid.prov_id = FI_XPU_PROV_EFA;

	/* Populate CQ-specific fields */
	dev_cq->cq_size = efa_cq->ibv_cq.ibv_cq_ex ?
		ibv_cq_ex_to_cq(efa_cq->ibv_cq.ibv_cq_ex)->cqe : 0;
	dev_cq->entry_size = efa_cq->entry_size;

	/*
	 * Map the CQ buffer into device memory if possible.
	 * The actual CQ ring buffer mapping depends on the ibv_cq
	 * internal layout. Import with DEVICEMAP so the XPU kernel
	 * can poll the CQ directly.
	 */
	if (efa_cq->ibv_cq.ibv_cq_ex) {
		void *cq_dev_addr = NULL;

		ret = xpu_import(xctx, efa_cq->ibv_cq.ibv_cq_ex,
				 efa_cq->entry_size *
				 ibv_cq_ex_to_cq(efa_cq->ibv_cq.ibv_cq_ex)->cqe,
				 FI_XPU_IMPORT_DEVICEMAP, &cq_dev_addr);
		if (ret == 0)
			dev_cq->cq_buf = cq_dev_addr;
	}

	*xpu_cq = &dev_cq->fid;
	*size = sizeof(struct fi_xpu_efa_cq);

	return 0;
}

/* ----------------------------------------------------------------
 * Counter export
 * ---------------------------------------------------------------- */

int efa_cntr_export_xpu(struct fid_cntr *cntr, uint64_t flags,
			struct fid_xpu_cntr **xpu_cntr, size_t *size)
{
	struct efa_cntr *efa_cntr;
	struct efa_xpu_ctx *xctx;
	struct fi_xpu_efa_cntr *dev_cntr;
	struct fid_xpu_ctx *fid_ctx;
	void *dev_buf = NULL;
	int ret;
	int dmabuf_fd = -1;
	uint64_t dmabuf_offset = 0;

	if (!cntr || !xpu_cntr || !size)
		return -FI_EINVAL;

	efa_cntr = container_of(cntr, struct efa_cntr,
				util_cntr.cntr_fid);

	fid_ctx = (struct fid_xpu_ctx *)cntr->fid.context;
	if (!fid_ctx)
		return -FI_EINVAL;

	xctx = container_of(fid_ctx, struct efa_xpu_ctx, ctx);

	/* Allocate device-side counter struct */
	ret = xpu_alloc(xctx, sizeof(struct fi_xpu_efa_cntr),
			64, /* alignment */
			(flags & FI_XPU_ALLOC_DMABUF) ? FI_XPU_ALLOC_DMABUF : 0,
			&dev_buf, &dmabuf_fd, &dmabuf_offset);
	if (ret)
		return ret;

	dev_cntr = (struct fi_xpu_efa_cntr *)dev_buf;

	/* Populate the XPU header */
	dev_cntr->fid.fid.fclass = FI_CLASS_XPU_CNTR;
	dev_cntr->fid.fid.prov_id = FI_XPU_PROV_EFA;

	/*
	 * Map the hardware completion counter into device memory.
	 * If the counter was created with device memory backing
	 * (comp_use_device_mem), the memory is already device-resident
	 * and we just record the pointer. Otherwise, import the
	 * host-side counter memory into the device address space.
	 */
	if (efa_cntr->ibv_comp_cntr) {
		void *cntr_dev_addr = NULL;
		void *err_dev_addr = NULL;

		if (efa_cntr->comp_use_device_mem) {
			/*
			 * Counter memory already on device; ibv_comp_cntr
			 * holds the device pointer directly.
			 */
			dev_cntr->value_addr = (volatile uint64_t *)
				efa_cntr->ibv_comp_cntr;
		} else {
			ret = xpu_import(xctx, efa_cntr->ibv_comp_cntr,
					 sizeof(uint64_t),
					 FI_XPU_IMPORT_DEVICEMAP,
					 &cntr_dev_addr);
			if (ret == 0)
				dev_cntr->value_addr =
					(volatile uint64_t *)cntr_dev_addr;
		}

		/* Error counter mapping */
		if (efa_cntr->err_use_device_mem) {
			dev_cntr->err_addr = (volatile uint64_t *)
				((char *)efa_cntr->ibv_comp_cntr +
				 sizeof(uint64_t));
		} else {
			ret = xpu_import(xctx,
					 (char *)efa_cntr->ibv_comp_cntr +
					 sizeof(uint64_t),
					 sizeof(uint64_t),
					 FI_XPU_IMPORT_DEVICEMAP,
					 &err_dev_addr);
			if (ret == 0)
				dev_cntr->err_addr =
					(volatile uint64_t *)err_dev_addr;
		}
	}

	*xpu_cntr = &dev_cntr->fid;
	*size = sizeof(struct fi_xpu_efa_cntr);

	return 0;
}

/* ----------------------------------------------------------------
 * AV lookup (single-entry)
 * ---------------------------------------------------------------- */

int efa_av_lookup2(struct fid_av *av, fi_addr_t fi_addr,
		   void *buf, size_t *len, uint64_t flags,
		   struct fid_xpu_ctx *ctx)
{
	struct efa_av *efa_av;
	struct efa_av_entry *av_entry;
	struct fi_xpu_efa_peer *peer;
	struct efa_conn *conn;

	if (!av || !buf || !len)
		return -FI_EINVAL;

	if (*len < sizeof(struct fi_xpu_efa_peer))
		return -FI_ETOOSMALL;

	efa_av = container_of(av, struct efa_av, util_av.av_fid);

	/* Resolve fi_addr to the AV entry */
	av_entry = (struct efa_av_entry *)
		ofi_av_get_addr(&efa_av->util_av, fi_addr);
	if (!av_entry)
		return -FI_EINVAL;

	conn = &av_entry->conn;
	if (!conn->ah)
		return -FI_ENODATA;

	peer = (struct fi_xpu_efa_peer *)buf;
	memset(peer, 0, sizeof(*peer));

	/* Copy the raw GID from the EFA endpoint address */
	memcpy(peer->gid, av_entry->ep_addr, EFA_GID_LEN);
	peer->qpn = conn->ep_addr ? conn->ep_addr->qpn : 0;
	peer->qkey = conn->ep_addr ? conn->ep_addr->qkey : 0;

	/* AH number from the address handle */
	peer->ahn = conn->ah->ahn;

	*len = sizeof(struct fi_xpu_efa_peer);
	return 0;
}

/* ----------------------------------------------------------------
 * MR descriptor export (single-entry)
 * ---------------------------------------------------------------- */

int efa_mr_get_desc(struct fid_mr *mr, void *buf, size_t *len,
		    uint64_t flags, struct fid_xpu_ctx *ctx)
{
	struct efa_mr *efa_mr;
	struct fi_xpu_efa_desc *desc;

	if (!mr || !buf || !len)
		return -FI_EINVAL;

	if (*len < sizeof(struct fi_xpu_efa_desc))
		return -FI_ETOOSMALL;

	efa_mr = container_of(mr, struct efa_mr, mr_fid);

	desc = (struct fi_xpu_efa_desc *)buf;
	memset(desc, 0, sizeof(*desc));

	desc->lkey = efa_mr->lkey;

	*len = sizeof(struct fi_xpu_efa_desc);
	return 0;
}
