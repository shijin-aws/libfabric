/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/* SPDX-FileCopyrightText: Copyright Amazon.com, Inc. or its affiliates. All
 * rights reserved. */

/*
 * EFA provider: OFI Accelerator API implementation (opaque export model).
 *
 * fi_acc_ep_export():  builds GPU-resident fi_acc_dev_ep and returns void*
 * fi_acc_cq_export():  builds GPU-resident fi_acc_dev_cq and returns void*
 * fi_acc_cntr_export(): returns GPU-resident fi_acc_dev_cntr as void*
 * fi_acc_mr_export():  builds GPU-resident fi_acc_dev_desc and returns void*
 * fi_acc_av_export():  builds GPU-resident fi_acc_dev_peer and returns void*
 *
 * The consumer never sees the struct internals — only fi_acc_device.h's
 * inline device functions dereference them.
 */

#include "config.h"

#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "efa.h"
#include "efa_acc.h"
#include "efa_base_ep.h"
#include "efa_cq.h"
#include "efa_cntr.h"
#include "efa_av.h"
#include "efa_mr.h"
#include "efa_conn.h"
#include "fi_ext_efa.h"

/* Include EFA device struct definitions for building opaque blobs.
 * This is the same header consumers include from their .cu files. */
#include "acc_cuda/fi_ext_efa_acc.cuh"

#if HAVE_EFADV_QUERY_QP_WQS
#include <infiniband/efadv.h>
#endif

/*
 * Helper: allocate GPU memory and H2D copy a host struct.
 * Uses acc_info callbacks — the consumer's GPU allocator.
 */
static int acc_gpu_alloc_and_copy(struct fi_acc_info *ai, const void *host_data,
				  size_t size, void **dev_ptr)
{
	void *gpu_mem = NULL;
	int fd = -1;
	uint64_t offset = 0;
	int ret;

	/* Use alloc callback to get GPU memory */
	ret = ai->user.alloc(ai->device, (uint64_t)size, 0,
			     FI_ACC_ALLOC_GPU_HBM, &gpu_mem, &fd, &offset);
	if (ret)
		return ret;

	/*
	 * We need H2D memcpy. The acc_info doesn't have a memcpy callback,
	 * so we rely on the GPU memory being host-accessible for write
	 * (VMM allocations are typically mapped with RW access).
	 * In production, this would use cudaMemcpy or the HMEM subsystem.
	 *
	 * For now, store the host struct into GPU memory via the provider's
	 * HMEM copy infrastructure.
	 */
	memcpy(gpu_mem, host_data, size);  /* Works if GPU mem is host-mapped */

	if (fd >= 0)
		close(fd);  /* Don't need DMA-BUF fd for plain alloc */

	*dev_ptr = gpu_mem;
	return 0;
}

/*
 * =============================================================================
 * fi_acc_ep_export — Build opaque GPU-resident EP descriptor
 * =============================================================================
 */
int efa_acc_ep_export(struct fid_ep *ep_fid, uint64_t flags,
		      void **acc_ep, size_t *size)
{
#if HAVE_EFADV_QUERY_QP_WQS
	struct efa_base_ep *base_ep;
	struct efa_acc_state *acc;
	struct fi_acc_info *ai;
	struct efadv_wq_attr qp_sq_attr = {};
	struct efadv_wq_attr qp_rq_attr = {};
	struct fi_acc_efa_ep h_ep = {};
	long page_size;
	int ret;

	if (!ep_fid || !acc_ep || !size)
		return -FI_EINVAL;

	base_ep = container_of(ep_fid, struct efa_base_ep, util_ep.ep_fid);
	acc = base_ep->acc_state;
	if (!acc)
		return -FI_ENODATA;

	ai = &acc->acc_info;

	/* Query HW queue geometry */
	ret = efadv_query_qp_wqs(base_ep->qp->ibv_qp,
				 &qp_sq_attr, &qp_rq_attr,
				 sizeof(qp_sq_attr));
	if (ret)
		return (ret == EOPNOTSUPP) ? -FI_EOPNOTSUPP : -FI_EINVAL;

	page_size = sysconf(_SC_PAGESIZE);

	/* Map SQ buffer (BAR MMIO) → GPU */
	void *sq_buf_dev = qp_sq_attr.buffer;
	ret = ai->user.import(ai->device, -1, 0,
			      (uint64_t)qp_sq_attr.num_entries * qp_sq_attr.entry_size,
			      FI_ACC_IMPORT_IOMEMORY | FI_ACC_IMPORT_DEVICEMAP,
			      &sq_buf_dev);
	if (ret) return ret;

	/* Map SQ doorbell (BAR MMIO) → GPU */
	void *sq_db_dev = qp_sq_attr.doorbell;
	ret = ai->user.import(ai->device, -1, 0, (uint64_t)page_size,
			      FI_ACC_IMPORT_IOMEMORY | FI_ACC_IMPORT_DEVICEMAP,
			      &sq_db_dev);
	if (ret) return ret;

	/* Map RQ buffer (host RAM) → GPU */
	void *rq_buf_dev = NULL;
	void *rq_db_dev = NULL;
	if (qp_rq_attr.buffer) {
		rq_buf_dev = qp_rq_attr.buffer;
		ret = ai->user.import(ai->device, -1, 0,
				      (uint64_t)qp_rq_attr.num_entries * qp_rq_attr.entry_size,
				      FI_ACC_IMPORT_DEVICEMAP, &rq_buf_dev);
		if (ret) return ret;

		rq_db_dev = qp_rq_attr.doorbell;
		ret = ai->user.import(ai->device, -1, 0, (uint64_t)page_size,
				      FI_ACC_IMPORT_IOMEMORY | FI_ACC_IMPORT_DEVICEMAP,
				      &rq_db_dev);
		if (ret) return ret;
	}

	/* Build fi_acc_dev_ep on host stack */
	h_ep.sq.buf             = (uint8_t *)sq_buf_dev;
	h_ep.sq.db              = (uint32_t *)sq_db_dev;
	h_ep.sq.queue_mask      = qp_sq_attr.num_entries - 1;
	h_ep.sq.queue_size_shift = __builtin_ctz(qp_sq_attr.num_entries);
	h_ep.sq.max_batch       = qp_sq_attr.max_batch;
	h_ep.sq.entry_size      = qp_sq_attr.entry_size;
	h_ep.sq.pc              = 0;
	h_ep.sq.phase           = 0;
	h_ep.sq.wqes_pending    = 0;

	if (qp_rq_attr.buffer) {
		h_ep.rq.buf             = (uint8_t *)rq_buf_dev;
		h_ep.rq.db              = (uint32_t *)rq_db_dev;
		h_ep.rq.queue_mask      = qp_rq_attr.num_entries - 1;
		h_ep.rq.queue_size_shift = __builtin_ctz(qp_rq_attr.num_entries);
		h_ep.rq.max_batch       = qp_rq_attr.max_batch;
		h_ep.rq.entry_size      = qp_rq_attr.entry_size;
		h_ep.rq.pc              = 0;
		h_ep.rq.phase           = 0;
		h_ep.rq.wqes_pending    = 0;
	}

	h_ep.sq_lock          = 0;
	h_ep.submitted_count  = 0;
	h_ep.sq_size          = qp_sq_attr.num_entries;
	h_ep.local_cntr       = NULL; /* Set after counter bind/export */

	/* If a write counter was bound and exported, link it */
	if (acc->cntr_value_dev)
		h_ep.local_cntr = (volatile uint64_t *)acc->cntr_value_dev;

	/* Allocate GPU memory and H2D copy */
	ret = acc_gpu_alloc_and_copy(ai, &h_ep, sizeof(h_ep), acc_ep);
	if (ret) return ret;

	*size = sizeof(struct fi_acc_efa_ep);
	return FI_SUCCESS;
#else
	return -FI_EOPNOTSUPP;
#endif
}

/*
 * =============================================================================
 * fi_acc_cq_export — Build opaque GPU-resident CQ descriptor
 * =============================================================================
 */
int efa_acc_cq_export(struct fid_cq *cq_fid, uint64_t flags,
		      void **acc_cq, size_t *size)
{
#if HAVE_EFADV_QUERY_CQ
	struct efa_cq *efa_cq;
	struct efa_acc_state *acc;
	struct fi_acc_info *ai;
	struct efadv_cq_attr efadv_attr = {};
	struct fi_acc_efa_cq h_cq = {};
	int ret;

	if (!cq_fid || !acc_cq || !size)
		return -FI_EINVAL;

	efa_cq = container_of(cq_fid, struct efa_cq, util_cq.cq_fid);
	acc = efa_cq->acc_state;
	if (!acc)
		return -FI_ENODATA;

	ai = &acc->acc_info;

	ret = efadv_query_cq(ibv_cq_ex_to_cq(efa_cq->ibv_cq.ibv_cq_ex),
			     &efadv_attr, sizeof(efadv_attr));
	if (ret)
		return (ret == EOPNOTSUPP) ? -FI_EOPNOTSUPP : -FI_EINVAL;

	/* Map CQ buffer (host RAM) → GPU.
	 * On P5en, host pointer is directly CUDA-readable; import may be no-op. */
	void *cq_buf_dev = efadv_attr.buffer;
	ret = ai->user.import(ai->device, -1, 0,
			      (uint64_t)efadv_attr.num_entries * efadv_attr.entry_size,
			      FI_ACC_IMPORT_DEVICEMAP, &cq_buf_dev);
	if (ret) return ret;

	h_cq.buf              = (uint8_t *)cq_buf_dev;
	h_cq.entry_size       = efadv_attr.entry_size;
	h_cq.queue_mask       = efadv_attr.num_entries - 1;
	h_cq.queue_size_shift = __builtin_ctz(efadv_attr.num_entries);
	h_cq.cc               = 0;
	h_cq.phase            = 1;

	ret = acc_gpu_alloc_and_copy(ai, &h_cq, sizeof(h_cq), acc_cq);
	if (ret) return ret;

	*size = sizeof(struct fi_acc_efa_cq);
	return FI_SUCCESS;
#else
	return -FI_EOPNOTSUPP;
#endif
}

/*
 * =============================================================================
 * fi_acc_cntr_export — Return opaque GPU-resident counter handle
 * =============================================================================
 */
int efa_acc_cntr_export(struct fid_cntr *cntr_fid, uint64_t flags,
			void **acc_cntr, size_t *size)
{
	struct efa_cntr *efa_cntr;
	struct efa_acc_state *acc;
	struct fi_acc_info *ai;
	struct fi_acc_efa_cntr h_cntr = {};
	int ret;

	if (!cntr_fid || !acc_cntr || !size)
		return -FI_EINVAL;

	efa_cntr = container_of(cntr_fid, struct efa_cntr, util_cntr.cntr_fid);
	acc = efa_cntr->acc_state;
	if (!acc || !acc->cntr_value_dev)
		return -FI_ENODATA;

	ai = &acc->acc_info;
	h_cntr.value = (volatile uint64_t *)acc->cntr_value_dev;

	ret = acc_gpu_alloc_and_copy(ai, &h_cntr, sizeof(h_cntr), acc_cntr);
	if (ret) return ret;

	*size = sizeof(struct fi_acc_efa_cntr);
	return FI_SUCCESS;
}

/*
 * =============================================================================
 * fi_acc_mr_export — Return opaque GPU-resident MR descriptor
 * =============================================================================
 */
int efa_acc_mr_export(struct fid_mr *mr_fid, uint64_t flags,
		      void **acc_desc, size_t *size)
{
	struct efa_mr *efa_mr;
	struct fi_acc_efa_desc h_desc = {};
	struct efa_base_ep *base_ep;
	struct efa_acc_state *acc;
	struct fi_acc_info *ai;
	int ret;

	if (!mr_fid || !acc_desc || !size)
		return -FI_EINVAL;

	efa_mr = container_of(mr_fid, struct efa_mr, mr_fid);
	if (!efa_mr->ibv_mr)
		return -FI_ENODATA;

	h_desc.lkey = efa_mr->ibv_mr->lkey;

	/* Need acc_info to allocate GPU memory for the desc.
	 * Get it from the MR's domain's first EP with acc_state. */
	base_ep = container_of(
		efa_mr->domain->base_ep_list.next,
		struct efa_base_ep, base_ep_entry);
	acc = base_ep ? base_ep->acc_state : NULL;
	if (!acc)
		return -FI_ENODATA;
	ai = &acc->acc_info;

	ret = acc_gpu_alloc_and_copy(ai, &h_desc, sizeof(h_desc), acc_desc);
	if (ret) return ret;

	*size = sizeof(struct fi_acc_efa_desc);
	return FI_SUCCESS;
}

/*
 * =============================================================================
 * fi_acc_av_export — Return opaque GPU-resident peer address handle
 * =============================================================================
 */
int efa_acc_av_export(struct fid_av *av_fid, fi_addr_t fi_addr,
		      uint64_t flags, void **acc_peer, size_t *size)
{
	struct efa_av *efa_av;
	struct efa_conn *conn;
	struct fi_acc_efa_peer h_peer = {};
	struct efa_acc_state *acc;
	struct fi_acc_info *ai;
	int ret;

	if (!av_fid || !acc_peer || !size)
		return -FI_EINVAL;

	efa_av = container_of(av_fid, struct efa_av, util_av.av_fid);
	conn = efa_av_addr_to_conn(efa_av, fi_addr);
	if (!conn || !conn->ah || !conn->ep_addr)
		return -FI_ENODATA;

	h_peer.ahn         = conn->ah->ahn;
	h_peer.remote_qpn  = conn->ep_addr->qpn;
	h_peer.remote_qkey = conn->ep_addr->qkey;

	/* Get acc_info from domain's first EP */
	acc = NULL;
	if (efa_av->domain && !dlist_empty(&efa_av->domain->base_ep_list)) {
		struct efa_base_ep *ep = container_of(
			efa_av->domain->base_ep_list.next,
			struct efa_base_ep, base_ep_entry);
		acc = ep->acc_state;
	}
	if (!acc)
		return -FI_ENODATA;
	ai = &acc->acc_info;

	ret = acc_gpu_alloc_and_copy(ai, &h_peer, sizeof(h_peer), acc_peer);
	if (ret) return ret;

	*size = sizeof(struct fi_acc_efa_peer);
	return FI_SUCCESS;
}

/*
 * =============================================================================
 * fi_acc_av_export_batch — Bulk peer export (target addressing table)
 * =============================================================================
 */
int efa_acc_av_export_batch(struct fid_av *av_fid, const fi_addr_t *fi_addrs,
			    size_t count, uint64_t flags,
			    void **acc_peers, size_t *size)
{
	struct efa_av *efa_av;
	struct fi_acc_efa_peer *h_peers;
	struct efa_acc_state *acc;
	struct fi_acc_info *ai;
	size_t i;
	int ret;

	if (!av_fid || !fi_addrs || !acc_peers || !size || count == 0)
		return -FI_EINVAL;

	efa_av = container_of(av_fid, struct efa_av, util_av.av_fid);

	/* Get acc_info */
	acc = NULL;
	if (efa_av->domain && !dlist_empty(&efa_av->domain->base_ep_list)) {
		struct efa_base_ep *ep = container_of(
			efa_av->domain->base_ep_list.next,
			struct efa_base_ep, base_ep_entry);
		acc = ep->acc_state;
	}
	if (!acc)
		return -FI_ENODATA;
	ai = &acc->acc_info;

	/* Build host array */
	h_peers = calloc(count, sizeof(*h_peers));
	if (!h_peers)
		return -FI_ENOMEM;

	for (i = 0; i < count; i++) {
		struct efa_conn *conn;
		if (fi_addrs[i] == FI_ADDR_UNSPEC)
			continue;
		conn = efa_av_addr_to_conn(efa_av, fi_addrs[i]);
		if (!conn || !conn->ah || !conn->ep_addr)
			continue;
		h_peers[i].ahn         = conn->ah->ahn;
		h_peers[i].remote_qpn  = conn->ep_addr->qpn;
		h_peers[i].remote_qkey = conn->ep_addr->qkey;
	}

	/* Alloc GPU and copy */
	ret = acc_gpu_alloc_and_copy(ai, h_peers,
				     count * sizeof(*h_peers), acc_peers);
	free(h_peers);
	if (ret) return ret;

	*size = count * sizeof(struct fi_acc_efa_peer);
	return FI_SUCCESS;
}

/*
 * =============================================================================
 * fi_acc_mr_get_info — Export MR info for key exchange
 * =============================================================================
 */
int efa_acc_mr_get_info(struct fid_mr *mr_fid, uint64_t flags,
			uint32_t *lkey, uint64_t *addr, uint64_t *rkey)
{
	struct efa_mr *efa_mr;

	if (!mr_fid)
		return -FI_EINVAL;

	efa_mr = container_of(mr_fid, struct efa_mr, mr_fid);
	if (!efa_mr->ibv_mr)
		return -FI_ENODATA;

	if (lkey) *lkey = efa_mr->ibv_mr->lkey;
	if (addr) *addr = (uint64_t)(uintptr_t)efa_mr->ibv_mr->addr;
	if (rkey) *rkey = (uint64_t)fi_mr_key(&efa_mr->mr_fid);

	return FI_SUCCESS;
}

/*
 * =============================================================================
 * State lifecycle
 * =============================================================================
 */
struct efa_acc_state *efa_acc_state_create(const struct fi_acc_info *acc_info)
{
	struct efa_acc_state *acc;
	if (!acc_info) return NULL;
	acc = calloc(1, sizeof(*acc));
	if (!acc) return NULL;
	acc->acc_info = *acc_info;
	acc->cntr_dmabuf_fd = -1;
	return acc;
}

void efa_acc_state_destroy(struct efa_acc_state *acc)
{
	if (!acc) return;
	if (acc->cntr_alloc_addr && acc->acc_info.user.free)
		acc->acc_info.user.free(acc->acc_info.device, acc->cntr_alloc_addr);
	if (acc->cntr_dmabuf_fd >= 0)
		close(acc->cntr_dmabuf_fd);
	free(acc);
}
