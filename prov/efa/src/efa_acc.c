/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/* SPDX-FileCopyrightText: Copyright Amazon.com, Inc. or its affiliates. All
 * rights reserved. */

/*
 * EFA provider: OFI Accelerator API implementation (opaque export model).
 *
 * fi_ep_export_acc():  builds GPU-resident fi_acc_dev_ep and returns void*
 * fi_cq_export_acc():  builds GPU-resident fi_acc_dev_cq and returns void*
 * fi_cntr_export_acc(): returns GPU-resident fi_acc_dev_cntr as void*
 * fi_mr_export_acc():  builds GPU-resident fi_acc_dev_desc and returns void*
 * fi_av_export_acc():  builds GPU-resident fi_acc_dev_peer and returns void*
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

/*
 * Import flag legend (defined in fi_acc.h):
 *   FI_ACC_IMPORT_IOMEMORY  — host VA is PCIe BAR MMIO
 *   FI_ACC_IMPORT_DEVICEMAP — map into accelerator address space
 * BAR regions (SQ buffer, doorbells) need both; host RAM regions
 * (RQ buffer, host CQ ring) need DEVICEMAP only.
 */

#if HAVE_EFADV_QUERY_QP_WQS
#include <infiniband/efadv.h>
#endif

/*
 * Helper: Import a host VA into accelerator address space.
 *
 * FI_ACC_MEM_USER_ALLOC: use consumer's import callback.
 * FI_ACC_MEM_PROVIDER: use provider's HMEM ops (cuda_host_register +
 *                      cuMemHostGetDevicePointer via HMEM infra).
 *
 * host_va: provider-owned host virtual address (BAR MMIO or host RAM)
 * dev_ptr: [out] resulting device pointer for the same physical memory
 */
static int acc_import_region(struct fi_acc_info *ai, void *host_va,
			     size_t size, uint64_t flags, void **dev_ptr)
{
	if (!ai)
		return -FI_EINVAL;

	if (ai->mem_type == FI_ACC_MEM_USER_ALLOC) {
		if (!ai->import)
			return -FI_EINVAL;
		return ai->import(ai->device, host_va, (uint64_t)size,
				  flags, dev_ptr);
	}

	/* FI_ACC_MEM_PROVIDER: use HMEM infrastructure.
	 * ofi_hmem_get_device_ptr registers the host VA and returns
	 * the GPU device pointer (cudaHostRegister + cudaHostGetDevicePointer). */
	return ofi_hmem_get_device_ptr(ai->iface, host_va, size, flags, dev_ptr);
}

/*
 * Helper: Allocate GPU memory for device-resident structs + H2D copy.
 *
 * FI_ACC_MEM_USER_ALLOC: use consumer's alloc callback.
 * FI_ACC_MEM_PROVIDER: use provider's HMEM ops (ofi_hmem_dev_alloc).
 */
static int acc_gpu_alloc_and_copy(struct fi_acc_info *ai, const void *host_data,
				  size_t size, void **dev_ptr)
{
	void *gpu_mem = NULL;
	int ret;

	if (!ai)
		return -FI_EINVAL;

	if (ai->mem_type == FI_ACC_MEM_USER_ALLOC) {
		int fd = -1;
		uint64_t offset = 0;

		if (!ai->alloc)
			return -FI_EINVAL;

		ret = ai->alloc(ai->device, (uint64_t)size, 0,
				0, &gpu_mem, &fd, &offset);
		if (ret) return ret;
		if (fd >= 0) close(fd);
	} else {
		/* FI_ACC_MEM_PROVIDER: use HMEM infrastructure */
		ret = ofi_hmem_dev_alloc(ai->iface, ai->device, &gpu_mem, size);
		if (ret)
			return -FI_ENOMEM;
	}

	/* H2D copy via HMEM */
	ret = (int)ofi_copy_to_hmem(ai->iface, ai->device, gpu_mem,
				    host_data, size);
	if (ret < 0) {
		if (ai->mem_type == FI_ACC_MEM_USER_ALLOC) {
			if (ai->free)
				ai->free(ai->device, gpu_mem);
		} else {
			ofi_hmem_dev_free(ai->iface, gpu_mem);
		}
		return ret;
	}

	*dev_ptr = gpu_mem;
	return 0;
}

/*
 * =============================================================================
 * fi_ep_export_acc — Build opaque GPU-resident EP descriptor
 * =============================================================================
 */
int efa_ep_export_acc(struct fid_ep *ep_fid, uint64_t flags,
		      void **acc_ep, size_t *size)
{
#if HAVE_EFADV_QUERY_QP_WQS
	struct efa_base_ep *base_ep;
	struct efa_acc_ep_state *acc;
	struct fi_acc_info *ai;
	struct efadv_wq_attr qp_sq_attr = {};
	struct efadv_wq_attr qp_rq_attr = {};
	struct fi_acc_efa_ep h_ep = {};
	int ret;

	if (!ep_fid || !acc_ep || !size)
		return -FI_EINVAL;

	base_ep = container_of(ep_fid, struct efa_base_ep, util_ep.ep_fid);
	acc = base_ep->acc_state;
	if (!acc)
		return -FI_ENODATA;

	ai = &acc->base.acc_info;

	/* Query HW queue geometry */
	ret = efadv_query_qp_wqs(base_ep->qp->ibv_qp,
				 &qp_sq_attr, &qp_rq_attr,
				 sizeof(qp_sq_attr));
	if (ret)
		return (ret == EOPNOTSUPP) ? -FI_EOPNOTSUPP : -FI_EINVAL;

	/* Map SQ buffer (BAR MMIO) → GPU */
	void *sq_buf_dev = NULL;
	ret = acc_import_region(ai, qp_sq_attr.buffer,
				(size_t)qp_sq_attr.num_entries * qp_sq_attr.entry_size,
				FI_ACC_IMPORT_IOMEMORY | FI_ACC_IMPORT_DEVICEMAP,
				&sq_buf_dev);
	if (ret) return ret;

	/* Map SQ doorbell (BAR MMIO) → GPU. Register only the 4-byte
	 * doorbell register (as efa_gda.c does): the doorbell VA is not
	 * page-aligned and registering a full page would cross into an
	 * unmapped page. */
	void *sq_db_dev = NULL;
	ret = acc_import_region(ai, qp_sq_attr.doorbell, sizeof(uint32_t),
				FI_ACC_IMPORT_IOMEMORY | FI_ACC_IMPORT_DEVICEMAP,
				&sq_db_dev);
	if (ret) return ret;

	/* Map RQ buffer (host RAM) → GPU */
	void *rq_buf_dev = NULL;
	void *rq_db_dev = NULL;
	if (qp_rq_attr.buffer) {
		ret = acc_import_region(ai, qp_rq_attr.buffer,
					(size_t)qp_rq_attr.num_entries * qp_rq_attr.entry_size,
					FI_ACC_IMPORT_DEVICEMAP, &rq_buf_dev);
		if (ret) return ret;

		ret = acc_import_region(ai, qp_rq_attr.doorbell, sizeof(uint32_t),
					FI_ACC_IMPORT_IOMEMORY | FI_ACC_IMPORT_DEVICEMAP,
					&rq_db_dev);
		if (ret) return ret;
	}

	/* Build fi_acc_dev_ep on host stack */
	h_ep.hdr.provider       = FI_ACC_PROV_EFA;
	h_ep.hdr.version        = 1;
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
	h_ep.local_cntr       = NULL;

	/*
	 * Link to the bound write counter's GPU pointer for SQ backpressure.
	 * The counter was created with FI_ACC and has its own acc_state
	 * containing the GPU HBM pointer the NIC writes to.
	 */
	{
		struct util_cntr *wr_cntr = base_ep->util_ep.cntrs[CNTR_WR];
		if (wr_cntr) {
			struct efa_cntr *efa_cntr = container_of(
				wr_cntr, struct efa_cntr, util_cntr);
			if (efa_cntr->acc_state && efa_cntr->acc_state->cntr_value_dev)
				h_ep.local_cntr = (volatile uint64_t *)
					efa_cntr->acc_state->cntr_value_dev;
		}
	}

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
 * fi_cq_export_acc — Build opaque GPU-resident CQ descriptor
 * =============================================================================
 */
int efa_cq_export_acc(struct fid_cq *cq_fid, uint64_t flags,
		      void **acc_cq, size_t *size)
{
#if HAVE_EFADV_QUERY_CQ
	struct efa_cq *efa_cq;
	struct efa_acc_cq_state *acc;
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

	ai = &acc->base.acc_info;

	ret = efadv_query_cq(ibv_cq_ex_to_cq(efa_cq->ibv_cq.ibv_cq_ex),
			     &efadv_attr, sizeof(efadv_attr));
	if (ret)
		return (ret == EOPNOTSUPP) ? -FI_EOPNOTSUPP : -FI_EINVAL;

	/*
	 * If the CQ was created with FI_ACC + alloc (GPU-backed CQ),
	 * the buffer is already in GPU memory — use the stored pointer.
	 * Otherwise (standard host CQ), import the host VA into GPU.
	 */
	void *cq_buf_dev = NULL;
	if (acc->cq_buf_dev) {
		cq_buf_dev = acc->cq_buf_dev;
	} else {
		ret = acc_import_region(ai, efadv_attr.buffer,
					(size_t)efadv_attr.num_entries * efadv_attr.entry_size,
					FI_ACC_IMPORT_DEVICEMAP, &cq_buf_dev);
		if (ret) return ret;
	}

	h_cq.hdr.provider     = FI_ACC_PROV_EFA;
	h_cq.hdr.version      = 1;
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
 * fi_cntr_export_acc — Return opaque GPU-resident counter handle
 * =============================================================================
 */
int efa_cntr_export_acc(struct fid_cntr *cntr_fid, uint64_t flags,
			void **acc_cntr, size_t *size)
{
	struct efa_cntr *efa_cntr;
	struct efa_acc_cntr_state *acc;
	struct fi_acc_info *ai;
	struct fi_acc_efa_cntr h_cntr = {};
	int ret;

	if (!cntr_fid || !acc_cntr || !size)
		return -FI_EINVAL;

	efa_cntr = container_of(cntr_fid, struct efa_cntr, util_cntr.cntr_fid);
	acc = efa_cntr->acc_state;
	if (!acc || !acc->cntr_value_dev)
		return -FI_ENODATA;

	ai = &acc->base.acc_info;
	h_cntr.hdr.provider = FI_ACC_PROV_EFA;
	h_cntr.hdr.version = 1;
	h_cntr.value = (volatile uint64_t *)acc->cntr_value_dev;
	h_cntr.err_value = (volatile uint64_t *)acc->cntr_err_dev;

	ret = acc_gpu_alloc_and_copy(ai, &h_cntr, sizeof(h_cntr), acc_cntr);
	if (ret) return ret;

	*size = sizeof(struct fi_acc_efa_cntr);
	return FI_SUCCESS;
}

/*
 * =============================================================================
 * fi_mr_export_acc — Export MR descriptors as contiguous GPU array
 * =============================================================================
 */
int efa_mr_export_acc(struct fid_mr **mrs, size_t count, uint64_t flags,
		      void **acc_descs, size_t *size)
{
	struct fi_acc_efa_desc *h_descs;
	struct fi_acc_info *ai;
	size_t i;
	int ret;

	if (!mrs || !acc_descs || !size || count == 0)
		return -FI_EINVAL;

	/* Build host array, validating each MR has acc_info */
	h_descs = calloc(count, sizeof(*h_descs));
	if (!h_descs)
		return -FI_ENOMEM;

	ai = NULL;
	for (i = 0; i < count; i++) {
		struct efa_mr *efa_mr = container_of(mrs[i], struct efa_mr, mr_fid);

		if (!efa_mr->acc_info) {
			EFA_WARN(FI_LOG_MR,
				 "MR[%zu] missing acc_info (not registered with FI_ACC)\n", i);
			free(h_descs);
			return -FI_ENODATA;
		}
		if (!efa_mr->ibv_mr) {
			EFA_WARN(FI_LOG_MR,
				 "MR[%zu] missing ibv_mr\n", i);
			free(h_descs);
			return -FI_ENODATA;
		}

		/* Use acc_info from the first MR for GPU allocation */
		if (!ai)
			ai = efa_mr->acc_info;

		h_descs[i].lkey = efa_mr->ibv_mr->lkey;
	}

	/* Alloc GPU and copy */
	ret = acc_gpu_alloc_and_copy(ai, h_descs,
				     count * sizeof(*h_descs), acc_descs);
	free(h_descs);
	if (ret) return ret;

	*size = count * sizeof(struct fi_acc_efa_desc);
	return FI_SUCCESS;
}

/*
 * =============================================================================
 * fi_av_export_acc — Export peer addresses as contiguous GPU array
 * =============================================================================
 */
int efa_av_export_acc(struct fid_av *av_fid, const fi_addr_t *fi_addrs,
		      size_t count, uint64_t flags,
		      void **acc_peers, size_t *size)
{
	struct efa_av *efa_av;
	struct fi_acc_efa_peer *h_peers;
	struct fi_acc_info *ai;
	size_t i;
	int ret;

	if (!av_fid || !fi_addrs || !acc_peers || !size || count == 0)
		return -FI_EINVAL;

	efa_av = container_of(av_fid, struct efa_av, util_av.av_fid);

	ai = efa_av->acc_info;
	if (!ai) {
		EFA_WARN(FI_LOG_AV,
			 "AV missing acc_info (not opened with acc_info)\n");
		return -FI_ENODATA;
	}

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
 * fi_mr_get_acc_info — Export MR info for key exchange
 * =============================================================================
 */
int efa_mr_get_acc_info(struct fid_mr *mr_fid, uint64_t flags,
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
 * fi_open_ops dispatch — shared fi_acc_ops table
 * =============================================================================
 */
static struct fi_acc_ops efa_acc_ops = {
	.size        = sizeof(struct fi_acc_ops),
	.ep_export   = efa_ep_export_acc,
	.cq_export   = efa_cq_export_acc,
	.cntr_export = efa_cntr_export_acc,
	.mr_export   = efa_mr_export_acc,
	.av_export   = efa_av_export_acc,
	.mr_get_info = efa_mr_get_acc_info,
};

int efa_acc_ops_open(struct fid *fid, const char *name, uint64_t flags,
		     void **ops, void *context)
{
	if (!name || strcmp(name, FI_ACC_OPS_NAME))
		return -FI_EINVAL;

	*ops = &efa_acc_ops;
	return FI_SUCCESS;
}

/*
 * =============================================================================
 * State lifecycle
 * =============================================================================
 */
struct efa_acc_ep_state *efa_acc_ep_state_create(const struct fi_acc_info *acc_info)
{
	struct efa_acc_ep_state *acc;
	if (!acc_info) return NULL;
	acc = calloc(1, sizeof(*acc));
	if (!acc) return NULL;
	acc->base.acc_info = *acc_info;
	return acc;
}

struct efa_acc_cq_state *efa_acc_cq_state_create(const struct fi_acc_info *acc_info)
{
	struct efa_acc_cq_state *acc;
	if (!acc_info) return NULL;
	acc = calloc(1, sizeof(*acc));
	if (!acc) return NULL;
	acc->base.acc_info = *acc_info;
	return acc;
}

struct efa_acc_cntr_state *efa_acc_cntr_state_create(const struct fi_acc_info *acc_info)
{
	struct efa_acc_cntr_state *acc;
	if (!acc_info) return NULL;
	acc = calloc(1, sizeof(*acc));
	if (!acc) return NULL;
	acc->base.acc_info = *acc_info;
	return acc;
}

void efa_acc_ep_state_destroy(struct efa_acc_ep_state *acc)
{
	if (!acc) return;
	free(acc);
}

void efa_acc_cq_state_destroy(struct efa_acc_cq_state *acc)
{
	if (!acc) return;
	free(acc);
}

void efa_acc_cntr_state_destroy(struct efa_acc_cntr_state *acc)
{
	struct fi_acc_info *ai;
	if (!acc) return;
	ai = &acc->base.acc_info;
	if (acc->cntr_alloc_addr) {
		if (ai->mem_type == FI_ACC_MEM_USER_ALLOC) {
			if (ai->free)
				ai->free(ai->device, acc->cntr_alloc_addr);
		} else {
			ofi_hmem_dev_free(ai->iface, acc->cntr_alloc_addr);
		}
	}
	if (acc->cntr_err_alloc_addr) {
		if (ai->mem_type == FI_ACC_MEM_USER_ALLOC) {
			if (ai->free)
				ai->free(ai->device, acc->cntr_err_alloc_addr);
		} else {
			ofi_hmem_dev_free(ai->iface, acc->cntr_err_alloc_addr);
		}
	}
	free(acc);
}
