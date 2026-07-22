/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/* SPDX-FileCopyrightText: Copyright Amazon.com, Inc. or its affiliates. All
 * rights reserved. */

/*
 * EFA provider: OFI Accelerator API implementation.
 *
 * Implements the portable fi_acc_*_export() functions for the EFA provider.
 * Internally calls the same rdma-core/efadv APIs that fi_efa_ops_gda uses
 * (efadv_query_qp_wqs, efadv_query_cq, efadv_create_comp_cntr) and uses
 * the fi_acc_info callbacks to map resources into accelerator memory.
 *
 * Call flow:
 *   fi_acc_ep_export() → efadv_query_qp_wqs() → acc_info.import() → device ptrs
 *   fi_acc_cq_export() → efadv_query_cq()     → acc_info.import() → device ptrs
 *   fi_acc_cntr_export() → return DMA-BUF ptr (set during cntr_open)
 *   fi_acc_mr_export() → ibv_mr->lkey
 *   fi_acc_av_lookup() → efa_av_addr_to_conn() → conn->ah->ahn, conn->ep_addr->qpn/qkey
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

#if HAVE_EFADV_QUERY_QP_WQS
#include <infiniband/efadv.h>
#endif

/*
 * =============================================================================
 * fi_acc_ep_export — Export EP SQ/RQ for accelerator access
 *
 * This replaces the manual workflow:
 *   gda_ops->query_qp_wqs(ep, &sq, &rq)
 *   cuMemHostRegister(sq.buffer, ..., IOMEMORY|DEVICEMAP)
 *   cuMemHostGetDevicePointer(&dev_ptr, sq.buffer, 0)
 *   cuMemHostRegister(sq.doorbell, ..., IOMEMORY|DEVICEMAP)
 *   cuMemHostGetDevicePointer(&dev_ptr, sq.doorbell, 0)
 *   ... build efa_cuda_qp ...
 *
 * With the OFI Accelerator API, all of that is encapsulated:
 *   fi_acc_ep_export(ep, 0, &attr)
 *   → attr.sq.buffer is already a device pointer
 *   → attr.sq.doorbell is already a device pointer
 * =============================================================================
 */
int efa_acc_ep_export(struct fid_ep *ep_fid, uint64_t flags,
		      struct fi_acc_ep_attr *attr)
{
#if HAVE_EFADV_QUERY_QP_WQS
	struct efa_base_ep *base_ep;
	struct efa_acc_state *acc;
	struct fi_acc_info *ai;
	struct efadv_wq_attr qp_sq_attr = {};
	struct efadv_wq_attr qp_rq_attr = {};
	long page_size;
	int ret;

	if (!ep_fid || !attr)
		return -FI_EINVAL;

	base_ep = container_of(ep_fid, struct efa_base_ep, util_ep.ep_fid);
	acc = base_ep->acc_state;
	if (!acc) {
		EFA_WARN(FI_LOG_EP_CTRL,
			 "fi_acc_ep_export: endpoint not created with FI_ACC\n");
		return -FI_ENODATA;
	}

	ai = &acc->acc_info;
	if (!ai->user.import) {
		EFA_WARN(FI_LOG_EP_CTRL,
			 "fi_acc_ep_export: acc_info.import callback is NULL\n");
		return -FI_EINVAL;
	}

	/*
	 * Query raw HW queue geometry from EFA device via rdma-core.
	 * Returns host VAs of SQ/RQ ring buffers and doorbell registers.
	 */
	ret = efadv_query_qp_wqs(base_ep->qp->ibv_qp,
				 &qp_sq_attr, &qp_rq_attr,
				 sizeof(qp_sq_attr));
	if (ret) {
		EFA_WARN(FI_LOG_EP_CTRL,
			 "efadv_query_qp_wqs failed: %d\n", ret);
		return (ret == EOPNOTSUPP) ? -FI_EOPNOTSUPP : -FI_EINVAL;
	}

	page_size = sysconf(_SC_PAGESIZE);

	/*
	 * Map SQ ring buffer (NIC BAR MMIO) into accelerator address space.
	 * The import callback calls cuMemHostRegister(IOMEMORY|DEVICEMAP)
	 * and cuMemHostGetDevicePointer() internally.
	 */
	void *sq_buf_dev = qp_sq_attr.buffer;
	ret = ai->user.import(ai->device, -1, 0,
			      (uint64_t)qp_sq_attr.num_entries * qp_sq_attr.entry_size,
			      FI_ACC_IMPORT_IOMEMORY | FI_ACC_IMPORT_DEVICEMAP,
			      &sq_buf_dev);
	if (ret) {
		EFA_WARN(FI_LOG_EP_CTRL,
			 "import SQ buffer failed: %d\n", ret);
		return ret;
	}
	acc->sq_buf_dev = sq_buf_dev;

	/*
	 * Map SQ doorbell register (NIC BAR MMIO, 4 bytes).
	 * We register one full page as required by cuMemHostRegister.
	 */
	void *sq_db_dev = qp_sq_attr.doorbell;
	ret = ai->user.import(ai->device, -1, 0,
			      (uint64_t)page_size,
			      FI_ACC_IMPORT_IOMEMORY | FI_ACC_IMPORT_DEVICEMAP,
			      &sq_db_dev);
	if (ret) {
		EFA_WARN(FI_LOG_EP_CTRL,
			 "import SQ doorbell failed: %d\n", ret);
		return ret;
	}
	acc->sq_db_dev = sq_db_dev;

	/*
	 * Map RQ buffer (host RAM, not BAR — only needs DEVICEMAP).
	 * RQ is regular host memory mmap'd by rdma-core.
	 */
	if (qp_rq_attr.buffer) {
		void *rq_buf_dev = qp_rq_attr.buffer;
		ret = ai->user.import(ai->device, -1, 0,
				      (uint64_t)qp_rq_attr.num_entries * qp_rq_attr.entry_size,
				      FI_ACC_IMPORT_DEVICEMAP,
				      &rq_buf_dev);
		if (ret) {
			EFA_WARN(FI_LOG_EP_CTRL,
				 "import RQ buffer failed: %d\n", ret);
			return ret;
		}
		acc->rq_buf_dev = rq_buf_dev;

		/* Map RQ doorbell (BAR MMIO) */
		void *rq_db_dev = qp_rq_attr.doorbell;
		ret = ai->user.import(ai->device, -1, 0,
				      (uint64_t)page_size,
				      FI_ACC_IMPORT_IOMEMORY | FI_ACC_IMPORT_DEVICEMAP,
				      &rq_db_dev);
		if (ret) {
			EFA_WARN(FI_LOG_EP_CTRL,
				 "import RQ doorbell failed: %d\n", ret);
			return ret;
		}
		acc->rq_db_dev = rq_db_dev;
	}

	/* Fill output structure with device pointers + queue geometry */
	memset(attr, 0, sizeof(*attr));

	attr->sq.buffer      = acc->sq_buf_dev;
	attr->sq.doorbell    = acc->sq_db_dev;
	attr->sq.num_entries = qp_sq_attr.num_entries;
	attr->sq.entry_size  = qp_sq_attr.entry_size;
	attr->sq.max_batch   = qp_sq_attr.max_batch;

	if (qp_rq_attr.buffer) {
		attr->rq.buffer      = acc->rq_buf_dev;
		attr->rq.doorbell    = acc->rq_db_dev;
		attr->rq.num_entries = qp_rq_attr.num_entries;
		attr->rq.entry_size  = qp_rq_attr.entry_size;
		attr->rq.max_batch   = qp_rq_attr.max_batch;
	}

	/* EFA device constants */
	attr->max_inline_data = 32;
	attr->max_rdma_sges   = 2;

	return FI_SUCCESS;
#else
	return -FI_EOPNOTSUPP;
#endif /* HAVE_EFADV_QUERY_QP_WQS */
}

/*
 * =============================================================================
 * fi_acc_cq_export — Export CQ ring buffer for accelerator polling
 *
 * CQ buffer lives in system RAM (rdma-core mmap). On EFA/P5en the CUDA
 * runtime can read host-registered memory directly from GPU kernels.
 * The import callback makes the host pointer accessible from the device.
 *
 * Replaces: gda_ops->query_cq(cq, &efa_cq_attr)
 * =============================================================================
 */
int efa_acc_cq_export(struct fid_cq *cq_fid, uint64_t flags,
		      struct fi_acc_cq_attr *attr)
{
#if HAVE_EFADV_QUERY_CQ
	struct efa_cq *efa_cq;
	struct efa_acc_state *acc;
	struct fi_acc_info *ai;
	struct efadv_cq_attr efadv_attr = {};
	int ret;

	if (!cq_fid || !attr)
		return -FI_EINVAL;

	efa_cq = container_of(cq_fid, struct efa_cq, util_cq.cq_fid);
	acc = efa_cq->acc_state;
	if (!acc) {
		EFA_WARN(FI_LOG_CQ,
			 "fi_acc_cq_export: CQ not created with FI_ACC\n");
		return -FI_ENODATA;
	}

	ai = &acc->acc_info;

	/* Query CQ ring geometry from rdma-core */
	ret = efadv_query_cq(ibv_cq_ex_to_cq(efa_cq->ibv_cq.ibv_cq_ex),
			     &efadv_attr, sizeof(efadv_attr));
	if (ret) {
		EFA_WARN(FI_LOG_CQ,
			 "efadv_query_cq failed: %d\n", ret);
		return (ret == EOPNOTSUPP) ? -FI_EOPNOTSUPP : -FI_EINVAL;
	}

	/*
	 * Map CQ buffer into accelerator.
	 * CQ is in host RAM (not BAR), so only DEVICEMAP is needed.
	 * On P5en, the host pointer is directly CUDA-readable without
	 * explicit registration — import can be a pass-through.
	 */
	void *cq_buf_dev = efadv_attr.buffer;
	ret = ai->user.import(ai->device, -1, 0,
			      (uint64_t)efadv_attr.num_entries * efadv_attr.entry_size,
			      FI_ACC_IMPORT_DEVICEMAP,
			      &cq_buf_dev);
	if (ret) {
		EFA_WARN(FI_LOG_CQ,
			 "import CQ buffer failed: %d\n", ret);
		return ret;
	}
	acc->cq_buf_dev = cq_buf_dev;

	/* Fill output */
	memset(attr, 0, sizeof(*attr));
	attr->buffer      = cq_buf_dev;
	attr->entry_size  = efadv_attr.entry_size;
	attr->num_entries = efadv_attr.num_entries;

	return FI_SUCCESS;
#else
	return -FI_EOPNOTSUPP;
#endif /* HAVE_EFADV_QUERY_CQ */
}

/*
 * =============================================================================
 * fi_acc_cntr_export — Export counter value pointer for accelerator access
 *
 * For counters opened with FI_ACC + FI_ACC_CNTR_EXTERNAL_MEM, the counter
 * value lives in GPU HBM (allocated via DMA-BUF by the acc_info.alloc
 * callback during fi_cntr_open). The NIC writes directly to that address.
 *
 * Replaces: The consumer reading cntr->gpu_ptr() after gda_ops->cntr_open_ext()
 * =============================================================================
 */
int efa_acc_cntr_export(struct fid_cntr *cntr_fid, uint64_t flags,
			struct fi_acc_cntr_attr *attr)
{
	struct efa_cntr *efa_cntr;
	struct efa_acc_state *acc;

	if (!cntr_fid || !attr)
		return -FI_EINVAL;

	efa_cntr = container_of(cntr_fid, struct efa_cntr, util_cntr.cntr_fid);
	acc = efa_cntr->acc_state;
	if (!acc) {
		EFA_WARN(FI_LOG_CNTR,
			 "fi_acc_cntr_export: counter not created with FI_ACC\n");
		return -FI_ENODATA;
	}

	if (!acc->cntr_value_dev) {
		EFA_WARN(FI_LOG_CNTR,
			 "fi_acc_cntr_export: no device memory for counter "
			 "(was FI_ACC_CNTR_EXTERNAL_MEM specified?)\n");
		return -FI_ENODATA;
	}

	memset(attr, 0, sizeof(*attr));
	attr->value = (volatile uint64_t *)acc->cntr_value_dev;

	return FI_SUCCESS;
}

/*
 * =============================================================================
 * fi_acc_mr_export — Export MR local key for accelerator WQE construction
 *
 * The lkey is needed by the GPU kernel to fill the SGE (scatter-gather entry)
 * in the WQE. EFA stores lkey in ibv_mr->lkey.
 *
 * Replaces: gda_ops->get_mr_lkey(mr)
 * =============================================================================
 */
int efa_acc_mr_export(struct fid_mr *mr_fid, uint64_t flags,
		      struct fi_acc_mr_attr *attr)
{
	struct efa_mr *efa_mr;

	if (!mr_fid || !attr)
		return -FI_EINVAL;

	efa_mr = container_of(mr_fid, struct efa_mr, mr_fid);
	if (!efa_mr->ibv_mr) {
		EFA_WARN(FI_LOG_MR,
			 "fi_acc_mr_export: MR not registered (ibv_mr is NULL)\n");
		return -FI_ENODATA;
	}

	memset(attr, 0, sizeof(*attr));
	attr->lkey = efa_mr->ibv_mr->lkey;

	return FI_SUCCESS;
}

/*
 * =============================================================================
 * fi_acc_av_lookup — Export resolved peer address for accelerator WQE
 *
 * Translates a libfabric fi_addr_t into the raw EFA addressing triple
 * (AHN, remote_qpn, remote_qkey) that the GPU kernel writes into the
 * WQE destination fields.
 *
 * Replaces: gda_ops->query_addr(ep, fi_addr, &ahn, &qpn, &qkey)
 *
 * Note: The original gda_ops->query_addr takes an EP argument because
 * the AV is accessed via the EP's bound AV. In the OFI Acc API, we
 * take the AV directly since the consumer already has it. The EP is
 * needed internally only to resolve the AV, which we can get from the
 * AV fid directly.
 * =============================================================================
 */
int efa_acc_av_lookup(struct fid_av *av_fid, fi_addr_t fi_addr,
		      uint64_t flags, struct fi_acc_peer_addr *addr)
{
	struct efa_av *efa_av;
	struct efa_conn *conn;

	if (!av_fid || !addr)
		return -FI_EINVAL;

	efa_av = container_of(av_fid, struct efa_av, util_av.av_fid);
	conn = efa_av_addr_to_conn(efa_av, fi_addr);
	if (!conn) {
		EFA_WARN(FI_LOG_AV,
			 "fi_acc_av_lookup: no connection for fi_addr %lu\n",
			 fi_addr);
		return -FI_ENODATA;
	}

	if (!conn->ah || !conn->ep_addr) {
		EFA_WARN(FI_LOG_AV,
			 "fi_acc_av_lookup: connection incomplete for fi_addr %lu "
			 "(ah=%p, ep_addr=%p)\n",
			 fi_addr, (void *)conn->ah, (void *)conn->ep_addr);
		return -FI_ENODATA;
	}

	memset(addr, 0, sizeof(*addr));
	addr->address_handle = conn->ah->ahn;
	addr->remote_qpn     = conn->ep_addr->qpn;
	addr->remote_qkey    = conn->ep_addr->qkey;

	return FI_SUCCESS;
}

/*
 * =============================================================================
 * fi_acc_av_lookup_batch — Bulk export of peer addresses
 *
 * Builds the [total_slots * nranks] target table that GDAKI uses.
 * Each entry is resolved independently through the same AV.
 * Entries with FI_ADDR_UNSPEC are left zeroed (asymmetric peer counts).
 * =============================================================================
 */
int efa_acc_av_lookup_batch(struct fid_av *av_fid, const fi_addr_t *fi_addrs,
			    size_t count, uint64_t flags,
			    struct fi_acc_peer_addr *addrs)
{
	struct efa_av *efa_av;
	size_t i;
	int any_failed = 0;

	if (!av_fid || !fi_addrs || !addrs)
		return -FI_EINVAL;

	efa_av = container_of(av_fid, struct efa_av, util_av.av_fid);
	memset(addrs, 0, count * sizeof(*addrs));

	for (i = 0; i < count; i++) {
		struct efa_conn *conn;

		if (fi_addrs[i] == FI_ADDR_UNSPEC)
			continue;

		conn = efa_av_addr_to_conn(efa_av, fi_addrs[i]);
		if (!conn || !conn->ah || !conn->ep_addr) {
			any_failed = 1;
			continue;
		}

		addrs[i].address_handle = conn->ah->ahn;
		addrs[i].remote_qpn    = conn->ep_addr->qpn;
		addrs[i].remote_qkey   = conn->ep_addr->qkey;
	}

	return any_failed ? -FI_ENODATA : FI_SUCCESS;
}

/*
 * =============================================================================
 * fi_acc_mr_get_info — Export local MR info for key exchange
 *
 * Returns (lkey, local_addr, rkey) so the consumer can:
 *   1. Use lkey in local SGEs (GPU kernel writes this into WQE)
 *   2. Allgather (addr, rkey) across ranks
 *   3. Peers build fi_acc_mr_peer arrays for remote RDMA targeting
 *
 * Replaces: gda_ops->get_mr_lkey() + fi_mr_key() + raw addr extraction
 * =============================================================================
 */
int efa_acc_mr_get_info(struct fid_mr *mr_fid, uint64_t flags,
			uint32_t *lkey, uint64_t *addr, uint64_t *rkey)
{
	struct efa_mr *efa_mr;

	if (!mr_fid)
		return -FI_EINVAL;

	efa_mr = container_of(mr_fid, struct efa_mr, mr_fid);
	if (!efa_mr->ibv_mr) {
		EFA_WARN(FI_LOG_MR,
			 "fi_acc_mr_get_info: MR not registered\n");
		return -FI_ENODATA;
	}

	if (lkey)
		*lkey = efa_mr->ibv_mr->lkey;
	if (addr)
		*addr = (uint64_t)(uintptr_t)efa_mr->ibv_mr->addr;
	if (rkey)
		*rkey = (uint64_t)fi_mr_key(&efa_mr->mr_fid);

	return FI_SUCCESS;
}

/*
 * =============================================================================
 * efa_acc_cntr_open — Create hardware counter with GPU HBM backing
 *
 * This replaces the GDAKI manual sequence:
 *   1. nccl_net_ofi_gpu_vmm_alloc() → GPU HBM for counter value
 *   2. nccl_net_ofi_gpu_get_dma_buf_fd() → DMA-BUF fd
 *   3. gda_ops->cntr_open_ext(domain, &attr, &cntr, NULL, &efa_attr)
 *
 * With the OFI Accelerator API, the consumer calls fi_cntr_open() with
 * FI_ACC flag and the provider internally:
 *   1. Calls acc_info.alloc() → gets GPU HBM ptr + DMA-BUF fd
 *   2. Passes DMA-BUF to efadv_create_comp_cntr()
 *   3. Stores GPU ptr in acc_state->cntr_value_dev for later export
 * =============================================================================
 */
int efa_acc_cntr_open(struct fid_domain *domain_fid,
		      struct fi_cntr_attr *attr,
		      struct fi_acc_info *acc_info,
		      struct fid_cntr **cntr_fid,
		      void *context)
{
#if HAVE_EFADV_CREATE_COMP_CNTR
	struct efa_acc_state *acc;
	struct efa_cntr *cntr;
	void *gpu_mem = NULL;
	int dmabuf_fd = -1;
	uint64_t dmabuf_offset = 0;
	int ret;

	if (!domain_fid || !attr || !acc_info || !cntr_fid)
		return -FI_EINVAL;

	if (!acc_info->user.alloc) {
		EFA_WARN(FI_LOG_CNTR,
			 "efa_acc_cntr_open: acc_info.alloc callback is NULL\n");
		return -FI_EINVAL;
	}

	/* Allocate acc_state */
	acc = calloc(1, sizeof(*acc));
	if (!acc)
		return -FI_ENOMEM;
	acc->acc_info = *acc_info;
	acc->cntr_dmabuf_fd = -1;

	/*
	 * Step 1: Allocate GPU HBM for the counter value via consumer callback.
	 * This calls cuMemCreate + cuMemMap + cuMemExportToShareableHandle
	 * (or equivalent) and returns a GPU pointer + DMA-BUF fd.
	 */
	ret = acc_info->user.alloc(acc_info->device,
				   sizeof(uint64_t), /* size */
				   0,                /* alignment */
				   FI_ACC_ALLOC_GPU_HBM,
				   &gpu_mem, &dmabuf_fd, &dmabuf_offset);
	if (ret) {
		EFA_WARN(FI_LOG_CNTR,
			 "efa_acc_cntr_open: acc_info.alloc failed: %d\n", ret);
		free(acc);
		return ret;
	}
	acc->cntr_value_dev = gpu_mem;
	acc->cntr_dmabuf_fd = dmabuf_fd;
	acc->cntr_alloc_addr = gpu_mem;

	/*
	 * Step 2: Create the EFA hardware counter backed by this DMA-BUF.
	 * Same as gda_ops->cntr_open_ext() but called internally.
	 */
	struct fi_efa_comp_cntr_init_attr efa_attr = {};
	efa_attr.flags = FI_EFA_COMP_CNTR_INIT_WITH_COMP_EXTERNAL_MEM;
	efa_attr.comp_cntr_ext_mem.type = FI_EFA_MEMORY_LOCATION_DMABUF;
	efa_attr.comp_cntr_ext_mem.dmabuf.fd = dmabuf_fd;
	efa_attr.comp_cntr_ext_mem.dmabuf.offset = dmabuf_offset;

	cntr = calloc(1, sizeof(*cntr));
	if (!cntr) {
		if (acc_info->user.free)
			acc_info->user.free(acc_info->device, gpu_mem);
		free(acc);
		return -FI_ENOMEM;
	}

	ret = efa_hw_cntr_open(domain_fid, attr, cntr, cntr_fid, context, &efa_attr);
	if (ret) {
		EFA_WARN(FI_LOG_CNTR,
			 "efa_acc_cntr_open: efa_hw_cntr_open failed: %d\n", ret);
		free(cntr);
		if (acc_info->user.free)
			acc_info->user.free(acc_info->device, gpu_mem);
		free(acc);
		return ret;
	}

	/* Mark counter as using device memory (GPU reads, not CPU reads) */
	cntr->comp_use_device_mem = true;

	/* Attach acc_state to counter for later export */
	cntr->acc_state = acc;

	return FI_SUCCESS;
#else
	return -FI_EOPNOTSUPP;
#endif /* HAVE_EFADV_CREATE_COMP_CNTR */
}

/*
 * =============================================================================
 * efa_acc_state_create — Allocate and initialize acc_state for an object
 *
 * Called when FI_ACC flag is detected during fi_*_open(). Copies the
 * consumer's fi_acc_info callbacks into the state object.
 * =============================================================================
 */
struct efa_acc_state *efa_acc_state_create(const struct fi_acc_info *acc_info)
{
	struct efa_acc_state *acc;

	if (!acc_info)
		return NULL;

	acc = calloc(1, sizeof(*acc));
	if (!acc)
		return NULL;

	acc->acc_info = *acc_info;
	acc->cntr_dmabuf_fd = -1;
	return acc;
}

/*
 * =============================================================================
 * efa_acc_state_destroy — Free acc_state and unmap device memory
 *
 * Called during fi_close() of the owning object (EP, CQ, counter).
 * =============================================================================
 */
void efa_acc_state_destroy(struct efa_acc_state *acc)
{
	if (!acc)
		return;

	/* Free counter GPU memory if we allocated it */
	if (acc->cntr_alloc_addr && acc->acc_info.user.free) {
		acc->acc_info.user.free(acc->acc_info.device,
					acc->cntr_alloc_addr);
	}

	/* Close DMA-BUF fd */
	if (acc->cntr_dmabuf_fd >= 0) {
		close(acc->cntr_dmabuf_fd);
	}

	/*
	 * Note: SQ/RQ/CQ device mappings (created by acc_info.import)
	 * are owned by the CUDA runtime (cuMemHostRegister). They become
	 * invalid when the underlying libfabric EP/CQ closes and the
	 * BAR mapping disappears. The CUDA driver handles cleanup of
	 * stale registrations. For robust cleanup, the consumer should
	 * call cuMemHostUnregister before fi_close — but that's the
	 * consumer's responsibility (same as today with gda_ops).
	 */

	free(acc);
}
