/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/* SPDX-FileCopyrightText: Copyright (c) 2013-2018 Intel Corporation, Inc.  All rights reserved. */
/* SPDX-FileCopyrightText: Copyright Amazon.com, Inc. or its affiliates. All rights reserved. */

#include "ofi_util.h"
#include "efa.h"
#include "efa_cntr.h"
#include "efa_hw_cntr.h"
#include "efa_cq.h"
#include "efa_acc.h"

int efa_cntr_wait(struct fid_cntr *cntr_fid, uint64_t threshold, int timeout)
{
	struct util_cntr *cntr;
	uint64_t start, errcnt;
	int ret = -FI_ETIMEDOUT;
	int numtry = 5;
	int tryid = 0;
	int waitim = 1;
	static const int waitim_max = 1000; /* cap at 1ms */

	cntr = container_of(cntr_fid, struct util_cntr, cntr_fid);

	assert(cntr->wait);
	errcnt = ofi_atomic_get64(&cntr->err);
	start = (timeout >= 0) ? ofi_gettime_ms() : 0;

	for (tryid = 0; tryid < numtry; ++tryid) {
		cntr->progress(cntr);
		if (threshold <= ofi_atomic_get64(&cntr->cnt))
			return FI_SUCCESS;

		if (errcnt != ofi_atomic_get64(&cntr->err))
			return -FI_EAVAIL;

		if (timeout >= 0) {
			timeout -= (int)(ofi_gettime_ms() - start);
			if (timeout <= 0)
				return -FI_ETIMEDOUT;
		} else {
			tryid = 0;
		}

		ret = ofi_wait(&cntr->wait->wait_fid, waitim);
		if (ret == -FI_ETIMEDOUT)
			ret = 0;

		if (waitim < waitim_max)
			waitim *= 2;
	}

	return ret;
}

static struct fi_ops_cntr efa_cntr_ops = {
	.size = sizeof(struct fi_ops_cntr),
	.read = ofi_cntr_read,
	.readerr = ofi_cntr_readerr,
	.add = ofi_cntr_add,
	.adderr = ofi_cntr_adderr,
	.set = ofi_cntr_set,
	.seterr = ofi_cntr_seterr,
	.wait = efa_cntr_wait
};

static int efa_cntr_close(struct fid *fid)
{
	struct efa_cntr *cntr;

	cntr = container_of(fid, struct efa_cntr, util_cntr.cntr_fid.fid);

	if (cntr->acc_state)
		efa_acc_cntr_state_destroy(cntr->acc_state);

	efa_cntr_destruct(cntr);
	free(cntr);
	return 0;
}

static struct fi_ops efa_cntr_fi_ops = {
	.size = sizeof(efa_cntr_fi_ops),
	.close = efa_cntr_close,
	.bind = fi_no_bind,
	.control = fi_no_control,
	.ops_open = fi_no_ops_open,
};

void efa_cntr_progress_ibv_cq_poll_list(struct efa_cntr *efa_cntr)
{
	struct dlist_entry *item;
	struct efa_ibv_cq_poll_list_entry *poll_list_entry;
	struct efa_cq *efa_cq;

	assert(ofi_genlock_held(&efa_cntr->util_cntr.ep_list_lock));

	dlist_foreach(&efa_cntr->ibv_cq_poll_list, item) {
		poll_list_entry = container_of(item, struct efa_ibv_cq_poll_list_entry, entry);
		efa_cq = container_of(poll_list_entry->cq, struct efa_cq, ibv_cq);
		ofi_genlock_lock(&efa_cq->util_cq.ep_list_lock);
		(void) efa_cq->poll_ibv_cq(efa_env.efa_cq_read_size, poll_list_entry->cq);
		ofi_genlock_unlock(&efa_cq->util_cq.ep_list_lock);
	}
}

static void efa_cntr_progress(struct util_cntr *cntr)
{
	struct efa_cntr *efa_cntr;

	efa_cntr = container_of(cntr, struct efa_cntr, util_cntr);

	ofi_genlock_lock(&cntr->ep_list_lock);
	efa_cntr_progress_ibv_cq_poll_list(efa_cntr);
	ofi_genlock_unlock(&cntr->ep_list_lock);
}

int efa_cntr_construct(struct efa_cntr *cntr, struct fid_domain *domain,
		       struct fi_cntr_attr *attr,
		       ofi_cntr_progress_func progress, void *context)
{
	dlist_init(&cntr->ibv_cq_poll_list);
	return ofi_cntr_init(&efa_prov, domain, attr, &cntr->util_cntr,
			     progress, context);
}

void efa_cntr_destruct(struct efa_cntr *cntr)
{
	ofi_cntr_cleanup(&cntr->util_cntr);
}

int efa_cntr_open(struct fid_domain *domain, struct fi_cntr_attr *attr,
		  struct fid_cntr **cntr_fid, void *context)
{
	int ret;
	struct efa_cntr *cntr;

	cntr = calloc(1, sizeof(*cntr));
	if (!cntr)
		return -FI_ENOMEM;

#if HAVE_EFADV_CREATE_COMP_CNTR
	{
		struct efadv_comp_cntr_init_attr efa_cc_attr = {0};

		/*
		 * OFI Accelerator API: if FI_ACC flag + acc_info present,
		 * allocate GPU HBM for counter via acc_info.alloc() and
		 * pass DMA-BUF fd to efadv_create_comp_cntr so the NIC
		 * writes counter values directly to GPU memory.
		 */
		if (attr && (attr->flags & FI_ACC) && attr->acc_info) {
			struct fi_acc_info *ai = attr->acc_info;
			struct fi_cntr_attr acc_attr = *attr;
			void *comp_ptr = NULL;
			void *err_ptr = NULL;
			int comp_fd = -1, err_fd = -1;
			uint64_t comp_offset = 0, err_offset = 0;

			/* Clear FI_ACC from flags before passing to hw_cntr_open
			 * (it rejects unknown flags) */
			acc_attr.flags &= ~FI_ACC;

			/* Allocate GPU HBM for completion counter (8 bytes) */
			if (ai->mem_type == FI_ACC_MEM_USER_ALLOC) {
				if (!ai->alloc) {
					free(cntr);
					return -FI_EINVAL;
				}
				ret = ai->alloc(ai->device, 8, 8, 0,
						&comp_ptr, &comp_fd, &comp_offset);
			} else {
				ret = ofi_hmem_dev_alloc(ai->iface, ai->device,
							 &comp_ptr, 8);
				if (!ret)
					ret = ofi_hmem_get_dmabuf_fd(
						ai->iface, comp_ptr, 8,
						&comp_fd, &comp_offset);
			}
			if (ret) {
				EFA_WARN(FI_LOG_CNTR,
					 "Failed to allocate GPU HBM for comp counter: %d\n", ret);
				free(cntr);
				return ret;
			}

			/* Allocate GPU HBM for error counter (8 bytes) */
			if (ai->mem_type == FI_ACC_MEM_USER_ALLOC) {
				ret = ai->alloc(ai->device, 8, 8, 0,
						&err_ptr, &err_fd, &err_offset);
			} else {
				ret = ofi_hmem_dev_alloc(ai->iface, ai->device,
							 &err_ptr, 8);
				if (!ret)
					ret = ofi_hmem_get_dmabuf_fd(
						ai->iface, err_ptr, 8,
						&err_fd, &err_offset);
			}
			if (ret) {
				EFA_WARN(FI_LOG_CNTR,
					 "Failed to allocate GPU HBM for err counter: %d\n", ret);
				if (ai->mem_type == FI_ACC_MEM_USER_ALLOC) {
					if (ai->free)
						ai->free(ai->device, comp_ptr);
				} else {
					ofi_hmem_dev_free(ai->iface, comp_ptr);
				}
				if (comp_fd >= 0)
					close(comp_fd);
				free(cntr);
				return ret;
			}

			/* Configure efadv to use external DMA-BUF for both */
			efa_cc_attr.flags |= EFADV_COMP_CNTR_INIT_WITH_COMP_EXTERNAL_MEM;
			efa_cc_attr.comp_cntr_ext_mem.type = EFADV_MEMORY_LOCATION_DMABUF;
			efa_cc_attr.comp_cntr_ext_mem.dmabuf.fd = comp_fd;
			efa_cc_attr.comp_cntr_ext_mem.dmabuf.offset = comp_offset;

			efa_cc_attr.flags |= EFADV_COMP_CNTR_INIT_WITH_ERR_EXTERNAL_MEM;
			efa_cc_attr.err_cntr_ext_mem.type = EFADV_MEMORY_LOCATION_DMABUF;
			efa_cc_attr.err_cntr_ext_mem.dmabuf.fd = err_fd;
			efa_cc_attr.err_cntr_ext_mem.dmabuf.offset = err_offset;

			ret = efa_hw_cntr_open(domain, &acc_attr, cntr, cntr_fid,
					       context, &efa_cc_attr);
			if (ret) {
				if (ai->mem_type == FI_ACC_MEM_USER_ALLOC) {
					if (ai->free) {
						ai->free(ai->device, comp_ptr);
						ai->free(ai->device, err_ptr);
					}
				} else {
					ofi_hmem_dev_free(ai->iface, comp_ptr);
					ofi_hmem_dev_free(ai->iface, err_ptr);
				}
				if (comp_fd >= 0)
					close(comp_fd);
				if (err_fd >= 0)
					close(err_fd);
				free(cntr);
				return ret;
			}

			/* fds consumed by NIC — close our copies */
			if (comp_fd >= 0)
				close(comp_fd);
			if (err_fd >= 0)
				close(err_fd);

			/* Store acc_state on the counter for later export */
			cntr->acc_state = efa_acc_cntr_state_create(ai);
			if (!cntr->acc_state) {
				fi_close(&cntr->util_cntr.cntr_fid.fid);
				return -FI_ENOMEM;
			}
			cntr->acc_state->cntr_value_dev = comp_ptr;
			cntr->acc_state->cntr_alloc_addr = comp_ptr;
			cntr->acc_state->cntr_err_dev = err_ptr;
			cntr->acc_state->cntr_err_alloc_addr = err_ptr;
			cntr->comp_use_device_mem = true;
			cntr->err_use_device_mem = true;

			EFA_INFO(FI_LOG_CNTR,
				 "Opened FI_ACC hardware counter (GPU HBM) cntr_fid: %p\n",
				 *cntr_fid);
			return FI_SUCCESS;
		}

		/* Standard (non-ACC) HW counter path */
		ret = efa_hw_cntr_open(domain, attr, cntr, cntr_fid, context, &efa_cc_attr);
		if (!ret) {
			return FI_SUCCESS;
		}
	}
#endif
	/* Fall back to software counter */
	ret = efa_cntr_construct(cntr, domain, attr, efa_cntr_progress, context);
	if (ret) {
		free(cntr);
		return ret;
	}

	*cntr_fid = &cntr->util_cntr.cntr_fid;
	cntr->util_cntr.cntr_fid.ops = &efa_cntr_ops;
	cntr->util_cntr.cntr_fid.fid.ops = &efa_cntr_fi_ops;

	EFA_INFO(FI_LOG_CNTR, "Opened software counter with cntr_fid: %p\n", *cntr_fid);
	return FI_SUCCESS;
}

void efa_cntr_report_tx_completion(struct util_ep *ep, uint64_t flags)
{
	struct util_cntr *cntr;
	struct efa_cntr *efa_cntr;

	flags &= (FI_SEND | FI_WRITE | FI_READ);
	assert(flags == FI_SEND || flags == FI_WRITE || flags == FI_READ);

	if (flags == FI_SEND)
		cntr = ep->cntrs[CNTR_TX];
	else if (flags == FI_WRITE)
		cntr = ep->cntrs[CNTR_WR];
	else if (flags == FI_READ)
		cntr = ep->cntrs[CNTR_RD];
	else
		cntr = NULL;

	if (!cntr)
		return;

	/* Skip cntr add for hardware counter */
	efa_cntr = container_of(cntr, struct efa_cntr, util_cntr);
	if (efa_cntr->ibv_comp_cntr)
		return;

	cntr->cntr_fid.ops->add(&cntr->cntr_fid, 1);
}

void efa_cntr_report_rx_completion(struct util_ep *ep, uint64_t flags)
{
	struct util_cntr *cntr;
	struct efa_cntr *efa_cntr;

	flags &= (FI_RECV | FI_REMOTE_WRITE | FI_REMOTE_READ);
	assert(flags == FI_RECV || flags == FI_REMOTE_WRITE || flags == FI_REMOTE_READ);

	if (flags == FI_RECV)
		cntr = ep->cntrs[CNTR_RX];
	else if (flags == FI_REMOTE_READ)
		cntr = ep->cntrs[CNTR_REM_RD];
	else if (flags == FI_REMOTE_WRITE)
		cntr = ep->cntrs[CNTR_REM_WR];
	else
		cntr = NULL;

	if (!cntr)
		return;

	/* Skip cntr add for hardware counter */
	efa_cntr = container_of(cntr, struct efa_cntr, util_cntr);
	if (efa_cntr->ibv_comp_cntr)
		return;

	cntr->cntr_fid.ops->add(&cntr->cntr_fid, 1);
}

void efa_cntr_report_error(struct util_ep *ep, uint64_t flags)
{
	flags = flags & (FI_SEND | FI_READ | FI_WRITE | FI_ATOMIC |
			 FI_RECV | FI_REMOTE_READ | FI_REMOTE_WRITE);

	struct util_cntr *cntr;
	struct efa_cntr *efa_cntr;

	if (flags == FI_WRITE || flags == FI_ATOMIC)
		cntr = ep->cntrs[CNTR_WR];
	else if (flags == FI_READ)
		cntr = ep->cntrs[CNTR_RD];
	else if (flags == FI_SEND)
		cntr = ep->cntrs[CNTR_TX];
	else if (flags == FI_RECV)
		cntr = ep->cntrs[CNTR_RX];
	else if (flags == FI_REMOTE_READ)
		cntr = ep->cntrs[CNTR_REM_RD];
	else if (flags == FI_REMOTE_WRITE)
		cntr = ep->cntrs[CNTR_REM_WR];
	else
		cntr = NULL;

	if (!cntr)
		return;

	/* Skip cntr adderr for hardware counter */
	efa_cntr = container_of(cntr, struct efa_cntr, util_cntr);
	if (efa_cntr->ibv_comp_cntr)
		return;

	cntr->cntr_fid.ops->adderr(&cntr->cntr_fid, 1);
}
