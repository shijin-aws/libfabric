/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/* SPDX-FileCopyrightText: Copyright Amazon.com, Inc. or its affiliates. All
 * rights reserved. */

#ifndef EFA_ACC_H
#define EFA_ACC_H

#include <rdma/fi_acc.h>

/*
 * EFA provider accelerator state.
 *
 * Attached to EFA objects (EP, CQ, counter) created with FI_ACC flag.
 * Holds the consumer-provided fi_acc_info callbacks and tracks
 * device-mapped pointers produced during fi_acc_*_export() calls.
 *
 * Lifecycle:
 *   - Allocated during fi_*_open() when FI_ACC flag is present
 *   - Populated during fi_acc_*_export()
 *   - Freed during fi_close()
 *
 * The acc_state pointer is stored in:
 *   struct efa_base_ep -> acc_state   (for EP export)
 *   struct efa_cq      -> acc_state   (for CQ export)
 *   struct efa_cntr    -> acc_state   (for counter export)
 */
struct efa_acc_state {
	/* Consumer-provided accelerator callbacks (copied at object open time) */
	struct fi_acc_info acc_info;

	/*
	 * Device-mapped pointers (filled during fi_acc_*_export).
	 * These are the device-accessible VAs returned by acc_info.import().
	 */
	void *sq_buf_dev;       /* SQ ring buffer → device ptr (BAR MMIO) */
	void *sq_db_dev;        /* SQ doorbell → device ptr (BAR MMIO) */
	void *rq_buf_dev;       /* RQ ring buffer → device ptr (host RAM) */
	void *rq_db_dev;        /* RQ doorbell → device ptr (BAR MMIO) */
	void *cq_buf_dev;       /* CQ ring buffer → device ptr (host RAM) */

	/*
	 * Counter value device pointer.
	 * For DMA-BUF backed counters: the GPU HBM address where the NIC
	 * writes the counter value. Set during fi_cntr_open() with FI_ACC.
	 */
	void *cntr_value_dev;

	/* DMA-BUF metadata for counter memory (for cleanup) */
	int   cntr_dmabuf_fd;
	void *cntr_alloc_addr;
};

/*
 * EFA provider implementation of OFI Accelerator API export functions.
 */

int efa_acc_ep_export(struct fid_ep *ep, uint64_t flags,
		      struct fi_acc_ep_attr *attr);

int efa_acc_cq_export(struct fid_cq *cq, uint64_t flags,
		      struct fi_acc_cq_attr *attr);

int efa_acc_cntr_export(struct fid_cntr *cntr, uint64_t flags,
			struct fi_acc_cntr_attr *attr);

int efa_acc_mr_export(struct fid_mr *mr, uint64_t flags,
		      struct fi_acc_mr_attr *attr);

int efa_acc_av_lookup(struct fid_av *av, fi_addr_t fi_addr,
		      uint64_t flags, struct fi_acc_peer_addr *addr);

int efa_acc_av_lookup_batch(struct fid_av *av, const fi_addr_t *fi_addrs,
			    size_t count, uint64_t flags,
			    struct fi_acc_peer_addr *addrs);

int efa_acc_mr_get_info(struct fid_mr *mr, uint64_t flags,
			uint32_t *lkey, uint64_t *addr, uint64_t *rkey);

/*
 * Accelerator-aware counter open.
 * Allocates GPU HBM for the counter value via acc_info.alloc(),
 * exports it as DMA-BUF, and passes to efadv_create_comp_cntr().
 */
int efa_acc_cntr_open(struct fid_domain *domain,
		      struct fi_cntr_attr *attr,
		      struct fi_acc_info *acc_info,
		      struct fid_cntr **cntr_fid,
		      void *context);

/*
 * State lifecycle management.
 * Called from fi_*_open() and fi_close() paths.
 */
struct efa_acc_state *efa_acc_state_create(const struct fi_acc_info *acc_info);
void efa_acc_state_destroy(struct efa_acc_state *acc);

#endif /* EFA_ACC_H */
