/*
 * Copyright (c) 2026 Amazon.com, Inc. or its affiliates. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef FI_ACC_H
#define FI_ACC_H

#include <rdma/fabric.h>
#include <rdma/fi_domain.h>
#include <rdma/fi_endpoint.h>
#include <rdma/fi_eq.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * =============================================================================
 * OFI Accelerator API
 *
 * Enables GPU/accelerator-initiated communication (GPU Direct Async — Kernel
 * Initiated). The accelerator bypasses the CPU on the data path by directly
 * constructing WQEs, writing to NIC work queues, and ringing doorbells.
 *
 * Host-side:
 *   - Create resources (EP, CQ, counters, AV) with FI_ACC flag
 *   - Provider maps queues into accelerator address space
 *   - Export structured resource descriptors for device-side use
 *
 * Device-side:
 *   - Accelerator kernel uses exported descriptors to post WQEs,
 *     poll CQ, and read counters without CPU involvement
 * =============================================================================
 */

/*
 * Capability / flag bit for accelerator support.
 * Used in fi_info->caps, fi_cq_attr->flags, fi_cntr_attr->flags, etc.
 * Defined in rdma/fabric.h as (1ULL << 44).
 */
#ifndef FI_ACC
#define FI_ACC			(1ULL << 44)
#endif

/*
 * =============================================================================
 * Accelerator memory info
 *
 * Passed as part of object attributes when creating accelerator-accessible
 * resources. The provider calls these callbacks to allocate/import memory
 * accessible from both the NIC and the accelerator device.
 * =============================================================================
 */

enum fi_acc_mem_type {
	FI_ACC_MEM_USER_ALLOC,   /* User provides alloc/import callbacks */
	FI_ACC_MEM_DMABUF,       /* Provider exports DMA-BUF fd+offset */
};

struct fi_acc_info {
	enum fi_hmem_iface   iface;     /* FI_HMEM_CUDA, FI_HMEM_ZE, etc. */
	uint64_t             device;    /* Device ordinal */
	enum fi_acc_mem_type mem_type;

	union {
		/* FI_ACC_MEM_USER_ALLOC: consumer provides allocation hooks */
		struct {
			/**
			 * alloc - Allocate accelerator-accessible memory.
			 * @device:    Accelerator device ordinal
			 * @size:      Requested size in bytes
			 * @alignment: Required alignment (0 = provider choice)
			 * @flags:     FI_ACC_ALLOC_* flags
			 * @addr:      [out] Device-accessible virtual address
			 * @fd:        [out] DMA-BUF fd (-1 if not applicable)
			 * @offset:    [out] Offset within DMA-BUF
			 *
			 * Used for hardware counters — NIC writes directly
			 * to accelerator memory via DMA-BUF.
			 */
			int (*alloc)(uint64_t device, uint64_t size,
				     uint64_t alignment, uint64_t flags,
				     void **addr, int *fd, uint64_t *offset);

			/**
			 * import - Map provider-owned region into accelerator.
			 * @device:  Accelerator device ordinal
			 * @fd:      File descriptor (or -1 for host VA import)
			 * @offset:  Offset within the fd-backed region
			 * @size:    Size of the region in bytes
			 * @flags:   FI_ACC_IMPORT_* flags
			 * @addr:    [in/out] Host VA in, device VA out
			 *
			 * Used for SQ buffer (BAR MMIO), doorbell (BAR MMIO),
			 * and CQ buffer (host RAM) mapping.
			 */
			int (*import)(uint64_t device, int fd,
				      uint64_t offset, uint64_t size,
				      uint64_t flags, void **addr);

			/**
			 * free - Release memory allocated by alloc.
			 */
			void (*free)(uint64_t device, void *addr);
		} user;

		/* FI_ACC_MEM_DMABUF: provider fills after object creation */
		struct {
			int      fd;
			uint64_t offset;
			uint64_t size;
		} dmabuf;
	};
};

/* Flags for fi_acc_info.user.alloc */
#define FI_ACC_ALLOC_GPU_HBM       (1ULL << 0)
#define FI_ACC_ALLOC_BAR_MAPPABLE  (1ULL << 1)

/* Flags for fi_acc_info.user.import */
#define FI_ACC_IMPORT_IOMEMORY     (1ULL << 0)  /* Region is device MMIO */
#define FI_ACC_IMPORT_DEVICEMAP    (1ULL << 1)  /* Map into accelerator AS */

/* Flags for fi_acc_cntr_attr */
#define FI_ACC_CNTR_EXTERNAL_MEM   (1ULL << 0)  /* Counter in ext. device mem */

/*
 * =============================================================================
 * Exported resource structures (structured, not opaque)
 *
 * Returned by fi_*_export_acc(). Contains all information the accelerator
 * kernel needs to directly operate the hardware queues.
 * =============================================================================
 */

/** Work Queue (SQ or RQ) attributes — one per direction */
struct fi_acc_wq_attr {
	void     *buffer;       /* Device-accessible ptr to ring buffer */
	void     *doorbell;     /* Device-accessible ptr to doorbell reg */
	uint32_t  num_entries;  /* Ring depth (power of 2) */
	uint32_t  entry_size;   /* Bytes per WQE/RQE */
	uint32_t  max_batch;    /* Max WQEs per doorbell ring (HW limit) */
};

/** Exported endpoint: SQ + RQ queue geometry */
struct fi_acc_ep_attr {
	struct fi_acc_wq_attr sq;
	struct fi_acc_wq_attr rq;
	uint32_t max_inline_data;
	uint32_t max_rdma_sges;
};

/** Exported CQ: completion ring buffer geometry */
struct fi_acc_cq_attr {
	void     *buffer;       /* Device-accessible ptr to CQ ring */
	uint32_t  entry_size;   /* Bytes per CQE */
	uint32_t  num_entries;  /* Ring depth (power of 2) */
};

/** Exported counter: device-resident counter value pointer */
struct fi_acc_cntr_attr {
	volatile uint64_t *value;  /* Device ptr to NIC-written counter */
};

/** Exported MR: local key for WQE SGE construction */
struct fi_acc_mr_attr {
	uint32_t lkey;          /* Local key for use in WQE SGE fields */
};

/** Exported peer address: raw HW addressing for WQE destination */
struct fi_acc_peer_addr {
	uint16_t address_handle;   /* NIC-level address handle (AHN) */
	uint16_t remote_qpn;       /* Remote queue pair number */
	uint32_t remote_qkey;      /* Queue key */
};

/*
 * =============================================================================
 * Scope definitions — cooperative thread model for device-side operations
 * =============================================================================
 */

enum fi_acc_scope {
	FI_ACC_WORK_ITEM,    /* Single thread (CUDA thread / SYCL work-item) */
	FI_ACC_SUBGROUP,     /* Warp (CUDA) / Subgroup (SYCL) */
	FI_ACC_WORK_GROUP,   /* Thread block (CUDA) / Work-group (SYCL) */
};

/*
 * =============================================================================
 * Host-side API — Resource export functions
 *
 * These are called after fi_enable() to extract device-accessible resource
 * descriptors. The provider uses the fi_acc_info callbacks to perform
 * accelerator-specific memory mapping (BAR MMIO, DMA-BUF, etc.).
 * =============================================================================
 */

/**
 * fi_acc_ep_export - Export endpoint queue resources for accelerator access.
 * @ep:     Enabled endpoint (created/opened with FI_ACC hint)
 * @flags:  Reserved, must be 0
 * @attr:   [out] Structured SQ/RQ queue attributes with device pointers
 *
 * The provider internally:
 *   1. Queries underlying HW queue geometry (buffer VA, doorbell VA, depth)
 *   2. Calls acc_info->import() to map BAR MMIO into accelerator
 *   3. Returns device-accessible pointers in attr
 */
int fi_acc_ep_export(struct fid_ep *ep, uint64_t flags,
		     struct fi_acc_ep_attr *attr);

/**
 * fi_acc_cq_export - Export CQ ring buffer for accelerator polling.
 * @cq:     CQ (created with FI_ACC flag)
 * @flags:  Reserved, must be 0
 * @attr:   [out] CQ ring buffer attributes with device pointer
 */
int fi_acc_cq_export(struct fid_cq *cq, uint64_t flags,
		     struct fi_acc_cq_attr *attr);

/**
 * fi_acc_cntr_export - Export counter for accelerator access.
 * @cntr:   Counter (created with FI_ACC + FI_ACC_CNTR_EXTERNAL_MEM)
 * @flags:  Reserved, must be 0
 * @attr:   [out] Device pointer to NIC-written counter value
 *
 * The counter value lives in accelerator memory (GPU HBM).
 * The NIC writes directly via DMA-BUF. The accelerator kernel reads
 * the value without CPU involvement.
 */
int fi_acc_cntr_export(struct fid_cntr *cntr, uint64_t flags,
		       struct fi_acc_cntr_attr *attr);

/**
 * fi_acc_mr_export - Export MR local key for accelerator WQE construction.
 * @mr:     Registered memory region
 * @flags:  Reserved, must be 0
 * @attr:   [out] Local key for SGE fields in WQEs
 */
int fi_acc_mr_export(struct fid_mr *mr, uint64_t flags,
		     struct fi_acc_mr_attr *attr);

/**
 * fi_acc_av_lookup - Export resolved peer address for accelerator WQE.
 * @av:       Address vector
 * @fi_addr:  Address previously inserted via fi_av_insert
 * @flags:    Reserved, must be 0
 * @addr:     [out] Raw HW addressing tuple (AHN, QPN, QKEY)
 *
 * The accelerator kernel writes these values directly into WQE
 * destination fields for remote peer addressing.
 */
int fi_acc_av_lookup(struct fid_av *av, fi_addr_t fi_addr,
		     uint64_t flags, struct fi_acc_peer_addr *addr);

/**
 * fi_acc_av_lookup_batch - Export multiple peer addresses at once.
 * @av:       Address vector
 * @fi_addrs: Array of fi_addr_t previously inserted
 * @count:    Number of entries in fi_addrs[] and addrs[]
 * @flags:    Reserved, must be 0
 * @addrs:    [out] Array of raw HW addressing tuples
 *
 * Bulk version for building target addressing tables (e.g.,
 * [total_slots * nranks] for GDAKI). Entries whose fi_addr is
 * FI_ADDR_UNSPEC are left zeroed in output.
 */
int fi_acc_av_lookup_batch(struct fid_av *av, const fi_addr_t *fi_addrs,
			   size_t count, uint64_t flags,
			   struct fi_acc_peer_addr *addrs);

/*
 * =============================================================================
 * Remote MR info for accelerator-side RDMA targeting
 *
 * When the accelerator kernel constructs RDMA write/read WQEs, it needs
 * the remote peer's (virtual_address, rkey). This struct and function
 * support key exchange (allgather of MR info across ranks).
 * =============================================================================
 */

/** Per-peer remote MR metadata for WQE construction */
struct fi_acc_mr_peer {
	uint64_t remote_addr;   /* Remote base virtual address */
	uint32_t rkey;          /* Remote key */
	uint32_t pad;           /* Alignment padding */
};

/**
 * fi_acc_mr_get_info - Get local MR info for key exchange / allgather.
 * @mr:    Registered memory region
 * @flags: Reserved, must be 0
 * @lkey:  [out] Local key (for local SGE in WQEs)
 * @addr:  [out] Local base virtual address (FI_MR_VIRT_ADDR)
 * @rkey:  [out] Remote key (peers use this in their RDMA WQEs)
 *
 * The consumer calls this per-MR, allgathers (addr, rkey) across ranks,
 * and builds GPU-resident per-peer fi_acc_mr_peer arrays.
 */
int fi_acc_mr_get_info(struct fid_mr *mr, uint64_t flags,
		       uint32_t *lkey, uint64_t *addr, uint64_t *rkey);

/*
 * =============================================================================
 * Notes on multi-endpoint / multi-context GDAKI patterns
 *
 * The OFI Accelerator API is per-object (EP, CQ, counter, MR, AV).
 * For GDAKI-style contexts with multiple endpoints:
 *
 *   - Data EP:     fi_endpoint + fi_ep_bind(FI_WRITE cntr) + fi_enable
 *                  → fi_acc_ep_export() → data.qp/cq/sq_size
 *   - PutValue EP: same creation flow, separate EP
 *                  → fi_acc_ep_export() → pvdata.qp/cq/sq_size
 *   - SC EPs:      fi_endpoint + fi_ep_bind(FI_WRITE cntr)
 *                                       + fi_ep_bind(FI_REMOTE_WRITE cntr)
 *                  → fi_acc_ep_export() → per-SC qp/cq/sq_size
 *
 * Each EP is exported independently. The consumer builds the composite
 * device handle (nccl_ofi_gin_gdaki_dev_handle equivalent) by assembling
 * exported attrs from multiple EPs + counters + MRs + peer addresses.
 *
 * Multi-rail: each rail has its own domain → its own set of EPs/CQs/MRs.
 * The consumer creates resources per-rail and exports each set.
 * rail_id = contextId % num_rails.
 *
 * Target addressing: the consumer calls fi_acc_av_lookup_batch() per EP
 * to build the [total_slots * nranks] table mapping (slot, peer) → HW addr.
 * =============================================================================
 */

#ifdef __cplusplus
}
#endif

#endif /* FI_ACC_H */
