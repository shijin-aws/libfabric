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
 * OFI Accelerator API — Host-Side
 *
 * Enables GPU/accelerator-initiated communication. The provider handles all
 * hardware details (BAR MMIO mapping, WQE format, doorbell protocol) and
 * exports opaque device-accessible handles. The accelerator kernel uses
 * high-level device functions (fi_acc_write, fi_acc_cq_poll, etc.) from
 * fi_acc_device.h against these opaque handles.
 *
 * The consumer never sees ring buffers, doorbells, WQE layouts, or phase bits.
 * =============================================================================
 */

/*
 * Capability flag. Used in fi_info->caps to request accelerator support.
 * Defined in fabric.h as (1ULL << 44).
 */
#ifndef FI_ACC
#define FI_ACC			(1ULL << 44)
#endif

/*
 * =============================================================================
 * Accelerator memory info
 *
 * Passed during object creation (CQ, counter, EP). The provider calls these
 * callbacks internally to allocate/import device-accessible memory.
 * The consumer never calls import/alloc directly after object creation —
 * fi_acc_*_export() does it.
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
		struct {
			int (*alloc)(uint64_t device, uint64_t size,
				     uint64_t alignment, uint64_t flags,
				     void **addr, int *fd, uint64_t *offset);
			int (*import)(uint64_t device, int fd,
				      uint64_t offset, uint64_t size,
				      uint64_t flags, void **addr);
			void (*free)(uint64_t device, void *addr);
		} user;

		struct {
			int      fd;
			uint64_t offset;
			uint64_t size;
		} dmabuf;
	};
};

/* Flags for fi_acc_info.user.alloc */
#define FI_ACC_ALLOC_GPU_HBM       (1ULL << 0)

/* Flags for fi_acc_info.user.import (provider uses internally) */
#define FI_ACC_IMPORT_IOMEMORY     (1ULL << 0)
#define FI_ACC_IMPORT_DEVICEMAP    (1ULL << 1)

/* Flags for counter creation */
#define FI_ACC_CNTR_EXTERNAL_MEM   (1ULL << 0)

/*
 * =============================================================================
 * Scope — cooperative thread model hint for device-side operations
 * =============================================================================
 */

#ifndef FI_ACC_SCOPE_DEFINED
#define FI_ACC_SCOPE_DEFINED
enum fi_acc_scope {
	FI_ACC_WORK_ITEM,    /* Single thread */
	FI_ACC_SUBGROUP,     /* Warp (CUDA) / Subgroup (SYCL) */
	FI_ACC_WORK_GROUP,   /* Thread block (CUDA) / Work-group (SYCL) */
};
#endif

/*
 * =============================================================================
 * Host-side export functions — return OPAQUE device-accessible handles
 *
 * All returned pointers are device-accessible (GPU memory). The consumer
 * passes them directly to device-side fi_acc_* functions without inspecting
 * or constructing the contents.
 * =============================================================================
 */

/**
 * fi_acc_ep_export - Export endpoint for accelerator access.
 * @ep:       Enabled endpoint (created with FI_ACC hint)
 * @flags:    Reserved, must be 0
 * @acc_ep:   [out] Opaque device-accessible EP handle (GPU memory)
 * @size:     [out] Size of the exported handle in bytes
 *
 * The provider internally:
 *   - Queries HW queue geometry
 *   - Maps SQ/RQ/doorbell into accelerator address space
 *   - Allocates and populates a GPU-resident descriptor
 *   - Returns a pointer the device kernel can use with fi_acc_write() etc.
 */
int fi_acc_ep_export(struct fid_ep *ep, uint64_t flags,
		     void **acc_ep, size_t *size);

/**
 * fi_acc_cq_export - Export CQ for accelerator completion polling.
 * @cq:       CQ (created with FI_ACC)
 * @flags:    Reserved, must be 0
 * @acc_cq:   [out] Opaque device-accessible CQ handle (GPU memory)
 * @size:     [out] Size of the exported handle
 */
int fi_acc_cq_export(struct fid_cq *cq, uint64_t flags,
		     void **acc_cq, size_t *size);

/**
 * fi_acc_cntr_export - Export counter for accelerator access.
 * @cntr:     Counter (created with FI_ACC + FI_ACC_CNTR_EXTERNAL_MEM)
 * @flags:    Reserved, must be 0
 * @acc_cntr: [out] Opaque device-accessible counter handle (GPU memory)
 * @size:     [out] Size of the exported handle
 *
 * The counter value lives in accelerator memory (GPU HBM). The NIC
 * writes directly. fi_acc_cntr_read() on the device reads it in one
 * instruction with zero overhead.
 */
int fi_acc_cntr_export(struct fid_cntr *cntr, uint64_t flags,
		       void **acc_cntr, size_t *size);

/**
 * fi_acc_mr_export - Export MR descriptor for accelerator WQE construction.
 * @mr:       Registered memory region
 * @flags:    Reserved, must be 0
 * @acc_desc: [out] Opaque device-accessible MR descriptor
 * @size:     [out] Size of the exported descriptor
 *
 * The device kernel passes this as `desc` to fi_acc_write/send/read.
 */
int fi_acc_mr_export(struct fid_mr *mr, uint64_t flags,
		     void **acc_desc, size_t *size);

/**
 * fi_acc_av_export - Export resolved peer address for accelerator use.
 * @av:       Address vector
 * @fi_addr:  Address previously inserted via fi_av_insert
 * @flags:    Reserved, must be 0
 * @acc_peer: [out] Opaque device-accessible peer handle
 * @size:     [out] Size of the exported peer handle
 *
 * The device kernel passes this as `acc_peer` to fi_acc_write/send.
 * The provider stamps the raw HW addressing into WQEs internally.
 */
int fi_acc_av_export(struct fid_av *av, fi_addr_t fi_addr,
		     uint64_t flags, void **acc_peer, size_t *size);

/**
 * fi_acc_av_export_batch - Export multiple peer addresses at once.
 * @av:        Address vector
 * @fi_addrs:  Array of fi_addr_t
 * @count:     Number of entries
 * @flags:     Reserved, must be 0
 * @acc_peers: [out] Array of opaque peer handles (GPU memory, contiguous)
 * @size:      [out] Total size of the exported array
 *
 * For building target addressing tables. FI_ADDR_UNSPEC entries are
 * zeroed and safe to pass to device functions (they will return error).
 */
int fi_acc_av_export_batch(struct fid_av *av, const fi_addr_t *fi_addrs,
			   size_t count, uint64_t flags,
			   void **acc_peers, size_t *size);

/**
 * fi_acc_mr_get_info - Get local MR info for key exchange / allgather.
 * @mr:    Registered memory region
 * @flags: Reserved, must be 0
 * @lkey:  [out] Local key (passed via acc_desc on device side)
 * @addr:  [out] Local base virtual address (FI_MR_VIRT_ADDR)
 * @rkey:  [out] Remote key (peers use in their fi_acc_write rkey param)
 *
 * Used for allgather-based key exchange (regMrSym pattern).
 */
int fi_acc_mr_get_info(struct fid_mr *mr, uint64_t flags,
		       uint32_t *lkey, uint64_t *addr, uint64_t *rkey);

#ifdef __cplusplus
}
#endif

#endif /* FI_ACC_H */
