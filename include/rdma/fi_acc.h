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
 *
 * --- Callback roles ---
 *
 * alloc:  "Allocate fresh GPU memory that the NIC can DMA to."
 *         Called by the provider during fi_cntr_open(FI_ACC) and optionally
 *         fi_cq_open(FI_ACC). The provider needs memory in GPU HBM that the
 *         NIC can reach via DMA-BUF.
 *
 *         Outputs:
 *           addr   — GPU device pointer to the allocation
 *           fd     — DMA-BUF file descriptor (provider passes to NIC driver)
 *           offset — offset within the DMA-BUF
 *
 *         Example (CUDA): cuMemAlloc → cuMemGetDmaBufFd → return both.
 *
 * import: "Map a provider-owned host VA into the accelerator address space."
 *         Called by the provider during fi_acc_ep_export() and fi_acc_cq_export().
 *         The provider has a host-side address (e.g., BAR MMIO for the SQ ring,
 *         or host RAM for the CQ buffer) and needs a device pointer so GPU
 *         kernels can access it.
 *
 *         Parameters:
 *           host_addr — [in]  host virtual address to map
 *           dev_addr  — [out] resulting device pointer for the same memory
 *
 *         Flags are provider-defined and passed through to the consumer.
 *         The provider uses them to indicate memory type (e.g., BAR MMIO
 *         vs host RAM) so the consumer can use the correct registration
 *         method. The flag values are an implementation detail between
 *         the provider and consumer — not part of the public API.
 *
 *         Example (CUDA):
 *           cuMemHostRegister(host_addr, size, flags)
 *           cuMemHostGetDevicePointer(&dev_addr, host_addr, 0)
 *
 * free:   "Release GPU memory previously returned by alloc."
 *         Called by the provider during fi_close() cleanup.
 * =============================================================================
 */

enum fi_acc_mem_type {
	FI_ACC_MEM_USER_ALLOC,   /* User provides alloc/import/free callbacks */
	FI_ACC_MEM_PROVIDER,     /* Provider manages device memory internally */
};

/* Proposal-facing alias */
#define FI_ACC_MEM_USER		FI_ACC_MEM_USER_ALLOC

/*
 * Flags passed by the provider to the consumer's alloc callback.
 */
#define FI_ACC_ALLOC_DMABUF	(1ULL << 0) /* Consumer must export a DMA-BUF
					     * fd for the allocation (NIC will
					     * DMA directly to this memory) */

/*
 * Flags passed by the provider to the consumer's import callback.
 * The consumer translates these to its platform's equivalents
 * (e.g., CUDA: CU_MEMHOSTREGISTER_IOMEMORY / CU_MEMHOSTREGISTER_DEVICEMAP).
 */
#define FI_ACC_IMPORT_IOMEMORY	(1ULL << 0) /* Host addr is PCIe BAR MMIO */
#define FI_ACC_IMPORT_DEVICEMAP	(1ULL << 1) /* Map into device addr space */

struct fi_acc_info {
	enum fi_hmem_iface   iface;     /* FI_HMEM_CUDA, FI_HMEM_ZE, etc. */
	uint64_t             device;    /* Device ordinal */
	enum fi_acc_mem_type mem_type;

	/**
	 * alloc - Allocate accelerator memory exportable via DMA-BUF.
	 * @device:    Device ordinal
	 * @size:      Allocation size in bytes
	 * @alignment: Required alignment (0 = default)
	 * @flags:     FI_ACC_ALLOC_* flags
	 * @addr:      [out] Device pointer to allocated memory
	 * @fd:        [out] DMA-BUF fd for NIC access
	 * @offset:    [out] Offset within DMA-BUF
	 */
	int (*alloc)(uint64_t device, uint64_t size,
		     uint64_t alignment, uint64_t flags,
		     void **addr, int *fd, uint64_t *offset);

	/**
	 * import - Map a host address into accelerator address space.
	 * @device:    Device ordinal
	 * @host_addr: [in] Host virtual address (BAR MMIO or host RAM)
	 * @size:      Size of the region in bytes
	 * @flags:     FI_ACC_IMPORT_* flags indicating memory type
	 * @dev_addr:  [out] Resulting device pointer
	 */
	int (*import)(uint64_t device, void *host_addr,
		      uint64_t size, uint64_t flags,
		      void **dev_addr);

	/**
	 * free - Release memory previously returned by alloc.
	 * @device: Device ordinal
	 * @addr:   Device pointer from alloc
	 */
	void (*free)(uint64_t device, void *addr);
};

/*
 * =============================================================================
 * Scope — cooperative thread model hint for device-side operations
 * =============================================================================
 */

#ifndef FI_ACC_SCOPE_DEFINED
#define FI_ACC_SCOPE_DEFINED
enum fi_acc_scope {
	FI_ACC_WORK_ITEM  = 0,   /* Single thread owns the EP */
	FI_ACC_SUBGROUP   = 1,   /* Warp (CUDA) / Subgroup (SYCL) */
	FI_ACC_WORK_GROUP = 2,   /* Thread block (CUDA) / Work-group (SYCL) */
	FI_ACC_DEVICE     = 3,   /* Multiple work-groups on the device */
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

/*
 * =============================================================================
 * Provider dispatch — fi_open_ops() extension pattern
 *
 * Each exportable object (EP, CQ, counter, MR, AV) exposes an fi_acc ops
 * struct via fi_open_ops() on its fid. The static-inline fi_*_export_acc()
 * wrappers below hide this from the consumer.
 * =============================================================================
 */

#define FI_ACC_OPS_NAME "fi_acc_ops"

struct fi_acc_ops {
	size_t size;
	int (*ep_export)(struct fid_ep *ep, uint64_t flags,
			 void **acc_ep, size_t *size);
	int (*cq_export)(struct fid_cq *cq, uint64_t flags,
			 void **acc_cq, size_t *size);
	int (*cntr_export)(struct fid_cntr *cntr, uint64_t flags,
			   void **acc_cntr, size_t *size);
	int (*mr_export)(struct fid_mr **mrs, size_t count, uint64_t flags,
			 void **acc_descs, size_t *size);
	int (*av_export)(struct fid_av *av, const fi_addr_t *fi_addrs,
			 size_t count, uint64_t flags,
			 void **acc_peers, size_t *size);
	int (*mr_get_info)(struct fid_mr *mr, uint64_t flags,
			   uint32_t *lkey, uint64_t *addr, uint64_t *rkey);
};

static inline int fi_acc_get_ops(struct fid *fid, struct fi_acc_ops **ops)
{
	return fid->ops->ops_open(fid, FI_ACC_OPS_NAME, 0, (void **)ops, NULL);
}

/**
 * fi_ep_export_acc - Export endpoint for accelerator access.
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
static inline int fi_ep_export_acc(struct fid_ep *ep, uint64_t flags,
				   void **acc_ep, size_t *size)
{
	struct fi_acc_ops *ops;
	int ret = fi_acc_get_ops(&ep->fid, &ops);
	if (ret)
		return ret;
	return ops->ep_export(ep, flags, acc_ep, size);
}

/**
 * fi_cq_export_acc - Export CQ for accelerator completion polling.
 * @cq:       CQ (created with FI_ACC)
 * @flags:    Reserved, must be 0
 * @acc_cq:   [out] Opaque device-accessible CQ handle (GPU memory)
 * @size:     [out] Size of the exported handle
 */
static inline int fi_cq_export_acc(struct fid_cq *cq, uint64_t flags,
				   void **acc_cq, size_t *size)
{
	struct fi_acc_ops *ops;
	int ret = fi_acc_get_ops(&cq->fid, &ops);
	if (ret)
		return ret;
	return ops->cq_export(cq, flags, acc_cq, size);
}

/**
 * fi_cntr_export_acc - Export counter for accelerator access.
 * @cntr:     Counter (created with FI_ACC)
 * @flags:    Reserved, must be 0
 * @acc_cntr: [out] Opaque device-accessible counter handle (GPU memory)
 * @size:     [out] Size of the exported handle
 *
 * The counter value lives in accelerator memory (GPU HBM). The NIC
 * writes directly. fi_acc_cntr_read() on the device reads it in one
 * instruction with zero overhead.
 */
static inline int fi_cntr_export_acc(struct fid_cntr *cntr, uint64_t flags,
				     void **acc_cntr, size_t *size)
{
	struct fi_acc_ops *ops;
	int ret = fi_acc_get_ops(&cntr->fid, &ops);
	if (ret)
		return ret;
	return ops->cntr_export(cntr, flags, acc_cntr, size);
}

/**
 * fi_mr_export_acc - Export MR descriptors for accelerator WQE construction.
 * @mrs:      Array of registered memory regions
 * @count:    Number of MRs to export
 * @flags:    Reserved, must be 0
 * @acc_descs:[out] Contiguous array of opaque device-accessible MR descriptors
 * @size:     [out] Total size of the exported array (stride = size / count)
 *
 * Batch-native: the device kernel indexes into this array and passes the
 * entry as `desc` to fi_acc_write/send/read. For single MR, pass count=1.
 */
static inline int fi_mr_export_acc(struct fid_mr **mrs, size_t count,
				   uint64_t flags, void **acc_descs,
				   size_t *size)
{
	struct fi_acc_ops *ops;
	int ret;

	if (!mrs || !count)
		return -FI_EINVAL;
	ret = fi_acc_get_ops(&mrs[0]->fid, &ops);
	if (ret)
		return ret;
	return ops->mr_export(mrs, count, flags, acc_descs, size);
}

/**
 * fi_av_export_acc - Export resolved peer addresses for accelerator use.
 * @av:        Address vector
 * @fi_addrs:  Array of fi_addr_t (previously inserted via fi_av_insert)
 * @count:     Number of entries to export
 * @flags:     Reserved, must be 0
 * @acc_peers: [out] Contiguous array of opaque peer handles (GPU memory)
 * @size:      [out] Total size of the exported array (stride = size / count)
 *
 * Batch-native: the device kernel indexes into this array and passes the
 * entry as `acc_peer` to fi_acc_write/send. For single peer, pass count=1.
 * FI_ADDR_UNSPEC entries are zeroed.
 */
static inline int fi_av_export_acc(struct fid_av *av,
				   const fi_addr_t *fi_addrs, size_t count,
				   uint64_t flags, void **acc_peers,
				   size_t *size)
{
	struct fi_acc_ops *ops;
	int ret = fi_acc_get_ops(&av->fid, &ops);
	if (ret)
		return ret;
	return ops->av_export(av, fi_addrs, count, flags, acc_peers, size);
}

/**
 * fi_mr_get_acc_info - Get local MR info for key exchange / allgather.
 * @mr:    Registered memory region
 * @flags: Reserved, must be 0
 * @lkey:  [out] Local key (passed via acc_desc on device side)
 * @addr:  [out] Local base virtual address (FI_MR_VIRT_ADDR)
 * @rkey:  [out] Remote key (peers use in their fi_acc_write rkey param)
 *
 * Used for allgather-based key exchange (regMrSym pattern).
 */
static inline int fi_mr_get_acc_info(struct fid_mr *mr, uint64_t flags,
				     uint32_t *lkey, uint64_t *addr,
				     uint64_t *rkey)
{
	struct fi_acc_ops *ops;
	int ret = fi_acc_get_ops(&mr->fid, &ops);
	if (ret)
		return ret;
	return ops->mr_get_info(mr, flags, lkey, addr, rkey);
}

#ifdef __cplusplus
}
#endif

#endif /* FI_ACC_H */
