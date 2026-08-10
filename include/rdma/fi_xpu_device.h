/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/* SPDX-FileCopyrightText: Copyright Amazon.com, Inc. or its affiliates. All rights reserved. */

#ifndef FI_XPU_DEVICE_H
#define FI_XPU_DEVICE_H

/*
 * OFI XPU Device-Side API
 *
 * This header is compiled with a single XPU kernel compiler at a time.
 * It supports XPU programming environments with a C/C++ interface:
 *
 *   - NVIDIA CUDA (nvcc)
 *   - AMD ROCm HIP (hipcc)
 *   - Intel oneAPI Level Zero / SYCL (icpx -fsycl)
 *
 * The FI_XPU_FUNC macro adapts the function qualifier based on the
 * compiler detected at build time.
 *
 * Each exported XPU handle (fid_xpu_ep, fid_xpu_cq, fid_xpu_cntr) embeds
 * struct fid_xpu as its first member. The dispatch functions cast the
 * handle pointer to struct fid_xpu * to read fid->prov_id and route to
 * the correct provider-specific implementation.
 *
 * Provider-specific headers (fi_xpu_device_efa.h, etc.) define the
 * per-provider fi_xpu_<op>_<prov>() functions. When a provider implements
 * device-side support, its header is included here and corresponding cases
 * are added to each dispatch switch.
 */

#include <stdint.h>
#include <stddef.h>
#include <rdma/fi_xpu.h>

#if defined(__CUDACC__) || (defined(__HIP_DEVICE_COMPILE__) && __HIP_DEVICE_COMPILE__)
  #define FI_XPU_FUNC __device__ static inline
#elif defined(__SYCL_DEVICE_ONLY__)
  #define FI_XPU_FUNC static inline
#else
  #define FI_XPU_FUNC static inline
#endif

/*
 * Cooperative scope hints — specifies the set of threads issuing the
 * same operation collectively.
 */
enum {
	FI_XPU_WORK_ITEM,
	FI_XPU_SUBGROUP,
	FI_XPU_WORK_GROUP,
	FI_XPU_DEVICE,
};

/*
 * Provider-specific device headers go here.
 *
 * Example: when a provider implements its device-side header
 * (e.g. fi_xpu_device_efa.h), it defines fi_xpu_<op>_efa() functions.
 * Then include the header here and add a case in each dispatch switch:
 *
 *   #include <rdma/fi_xpu_device_efa.h>
 *
 *   case FI_XPU_PROV_EFA:
 *       return fi_xpu_send_efa(ep, ...);
 */


FI_XPU_FUNC int
fi_xpu_write(void *ep, const void *buf, size_t len, void *desc,
	     uint64_t data, void *dest_addr, uint64_t addr, uint64_t key,
	     void *context, uint64_t flags, int scope)
{
	struct fid_xpu *fid = (struct fid_xpu *)ep;

	switch (fid->prov_id) {
	default:
		return -FI_ENOSYS;
	}
}

FI_XPU_FUNC int
fi_xpu_read(void *ep, void *buf, size_t len, void *desc,
	    void *src_addr, uint64_t addr, uint64_t key,
	    void *context, uint64_t flags, int scope)
{
	struct fid_xpu *fid = (struct fid_xpu *)ep;

	switch (fid->prov_id) {
	default:
		return -FI_ENOSYS;
	}
}


FI_XPU_FUNC int
fi_xpu_send(void *ep, const void *buf, size_t len, void *desc,
	    uint64_t data, void *dest_addr, void *context,
	    uint64_t flags, int scope)
{
	struct fid_xpu *fid = (struct fid_xpu *)ep;

	switch (fid->prov_id) {
	default:
		return -FI_ENOSYS;
	}
}

FI_XPU_FUNC int
fi_xpu_recv(void *ep, void *buf, size_t len, void *desc,
	    void *src_addr, void *context, uint64_t flags, int scope)
{
	struct fid_xpu *fid = (struct fid_xpu *)ep;

	switch (fid->prov_id) {
	default:
		return -FI_ENOSYS;
	}
}


FI_XPU_FUNC int
fi_xpu_tsend(void *ep, const void *buf, size_t len, void *desc,
	     uint64_t data, void *dest_addr, uint64_t tag, void *context,
	     uint64_t flags, int scope)
{
	struct fid_xpu *fid = (struct fid_xpu *)ep;

	switch (fid->prov_id) {
	default:
		return -FI_ENOSYS;
	}
}

FI_XPU_FUNC int
fi_xpu_trecv(void *ep, void *buf, size_t len, void *desc,
	     void *src_addr, uint64_t tag, uint64_t ignore, void *context,
	     uint64_t flags, int scope)
{
	struct fid_xpu *fid = (struct fid_xpu *)ep;

	switch (fid->prov_id) {
	default:
		return -FI_ENOSYS;
	}
}


FI_XPU_FUNC int
fi_xpu_atomic(void *ep, const void *buf, size_t count, void *desc,
	      void *dest_addr, uint64_t addr, uint64_t key,
	      int datatype, int op, void *context,
	      uint64_t flags, int scope)
{
	struct fid_xpu *fid = (struct fid_xpu *)ep;

	switch (fid->prov_id) {
	default:
		return -FI_ENOSYS;
	}
}

FI_XPU_FUNC int
fi_xpu_fetch_atomic(void *ep, const void *buf, size_t count, void *desc,
		    void *result, void *result_desc,
		    void *dest_addr, uint64_t addr, uint64_t key,
		    int datatype, int op, void *context,
		    uint64_t flags, int scope)
{
	struct fid_xpu *fid = (struct fid_xpu *)ep;

	switch (fid->prov_id) {
	default:
		return -FI_ENOSYS;
	}
}

FI_XPU_FUNC int
fi_xpu_compare_atomic(void *ep, const void *buf, size_t count, void *desc,
		      const void *compare, void *compare_desc,
		      void *result, void *result_desc,
		      void *dest_addr, uint64_t addr, uint64_t key,
		      int datatype, int op, void *context,
		      uint64_t flags, int scope)
{
	struct fid_xpu *fid = (struct fid_xpu *)ep;

	switch (fid->prov_id) {
	default:
		return -FI_ENOSYS;
	}
}


FI_XPU_FUNC uint64_t
fi_xpu_cntr_read(void *cntr, int scope)
{
	struct fid_xpu *fid = (struct fid_xpu *)cntr;

	switch (fid->prov_id) {
	default:
		return 0;
	}
}

FI_XPU_FUNC uint64_t
fi_xpu_cntr_readerr(void *cntr, int scope)
{
	struct fid_xpu *fid = (struct fid_xpu *)cntr;

	switch (fid->prov_id) {
	default:
		return 0;
	}
}

FI_XPU_FUNC void
fi_xpu_cntr_wait(void *cntr, uint64_t threshold, int timeout, int scope)
{
	struct fid_xpu *fid = (struct fid_xpu *)cntr;

	switch (fid->prov_id) {
	default:
		return;
	}
}

FI_XPU_FUNC int
fi_xpu_cntr_add(void *cntr, uint64_t value, int scope)
{
	struct fid_xpu *fid = (struct fid_xpu *)cntr;

	switch (fid->prov_id) {
	default:
		return -FI_ENOSYS;
	}
}

FI_XPU_FUNC int
fi_xpu_cntr_set(void *cntr, uint64_t value, int scope)
{
	struct fid_xpu *fid = (struct fid_xpu *)cntr;

	switch (fid->prov_id) {
	default:
		return -FI_ENOSYS;
	}
}

FI_XPU_FUNC int
fi_xpu_cntr_adderr(void *cntr, uint64_t value, int scope)
{
	struct fid_xpu *fid = (struct fid_xpu *)cntr;

	switch (fid->prov_id) {
	default:
		return -FI_ENOSYS;
	}
}

FI_XPU_FUNC int
fi_xpu_cntr_seterr(void *cntr, uint64_t value, int scope)
{
	struct fid_xpu *fid = (struct fid_xpu *)cntr;

	switch (fid->prov_id) {
	default:
		return -FI_ENOSYS;
	}
}


FI_XPU_FUNC int64_t
fi_xpu_cq_read(void *cq, void *buf, size_t count, int scope)
{
	struct fid_xpu *fid = (struct fid_xpu *)cq;

	switch (fid->prov_id) {
	default:
		return -FI_ENOSYS;
	}
}

FI_XPU_FUNC int64_t
fi_xpu_cq_readfrom(void *cq, void *buf, size_t count,
		   void *src_addr, int scope)
{
	struct fid_xpu *fid = (struct fid_xpu *)cq;

	switch (fid->prov_id) {
	default:
		return -FI_ENOSYS;
	}
}

FI_XPU_FUNC int64_t
fi_xpu_cq_readerr(void *cq, void *buf, uint64_t flags, int scope)
{
	struct fid_xpu *fid = (struct fid_xpu *)cq;

	switch (fid->prov_id) {
	default:
		return -FI_ENOSYS;
	}
}

FI_XPU_FUNC int64_t
fi_xpu_cq_sread(void *cq, void *buf, size_t count,
		uint64_t threshold, int scope)
{
	struct fid_xpu *fid = (struct fid_xpu *)cq;

	switch (fid->prov_id) {
	default:
		return -FI_ENOSYS;
	}
}

FI_XPU_FUNC int64_t
fi_xpu_cq_sreadfrom(void *cq, void *buf, size_t count,
		    void *src_addr, uint64_t threshold, int scope)
{
	struct fid_xpu *fid = (struct fid_xpu *)cq;

	switch (fid->prov_id) {
	default:
		return -FI_ENOSYS;
	}
}

#endif /* FI_XPU_DEVICE_H */
