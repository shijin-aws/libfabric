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

#ifndef FI_ACC_DEVICE_H
#define FI_ACC_DEVICE_H

/*
 * =============================================================================
 * OFI Accelerator API — Unified Device Header
 *
 * This is the ONLY file consumers include from their device kernels:
 *
 *     #include <rdma/fi_acc_device.h>
 *
 * It works with any accelerator compiler (nvcc, hipcc, SYCL, or plain C)
 * and provides all device-side functions (fi_acc_write, fi_acc_send, etc.)
 * with runtime dispatch to the correct provider based on a tag in the
 * exported handle header.
 * =============================================================================
 */

#include <stdint.h>
#include <rdma/fi_errno.h>

/*
 * =============================================================================
 * Device function qualifier — adapts to the active compiler
 * =============================================================================
 */
#if defined(__CUDACC__) || (defined(__HIP_DEVICE_COMPILE__) && __HIP_DEVICE_COMPILE__)
  #define FI_ACC_DEV __device__ static inline
#elif defined(__SYCL_DEVICE_ONLY__)
  #define FI_ACC_DEV static inline
#else
  #define FI_ACC_DEV static inline
#endif

/*
 * =============================================================================
 * Scope hint for cooperative operations
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
 * Provider identifiers
 * =============================================================================
 */
#define FI_ACC_PROV_EFA    1
#define FI_ACC_PROV_VERBS  2
#define FI_ACC_PROV_CXI    3

/*
 * =============================================================================
 * Common handle header — every exported opaque handle (EP, CQ, CNTR)
 * MUST embed this struct as its first member. The dispatch layer reads
 * it to route to the correct provider implementation at runtime.
 *
 * Providers populate this at export time (fi_ep_export_acc, etc.).
 * Consumers never inspect it — handles remain opaque void*.
 * =============================================================================
 */
struct fi_acc_hdr {
	uint32_t provider;   /* FI_ACC_PROV_EFA, FI_ACC_PROV_VERBS, ... */
	uint32_t version;    /* handle layout version (provider-defined) */
};

/*
 * =============================================================================
 * Provider implementations — each uses FI_ACC_DEV and compiler-adaptive
 * intrinsic macros, so the same source works across CUDA/HIP/SYCL/C.
 * =============================================================================
 */
#include <rdma/acc/fi_acc_efa_device.h>
/* Future: #include <rdma/acc/fi_acc_verbs_device.h> */
/* Future: #include <rdma/acc/fi_acc_cxi_device.h> */

/*
 * =============================================================================
 * Dispatch functions — switch on provider tag in the handle
 * =============================================================================
 */

FI_ACC_DEV int
fi_acc_write(void *acc_ep, const void *buf, void *desc, uint64_t size,
	     uint64_t data, void *peer, uint64_t raddr, uint64_t rkey,
	     void *ctxt, int scope, uint64_t flags)
{
	struct fi_acc_hdr *hdr = (struct fi_acc_hdr *)acc_ep;
	switch (hdr->provider) {
	case FI_ACC_PROV_EFA:
		return fi_acc_write_efa(acc_ep, buf, desc, size, data, peer,
				       raddr, rkey, ctxt, scope, flags);
	default:
		return -FI_ENOSYS;
	}
}

FI_ACC_DEV int
fi_acc_read(void *acc_ep, void *buf, void *desc, uint64_t size,
	    void *peer, uint64_t raddr, uint64_t rkey,
	    void *ctxt, int scope, uint64_t flags)
{
	struct fi_acc_hdr *hdr = (struct fi_acc_hdr *)acc_ep;
	switch (hdr->provider) {
	case FI_ACC_PROV_EFA:
		return fi_acc_read_efa(acc_ep, buf, desc, size, peer,
				      raddr, rkey, ctxt, scope, flags);
	default:
		return -FI_ENOSYS;
	}
}

FI_ACC_DEV int
fi_acc_send(void *acc_ep, const void *buf, uint64_t size, void *desc,
	    uint64_t data, void *peer, void *ctxt, int scope, uint64_t flags)
{
	struct fi_acc_hdr *hdr = (struct fi_acc_hdr *)acc_ep;
	switch (hdr->provider) {
	case FI_ACC_PROV_EFA:
		return fi_acc_send_efa(acc_ep, buf, size, desc, data, peer,
				      ctxt, scope, flags);
	default:
		return -FI_ENOSYS;
	}
}

FI_ACC_DEV int
fi_acc_recv(void *acc_ep, void *buf, void *desc, uint64_t size,
	    void *peer, void *ctxt, int scope, uint64_t flags)
{
	struct fi_acc_hdr *hdr = (struct fi_acc_hdr *)acc_ep;
	switch (hdr->provider) {
	case FI_ACC_PROV_EFA:
		return fi_acc_recv_efa(acc_ep, buf, desc, size, peer, ctxt,
				      scope, flags);
	default:
		return -FI_ENOSYS;
	}
}

FI_ACC_DEV void
fi_acc_flush(void *acc_ep, uint64_t flags)
{
	struct fi_acc_hdr *hdr = (struct fi_acc_hdr *)acc_ep;
	switch (hdr->provider) {
	case FI_ACC_PROV_EFA:
		fi_acc_flush_efa(acc_ep, flags);
		break;
	default:
		break;
	}
}

/*
 * Completion — counters and CQ
 */

FI_ACC_DEV uint64_t
fi_acc_cntr_read(void *acc_cntr)
{
	struct fi_acc_hdr *hdr = (struct fi_acc_hdr *)acc_cntr;
	switch (hdr->provider) {
	case FI_ACC_PROV_EFA:
		return fi_acc_cntr_read_efa(acc_cntr);
	default:
		return 0;
	}
}

FI_ACC_DEV uint64_t
fi_acc_cntr_readerr(void *acc_cntr)
{
	struct fi_acc_hdr *hdr = (struct fi_acc_hdr *)acc_cntr;
	switch (hdr->provider) {
	case FI_ACC_PROV_EFA:
		return fi_acc_cntr_readerr_efa(acc_cntr);
	default:
		return 0;
	}
}

FI_ACC_DEV void
fi_acc_cntr_wait(void *acc_cntr, uint64_t target)
{
	struct fi_acc_hdr *hdr = (struct fi_acc_hdr *)acc_cntr;
	switch (hdr->provider) {
	case FI_ACC_PROV_EFA:
		fi_acc_cntr_wait_efa(acc_cntr, target);
		break;
	default:
		break;
	}
}

FI_ACC_DEV void *
fi_acc_cq_poll(void *acc_cq, uint32_t position)
{
	struct fi_acc_hdr *hdr = (struct fi_acc_hdr *)acc_cq;
	switch (hdr->provider) {
	case FI_ACC_PROV_EFA:
		return fi_acc_cq_poll_efa(acc_cq, position);
	default:
		return (void *)0;
	}
}

FI_ACC_DEV void
fi_acc_cq_pop(void *acc_cq, uint32_t amount)
{
	struct fi_acc_hdr *hdr = (struct fi_acc_hdr *)acc_cq;
	switch (hdr->provider) {
	case FI_ACC_PROV_EFA:
		fi_acc_cq_pop_efa(acc_cq, amount);
		break;
	default:
		break;
	}
}

FI_ACC_DEV uint32_t
fi_acc_wc_read_vendor_err(void *cqe)
{
	return fi_acc_wc_read_vendor_err_efa(cqe);
}

#endif /* FI_ACC_DEVICE_H */
