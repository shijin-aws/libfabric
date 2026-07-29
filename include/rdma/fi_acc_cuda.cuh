/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/* SPDX-FileCopyrightText: Copyright Amazon.com, Inc. or its affiliates. All
 * rights reserved. */

#ifndef FI_ACC_CUDA_CUH
#define FI_ACC_CUDA_CUH

/*
 * =============================================================================
 * OFI Accelerator API — Unified CUDA Device Header
 *
 * This is the ONLY file consumers include from their .cu kernels:
 *
 *     #include <rdma/fi_acc_cuda.cuh>
 *
 * It provides all device-side functions (fi_acc_write, fi_acc_send, etc.)
 * with runtime dispatch to the correct provider based on a tag in the
 * exported handle header.
 *
 * Internally it includes each provider's CUDA implementation and
 * generates a switch-case dispatch. Dead-code elimination removes
 * unused providers when only one is compiled in.
 * =============================================================================
 */

#include <stdint.h>
#include <rdma/fi_acc_device.h>

/*
 * =============================================================================
 * Provider identifiers (from fi_acc_device.h):
 *   FI_ACC_PROV_EFA, FI_ACC_PROV_VERBS, FI_ACC_PROV_CXI
 * =============================================================================
 */

/*
 * =============================================================================
 * Common handle header (struct fi_acc_hdr) is defined in fi_acc_device.h.
 * Every exported opaque handle embeds it as the first member.
 * =============================================================================
 */

/*
 * =============================================================================
 * Provider implementations (CUDA-specific)
 * =============================================================================
 */

/* Error codes */
#include <rdma/fi_errno.h>

#include <rdma/acc/fi_acc_efa_cuda.cuh>
/* Future: #include <rdma/acc/fi_acc_verbs_cuda.cuh> */
/* Future: #include <rdma/acc/fi_acc_cxi_cuda.cuh> */

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
		return -FI_ENOSYS; /* FI_ENOSYS */
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
 * The counter/CQ handles also carry the provider tag.
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
	/* CQE is from a CQ we already know the provider for,
	 * but we don't have the hdr here. EFA-only for now. */
	return fi_acc_wc_read_vendor_err_efa(cqe);
}

#endif /* FI_ACC_CUDA_CUH */
