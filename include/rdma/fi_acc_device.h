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
 * OFI Accelerator API — Device-Side Common Definitions
 *
 * This header provides common macros and types used by all provider
 * device implementations. It does NOT contain function declarations —
 * consumers include the provider-specific device header directly:
 *
 *   EFA: #include "acc_cuda/fi_acc_efa_device.h"
 *
 * The provider header includes this file for the FI_ACC_DEV macro and
 * fi_acc_scope enum, then provides the inlined function implementations.
 * =============================================================================
 */

#include <stdint.h>

/* Device function qualifier.
 * Note: test __HIP_DEVICE_COMPILE__'s value, not definedness — HIP host
 * builds define it to 0. */
#if defined(__CUDACC__) || (defined(__HIP_DEVICE_COMPILE__) && __HIP_DEVICE_COMPILE__)
  #define FI_ACC_DEV __device__ static inline
#elif defined(__SYCL_DEVICE_ONLY__)
  #define FI_ACC_DEV static inline
#else
  #define FI_ACC_DEV static inline
#endif

/* Scope hint for cooperative operations */
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
 * Device-side API functions (provided by provider device header):
 *
 *   int      fi_acc_write(void *acc_ep, const void *buf, void *desc,
 *                         uint64_t size, uint64_t data, void *peer,
 *                         uint64_t raddr, uint64_t rkey, void *ctxt,
 *                         int scope, uint64_t flags);
 *   int      fi_acc_read(void *acc_ep, void *buf, void *desc,
 *                        uint64_t size, void *peer, uint64_t raddr,
 *                        uint64_t rkey, void *ctxt, int scope,
 *                        uint64_t flags);
 *   int      fi_acc_send(void *acc_ep, const void *buf, uint64_t size,
 *                        void *desc, uint64_t data, void *peer,
 *                        void *ctxt, int scope, uint64_t flags);
 *   int      fi_acc_recv(void *acc_ep, void *buf, void *desc,
 *                        uint64_t size, void *peer, void *ctxt,
 *                        int scope, uint64_t flags);
 *   void     fi_acc_flush(void *acc_ep, uint64_t flags);
 *   uint64_t fi_acc_cntr_read(void *acc_cntr);
 *   uint64_t fi_acc_cntr_readerr(void *acc_cntr);
 *   void     fi_acc_cntr_wait(void *acc_cntr, uint64_t target);
 *   void    *fi_acc_cq_poll(void *acc_cq, uint32_t position);
 *   void     fi_acc_cq_pop(void *acc_cq, uint32_t amount);
 *   uint32_t fi_acc_wc_read_vendor_err(void *cqe);
 *
 * Flags: FI_MORE defers the doorbell (ring via fi_acc_flush or a
 * subsequent post without FI_MORE); FI_REMOTE_CQ_DATA carries `data`
 * as immediate data. The scope parameter declares the widest set of
 * threads that may concurrently post to the same EP handle.
 */

#endif /* FI_ACC_DEVICE_H */
