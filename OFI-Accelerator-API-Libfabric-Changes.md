# OFI Accelerator API — Libfabric Source Code Changes

## Overview

This document describes all source code changes made to the libfabric `fi_accelerator` branch
to implement the OFI Accelerator API. The API enables GPU/accelerator-initiated communication
(GPU Direct Async — Kernel Initiated) through a portable interface that replaces
provider-specific extensions like `fi_efa_ops_gda`.

---

## Modified Files

### 1. `include/rdma/fabric.h`

**Change:** Added `FI_ACC` capability flag at bit 44.

```c
#define FI_ACC			(1ULL << 44)
/* #define FI_XPU_TRIGGER		(1ULL << 44) -- replaced by FI_ACC */
```

**Rationale:** Bit 44 was reserved (`FI_XPU_TRIGGER`, commented out) and is now used for the
accelerator API capability. Consumers pass `FI_ACC` in `fi_info->caps` to request
accelerator-capable resources.

---

### 2. `prov/efa/src/efa_base_ep.h`

**Change:** Added `struct efa_acc_state *acc_state` field and forward declaration.

```c
struct efa_acc_state;
// ...
struct efa_base_ep {
    // ... existing fields ...
    /* OFI Accelerator API state (non-NULL if created with FI_ACC) */
    struct efa_acc_state *acc_state;
};
```

**Rationale:** The EP needs to hold accelerator state (mapped device pointers, callbacks)
between object creation and export.

---

### 3. `prov/efa/src/efa_cq.h`

**Change:** Added `struct efa_acc_state *acc_state` field and forward declaration.

```c
struct efa_acc_state;
// ...
struct efa_cq {
    // ... existing fields ...
    /* OFI Accelerator API state (non-NULL if created with FI_ACC) */
    struct efa_acc_state *acc_state;
};
```

---

### 4. `prov/efa/src/efa_cntr.h`

**Change:** Added `struct efa_acc_state *acc_state` field and forward declaration.

```c
struct efa_acc_state;
// ...
struct efa_cntr {
    // ... existing fields ...
    /* OFI Accelerator API state (non-NULL if created with FI_ACC) */
    struct efa_acc_state *acc_state;
};
```

---

## New Files

### 5. `include/rdma/fi_acc.h` — Public Host-Side API Header

**Purpose:** Defines the portable OFI Accelerator API that consumers use on the host side.

**Key Contents:**

| Symbol | Description |
|--------|-------------|
| `FI_ACC` | Capability flag (1ULL << 44) |
| `struct fi_acc_info` | Memory allocation callbacks (alloc/import/free) passed at object creation |
| `enum fi_acc_mem_type` | `FI_ACC_MEM_USER` or `FI_ACC_MEM_PROVIDER` |
| `FI_ACC_IMPORT_IOMEMORY` | Import flag for BAR MMIO regions |
| `FI_ACC_IMPORT_DEVICEMAP` | Import flag for device address space mapping |
| `FI_ACC_CNTR_EXTERNAL_MEM` | Counter lives in external device memory |
| `struct fi_acc_wq_attr` | Work queue geometry (buffer, doorbell, depth, entry_size, max_batch) |
| `struct fi_acc_ep_attr` | Exported EP: SQ + RQ attrs |
| `struct fi_acc_cq_attr` | Exported CQ: buffer, entry_size, num_entries |
| `struct fi_acc_cntr_attr` | Exported counter: device pointer to NIC-written value |
| `struct fi_acc_mr_attr` | Exported MR: lkey |
| `struct fi_acc_peer_addr` | Exported peer: AHN, remote_qpn, remote_qkey |
| `enum fi_acc_scope` | `FI_ACC_WORK_ITEM` / `FI_ACC_SUBGROUP` / `FI_ACC_WORK_GROUP` |
| `fi_acc_ep_export()` | Export EP queue resources with device pointers |
| `fi_acc_cq_export()` | Export CQ ring buffer |
| `fi_acc_cntr_export()` | Export counter device pointer |
| `fi_acc_mr_export()` | Export MR lkey |
| `fi_acc_av_lookup()` | Export resolved peer address |

---

### 6. `include/rdma/fi_acc_device.h` — Device-Side API Header

**Purpose:** Inline functions callable from GPU/accelerator kernels. Replaces efa-dp-direct.

**Compiler Detection:**
- CUDA (`__CUDACC__`): uses `__threadfence_system()`, `atomicCAS`, etc.
- HIP (`__HIP_DEVICE_COMPILE__`): same intrinsics
- SYCL (`__SYCL_DEVICE_ONLY__`): placeholder
- Host: no-op stubs for type-checking

**Key Types:**

| Type | Description |
|------|-------------|
| `struct fi_acc_dev_wq` | Work queue state (pc, phase, queue_mask, buf, db, entry_size, etc.) |
| `struct fi_acc_dev_qp` | QP = SQ + RQ + inline/sge limits |
| `struct fi_acc_dev_cq` | CQ state (cc, phase, queue_mask, buf, entry_size) |
| `struct fi_acc_dev_cntr` | Counter (volatile uint64_t *value) |
| `struct fi_acc_dev_peer` | Peer addressing (ahn, remote_qpn, remote_qkey) |
| `struct fi_acc_dev_wqe` | Opaque 64-byte WQE buffer |

**Key Functions:**

| Function | Replaces (efa-dp-direct) |
|----------|--------------------------|
| `fi_acc_dev_write_prep()` | `efa_cuda_init_rdma_write_wr()` + `efa_cuda_wr_set_sge()` |
| `fi_acc_dev_wr_set_peer()` | `efa_cuda_wr_set_remote()` |
| `fi_acc_dev_sq_start_batch()` | `efa_cuda_start_sq_batch()` |
| `fi_acc_dev_sq_place()` | `efa_cuda_sq_batch_place_wr()` |
| `fi_acc_dev_sq_flush()` | `efa_cuda_flush_sq_wrs()` |
| `fi_acc_dev_cq_poll()` | `efa_cuda_cq_poll()` |
| `fi_acc_dev_cq_pop()` | `efa_cuda_cq_pop()` |
| `fi_acc_dev_cntr_read()` | `*cntr_ptr` (direct read) |
| `fi_acc_dev_cntr_wait()` | Manual spin loop |
| `fi_acc_dev_sq_check()` | Backpressure spin |
| `fi_acc_dev_lock()` / `fi_acc_dev_unlock()` | `atomicCAS` / `atomicExch` spinlock |
| `fi_acc_dev_post_recv()` | `efa_cuda_post_recv_wr()` |
| `fi_acc_dev_rq_flush()` | `efa_cuda_flush_rq_wrs()` |

---

### 7. `prov/efa/src/efa_acc.h` — EFA Provider Accelerator Header

**Purpose:** Internal EFA provider definitions for accelerator state and function declarations.

**Key Type:**

```c
struct efa_acc_state {
    struct fi_acc_info acc_info;     /* Consumer callbacks */
    void *sq_buf_dev;               /* SQ ring → device ptr */
    void *sq_db_dev;                /* SQ doorbell → device ptr */
    void *rq_buf_dev;               /* RQ ring → device ptr */
    void *rq_db_dev;                /* RQ doorbell → device ptr */
    void *cq_buf_dev;               /* CQ ring → device ptr */
    void *cntr_value_dev;           /* Counter → GPU HBM ptr */
    int   cntr_dmabuf_fd;           /* DMA-BUF fd for cleanup */
    void *cntr_alloc_addr;          /* alloc addr for cleanup */
};
```

---

### 8. `prov/efa/src/efa_acc.c` — EFA Provider Accelerator Implementation

**Purpose:** Implements all 5 `fi_acc_*_export()` functions for the EFA provider.

**Implementation Details:**

| Function | Internal Call | Memory Mapping |
|----------|--------------|----------------|
| `efa_acc_ep_export()` | `efadv_query_qp_wqs()` | `acc_info.import(IOMEMORY\|DEVICEMAP)` for SQ buffer/doorbell; `import(DEVICEMAP)` for RQ buffer |
| `efa_acc_cq_export()` | `efadv_query_cq()` | `acc_info.import(DEVICEMAP)` for CQ buffer (host RAM) |
| `efa_acc_cntr_export()` | Returns stored ptr | GPU HBM pointer set during cntr_open |
| `efa_acc_mr_export()` | `ibv_mr->lkey` | Direct field read |
| `efa_acc_av_lookup()` | `efa_av_addr_to_conn()` | `conn->ah->ahn`, `conn->ep_addr->qpn/qkey` |

**Conditional Compilation:**
- `HAVE_EFADV_QUERY_QP_WQS` guards `efa_acc_ep_export()`
- `HAVE_EFADV_QUERY_CQ` guards `efa_acc_cq_export()`
- Falls back to `-FI_EOPNOTSUPP` when rdma-core lacks the APIs

---

## Architecture Diagram

```
Consumer Application
    │
    │  #include <rdma/fi_acc.h>           ← host setup
    │  #include <rdma/fi_acc_device.h>    ← GPU kernel
    │
    ▼
┌──────────────────────────────────────────────────┐
│  Public API (include/rdma/)                       │
│                                                   │
│  fi_getinfo(caps = FI_ACC)                        │
│  fi_cq_open(flags = FI_ACC, acc_info = ...)       │
│  fi_cntr_open(flags = FI_ACC, acc_info = ...)     │
│  fi_endpoint(FI_ACC) + bind + enable              │
│                                                   │
│  fi_acc_ep_export(ep, &attr)   → SQ/RQ geometry   │
│  fi_acc_cq_export(cq, &attr)   → CQ ring buffer  │
│  fi_acc_cntr_export(cntr, &attr)→ GPU HBM ptr     │
│  fi_acc_mr_export(mr, &attr)   → lkey            │
│  fi_acc_av_lookup(av, addr, &peer) → AHN/QPN     │
└──────────────────────┬───────────────────────────┘
                       │ provider dispatch
                       ▼
┌──────────────────────────────────────────────────┐
│  EFA Provider (prov/efa/src/efa_acc.c)            │
│                                                   │
│  efadv_query_qp_wqs() → host VA of SQ/RQ/DB      │
│    → acc_info.import(IOMEMORY|DEVICEMAP)          │
│    → device pointer returned in fi_acc_ep_attr    │
│                                                   │
│  efadv_query_cq() → host VA of CQ ring           │
│    → acc_info.import(DEVICEMAP)                   │
│    → device pointer returned in fi_acc_cq_attr    │
│                                                   │
│  efa_av_addr_to_conn() → conn->ah->ahn           │
│    → fi_acc_peer_addr filled                      │
└──────────────────────────────────────────────────┘
```

---

## Remaining Work

1. **Object creation hooks** — Allocate `efa_acc_state` when `FI_ACC` flag detected in
   `fi_cq_open()` / `fi_cntr_open()` / `fi_endpoint()`.

2. **Counter open path** — Wire `efa_acc_cntr_open()` to call `acc_info.alloc()` for GPU
   HBM, export DMA-BUF, pass to `efadv_create_comp_cntr()`.

3. **Provider ops registration** — Make `fi_acc_*_export()` callable via public API dispatch
   (either new fid ops or `fi_open_ops` pattern).

4. **Cleanup on close** — Free `efa_acc_state`, unregister device memory in destructors.

5. **Build system** — Add `efa_acc.c` to `Makefile.include` in the EFA provider.


---

## Comparison with Original OFI Accelerator API Proposal

The original proposal (Jianxin Xiong, 4/21/2026) defines a high-level API with
opaque exports and simplified device-side calls. Our implementation diverges in
several significant ways based on production GDAKI requirements discovered
through analysis of aws-ofi-nccl, efa-dp-direct, and perftest.

### Host-Side API: What We Changed

| Proposal API | Our Implementation | Rationale |
|---|---|---|
| `fi_ep_export_acc(ep, flags, void **acc_ep, size_t *size)` → opaque blob | `fi_acc_ep_export(ep, flags, struct fi_acc_ep_attr *attr)` → structured output with SQ/RQ buffer, doorbell, num_entries, entry_size, max_batch | Consumer needs individual queue geometry to build device-side QP descriptor and compute backpressure (sq_size). An opaque blob forces provider-specific unpacking. |
| `fi_cq_export_acc(cq, flags, void **acc_cq, size_t *size)` → opaque blob | `fi_acc_cq_export(cq, flags, struct fi_acc_cq_attr *attr)` → buffer ptr, entry_size, num_entries | Consumer needs entry_size for CQ offset calculation and num_entries for phase-bit wrap logic. |
| `fi_cntr_export_acc(cntr, flags, void **acc_cntr, size_t *size)` → opaque blob | `fi_acc_cntr_export(cntr, flags, struct fi_acc_cntr_attr *attr)` → `volatile uint64_t *value` | The only thing the device kernel reads is the counter value pointer. No blob needed. |
| `fi_acc_info.alloc/import` (two callbacks) | `fi_acc_info.user.alloc/import/free` (three callbacks) + `enum fi_acc_mem_type` | Added `free` for cleanup. Added `FI_ACC_IMPORT_IOMEMORY`/`FI_ACC_IMPORT_DEVICEMAP` flags to distinguish BAR MMIO from host RAM mapping. |
| `fi_acc_info` on `fi_cq_attr` | `fi_acc_info` passed via `efa_acc_state` at object creation | Same intent, but we store acc_info in provider-internal state rather than extending the public attr structs (less ABI disruption). |
| (not in proposal) | `fi_acc_mr_export(mr, flags, struct fi_acc_mr_attr *attr)` | **Added.** The proposal omits MR lkey export. GPU kernels need lkey for SGE fields. |
| (not in proposal) | `fi_acc_av_lookup(av, fi_addr, flags, struct fi_acc_peer_addr *addr)` | **Added.** The proposal's `fi_acc_send(..., peer, ...)` hides addressing, but real HW needs explicit (AHN, QPN, QKEY) in WQE destination fields. |
| (not in proposal) | `fi_acc_av_lookup_batch(av, fi_addrs[], count, flags, addrs[])` | **Added.** Bulk version for building [total_slots × nranks] target tables as used by GDAKI. |
| (not in proposal) | `fi_acc_mr_get_info(mr, flags, &lkey, &addr, &rkey)` | **Added.** Exports (lkey, local_addr, rkey) for allgather-based key exchange (regMrSym pattern). |
| (not in proposal) | `efa_acc_cntr_open(domain, attr, acc_info, &cntr, ctx)` | **Added.** Integrates GPU HBM allocation + DMA-BUF export + efadv_create_comp_cntr into one call, replacing 3 separate manual steps. |

### Host-Side API: What We Kept from the Proposal

| Proposal API | Our Implementation | Notes |
|---|---|---|
| `FI_ACC` capability flag in `fi_info->caps` | `#define FI_ACC (1ULL << 44)` in `fabric.h` | Same concept. We use bit 44 (was reserved `FI_XPU_TRIGGER`). |
| `fi_acc_info` with `iface` + `device` + allocation callbacks | `struct fi_acc_info` with `iface`, `device`, `mem_type`, union of `user`/`dmabuf` | Extended with `mem_type` enum and `free` callback. |
| `enum fi_acc_scope` (WORK_ITEM / SUBGROUP / WORK_GROUP) | `enum fi_acc_scope` in `fi_acc.h` | Kept as-is. Not yet used in device functions (scope is implicit in how threads call start_batch/place/flush). |

### Device-Side API: What We Changed

| Proposal API | Our Implementation | Rationale |
|---|---|---|
| `fi_acc_send(acc_ep, buf, size, desc, data, peer, ctxt, scope, flags)` | `fi_acc_dev_write_prep()` + `fi_acc_dev_wr_set_peer()` + `fi_acc_dev_sq_start_batch()` + `fi_acc_dev_sq_place()` + `fi_acc_dev_sq_flush()` | The proposal's fire-and-forget model doesn't map to real HW. Production uses explicit batch lifecycle: reserve → prepare WQE → place → flush (doorbell). Our API exposes this. |
| `fi_acc_write(acc_ep, buf, desc, size, data, peer, raddr, rkey, ctxt, scope, flags)` | Same decomposed pattern as above | Same reasoning. One `fi_acc_write()` would hide batching, phase-bit stamping, and doorbell amortization. |
| `fi_acc_cq_read(acc_cq, ...)` | `fi_acc_dev_cq_poll(cq, position)` + `fi_acc_dev_cq_pop(cq, amount)` | Position-based parallel polling (thread N polls position N) is essential for cooperative BW kernels. A single `cq_read()` doesn't support this. |
| `fi_acc_cntr_read(acc_cntr, ...)` | `fi_acc_dev_cntr_read(cntr)` + `fi_acc_dev_cntr_wait(cntr, target)` | Essentially the same, but we add `fi_acc_dev_sq_check()` for backpressure pattern. |
| `fi_acc_flush(acc_ep)` | `fi_acc_dev_sq_flush(qp)` | Same concept, narrower scope (per-QP, not per-EP). |
| (not in proposal) | `fi_acc_dev_lock(lock)` / `fi_acc_dev_unlock(lock)` | **Added.** Per-QP spinlock for multi-CTA serialization. Required when multiple thread blocks target the same QP. |
| (not in proposal) | `fi_acc_dev_post_recv(qp, index, addr, len, lkey)` + `fi_acc_dev_rq_flush(qp, count)` | **Added.** GPU-side recv posting. Validated by perftest; needed for send/recv and write+IMM patterns. |
| (not in proposal) | `fi_acc_dev_sq_check(submitted, cntr, sq_size, batch)` | **Added.** SQ overflow backpressure. GPU spins until in-flight WRs allow new batch. Critical gap in the proposal. |
| (implicit in proposal via scope) | `fi_acc_dev_sq_start_batch(qp, batch_size)` | **Explicit batch reservation.** The proposal implies batching via `scope` parameter; our API makes it explicit with a count, matching the real HW doorbell amortization model. |

### Device-Side API: What We Kept from the Proposal

| Proposal Concept | Our Implementation | Notes |
|---|---|---|
| Device functions callable from compute kernels | `FI_ACC_DEV` qualifier (maps to `__device__ static inline` for CUDA) | Same intent. We add HIP and SYCL macro paths. |
| Scope concept for cooperative operations | Implicitly supported: thread 0 calls start_batch/flush, all threads call place | We don't pass scope as a parameter; the cooperation pattern is in the calling code. |

### Summary of Gaps Filled

The original proposal identifies high-level semantics but leaves critical
production concerns unaddressed. Our implementation fills these gaps:

| Gap in Proposal | How We Address It |
|---|---|
| No SQ backpressure mechanism | `fi_acc_dev_sq_check()` — spin on counter until room available |
| No explicit batch submission model | `start_batch` → `place` × N → `flush` lifecycle |
| Opaque blob exports | Structured `fi_acc_*_attr` with individual fields |
| No hardware counter export | `fi_acc_cntr_export()` → GPU HBM pointer |
| No address resolution export | `fi_acc_av_lookup()` / `fi_acc_av_lookup_batch()` |
| No MR key export | `fi_acc_mr_export()` + `fi_acc_mr_get_info()` |
| No GPU-side recv posting | `fi_acc_dev_post_recv()` + `fi_acc_dev_rq_flush()` |
| No multi-CTA serialization | `fi_acc_dev_lock()` / `fi_acc_dev_unlock()` |
| No DMA-BUF first-class support | `FI_ACC_IMPORT_IOMEMORY` / `FI_ACC_ALLOC_DMABUF` flags |
| No position-based CQ polling | `fi_acc_dev_cq_poll(cq, position)` — thread N polls slot N |

After analyzing the aws-ofi-nccl `nccl_ofi_gin_gdaki_resources.h` and
`nccl_ofi_gin_gdaki_dev.h`, the following additions ensure the OFI
Accelerator API fully covers the GDAKI workflow:

### Added APIs

| Function | Purpose | Replaces |
|----------|---------|----------|
| `fi_acc_av_lookup_batch()` | Bulk resolve [total_slots × nranks] target table | Loop of `gda_ops->query_addr()` in `gdaki_target_addressing::populate()` |
| `fi_acc_mr_get_info()` | Export (lkey, local_addr, rkey) for allgather | `gda_ops->get_mr_lkey()` + `fi_mr_key()` + addr extraction |
| `efa_acc_cntr_open()` | Create HW counter with GPU HBM via acc_info.alloc() + DMA-BUF + efadv_create_comp_cntr | `gdaki_hw_counter::create()` manual sequence |
| `efa_acc_state_create()` / `efa_acc_state_destroy()` | Lifecycle management for acc_state on EP/CQ/counter | Manual struct management |

### GDAKI Pattern Coverage

| GDAKI Pattern | OFI Acc API Coverage |
|---------------|---------------------|
| Data EP (QP + FI_WRITE counter) | `fi_endpoint()` + `fi_ep_bind(FI_WRITE)` + `fi_acc_ep_export()` + `fi_acc_cntr_export()` |
| PutValue EP (dedicated staging EP) | Same as Data EP — separate fi_endpoint + export |
| Signal/Counter EP (FI_WRITE + FI_REMOTE_WRITE) | `fi_endpoint()` + `fi_ep_bind()` both counters + `fi_acc_ep_export()` + 2× `fi_acc_cntr_export()` |
| Target addressing [total_slots × nranks] | `fi_av_insert()` per slot/peer + `fi_acc_av_lookup_batch()` |
| Multi-rail (contextId % num_rails) | Per-rail domain → per-rail EP/CQ/MR exports |
| SQ backpressure (submitted − counter + batch ≤ sq_size) | `fi_acc_ep_attr.sq.num_entries` = sq_size; `fi_acc_cntr_export()` = counter ptr |
| Per-QP spinlock (multi-CTA serialization) | Consumer allocates GPU uint32_t; uses `fi_acc_dev_lock()`/`fi_acc_dev_unlock()` |
| Scratch buffer (signal-only 0-byte writes) | `fi_mr_reg()` + `fi_acc_mr_get_info()` → allgather → GPU table |
| PutValue slot pool (per-EP slice) | Consumer allocates GPU buffer, `fi_mr_reg()` + `fi_acc_mr_get_info()` → lkey |
| Per-peer MR (regMrSym) | `fi_mr_reg()` + `fi_acc_mr_get_info()` → allgather (addr,rkey) per rank → GPU table |
| cntr_offset (reset-without-zeroing) | Pure software state — consumer manages on device |


---

## Design Direction: Opaque Export + Provider Device Library

### Goal

**Replace `fi_efa_ops_gda` and `efa-dp-direct` entirely with the OFI Accelerator API.**

The consumer (NCCL / aws-ofi-nccl) should not need:
- `fi_open_ops(FI_EFA_GDA_OPS)` — no provider-specific host ops
- `#include <efa_cuda_dp_impl.cuh>` — no provider-specific device library
- `cuMemHostRegister` / `cuMemHostGetDevicePointer` — no manual BAR mapping
- Knowledge of EFA WQE format, phase-bit protocol, or doorbell semantics

Everything is encapsulated behind the portable `fi_acc_*` API, with the
provider (libfabric EFA) shipping both host-side export functions and
device-side inline functions.

NCCL GIN today implements its own warp-cooperative SQ protocol rather than
using efa-dp-direct's `start_sq_batch`/`place_wr`/`flush_sq_wrs`. Our
`fi_acc_write()` encapsulates this pattern internally via `scope` + `flags`:
- `FI_ACC_SUBGROUP` scope → warp-cooperative slot reservation + parallel posting
- `FI_MORE` flag → deferred doorbell (aggregate requests)
- Internal dual backpressure (max_batch staging limit + counter-based ring overflow)
- Internal slot-order rendezvous for multi-group coordination
- Counter-only completion (no CQ polling on data path)

### Requirements from NCCL/aws-ofi-nccl Team

NCCL GIN today implements a ~200-line warp-cooperative SQ posting template
(`postRdmaWrite<mode>`) with atomic reservation, deferred doorbells, and dual
backpressure. All these operations are encapsulated inside our provider's
`fi_acc_write()` inline implementation. If NCCL adopts our API, their
`postRdmaWrite<mode>()` becomes a call to `fi_acc_write(scope, flags)`.

The efa-dp-direct developers have received feedback from NVIDIA:

> "We would like to have only device-side code in the NCCL repo. Today the
> only thing host and device code share is the QP/CQ layout (5 structs).
> The files `efa_cuda_dp_impl.cuh`, `efa_io_defs.h`, and `efa_cuda_dp.h`
> provide the entire device functionality. Can we move these into a separate
> directory which will be mirrored in NCCL?"

This maps directly to our architecture:

| efa-dp-direct (today) | OFI Accelerator API (target) |
|---|---|
| `efa_cuda_dp.h` — struct layouts (QP/CQ/WQ) | `fi_acc_device.h` — struct definitions (for compiler inlining) |
| `efa_cuda_dp_impl.cuh` — device function implementations | `fi_acc_device.h` — inline device functions |
| `efa_io_defs.h` — WQE/CQE HW formats | Internal to provider's device implementation |
| `efa_cuda_dp.cuh` — host+device declarations (mixed) | Split: host decls in `fi_acc.h`, device in `fi_acc_device.h` |
| `efa_cuda_dp.cu` — host-side QP/CQ create/destroy | `efa_acc.c` — provider does this inside `fi_acc_ep_export()` |

NCCL mirrors only `fi_acc_device.h` into its tree — one file, provider-neutral
API, same pattern as the proposal but shipped by libfabric.

### Architecture: Opaque Export + Inlined Device Functions

```
┌──────────────────────────────────────────────────────────┐
│ Consumer (NCCL / aws-ofi-nccl)                           │
│                                                          │
│ Host code:                                               │
│   #include <rdma/fi_acc.h>                               │
│   fi_acc_ep_export(ep, flags, &acc_ep, &acc_ep_size);    │
│   fi_acc_cq_export(cq, flags, &acc_cq, &acc_cq_size);   │
│   fi_acc_cntr_export(cntr, flags, &acc_cntr, &size);     │
│   // All opaque GPU blobs — consumer never peeks inside  │
│                                                          │
│ Device code:                                             │
│   #include <rdma/fi_acc_device.h>                        │
│   fi_acc_write(acc_ep, buf, len, lkey, raddr, rkey,      │
│                acc_peer, scope, flags);                   │
│   fi_acc_cq_poll(acc_cq, &entry);                        │
│   fi_acc_cntr_read(acc_cntr);                            │
│   // Consumer calls high-level functions, never touches  │
│   // ring buffers, doorbells, or WQE formats directly    │
└──────────────────────────────────────────────────────────┘

What the provider does internally (invisible to consumer):
  fi_acc_ep_export():
    1. efadv_query_qp_wqs() → host VAs of SQ/RQ/doorbells
    2. acc_info.import() → map BAR MMIO into GPU address space
    3. Allocate GPU memory for fi_acc_dev_ep struct
    4. Fill struct with device ptrs, ring geometry, phase state
    5. H2D copy → return opaque GPU pointer to consumer

  fi_acc_write() [inline device function, in fi_acc_device.h]:
    1. Build WQE from parameters (opcode, raddr, rkey, SGE)
    2. Stamp phase bit
    3. Write 64 bytes to SQ ring slot (BAR MMIO)
    4. __threadfence_system() + doorbell write
    (All inlined — zero overhead vs raw efa-dp-direct calls)
```

### What's Opaque vs. What's Exposed

| Resource | Export API | Device-side access | Notes |
|---|---|---|---|
| **EP (QP)** | `fi_acc_ep_export() → void *acc_ep` | `fi_acc_write(acc_ep, ...)` / `fi_acc_send(acc_ep, ...)` | Fully opaque. Ring buffer, doorbell, WQE format all hidden. |
| **CQ** | `fi_acc_cq_export() → void *acc_cq` | `fi_acc_cq_poll(acc_cq, position)` / `fi_acc_cq_pop(acc_cq, n)` | Fully opaque. Phase-bit protocol, entry format hidden. |
| **Counter** | `fi_acc_cntr_export() → void *acc_cntr` | `fi_acc_cntr_read(acc_cntr)` / `fi_acc_cntr_wait(acc_cntr, target)` | Opaque. With EFA HW counter in GPU HBM, `fi_acc_cntr_read()` inlines to a single `ld.global.volatile` — same as raw pointer read, zero overhead. |
| **Peer address** | `fi_acc_av_export(av, fi_addr) → void *acc_peer` | Passed to `fi_acc_write(..., acc_peer, ...)` | Opaque. Provider stamps (AHN, QPN, QKEY) into WQE internally. |
| **MR descriptor** | `fi_acc_mr_export(mr) → void *acc_desc` | Passed as `desc` to `fi_acc_write(..., desc, ...)` | Opaque. Provider extracts lkey internally. |
| **SQ lock** | Inside acc_ep | `fi_acc_ep_lock(acc_ep)` / `fi_acc_ep_unlock(acc_ep)` | Hidden inside opaque EP. Device function does `atomicCAS` on internal field. |
| **Backpressure** | Inside acc_ep + acc_cntr | `fi_acc_write()` spins internally if SQ full | Provider checks `(submitted - *cntr + 1) <= sq_size` before posting. Consumer never sees sq_size or submitted_count. |

### Counter Read is Fully Opaque — No Performance Loss

With EFA's HW counter in GPU HBM, `fi_acc_cntr_read(acc_cntr)` is:

```c
FI_ACC_DEV uint64_t fi_acc_cntr_read(void *acc_cntr) {
    struct fi_acc_dev_cntr *c = (struct fi_acc_dev_cntr *)acc_cntr;
    return *c->value;  // single volatile load from GPU HBM
}
```

This inlines to one instruction. The consumer calls `fi_acc_cntr_read()` for:
- Signal detection: `while (fi_acc_cntr_read(signal_cntr) < expected) {}`
- Flush/completion: `while (fi_acc_cntr_read(write_cntr) < submitted) {}`

No raw pointer exposure needed.

### Device-Side API (High-Level)

```c
// === Data transfer (replaces WQE construction + batch + flush) ===
int fi_acc_write(void *acc_ep,
                 const void *buf, size_t len, void *desc,
                 uint64_t raddr, uint32_t rkey,
                 void *acc_peer,
                 enum fi_acc_scope scope, uint64_t flags);

int fi_acc_send(void *acc_ep,
                const void *buf, size_t len, void *desc,
                void *acc_peer,
                enum fi_acc_scope scope, uint64_t flags);

int fi_acc_read(void *acc_ep,
                void *buf, size_t len, void *desc,
                uint64_t raddr, uint32_t rkey,
                void *acc_peer,
                enum fi_acc_scope scope, uint64_t flags);

// === Completion (replaces phase-bit CQ polling) ===
void *fi_acc_cq_poll(void *acc_cq, uint32_t position);
void  fi_acc_cq_pop(void *acc_cq, uint32_t amount);

// === Counter (replaces raw pointer reads) ===
uint64_t fi_acc_cntr_read(void *acc_cntr);
void     fi_acc_cntr_wait(void *acc_cntr, uint64_t target);

// === Receive posting (for send/recv and write+IMM) ===
int  fi_acc_post_recv(void *acc_ep, void *buf, size_t len, void *desc);
void fi_acc_flush_recv(void *acc_ep);

// === Serialization (multi-CTA on same EP) ===
void fi_acc_ep_lock(void *acc_ep);
void fi_acc_ep_unlock(void *acc_ep);
```

### What Disappears from Consumer's View

| Hidden (was exposed in Layer 2) | Now encapsulated in |
|---|---|
| `fi_acc_ep_attr` / `fi_acc_wq_attr` (buffer, doorbell, num_entries) | Provider fills opaque blob internally in `fi_acc_ep_export()` |
| `fi_acc_dev_sq_start_batch` / `sq_place` / `sq_flush` | Inside `fi_acc_write()` |
| `fi_acc_dev_write_prep` / `wr_set_peer` | Inside `fi_acc_write()` |
| Phase bit calculation / stamping | Inside `fi_acc_write()` |
| `FI_ACC_IMPORT_IOMEMORY` / `FI_ACC_IMPORT_DEVICEMAP` | Provider decides mapping policy internally |
| `submitted_count` / `sq_size` | Provider tracks inside acc_ep, checks in `fi_acc_write()` |
| WQE format (64 bytes, opcode layout, SGE offsets) | Provider-internal |
| `__threadfence_system()` + doorbell write pattern | Inside `fi_acc_write()` / provider's flush |

### What Remains Exposed (Irreducible Consumer Decisions)

| Exposed | Why |
|---|---|
| `fi_acc_cntr_read()` / `fi_acc_cntr_wait()` | Consumer decides *when* to check and *what value* to wait for (signal ID semantics are consumer logic). But the handle is opaque. |
| `fi_acc_cq_poll(position)` | Cooperative multi-thread polling requires position parameter. |
| `fi_acc_ep_lock()` / `fi_acc_ep_unlock()` | Multi-CTA serialization is caller's scheduling decision. |
| `fi_acc_scope` parameter | Consumer tells provider "this is cooperative" for optimization. |
| `void *acc_peer` selection | Consumer selects target peer per operation. |

### Struct Visibility: "Defined for Compiler, Opaque for Usage"

The device header defines internal structs so nvcc can inline functions, but
the consumer **never constructs or inspects them**:

```c
// In fi_acc_device.h — struct IS defined (compiler needs layout for inlining)
struct fi_acc_dev_ep {
    /* INTERNAL — DO NOT ACCESS DIRECTLY */
    struct { uint8_t *buf; uint32_t *db; uint32_t pc; int phase; ... } sq;
    uint32_t sq_lock;
    uint64_t submitted_count;
    volatile uint64_t *local_cntr;
    // ...
};

// Consumer code — treats as void*, calls functions
void *acc_ep;
fi_acc_write(acc_ep, buf, len, desc, raddr, rkey, peer, scope, 0);
```

Same model as efa-dp-direct today: structs visible in header for compilation,
consumers only call API functions.

### Migration Path

Our current Layer 2 code (structured export, manual batch/place/flush) becomes
the **provider-internal implementation** of the high-level device functions:

```
Current (Layer 2, exposed):              Target (Layer 1, encapsulated):
─────────────────────────                ──────────────────────────────
Consumer calls:                          Consumer calls:
  fi_acc_ep_export → fi_acc_ep_attr        fi_acc_ep_export → void *acc_ep
  fi_acc_dev_write_prep(wr, ...)           fi_acc_write(acc_ep, buf, len, ...)
  fi_acc_dev_wr_set_peer(wr, peer)           ↓ provider internally does:
  fi_acc_dev_sq_start_batch(qp, 1)           write_prep + set_peer +
  fi_acc_dev_sq_place(qp, 0, wr)             start_batch + place + flush
  fi_acc_dev_sq_flush(qp)                    + backpressure + lock mgmt
```

The code we wrote doesn't go away — it becomes the guts of `fi_acc_write()`.
