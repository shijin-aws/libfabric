# OFI Accelerator API — Proposal

## 1. Background

Modern AI workloads, especially Mixture-of-Experts (MoE) architectures,
increasingly demand low-latency, fine-grained GPU-to-GPU communication with
device-side control. Traditional host-initiated models, where the CPU
orchestrates all RDMA operations, add coordination overhead that limits
performance for workloads requiring tight integration of computation and
communication. GPU Direct Async (GDA) networking addresses this by allowing
GPU kernels to post RDMA requests directly to the NIC, eliminating the CPU
from the data-path critical path. Multiple projects have adopted GDA in
different ways:
[DeepEP](https://github.com/deepseek-ai/DeepEP) (by DeepSeek) is a
high-performance MoE communication library that originally used NVSHMEM with
InfiniBand GPUDirect Async (IBGDA);
[pplx-kernels](https://github.com/ppl-ai/pplx-kernels) (by Perplexity)
provides MoE dispatch/combine kernels with its own flexible transport layers
including IBGDA, IBRC, and EFA;
and various other AI frameworks are exploring similar GPU-initiated approaches.
This growing fragmentation motivates a unified standard.

NCCL GIN (GPU-Initiated Networking), introduced in NCCL 2.28
([paper](https://arxiv.org/abs/2511.15076)), is a standard framework for
device-initiated RDMA communication within NCCL, aiming to consolidate this
fragmentation. DeepEP V2 has already adopted NCCL GIN as its backend. GIN
builds on a three-layer architecture: host-side APIs for device communicator
setup and collective memory window registration; device-side APIs for remote
memory operations callable from CUDA kernels; and a network plugin
architecture with dual semantics — GPUDirect Async Kernel-Initiated (GDAKI)
for direct GPU-to-NIC communication, and Proxy for equivalent functionality
via lock-free GPU-to-CPU queues over standard RDMA networks. For
InfiniBand/RoCE fabrics, NCCL GIN's GDAKI backend
([gin_gdaki.h](https://github.com/amazon-contributing/upstream-to-nccl/blob/dev/src/include/nccl_device/gin/gdaki/gin_gdaki.h))
uses [DOCA GPUNetIO](https://docs.nvidia.com/doca/sdk/gpunetio-programming-guide),
NVIDIA's GPU-centric networking library that enables CUDA kernels to directly
control RDMA communications (InfiniBand or RoCE) without CPU intervention,
with parameterized resource sharing modes (Exclusive/CTA/GPU) controlling
internal atomic scope.

For EFA, GDA support has been upstreamed to NCCL GIN using a mixture of
components: on the host side, provider-specific libfabric EFA domain ops
(`fi_efa_ops_gda` accessed via `fi_open_ops(domain, FI_EFA_GDA_OPS)`) allow
creating QP, CQ, and counter resources visible to GPU kernels (e.g., counters
backed by DMA-BUF in GPU HBM, CQs placed in GPU memory), and querying
EFA-specific internal metadata for endpoints and address resolution. On the
device side, the NCCL GIN EFA-GDA kernel
([gin_efa_gda.h](https://github.com/amazon-contributing/upstream-to-nccl/blob/dev/src/include/nccl_device/gin/efa_gda/gin_efa_gda.h))
uses [efa-dp-direct](https://github.com/amzn/efa-dp-direct) for WQE
construction, combined with its own hardcoded warp-cooperative logic that
directly manages the SQ ring, doorbells, backpressure, and completion
counters — all built on top of the raw queue metadata exposed by the host-side
ops.

To address the fragmentation of provider-specific host APIs (e.g.,
`fi_efa_ops_gda`), vendor device libraries (e.g., efa-dp-direct), and
provider details hardcoded in consumer kernels (SQ ring management,
doorbells, phase bits), the libfabric community has proposed a
[preliminary fi_accelerator API](https://github.com/ofiwg/libfabric/discussions/12166)
defining host-side export functions and device-side post/completion primitives.
This document aims to enhance and polish that preliminary API to ensure it
covers the existing GDAKI usage in production (NCCL GIN on both EFA and
InfiniBand/RoCE), validated against the actual
[gin_efa_gda.h](https://github.com/amazon-contributing/upstream-to-nccl/blob/dev/src/include/nccl_device/gin/efa_gda/gin_efa_gda.h)
and
[gin_gdaki.h](https://github.com/amazon-contributing/upstream-to-nccl/blob/dev/src/include/nccl_device/gin/gdaki/gin_gdaki.h)
implementations, while remaining general enough for other accelerator types
(Intel GPUs via SYCL/Level Zero, AMD GPUs via HIP) that may be supported in
the future.

---

## 2. API Overview

The OFI Accelerator API follows a two-phase model that mirrors how GDAKI
works in practice: the CPU sets up communication resources and exports them
as opaque handles, then the accelerator kernel uses those handles to post operations
and check completions without further CPU involvement.

On the host side, the API extends the existing libfabric object creation flow.
The consumer creates endpoints, CQs, counters, AVs, and MRs using standard
libfabric calls with a new `FI_ACC` flag and an accelerator info struct that
describes the accelerator environment. Once created, each object is exported to a
accelerator-accessible opaque handle. These handles encapsulate everything the
device-side functions need — ring buffer pointers, doorbells, counter
addresses, peer tables — without exposing hardware-specific details to the
consumer.

On the device side, the API provides communication functions callable from
accelerator kernels for posting RDMA operations (write, read, send/recv, tagged,
atomics), doorbell control (flush), and completion tracking (counters and CQ
polling). These device-side functions are provided as inlined implementations
in a provider-supplied header (e.g., a `.cuh` file for CUDA), compiled
directly into the consumer's accelerator kernel.

---

## 3. Host-Side API

### Object Creation

In standard libfabric, communication objects (endpoints, CQs, counters, AVs)
are created via calls like `fi_endpoint()`, `fi_cq_open()`, `fi_cntr_open()`,
each taking an attribute struct (e.g., `fi_cq_attr`, `fi_cntr_attr`,
`fi_ep_attr`) that configures the object's properties. These attribute structs
already have a `flags` field and are extensible.

The accelerator API extends this existing mechanism by adding a new `FI_ACC`
flag and a pointer to an `fi_acc_info` struct in the attribute structs. For
example, `fi_cq_attr` gains an `acc_info` field:

```c
struct fi_cq_attr {
    size_t              size;
    uint64_t            flags;          /* set FI_ACC here */
    enum fi_cq_format   format;
    enum fi_wait_obj    wait_obj;
    int                 signaling_vector;
    enum fi_cq_wait_cond wait_cond;
    void                *wait_set;
    struct fi_acc_info  *acc_info;      /* NEW: accelerator info */
};
```

Endpoints, counters, and AVs are similarly extended. When the provider sees
`FI_ACC`, it knows this object will later be exported to the accelerator and may
perform additional internal setup (e.g., allocating the CQ buffer in
accelerator-accessible memory, or choosing a counter implementation that supports
DMA-BUF). The `fi_acc_info` struct identifies the target accelerator and
tells the provider how to allocate and map memory between host and device:

```c
struct fi_acc_info {
    enum fi_hmem_iface   iface;      /* FI_HMEM_CUDA, FI_HMEM_ROCR, FI_HMEM_ZE */
    uint64_t             device;     /* accelerator device ordinal */
    enum fi_acc_mem_type mem_type;   /* FI_ACC_MEM_USER or FI_ACC_MEM_PROVIDER */
    /* Callbacks (used when mem_type == FI_ACC_MEM_USER): */
    int  (*alloc)(uint64_t device, uint64_t size, uint64_t alignment,
                  uint64_t flags, void **addr, int *fd, uint64_t *offset);
    int  (*import)(uint64_t device, void *host_addr, uint64_t size,
                   uint64_t flags, void **dev_addr);
    void (*free)(uint64_t device, void *addr);
};
```

With `FI_ACC_MEM_PROVIDER` (the default), the provider manages accelerator memory
internally using the libfabric HMEM interface, requiring no callbacks from the
consumer. With `FI_ACC_MEM_USER`, the consumer provides three callbacks that
the provider invokes during object creation and export — the consumer handles
all accelerator memory operations on behalf of the provider.

**`alloc(device, size, alignment, flags, &addr, &fd, &offset)`** — The
provider calls this when it needs fresh accelerator memory. The consumer allocates
`size` bytes on the specified accelerator device and returns the device pointer in
`*addr`. If the provider passes `FI_ACC_ALLOC_DMABUF` in `flags`, the
consumer must also export a DMA-BUF file descriptor (returned in `*fd` and
`*offset`) so the NIC driver can DMA directly to/from this accelerator memory. This
is used for hardware counters and CQ buffers that the NIC writes into. If
the flag is not set, `fd` can be -1 (the memory is only accessed by the accelerator
kernel, not the NIC).

**`import(device, host_addr, size, flags, &dev_addr)`** — The provider calls
this when it has a host-side address (typically NIC BAR MMIO or host memory)
that the accelerator kernel needs to access. The consumer maps this host address into
the accelerator device address space and returns the device-visible pointer in
`*dev_addr`. The flags tell the consumer what kind of memory it is:
`FI_ACC_IMPORT_IOMEMORY` means the address points to PCIe BAR MMIO (NIC
device I/O memory — e.g., SQ buffer, doorbell register), and
`FI_ACC_IMPORT_DEVICEMAP` means the resulting pointer must be accessible from
accelerator kernels. For CUDA, the consumer translates these to
`cuMemHostRegister(IOMEMORY | DEVICEMAP)` + `cuMemHostGetDevicePointer()`.

**`free(device, addr)`** — The provider calls this to release memory
previously allocated via `alloc`. The consumer frees the accelerator memory.

The callbacks use libfabric-defined flags rather than platform-specific ones,
so the same provider code works regardless of whether the consumer uses CUDA,
HIP, or Level Zero — each consumer translates the flags to its platform's
equivalent. See [Appendix A](#appendix-a-cuda-callback-implementation) for a
concrete CUDA implementation of these callbacks.

The `FI_ACC` flag and `fi_acc_info` are passed through the standard attribute
structs when opening objects:

```c
// CQ with accelerator support
cq_attr.flags = FI_ACC;
cq_attr.acc_info = &my_acc_info;
fi_cq_open(domain, &cq_attr, &cq, context);

// Counter with accelerator support
cntr_attr.flags = FI_ACC;
cntr_attr.acc_info = &my_acc_info;
fi_cntr_open(domain, &cntr_attr, &cntr, context);

// Endpoint with accelerator support
info->ep_attr->acc_info = &my_acc_info;
fi_endpoint2(domain, info, &ep, FI_ACC, context);
```

### Exporting Objects

Once objects are created, bound, and enabled, the consumer exports each to a
accelerator-accessible opaque handle. The provider builds the device-side blob
internally (populates ring geometry, doorbell pointers, phase state,
backpressure fields) using the memory callbacks from `fi_acc_info`. The
consumer never inspects or constructs these structs — it passes the opaque
handles directly to the device-side API.

The exports fall into two categories: object handle exports (EP, Counter, CQ)
where one object produces one opaque handle, and table exports (MR, AV) where
N items produce one accelerator-resident table.

**Endpoint Export:**

```c
int fi_ep_export_acc(struct fid_ep *ep, uint64_t flags,
                     void **acc_ep, size_t *acc_ep_size);
```

What the provider does inside `fi_ep_export_acc()`:
1. Queries raw HW queue addresses (e.g., SQ buffer, doorbell, RQ)
2. Calls `acc_info.import()` with `FI_ACC_IMPORT_IOMEMORY | FI_ACC_IMPORT_DEVICEMAP`
   for BAR MMIO regions (SQ buffer, doorbell), and `FI_ACC_IMPORT_DEVICEMAP`
   only for regular host memory (RQ buffer) — gets accelerator device pointers
3. Allocates accelerator memory for the internal device EP struct via `acc_info.alloc()`
4. Fills the struct with device pointers, ring geometry, phase state, max_batch,
   sq_size
5. H2D copies → returns opaque `void*` to consumer

The resource sharing mode (atomic scope) is NOT declared at export time — it
is determined per-call by the `scope` parameter on `fi_acc_write()`. The
provider compiles all template instantiations into its device header;
`fi_acc_write()` dispatches with a single runtime switch on `scope`.

**Counter Export:**

```c
int fi_cntr_export_acc(struct fid_cntr *cntr, uint64_t flags,
                       void **acc_cntr, size_t *acc_cntr_size);
```

What the provider does inside `fi_cntr_export_acc()`:
1. `acc_info.alloc(FI_ACC_ALLOC_DMABUF)` → one GPU HBM allocation + one DMA-BUF
   fd, sized to hold both the completion counter and (if HW supports it) the
   error counter at different offsets within the same allocation
2. Binds the fd to the NIC counter so the NIC DMAs counter updates directly
   into GPU memory
3. Returns one opaque handle wrapping both accelerator pointers

The consumer never distinguishes comp vs err memory — both live behind the
single opaque handle. The device-side API exposes them as separate reads
(`fi_acc_cntr_read()` for completion, `fi_acc_cntr_readerr()` for errors),
mirroring host-side `fi_cntr_read()` / `fi_cntr_readerr()`. On hardware
without a device-visible error counter, `fi_acc_cntr_readerr()` degrades
gracefully.

Counters are the primary completion mechanism in NCCL GIN (not CQ polling),
used for: SQ backpressure (don't overrun the ring), flush/completion (wait
for all posted ops to complete), signal delivery (detect remote peer's
writes), and offset-based reset (software baseline since NIC counter is
read-only). Counter wrap semantics are queryable via the existing
`domain_attr->max_cntr_value`; device-side arithmetic must be modulo
`max_cntr_value + 1`.

**CQ Export:**

```c
int fi_cq_export_acc(struct fid_cq *cq, uint64_t flags,
                     void **acc_cq, size_t *acc_cq_size);
```

The provider can place the CQ ring in GPU HBM (alloc + DMA-BUF → NIC writes
CQEs directly to GPU memory) or map the host ring via `import()` — the
provider picks per its hardware. HW resource creation timing is an
implementation trade-off: the provider may create the HW CQ at `fi_cq_open()`
time (since `acc_info` with the `alloc` callback is already available) or
defer to export time. Either way this is provider-internal and invisible to
the consumer.

**MR Export (Batch-Native):**

```c
int fi_mr_export_acc(struct fid_mr **mrs, size_t count, uint64_t flags,
                     void **acc_descs, size_t *acc_descs_size);
```

Unlike the object handle exports above, MR export is a table builder. It
takes an array of MRs and exports their descriptors into one accelerator-resident
table with a single alloc + H2D copy. `count == 1` is the trivial case;
there is no separate single-item API. NCCL GIN uses this to export per-rail
MR keys for payload, scratch, and PutValue buffers.

**AV Export (Batch-Native):**

```c
int fi_av_export_acc(struct fid_av *av, fi_addr_t *addrs, size_t count,
                     uint64_t flags, void **acc_peers, size_t *acc_peers_size);
```

Like MR export, AV export takes an array and builds one accelerator-resident peer
table. NCCL GIN builds `[total_slots × nranks]` target tables — the GPU
kernel indexes the table to select the remote target per write. Passing the
full array in one call lets the provider resolve all peers with a single
alloc + H2D copy, instead of `nranks × total_slots` round trips.

**Size and indexing** (applies to both MR and AV tables): the `acc_*_size`
output is the total table size. The per-entry stride is derived as
`size / count`, and the consumer indexes the table with plain pointer
arithmetic on the device side. Entry contents remain opaque; only the stride
is derivable:

```c
// Host side:
void *acc_peers; size_t peers_size;
fi_av_export_acc(av, addrs, nranks, 0, &acc_peers, &peers_size);
size_t peer_stride = peers_size / nranks;

// Device side — select peer i:
void *peer = (char *)acc_peers + i * peer_stride;

// Similarly for MR descriptors:
void *desc = (char *)acc_descs + j * desc_stride;
```

### Host-Side Workflow Example

Putting it all together, here is a complete host-side workflow showing
discovery, object creation with `FI_ACC`, binding, and export — resulting in a
set of accelerator-accessible handles ready to be passed to a CUDA kernel:

```c
// Setup
hints = fi_allocinfo();
hints->caps |= FI_ACC;
fi_getinfo(version, node, service, flags, hints, &info);
fi_fabric(info->fabric_attr, &fabric, context);
fi_domain(fabric, info, &domain, context);

// Configure acc_info
my_acc_info.iface = FI_HMEM_CUDA;
my_acc_info.device = gpu_id;
my_acc_info.mem_type = FI_ACC_MEM_USER;
my_acc_info.alloc = my_cuda_alloc;
my_acc_info.import = my_cuda_import;
my_acc_info.free = my_cuda_free;

// Create objects with FI_ACC
cq_attr.flags = FI_ACC;
cq_attr.acc_info = &my_acc_info;
fi_cq_open(domain, &cq_attr, &cq, context);

cntr_attr.flags = FI_ACC;
cntr_attr.acc_info = &my_acc_info;
fi_cntr_open(domain, &cntr_attr, &cntr, context);

info->ep_attr->acc_info = &my_acc_info;
fi_endpoint2(domain, info, &ep, FI_ACC, context);

fi_ep_bind(ep, cq, FI_TRANSMIT);
fi_ep_bind(ep, cntr, FI_WRITE);
fi_ep_bind(ep, av, 0);
fi_enable(ep);

// Export to accelerator
fi_ep_export_acc(ep, 0, &acc_ep, &acc_ep_size);
fi_cntr_export_acc(cntr, 0, &acc_cntr, &acc_cntr_size);
fi_av_export_acc(av, peer_addrs, nranks, 0, &acc_peers, &acc_peers_size);
fi_mr_export_acc(my_mrs, num_mrs, 0, &acc_descs, &acc_descs_size);
```

---

## 4. Device-Side API

The device-side API provides communication functions callable from accelerator kernels.
These functions are provided as inlined implementations in the provider's
device header (e.g., a `.cuh` file for CUDA), compiled directly into the
consumer's accelerator kernel. The provider encapsulates the full posting protocol
internally — WQE construction, ring management, phase bits, doorbells,
backpressure — so the consumer only interacts with a high-level interface.

### Post Operations

The full accelerator-side surface:

```c
int fi_acc_send(void *acc_ep, const void *buf, size_t size, void *desc,
                uint64_t data, void *peer, void *ctxt,
                enum fi_acc_scope scope, uint64_t flags);
int fi_acc_recv(void *acc_ep, void *buf, void *desc, size_t size,
                void *peer, void *ctxt,
                enum fi_acc_scope scope, uint64_t flags);
int fi_acc_tsend(void *acc_ep, const void *buf, size_t size, void *desc,
                 uint64_t data, void *peer, uint64_t tag, void *ctxt,
                 enum fi_acc_scope scope, uint64_t flags);
int fi_acc_trecv(void *acc_ep, void *buf, size_t size, void *desc,
                 void *peer, uint64_t tag, uint64_t ignore, void *ctxt,
                 enum fi_acc_scope scope, uint64_t flags);
int fi_acc_write(void *acc_ep, const void *buf, void *desc, size_t size,
                 uint64_t data, void *peer, uint64_t raddr, uint64_t rkey,
                 void *ctxt, enum fi_acc_scope scope, uint64_t flags);
int fi_acc_read(void *acc_ep, void *buf, void *desc, size_t size,
                void *peer, uint64_t raddr, uint64_t rkey, void *ctxt,
                enum fi_acc_scope scope, uint64_t flags);
int fi_acc_flush(void *acc_ep, uint64_t flags);
```

Notes against production usage:
- `fi_acc_write` covers the NCCL GIN data path — the only post operation GIN
  uses. `data` maps to write-with-imm (perftest validates it); `ctxt` is the
  per-op context for CQ-based consumers (counter-only consumers pass NULL).
- `fi_acc_flush(acc_ep, flags)` flushes un-posted WQEs — rings the doorbell
  for all WQEs written with `FI_MORE` that haven't been submitted to the NIC
  yet. It applies to both TX and RX (distinguished by `flags`).
  It does NOT wait for completion; see the Completion section below for the
  consumer-owned drain pattern.
- `fi_acc_tsend`/`fi_acc_trecv`/atomics — no current GDA consumer uses these
  (NCCL GIN is write-only; perftest covers send/recv/write/read). EFA has no
  device-side tag matching or native atomics, so these would be unsupported
  (or emulated) there; portability across providers is TBD.
- `fi_acc_recv` — validated by perftest (GPU-side RQ posting for send/recv
  and write+imm patterns).

### Scope Parameter

The `scope` parameter declares the contention level on the EP — who else may
be posting to the same EP concurrently. The provider uses this to select the
atomic scope for internal coordination (slot reservation, rendezvous, doorbell
tracking). This maps directly to NCCL GIN's `ncclGinResourceSharingMode`
template parameter on `postRdmaWrite`, and DOCA's
`doca_gpu_dev_verbs_resource_sharing_mode`.

| Scope | CUDA contention boundary | Internal atomic scope | NCCL GIN equivalent |
|-------|-------------------------|----------------------|---------------------|
| `FI_ACC_WORK_ITEM` | One thread owns this EP | None (plain loads/stores) | `RESOURCE_SHARING_THREAD` / `DOCA_EXCLUSIVE` |
| `FI_ACC_SUBGROUP` | Warps within one CTA | `thread_scope_block` | `RESOURCE_SHARING_CTA` |
| `FI_ACC_WORK_GROUP` | Threads within one CTA | `thread_scope_block` | `RESOURCE_SHARING_CTA` |
| `FI_ACC_DEVICE` | Multiple CTAs on the GPU | `thread_scope_device` | `RESOURCE_SHARING_GPU` |

`FI_ACC_SUBGROUP` and `FI_ACC_WORK_GROUP` both use block-scope atomics (a
warp is always within a CTA); they differ only in how the consumer organizes
its threads, not in what the provider does internally.

Internally, the provider implements a runtime switch on
`scope` dispatching to template-instantiated code where the atomic scope is a
compile-time constant, so all atomic operations constant-fold to the
appropriate hardware instructions (`atom.cta` vs `atom.gpu` vs plain
load/store). Cost: one predictable branch at entry, then fully optimized code.

Rule of thumb for the consumer: use the scope matching the widest set of
threads that may concurrently post to the same EP handle.

### Flags

The device-side post functions inherit the same flags defined for their
host-side counterparts (`fi_write`, `fi_send`, etc.), including `FI_MORE`,
`FI_INJECT`, and provider-specific op flags (bits 60–63). Their semantics are
identical to the host-side definitions.

### Return Code and Backpressure

The post functions return `int`, consistent with libfabric's host-side
convention. There are two possible behaviors when the SQ is full:

The provider can handle backpressure internally — polling the hardware
completion counter and actively ringing doorbells for deferred WQEs to make
progress, returning `FI_SUCCESS` once space becomes available. This simplifies
the consumer — every call succeeds and the thread resumes once the NIC has
consumed enough prior work. The trade-off is that the accelerator thread is occupied
until the SQ drains.

Alternatively, the provider can return `-FI_EAGAIN` when the SQ is full,
letting the consumer own the retry. This gives the consumer flexibility to
interleave other work (e.g., processing completions) before retrying, matching
the host-side libfabric convention. The trade-off is added complexity in every
consumer's posting loop.

Which behavior is preferred for accelerator applications is an open discussion point.
Regardless of the choice, for cooperative scopes (`FI_ACC_SUBGROUP` and
above), all participating threads must receive the same return value so error
paths never diverge the group.

### Provider Implementation

The provider implements `fi_acc_write()` as an inlined device function in its
`.cuh` header. Internally it performs a runtime switch on `scope`, dispatching
to template-instantiated code for each atomic scope level. Within each
instantiation, the provider handles the full posting protocol: SQ slot
reservation (with the appropriate atomic scope), WQE construction, phase bit
computation, writing the WQE to the ring, backpressure enforcement, doorbell
management, and slot-order handoff. All of this is invisible to the consumer.

The provider handles all backpressure internally — `fi_acc_write()` spins when
the SQ is full and never returns an error. The consumer never sees internal
state like `sq_size`, `max_batch`, or `submitted_count`. It observes
backpressure only as `fi_acc_write()` taking longer to return.

For a detailed mapping of how NCCL GIN's `postRdmaWrite<mode>()` maps to
`fi_acc_write()`, including before/after code examples, see
[Appendix C](#appendix-c-nccl-gin-to-fi_acc_write-mapping).

### Completion

The completion API provides two mechanisms: hardware counters (primary, used by
NCCL GIN) and CQ polling (secondary, used by perftest). No scope parameter is
needed for completion — these are simple reads/waits.

**Counter functions:**

```c
uint64_t fi_acc_cntr_read(void *acc_cntr);
void     fi_acc_cntr_wait(void *acc_cntr, uint64_t target);
uint64_t fi_acc_cntr_readerr(void *acc_cntr);
```

**CQ functions:**

```c
ssize_t  fi_acc_cq_read(void *acc_cq, void *buf, size_t count);
ssize_t  fi_acc_cq_readerr(void *acc_cq, struct fi_cq_err_entry *buf, uint64_t flags);
```

**Waiting for completion — consumer-owned pattern:**

The API supports both counter-based and CQ-based completion. In practice,
CQ polling on the GPU is expensive (requires phase-bit checking, cache-line
reads from NIC-written memory), so NCCL GIN exclusively uses the counter path
— a single system-scope acquire load of a DMA-BUF-backed hardware counter in
GPU HBM. The typical application pattern is: snapshot the counter before
posting, count the number of posts, flush deferred WQEs, then spin on the
counter until it reaches the expected value. See
[Appendix B](#appendix-b-completion-drain-pattern) for a concrete code example.

CQ-based completion (`fi_acc_cq_read`, `fi_acc_cq_readerr`) remains available
for consumers that need per-operation status (opcode, error, immediate data),
such as perftest's GDA mode.
- Phase-bit protocol handled internally by the provider

**Error handling:**

NCCL GIN detects errors via counter timeout (counter stops advancing).
`fi_acc_cntr_readerr()` improves on this where the HW exposes a device-visible
error counter (EFA does): the GPU kernel can distinguish "slow" from "failed"
without waiting for a timeout. `fi_acc_wc_read_vendor_err()` is available for
CQ-based consumers. Host-side health monitoring remains more practical for
production error recovery.

---

## 5. Device Header Packaging

The device-side functions are shipped as provider-specific, accelerator-type-
specific header files. Each provider supplies one header per supported accelerator
runtime, implementing the same `fi_acc_*` function signatures. The consumer
includes the appropriate header at build time based on which provider and accelerator
runtime it targets.

The naming convention is:

```
fi_acc_<provider>_<iface>.cuh    — CUDA
fi_acc_<provider>_<iface>.hip.h  — HIP/ROCm
fi_acc_<provider>_<iface>.hpp    — SYCL/Level Zero
```

For example:
- `fi_acc_efa_cuda.cuh` — EFA provider for CUDA GPUs
- `fi_acc_verbs_cuda.cuh` — verbs provider for CUDA GPUs
- `fi_acc_efa_hip.h` — EFA provider for AMD GPUs

The consumer includes the one matching their build environment:

```c
#include <rdma/fi_acc_efa_cuda.cuh>
```

Since all headers implement the same function signatures, the consumer's accelerator
kernel code is portable across providers — switching providers only requires
changing the include at build time, without modifying the kernel source. Each
header contains the provider's inlined implementation (struct layouts, WQE
formats, atomic scope dispatch, backpressure logic), all compiled directly
into the consumer's accelerator binary.

---

## 6. Version/Compatibility Negotiation

The device-side structs are compiled into the consumer's binary via inlined
headers. The API leverages the existing `FI_VERSION(major, minor)` passed to
`fi_getinfo()` to negotiate compatibility — the provider uses this to
determine which device struct fields to populate at export time. No separate
version argument is needed on the export calls. Major version bumps (breaking
layout changes) require recompilation; minor versions are backward compatible
through append-only struct extension (see
[Appendix D](#appendix-d-comp_mask-extensibility) for implementation details).

---

## 7. Summary

This document proposes an OFI Accelerator API that brings accelerator-initiated
networking into the libfabric framework. The API follows a two-phase model:
the host side creates and exports communication resources (endpoints, counters,
CQs, MRs, AVs) as opaque accelerator-accessible handles, and the device side provides
inlined post and completion functions callable from accelerator kernels.

The next steps are to present this proposal to the libfabric community and
open a pull request for review. This API is expected to evolve in the near
term as it receives broader feedback and is validated through practical
implementation across providers.

---

## Appendix A: CUDA Callback Implementation

Example implementation of the `fi_acc_info` callbacks for CUDA:

```c
int my_cuda_alloc(uint64_t device, uint64_t size, uint64_t alignment,
                  uint64_t flags, void **addr, int *fd, uint64_t *offset) {
    cuCtxSetCurrent(gpu_contexts[device]);
    CUdeviceptr ptr;
    cuMemAlloc(&ptr, size);
    *addr = (void *)ptr;

    if (flags & FI_ACC_ALLOC_DMABUF) {
        cuMemGetDmaBufFd(ptr, fd);
        *offset = 0;
    } else {
        *fd = -1;
        *offset = 0;
    }
    return 0;
}

int my_cuda_import(uint64_t device, void *host_addr, uint64_t size,
                   uint64_t flags, void **dev_addr) {
    unsigned int cuda_flags = 0;
    if (flags & FI_ACC_IMPORT_IOMEMORY)
        cuda_flags |= CU_MEMHOSTREGISTER_IOMEMORY;
    if (flags & FI_ACC_IMPORT_DEVICEMAP)
        cuda_flags |= CU_MEMHOSTREGISTER_DEVICEMAP;

    cuMemHostRegister(host_addr, size, cuda_flags);
    CUdeviceptr ptr;
    cuMemHostGetDevicePointer(&ptr, host_addr, 0);
    *dev_addr = (void *)ptr;
    return 0;
}

void my_cuda_free(uint64_t device, void *addr) {
    cuMemFree((CUdeviceptr)addr);
}
```

---

## Appendix B: Completion Drain Pattern

The counter-based completion drain pattern used by NCCL GIN:

```c
// Baseline snapshot (before posting, or at any known-quiescent point):
uint64_t base = fi_acc_cntr_read(acc_cntr);

// ... N calls to fi_acc_write — consumer counts N itself ...

fi_acc_flush(acc_ep, FI_TRANSMIT);   // flush any FI_MORE-deferred WQEs

// Wait: modular compare per domain_attr->max_cntr_value
while (((fi_acc_cntr_read(acc_cntr) - base) & max_cntr_value) < N) { /* spin */ }
// or equivalently: fi_acc_cntr_wait(acc_cntr, base + N)
```

This is GIN's exact pattern generalized — GIN's baseline is implicitly 0
(counter and `submitted_count` both start at zero); the explicit snapshot also
subsumes reset-without-zeroing (the baseline IS the offset), and the remote
side uses the identical pattern on its FI_REMOTE_WRITE counter for signal
detection, including Add-by-N.

Contract requirements:
1. **1:1 tick guarantee** — every posted operation increments the bound
   FI_WRITE counter by exactly 1
2. **Flush before wait** — a `FI_MORE`-deferred WQE never completes until
   it is flushed; the wait must be preceded by `fi_acc_flush()` (or a
   non-`FI_MORE` post)
3. **Multi-poster tally** — for one EP-wide quiet across multiple
   threads/CTAs, the consumer aggregates its own N

Counter semantics:
- NIC-owned — software cannot write it
- Wraps at `max_cntr_value + 1` (EFA: 2^31) — all arithmetic uses
  `(a - b) & max_cntr_value`; wrap point queryable via `domain_attr`
- Read via system-scope acquire (bypasses GPU caches, coherent with NIC PCIe
  writes)

---

## Appendix C: NCCL GIN to `fi_acc_write` Mapping

Today, NCCL GIN's `putImplMode` calls `postRdmaWrite<mode>()` — a 200-line
warp-cooperative SQ posting function. With the accelerator API, this reduces
to a single `fi_acc_write()` call because the provider encapsulates the full
protocol internally:

| NCCL GIN does manually | `fi_acc_write()` encapsulates via |
|---|---|
| `cooperative_groups::labeled_partition(qp)` | Provider detects warp coalescing internally |
| Leader `pc.fetch_add(group_size)` | Provider does one atomic per subgroup internally |
| Parallel WQE write (all lanes) | Each lane's `fi_acc_write()` writes its own slot in parallel |
| Deferred doorbell (`aggregate` flag) | `flags = FI_MORE` |
| Un-rung depth backpressure (≤ max_batch) | Provider enforces internally — spins or force-rings deferred WQEs |
| Ring overflow backpressure (≤ sq_size via hw counter) | Provider enforces internally — spins on counter |
| Strict slot-order rendezvous (`wqes_completed`) | Provider manages handoff cursors internally |
| Phase bit computation | Provider computes from slot index internally |
| 64-byte WQE write to BAR MMIO | Provider does the memcpy internally |
| `__threadfence_system()` + doorbell MMIO write | Provider does fence + MMIO internally |
| `submitted_count += (chunk_next - db_rung)` | Provider tracks internally for flush |
| `ncclGinScope` template (atomic scope selection) | `scope` parameter — one switch dispatches |

**Before (GIN's `putImplMode`, per lane):**

```c
int idx = targetSlot * nranks + peer;
uint16_t ah   = ep->target_address_handles[idx];
uint16_t qpn  = ep->target_remote_qpns[idx];
uint32_t qkey = ep->target_qkey[idx];

postRdmaWrite<mode>(ep, ah, qpn, qkey,
                    absSrcAddr, srcLkey, writeBytes,
                    absDstAddr, dstRkey, optFlags);
```

**After (with fi_acc_write):**

```c
void *peer_h = (char *)acc_peers + (targetSlot * nranks + peer) * peer_stride;
void *desc   = (char *)acc_descs + rail_mr_idx * desc_stride;

fi_acc_write(acc_ep, (void *)absSrcAddr, desc, writeBytes, 0, peer_h,
             absDstAddr, dstRkey, NULL,
             FI_ACC_SUBGROUP,
             FI_EFA_WR_HIGH_PPS | (aggregate ? FI_MORE : 0));
```

The `(ah, qpn, qkey)` tuple becomes an opaque peer entry from the AV export;
`srcLkey` becomes the desc from the MR export. Signal Add-by-N stays an
application-level loop of N−1 zero-byte `fi_acc_write` calls.

**Provider internal steps** (when consumer calls with `FI_ACC_SUBGROUP, FI_MORE`):
1. Detects subgroup (warp lanes targeting same EP) via `labeled_partition`
2. Leader: atomic reserve N slots (one `fetch_add` for the whole group)
3. All lanes: build WQE (opcode, SGE, remote addr), compute phase bit, write
   64 bytes to the BAR MMIO SQ ring slot
4. `FI_MORE` → defer doorbell (unless doing so would exceed max_batch, in
   which case force-ring to make room)
5. Leader: `__threadfence_system()` to publish WQEs to NIC, then wait for
   doorbell turn (strict slot-order rendezvous), ring doorbell, advance
   cursors, hand off to next group

**Backpressure** (both encapsulated inside the provider):
```c
// (a) Un-rung depth (EFA staging limit):
//     chunk_next - db_rung ≤ max_batch
//     If exceeded: force-ring deferred WQEs to make room

// (b) Ring overflow (SQ overrun):
//     (chunk_next - *hw_cntr) & 0x7FFFFFFF ≤ sq_size
//     Spin until NIC consumes enough WQEs
```

---

## Appendix D: `comp_mask` Extensibility

All exported device structs use a `comp_mask` bitmask for forward-compatible
extension. New fields are always appended at the end and guarded by new bits:

```c
struct fi_acc_dev_ep {
    uint64_t comp_mask;
    // v1.0 fields (always present):
    uint8_t *sq_buf;
    uint32_t *sq_db;
    uint32_t sq_size;
    uint32_t max_batch;
    // v1.1 addition (only valid if comp_mask & FI_ACC_DEV_EP_INLINE):
    uint32_t max_inline_size;
};

#define FI_ACC_DEV_EP_INLINE  (1ULL << 0)
```

Rules:
- Provider zeroes the entire struct before filling (unknown fields = 0)
- New fields always at the end — never reorder existing fields
- Consumer checks `comp_mask` before reading extension fields
- Old consumer ignores unknown bits; new consumer against old provider sees
  bits unset and skips optional paths
