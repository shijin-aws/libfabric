# OFI Accelerator API — Analysis & Improvement Recommendations

Based on deep analysis of:
- The **OFI Accelerator API** proposal (slides by Jianxin Xiong, 4/21/2026)
- **efa-dp-direct** (v0.0.2) — direct GPU-to-NIC datapath library for EFA
- **aws-ofi-nccl** GIN/GDAKI — production integration of efa-dp-direct with NCCL via libfabric
- **perftest** (RDMA benchmark tool) — GDA mode implementation (`--use_dp_direct`)

---

## Current Production Architecture (efa-dp-direct + aws-ofi-nccl GDAKI)

### How it works today (without the OFI Accelerator API)

```
┌──────────────────────────────────────────────────────────────┐
│  GPU Kernel (NCCL)                                            │
│    #include "efa_cuda_dp_impl.cuh"                            │
│    efa_cuda_start_sq_batch(qp, N)                             │
│    efa_cuda_sq_batch_place_wr(qp, idx, wr)                    │
│    efa_cuda_flush_sq_wrs(qp)     ← __threadfence_system + DB  │
│    efa_cuda_cq_poll(cq, pos)     ← phase-bit polling          │
└──────────────────────────┬───────────────────────────────────┘
                           │ Direct HW access (BAR MMIO)
┌──────────────────────────┴───────────────────────────────────┐
│  Host Setup (aws-ofi-nccl GDAKI)                              │
│    1. fi_open_ops(domain, FI_EFA_GDA_OPS) → gda_ops           │
│    2. gda_ops->query_qp_wqs(ep) → sq_buffer, sq_doorbell      │
│    3. gda_ops->query_cq(cq) → cq_buffer, entry_size           │
│    4. gda_ops->query_addr(ep, fi_addr) → ahn, qpn, qkey       │
│    5. gda_ops->cntr_open_ext(domain) → HW counter in GPU mem   │
│    6. cuMemHostRegister(sq_buffer, IOMEMORY|DEVICEMAP)         │
│    7. cuMemHostRegister(doorbell, IOMEMORY|DEVICEMAP)          │
│    8. cuMemHostGetDevicePointer → GPU-visible pointers          │
│    9. efa_cuda_create_qp/cq(attrs) → GPU-resident descriptors  │
└──────────────────────────────────────────────────────────────┘
```

### Key design decisions in production:
1. **No libfabric abstraction on the device** — GPU code directly uses EFA HW I/O structures
2. **Provider-specific extension API** (`fi_efa_ops_gda`) — not portable across providers
3. **Manual MMIO mapping** — consumer calls `cuMemHostRegister` on BAR addresses
4. **Layout-compatible shadow structs** — aws-ofi-nccl defines its own types matching efa-dp-direct ABI
5. **Header-only device library** — zero overhead, compiled into user kernel

---

## Perftest GDA Mode — Standalone RDMA Benchmarking Reference

### Overview

The `perftest` RDMA benchmarking tool (`~/perftest`) implements GDA mode via the `--use_dp_direct` flag.
This provides a **standalone, minimal reference** for how GPU-initiated RDMA operations work end-to-end
without the complexity of NCCL or aws-ofi-nccl. It validates the efa-dp-direct primitives across all
RDMA operation types (send, write, write+imm, read) in both latency and bandwidth modes.

### Command-Line Usage

```bash
# Write bandwidth
ib_write_bw --use_cuda=0 --use_dp_direct -d <efa_device> <server_ip>

# Write latency
ib_write_lat --use_cuda=0 --use_dp_direct -d <efa_device> <server_ip>

# Read latency
ib_read_lat --use_cuda=0 --use_dp_direct -d <efa_device> <server_ip>

# Send latency
ib_send_lat --use_cuda=0 --use_dp_direct -d <efa_device> <server_ip>

# BW with multi-QP and batching
ib_write_bw --use_cuda=0 --use_dp_direct -q 4 --post_list=16 -d <efa_device> <server_ip>
```

### Architecture — Two-Phase Design

```
┌──────────────────────────────────────────────────────────────────┐
│  Phase 2: GPU Kernel Execution (cuda_resources.cu)                │
│                                                                    │
│  __shared__ efa_cuda_qp local_qp = *qp;   ← copy to SMEM        │
│  __shared__ efa_cuda_cq local_cq = *cq;                          │
│                                                                    │
│  loop:                                                            │
│    tposted[i] = clock64()                   ← GPU-side timing    │
│    efa_cuda_start_sq_batch(&local_qp, N)                          │
│    efa_cuda_init_*_wr(wr_buf, ...)          ← WQE in registers   │
│    efa_cuda_wr_set_sge(wr_buf, lkey, addr, len)                   │
│    efa_cuda_wr_set_remote(wr_buf, ah, qpn, qkey)                  │
│    efa_cuda_sq_batch_place_wr(&local_qp, idx, wr_buf)             │
│    efa_cuda_flush_sq_wrs(&local_qp)         ← fence + doorbell   │
│    cqe = efa_cuda_cq_poll(&local_cq, pos)   ← spin on phase bit  │
│    efa_cuda_cq_pop(&local_cq, 1)                                  │
│  *qp = local_qp; *cq = local_cq;           ← writeback          │
└──────────────────────────┬───────────────────────────────────────┘
                           │ Direct HW access (BAR MMIO + DMA-BUF)
┌──────────────────────────┴───────────────────────────────────────┐
│  Phase 1: Host-Side Setup (perftest_resources.c)                  │
│                                                                    │
│  1. Allocate GPU memory via DMA-BUF for CQ buffer                 │
│  2. efadv_create_cq() with EFADV_CQ_INIT_FLAGS_EXT_MEM_DMABUF    │
│  3. efa_cuda_create_cq(buffer, num_entries, entry_size)           │
│  4. Create QP via standard ibv_create_qp()                        │
│  5. efadv_query_qp_wqs(qp) → sq_buffer, sq_doorbell, rq_*        │
│  6. cuMemHostRegister(sq_buffer, IOMEMORY|DEVICEMAP)              │
│  7. cuMemHostRegister(sq_doorbell, IOMEMORY|DEVICEMAP)            │
│  8. cuMemHostGetDevicePointer() → GPU-visible pointers            │
│  9. efa_cuda_create_qp(sq_ptr, rq_ptr, doorbells, sizes)         │
│  10. Copy rem_qpn[] array to GPU for multi-QP tests              │
└──────────────────────────────────────────────────────────────────┘
```

### Host-Side Setup Code (perftest_resources.c)

**CQ creation with DMA-BUF:**
```c
// Allocate GPU memory for CQ buffer
cq_entries = next_power_of_2(tx_buffer_depth * num_of_qps);
buf_size = cq_entries * 32 + 4096;
ctx->memory->allocate_buffer(ctx->memory, 0, buf_size,
                             &send_dmabuf_fd, &send_dmabuf_offset, &send_cq_buffer);
p_cuMemsetD8((uint64_t)send_cq_buffer, 0, buf_size);

// Create CQ backed by GPU memory
struct efadv_cq_init_attr send_efa_attr = {
    .ext_mem_dmabuf.offset = send_dmabuf_offset,
    .ext_mem_dmabuf.length = buf_size,
    .ext_mem_dmabuf.fd = send_dmabuf_fd,
    .flags = EFADV_CQ_INIT_FLAGS_EXT_MEM_DMABUF,
};
ctx->send_cq = ibv_cq_ex_to_cq(efadv_create_cq(ctx->context, &send_cq_attr, &send_efa_attr, ...));

// Wrap for GPU-side use
struct efa_cuda_cq_attrs cq_attrs = { .buffer = send_cq_buffer,
                                      .num_entries = cq_entries,
                                      .entry_size = 32 };
ctx->gda_send_cq = efa_cuda_create_cq(&cq_attrs, sizeof(cq_attrs));
```

**QP setup + BAR mapping:**
```c
// After QP creation, query raw HW queue addresses
struct efadv_wq_attr sq_attr = {}, rq_attr = {};
efadv_query_qp_wqs(ctx->qp[i], &sq_attr, &rq_attr, sizeof(sq_attr));

// Map SQ BAR buffer for GPU access
cuMemHostRegister(sq_attr.buffer, sq_attr.num_entries * 64,
                  CU_MEMHOSTREGISTER_IOMEMORY | CU_MEMHOSTREGISTER_DEVICEMAP);
cuMemHostGetDevicePointer(&sq_ptr, sq_attr.buffer, 0);

// Map SQ doorbell MMIO for GPU access
cuMemHostRegister(sq_attr.doorbell, 4,
                  CU_MEMHOSTREGISTER_IOMEMORY | CU_MEMHOSTREGISTER_DEVICEMAP);
cuMemHostGetDevicePointer(&sq_db, sq_attr.doorbell, 0);

// Map RQ buffer (regular host memory, not BAR)
cuMemHostRegister(rq_attr.buffer, rq_attr.num_entries * 16,
                  CU_MEMHOSTREGISTER_DEVICEMAP);
cuMemHostGetDevicePointer(&rq_ptr, rq_attr.buffer, 0);

// Map RQ doorbell
cuMemHostRegister(rq_attr.doorbell, 4,
                  CU_MEMHOSTREGISTER_IOMEMORY | CU_MEMHOSTREGISTER_DEVICEMAP);
cuMemHostGetDevicePointer(&rq_db, rq_attr.doorbell, 0);

// Build GPU-resident QP descriptor
struct efa_cuda_qp_attrs qp_attrs = {
    .sq_buffer = sq_ptr,       .rq_buffer = rq_ptr,
    .sq_doorbell = sq_db,      .rq_doorbell = rq_db,
    .sq_num_entries = sq_attr.num_entries,
    .sq_entry_size = sq_attr.entry_size,
    .sq_max_batch = sq_attr.max_batch,
    .rq_num_entries = rq_attr.num_entries,
    .rq_entry_size = rq_attr.entry_size,
};
ctx->gda_qp[i] = efa_cuda_create_qp(&qp_attrs, sizeof(qp_attrs));
```

### GPU Kernel Implementations

#### Latency Kernels (single-thread, 1 operation at a time)

| Kernel | Operation | Synchronization Method |
|--------|-----------|----------------------|
| `run_iter_lat_read_kernel` | RDMA Read | Poll send CQ for read completion |
| `run_iter_lat_write_kernel` | RDMA Write | Polling byte: write last byte as flag, peer does `__ldcv` |
| `run_iter_lat_write_imm_kernel` | RDMA Write+IMM | Post recvs on GPU, poll recv CQ for notification |
| `run_iter_lat_send_kernel` | Send/Recv | Post recvs on GPU, poll recv CQ, then send back |

**Write latency ping-pong pattern (no IMM):**
```cuda
// Sender side:
*post_buf = (char)(++scnt);       // Write flag byte
__threadfence();                   // Ensure visible before RDMA
// ... post RDMA write ...

// Receiver side:
while (__ldcv((char*)poll_buf) != (char)rcnt);  // Spin on flag byte arrival
```

**Write+IMM latency pattern (uses recv CQ):**
```cuda
// Pre-post receives on GPU:
for (int i = 0; i < rx_depth; i++) {
    efa_cuda_post_recv_wr(&local_qp, i, recv_addr, recv_length, recv_lkey);
}
efa_cuda_flush_rq_wrs(&local_qp);

// Wait for incoming write+imm via recv CQ:
do { cqe = efa_cuda_cq_poll(&local_recv_cq, 0); } while (!cqe);
efa_cuda_cq_pop(&local_recv_cq, 1);

// Re-post receive for next iteration
efa_cuda_post_recv_wr(&local_qp, 0, recv_addr, recv_length, recv_lkey);
efa_cuda_flush_rq_wrs(&local_qp);
```

#### Bandwidth Kernel (multi-thread cooperative batching)

```cuda
// Launched with: <<<1, post_list * num_qps>>> threads
__global__ void run_iter_bw_kernel(...) {
    int tid = threadIdx.x;
    int sq_batch_index = tid % post_list;
    int batch_size = min(post_list, 16);
    efa_cuda_qp* qp = &local_qps[tid / post_list];  // per-QP assignment

    // Each thread prepares its own WQE (in registers)
    efa_cuda_init_rdma_write_wr(wr_buf, scnt + sq_batch_index, rkey, remote_addr);
    efa_cuda_wr_set_sge(wr_buf, lkey, send_addr, send_length);
    efa_cuda_wr_set_remote(wr_buf, ah, remote_qpn, remote_qkey);

    // Cooperative submission in sub-batches of 16:
    for (int i = 0; i < post_list / batch_size; i++) {
        if (sq_batch_index == 0)
            efa_cuda_start_sq_batch(qp, batch_size);   // Thread 0 reserves slots
        __syncthreads();

        if (sq_batch_index / batch_size == i)
            efa_cuda_sq_batch_place_wr(qp, sq_batch_index % batch_size, wr_buf);  // Parallel place
        __syncthreads();

        if (sq_batch_index == 0)
            efa_cuda_flush_sq_wrs(qp);                 // Thread 0 rings doorbell
        if (tid == 0) scnt += batch_size * num_qps;
        __syncthreads();
    }

    // CQ polling: all threads cooperatively poll (position = tid)
    do { cqe = efa_cuda_cq_poll(&local_send_cq, tid); } while (!cqe);
    __syncthreads();
    if (tid == 0) efa_cuda_cq_pop(&local_send_cq, post_list * num_qps);
}
```

#### Bidirectional BW (2 CUDA blocks)

```cuda
// Launched with: <<<2, send_threads>>>
// Block 0: recv side (single thread polls recv CQ, reposts RQ WRs)
// Block 1: send side (identical to run_iter_bw_kernel)
```

#### Server-Side Unsolicited Write Reception

```cuda
// For RDMA Write (no IMM) - server just polls CQ for incoming writes
// Launched with: <<<1, recv_post_list>>> threads
// All threads cooperatively poll CQ positions, thread 0 pops
```

### Supported Test Matrix

| Test Binary | GDA Kernels Used | Description |
|-------------|-----------------|-------------|
| `ib_write_bw` | `run_iter_bw_kernel` (client), `run_iter_bw_server_kernel` or `run_iter_bw_server_unsolicited_kernel` (server), `run_iter_bi_kernel` (duplex) | Write BW with multi-QP, multi-thread batching |
| `ib_write_lat` | `run_iter_lat_write_kernel`, `run_iter_lat_write_imm_kernel` | Write latency (polling byte or IMM+CQ) |
| `ib_read_bw` | `run_iter_bw_kernel` (client) | Read BW |
| `ib_read_lat` | `run_iter_lat_read_kernel` | Read latency |
| `ib_send_bw` | `run_iter_bw_kernel` (client), `run_iter_bw_server_kernel` (server) | Send BW with recv handling |
| `ib_send_lat` | `run_iter_lat_send_kernel` | Send/recv latency ping-pong |

### Key Design Patterns (vs. aws-ofi-nccl)

| Pattern | perftest | aws-ofi-nccl GDAKI |
|---------|----------|-------------------|
| **QP/CQ state management** | Copy to `__shared__` memory, writeback at end | Same (efa-dp-direct pattern) |
| **Thread model** | `post_list × num_qps` threads for BW; 1 thread for latency | Warp-level cooperative |
| **Batching** | Sub-batches of `min(post_list, 16)` | `start_sq_batch(warp_size)` |
| **CQ polling** | Parallel poll by thread position (`tid`) | Parallel poll by lane |
| **SQ backpressure** | Implicit: `scnt - ccnt < tx_depth` check | Explicit: spin on HW counter |
| **Timing** | `clock64()` on GPU, copy to host for reporting | Not applicable (NCCL timing) |
| **Address resolution** | Host resolves, passes (ah, qpn, qkey) as kernel args | `gda_ops->query_addr()` → GPU struct |
| **Memory registration** | Uses `efadv_query_qp_wqs` + `cuMemHostRegister` directly | Same, through libfabric ops |
| **Counter usage** | None (uses CQ only) | HW counter for SQ backpressure |
| **Multi-rail** | Multiple QPs (`num_of_qps`), single CQ | Per-rail QPs/CQs |

### Notable Implementation Details

1. **No HW counter usage** — perftest relies solely on CQ polling for backpressure (`ccnt < scnt` + `tx_depth` limit), unlike aws-ofi-nccl which uses DMA-BUF hardware counters. This is simpler but less efficient at scale.

2. **SQ entry size is hardcoded** — `sq_attr.num_entries * 64` for SQ registration (64 bytes per WQE), `rq_attr.num_entries * 16` for RQ (16 bytes per RQE).

3. **CQ entry size is 32 bytes** — hardcoded in `cq_attrs.entry_size = 32`.

4. **RQ buffer is NOT BAR-mapped** — Uses `CU_MEMHOSTREGISTER_DEVICEMAP` only (no `IOMEMORY` flag), suggesting RQ buffers are in regular host memory, not MMIO.

5. **Doorbell size is 4 bytes** — `cuMemHostRegister(sq_attr.doorbell, 4, ...)`.

6. **Build dependency** — Controlled by `HAVE_EFAGDA` compile flag and linked with `$(LIBEFAGDA)`. Compiled with `nvcc -arch=compute_80 -O3`.

7. **Max 32 QPs** — `#define GDA_MAX_QPS 32`, `__shared__ efa_cuda_qp local_qps[32]`.

8. **Thread limit** — `post_list * num_of_qps` must be ≤ 1024 (CUDA max threads per block).

---

## Gap Analysis: OFI Accelerator API vs. Production Reality

| Aspect | OFI Acc API Proposal | Production (efa-dp-direct + aws-ofi-nccl) | perftest GDA | Gap |
|--------|---------------------|-------------------------------------------|--------------|-----|
| **Memory allocation** | `fi_acc_info.alloc/import` callbacks | `cuMemHostRegister` + DMA-BUF for counters | DMA-BUF for CQ, `cuMemHostRegister(IOMEMORY)` for SQ/doorbell BAR | Proposal is more abstract; production needs both BAR-mapping and DMA-BUF |
| **Resource export** | `fi_ep_export_acc()` → opaque blob | `gda_ops->query_qp_wqs()` + manual GPU struct build | `efadv_query_qp_wqs()` + manual `cuMemHostRegister` + `efa_cuda_create_qp()` | Proposal hides the complexity; production needs fine-grained control |
| **Device API** | `fi_acc_send/recv/write/read` | `efa_cuda_init_send_wr` + `sq_batch_place_wr` + `flush_sq_wrs` | Same efa-dp-direct calls directly | Proposal is higher-level; production uses low-level WQE construction |
| **CQ handling** | `fi_acc_cq_read()` | `efa_cuda_cq_poll(cq, position)` + `cq_pop(amount)` | Same: `efa_cuda_cq_poll(cq, tid)` + `cq_pop(batch)` | Proposal abstracts away position-based parallel polling |
| **Scope/concurrency** | `FI_ACC_WORK_ITEM/SUBGROUP/WORK_GROUP` | Explicit `sq_lock` + `start_sq_batch(batch_size)` | `post_list × num_qps` threads; sub-batches of 16; `__syncthreads()` | Proposal formalizes what production does manually |
| **Counter support** | Not shown in proposal | `cntr_open_ext` with external GPU memory + DMA-BUF | **Not used** (CQ-only backpressure) | **Missing from proposal**; perftest shows it's optional but limits scalability |
| **Multi-operation batching** | Implicit via scope | Explicit `start_sq_batch` → N × `place_wr` → `flush` | Explicit: thread 0 reserves, all threads place in parallel, thread 0 flushes | Proposal needs clearer batch semantics |
| **SQ backpressure** | Not addressed | Kernel spins on `(submitted - *cntr + batch) <= sq_size` | Implicit: `post_list > tx_depth - (scnt - ccnt)` triggers CQ poll | **Critical gap** — perftest's approach doesn't scale |
| **Doorbell coalescing** | Not addressed | `FI_MORE` flag on host; explicit `flush` on device | `flush_sq_wrs()` after batch of ≤16 WQEs | Needs specification |
| **Multi-rail** | Not addressed | Round-robin across rails, per-rail QPs/CQs | Multiple QPs sharing single CQ (simpler model) | **Important for production** |
| **Recv posting on GPU** | Not addressed | N/A (NCCL doesn't post recvs on GPU) | `efa_cuda_post_recv_wr()` + `efa_cuda_flush_rq_wrs()` on GPU | perftest demonstrates GPU-side recv posting is viable |
| **GPU-side timing** | Not addressed | N/A | `clock64()` before/after each op | Useful for benchmarking; could be part of profiling API |

---

## Recommendations for Improving the OFI Accelerator API

### 1. Split Export Into Structured Components (Not Opaque Blobs)

The proposal's `fi_ep_export_acc()` returning an opaque `void *acc_ep` is too coarse. Production needs:

```c
struct fi_acc_ep_attrs {
    struct fi_acc_wq_attrs sq;   /* SQ buffer, doorbell, entry_size, num_entries, max_batch */
    struct fi_acc_wq_attrs rq;   /* RQ buffer, doorbell, entry_size, num_entries */
    struct fi_acc_cq_attrs cq;   /* CQ buffer, entry_size, num_entries */
    uint32_t max_inline_data;
    uint32_t max_rdma_sges;
};

int fi_ep_export_acc(struct fid_ep *ep, uint64_t flags,
                     struct fi_acc_ep_attrs *attrs);  /* structured output */
```

**Why:** The consumer (efa-dp-direct) needs to know entry sizes, queue depths, doorbell addresses individually. An opaque blob forces provider-specific unpacking.

### 2. Add Hardware Counter Export

Counters are essential for production (SQ backpressure, signal/notification delivery):

```c
struct fi_acc_cntr_attrs {
    enum fi_hmem_iface iface;
    uint64_t device;
    uint64_t flags;  /* FI_ACC_CNTR_EXTERNAL_MEM */
    /* For DMA-BUF based allocation: */
    int fd;
    uint64_t offset;
    uint64_t size;
};

int fi_cntr_open_acc(struct fid_domain *domain,
                     struct fi_cntr_attr *attr,
                     struct fi_acc_cntr_attrs *acc_attr,
                     struct fid_cntr **cntr, void *context);

int fi_cntr_export_acc(struct fid_cntr *cntr, uint64_t flags,
                       void **acc_cntr, size_t *acc_cntr_size);
```

**Why:** In production, EFA's `cntr_open_ext` with `FI_EFA_COMP_CNTR_INIT_WITH_COMP_EXTERNAL_MEM` allows the NIC to write counter values directly into GPU HBM. The GPU kernel reads them without any host round-trip. This is used for:
- **SQ backpressure**: `while (submitted - *counter + batch > sq_size) spin;`
- **Remote write notification**: remote peer polls `*remote_write_counter` to detect arrivals

### 3. Formalize the Batch Submission Model

The "scope" concept is good but insufficient. The API needs explicit batch lifecycle:

```c
/* Reserve N slots in SQ. Returns 0 on success, -FI_EAGAIN if SQ full. */
int fi_acc_sq_start_batch(void *acc_ep, int batch_size, uint64_t scope);

/* Place a prepared WR into slot `index`. Parallel-safe across scope threads. */
int fi_acc_sq_place(void *acc_ep, int index, void *wr_buf);

/* Commit the batch: threadfence + ring doorbell. */
void fi_acc_sq_flush(void *acc_ep);
```

**Why:** Production (efa-dp-direct) uses exactly this pattern: `start_sq_batch` → multiple `sq_batch_place_wr` → `flush_sq_wrs`. The proposal's `fi_acc_send()` implies a fire-and-forget model that doesn't map to the underlying hardware efficiently.

### 4. Add SQ Backpressure Mechanism

```c
/* Check available SQ slots. Non-blocking. */
int fi_acc_sq_available(void *acc_ep, void *acc_cntr);

/* Or: the export should include enough info for the kernel to compute this: */
struct fi_acc_sq_info {
    uint32_t sq_size;
    volatile uint64_t *completion_counter;  /* NIC-updated, in GPU memory */
};
```

**Why:** Without this, GPU kernels can overflow the SQ. In production, aws-ofi-nccl GDAKI implements:
```cuda
while ((submitted_count - *local_cntr_value + batch_size) > sq_size) {
    /* spin */
}
```

### 5. Support DMA-BUF as a First-Class Memory Allocation Method

The `fi_acc_info.alloc/import` callbacks are good, but the API should explicitly support DMA-BUF:

```c
enum fi_acc_mem_type {
    FI_ACC_MEM_HMEM,       /* Provider allocates via HMEM interface */
    FI_ACC_MEM_USER_ALLOC, /* User provides alloc/import callbacks */
    FI_ACC_MEM_DMABUF,     /* Provider exports DMA-BUF fd+offset */
};

struct fi_acc_info {
    enum fi_hmem_iface iface;
    uint64_t device;
    enum fi_acc_mem_type mem_type;
    union {
        struct { int (*alloc)(...); int (*import)(...); } user;
        struct { /* provider fills fd, offset after create */ } dmabuf;
    };
};
```

**Why:** In production, the CQ buffer uses DMA-BUF (`FI_EFA_CQ_INIT_FLAGS_EXT_MEM_DMABUF`), hardware counters use DMA-BUF for external memory, and SQ/doorbell use BAR MMIO mapping (not DMA-BUF). The API needs to handle both.

### 6. Address Resolution Export

The proposal is missing address export for the accelerator side:

```c
struct fi_acc_peer_addr {
    uint16_t address_handle;   /* NIC-level address handle */
    uint16_t remote_qpn;       /* Remote queue pair number */
    uint32_t remote_qkey;      /* Queue key */
};

int fi_av_export_acc(struct fid_av *av, fi_addr_t addr,
                     struct fi_acc_peer_addr *acc_addr);
```

**Why:** In production, `gda_ops->query_addr()` is critical — the GPU kernel needs (AHN, QPN, QKEY) to fill in WQE destination fields. The proposal's `fi_acc_send(..., peer, ...)` hides this, but real hardware needs explicit addressing in WQEs.

### 7. Clarify the Abstraction Level Decision

The fundamental tension is:

| | High-level (proposal) | Low-level (production) |
|-|----------------------|----------------------|
| **Device API** | `fi_acc_send(ep, buf, size, peer, ...)` | `init_send_wr` + `set_sge` + `set_remote` + `batch_place` + `flush` |
| **Portability** | ✅ Provider-independent | ❌ EFA-specific WQE format |
| **Performance** | ❌ Abstraction overhead | ✅ Zero-copy to HW ring |
| **Flexibility** | ❌ Limited batching control | ✅ Full control over submission |

**Recommendation:** Provide **both layers**:

```
Layer 1 (Portable, high-level):
    fi_acc_send() / fi_acc_write() / fi_acc_cq_read()
    - Provider implements device-side logic
    - Works across EFA, CXI, verbs, etc.
    - Performance penalty acceptable for portability

Layer 2 (Direct, low-level):
    fi_acc_export_wq() / fi_acc_export_cq() / fi_acc_export_peer()
    - Expose raw queue structures
    - Consumer brings own device-side library (like efa-dp-direct)
    - Maximum performance, provider-specific
```

This mirrors how libfabric already works: high-level API for portability, with provider-specific extensions (`fi_open_ops`) for performance-critical paths.

### 8. Multi-Rail Support

```c
struct fi_acc_info {
    ...
    uint16_t num_rails;  /* Number of NIC rails to use */
};

/* Export per-rail resources */
int fi_ep_export_acc_rail(struct fid_ep *ep, uint16_t rail_id,
                          uint64_t flags, void **acc_ep, size_t *size);
```

**Why:** aws-ofi-nccl uses up to 4 rails (EFA NICs) per instance. GDAKI creates per-rail QPs/CQs and the GPU kernel selects rails. The API should make this a first-class concept.

### 9. Error Handling on Device

The proposal doesn't address device-side error handling:

```c
/* Check for SQ errors (e.g., protection fault, remote disconnect) */
int fi_acc_sq_error(void *acc_ep);

/* Extended CQ error read */
int fi_acc_cq_readerr(void *acc_cq, struct fi_acc_cq_err_entry *err);
```

**Why:** In production, `efa_cuda_wc_read_vendor_err()` exists for checking error completions. The accelerator needs to detect and handle NIC errors without host intervention.

### 10. Version/Compatibility Negotiation

```c
/* During fi_getinfo, report accelerator API version supported */
struct fi_info {
    ...
    uint32_t acc_api_version;  /* FI_ACC_API_VERSION(major, minor) */
};
```

**Why:** efa-dp-direct uses `comp_mask` + `is_compatible()` checks extensively. As the HW and API evolve, the accelerator-side format may change. Negotiating version at `fi_getinfo` time prevents incompatible combinations.

---

## Summary of Priority Improvements

| Priority | Improvement | Rationale |
|----------|------------|-----------|
| **P0** | Hardware counter export | Essential for backpressure & signaling |
| **P0** | Structured (not opaque) export | Production needs individual queue attributes |
| **P0** | SQ backpressure mechanism | Prevents SQ overflow crashes |
| **P1** | Batch submission model | Maps to real HW doorbell amortization |
| **P1** | DMA-BUF support | Required for NIC→GPU direct writes |
| **P1** | Address resolution export | GPU needs (AHN, QPN, QKEY) for WQEs |
| **P1** | GPU-side recv posting | Validated by perftest; needed for send/recv and write+imm latency |
| **P2** | Two-layer API (portable + direct) | Resolves abstraction vs. performance tension |
| **P2** | Multi-rail | Critical for production bandwidth |
| **P2** | Error handling | Robustness in production |
| **P3** | Version negotiation | Future-proofing |

### Validation Coverage from perftest

The perftest GDA implementation provides concrete validation that the following operations
work correctly on the GPU side with efa-dp-direct:

| Operation | Latency Test | BW Test | Notes |
|-----------|-------------|---------|-------|
| RDMA Write | ✅ (polling byte sync) | ✅ (multi-QP, multi-thread) | Both solicited and unsolicited |
| RDMA Write+IMM | ✅ (recv CQ notification) | ✅ | GPU-side recv posting required |
| RDMA Read | ✅ | ✅ | Single-thread polling |
| Send/Recv | ✅ (ping-pong) | ✅ (multi-thread) | Full GPU-side recv management |
| Bidirectional | — | ✅ (2 CUDA blocks) | Separate send/recv blocks |
| Multi-QP | — | ✅ (up to 32 QPs) | Thread-to-QP assignment |
| Cooperative CQ poll | — | ✅ (N threads poll position N) | Demonstrates parallel completion |

This confirms the OFI Accelerator API must support at minimum:
- All RDMA verbs (send, recv, write, write+imm, read)
- GPU-side receive buffer posting and CQ management
- Cooperative multi-thread submission and completion
- Both latency-optimized (single-thread) and throughput-optimized (multi-thread) patterns

---

## Appendix: Mapping Between Systems

| OFI Acc API | efa-dp-direct | aws-ofi-nccl GDAKI | libfabric EFA provider | perftest GDA |
|------------|---------------|---------------------|----------------------|--------------|
| `fi_acc_info.alloc` | N/A (user provides) | `cuMemHostRegister` | `fi_efa_ops_gda` | `ctx->memory->allocate_buffer` (DMA-BUF) + `cuMemHostRegister` (BAR) |
| `fi_cq_attr.acc_info` | `efa_cuda_cq_attrs` | `fi_efa_cq_attr` | `fi_efa_cq_init_attr` | `efadv_cq_init_attr` + `efa_cuda_cq_attrs` |
| `fi_ep_export_acc` | `efa_cuda_create_qp` | `query_qp_wqs` + `gpu_qp.build` | `fi_efa_ops_gda.query_qp_wqs` | `efadv_query_qp_wqs` + `cuMemHostRegister` + `efa_cuda_create_qp` |
| `fi_cq_export_acc` | `efa_cuda_create_cq` | `query_cq` + `gpu_cq.build` | `fi_efa_ops_gda.query_cq` | `efadv_create_cq(EXT_MEM_DMABUF)` + `efa_cuda_create_cq` |
| `fi_acc_send` | `init_send_wr` + `set_sge` + `set_remote` + `place` + `flush` | same as efa-dp-direct | N/A (device-side) | same: `init_send_wr` + `set_sge` + `set_remote` + `place` + `flush` |
| `fi_acc_recv` | `post_recv_wr` + `flush_rq_wrs` | N/A (no GPU recv in NCCL) | N/A (device-side) | `efa_cuda_post_recv_wr` + `efa_cuda_flush_rq_wrs` |
| `fi_acc_write` | `init_rdma_write_wr` + ... | same as efa-dp-direct | N/A (device-side) | `efa_cuda_init_rdma_write_wr` + `set_sge` + `set_remote` + `place` + `flush` |
| `fi_acc_read` | `init_rdma_read_wr` + ... | same as efa-dp-direct | N/A (device-side) | `efa_cuda_init_rdma_read_wr` + `set_sge` + `set_remote` + `place` + `flush` |
| `fi_acc_cq_read` | `efa_cuda_cq_poll` + `cq_pop` | same as efa-dp-direct | N/A (device-side) | `efa_cuda_cq_poll(cq, tid)` + `efa_cuda_cq_pop(cq, batch)` |
| `FI_ACC_WORK_GROUP` | `start_sq_batch(warp_size)` + parallel `place_wr` | `sq_lock` + batch | N/A (device-side) | `start_sq_batch(batch_size)` + `__syncthreads()` + parallel `place_wr` |
| (missing) | N/A | `cntr_open_ext` + DMA-BUF | `fi_efa_ops_gda.cntr_open_ext` | Not used (CQ-only) |
| (missing) | N/A | `query_addr` → (AHN, QPN, QKEY) | `fi_efa_ops_gda.query_addr` | Host resolves, passes as kernel args |
