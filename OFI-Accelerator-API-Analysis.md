# OFI Accelerator API — Analysis & Improvement Recommendations

Based on deep analysis of:
- The **OFI Accelerator API** proposal (slides by Jianxin Xiong, 4/21/2026)
- **efa-dp-direct** (v0.0.2) — direct GPU-to-NIC datapath library for EFA
- **NCCL upstream GIN/EFA-GDA** (`upstream-to-nccl/src/include/nccl_device/gin/efa_gda/`) — the actual device-side NCCL integration
- **aws-ofi-nccl** GIN/GDAKI — host-side plugin that populates device handles
- **perftest** (RDMA benchmark tool) — GDA mode implementation (`--use_dp_direct`)

---

## Current Production Architecture (NCCL GIN EFA-GDA)

### How it works today

```
┌──────────────────────────────────────────────────────────────────────────┐
│  GPU Kernel (NCCL GIN — gin_efa_gda.h)                                    │
│                                                                           │
│  #include "efa_cuda_dp_impl.cuh"   ← ONLY for WQE struct/format macros   │
│                                                                           │
│  WQE CONSTRUCTION (from efa-dp-direct):                                   │
│    efa_cuda_init_rdma_write_wr(&wr, id, rkey, raddr)                      │
│    efa_cuda_wr_set_sge(&wr, lkey, addr, len)                              │
│    efa_cuda_wr_set_remote(&wr, ah, qpn, qkey)                             │
│    efa_cuda_wr_set_processing_hints(&wr, BURST_PPS_SENSITIVE)             │
│    EFA_SET(&wr.meta.ctrl2, PHASE, wqe_phase)                              │
│                                                                           │
│  SQ MANAGEMENT (GIN's own warp-cooperative protocol):                     │
│    1. coalesced_threads() + labeled_partition(qp) → warp group            │
│    2. Leader: pc_ref.fetch_add(group_size) → atomic slot reservation      │
│    3. Chunk into windows of ≤ max_batch                                   │
│    4. Leader: backpressure on un-rung depth (db_rung) AND hw counter      │
│    5. All lanes: direct 64-byte write to SQ ring slot (parallel)          │
│    6. Leader: __threadfence_system() → *db = target → advance cursors     │
│    7. Strict slot-order handoff via wqes_completed rendezvous             │
│                                                                           │
│  COMPLETION: counter-only (NO CQ polling)                                 │
│    hwCounterLoad(local_cntr_value) ← system-scope acquire load            │
│    Flush: spin until (submitted - *cntr) & 0x7FFFFFFF == 0                │
│                                                                           │
│  NOT USED from efa-dp-direct:                                             │
│    ❌ efa_cuda_start_sq_batch / sq_batch_place_wr / flush_sq_wrs          │
│    ❌ efa_cuda_cq_poll / cq_pop                                           │
│    ❌ efa_cuda_post_recv_wr / flush_rq_wrs                                │
└──────────────────────────┬───────────────────────────────────────────────┘
                           │ Direct HW access (BAR MMIO for SQ + doorbell)
                           │ PCIe coherent read (GPU HBM for HW counters)
┌──────────────────────────┴───────────────────────────────────────────────┐
│  Host Setup (aws-ofi-nccl GDAKI plugin)                                   │
│    1. fi_open_ops(domain, FI_EFA_GDA_OPS) → gda_ops                       │
│    2. gda_ops->cntr_open_ext(domain, DMA-BUF) → HW counter in GPU HBM    │
│    3. fi_endpoint() + fi_ep_bind(cntr, FI_WRITE) + fi_enable()            │
│    4. gda_ops->query_qp_wqs(ep) → sq_buffer, sq_doorbell, sizes          │
│    5. cuMemHostRegister(sq_buffer, IOMEMORY|DEVICEMAP)                    │
│    6. cuMemHostRegister(doorbell, IOMEMORY|DEVICEMAP)                     │
│    7. cuMemHostGetDevicePointer → GPU-visible pointers                     │
│    8. efa_cuda_create_qp(attrs) → GPU-resident efa_cuda_qp descriptor     │
│    9. gda_ops->query_addr(ep, fi_addr) → (ahn, qpn, qkey) per peer       │
│   10. Build nccl_ofi_gin_gdaki_dev_handle + H2D copy                      │
└──────────────────────────────────────────────────────────────────────────┘
```

### Key design decisions in NCCL GIN:
1. **efa-dp-direct is a WQE-format library only** — NCCL uses `init_rdma_write_wr`, `wr_set_sge`, `wr_set_remote` for WQE construction, but does NOT use its SQ management (`start_sq_batch`/`place_wr`/`flush`)
2. **No CQ polling on data path** — completion tracked entirely via NIC HW counters (FI_WRITE), read with system-scope acquire
3. **Warp-cooperative SQ posting** — `cooperative_groups::labeled_partition` groups lanes targeting the same QP; leader reserves slots atomically, all lanes write WQEs in parallel
4. **Deferred doorbell aggregation** — `ncclGinOptFlagsAggregateRequests` lets groups skip doorbell; a later group drains all deferred WQEs with one doorbell ring
5. **Dual backpressure** — (a) un-rung depth bounded by `max_batch`, (b) ring overflow bounded by `sq_size` via HW counter
6. **Counter wraps at 2^31** — all arithmetic uses `(producer - consumer) & 0x7FFFFFFF`
7. **Multiple endpoint flavors** — data EP, pvdata EP (PutValue staging), counter EPs, signal EPs (remote target only)
8. **Provider-specific extension API** (`fi_efa_ops_gda`) — not portable across providers
9. **Direct struct field access** — GIN accesses `qp->sq.wq.pc`, `qp->sq.wq.buf`, `qp->sq.wq.db`, `qp->sq.wq.max_batch`, `qp->sq.wq.wqes_completed`, `qp->sq.wq.wqes_posted` directly
10. **Three resource sharing modes** — Exclusive (one thread, no atomics), CTA (block-scope atomics), GPU (device-scope atomics); selected at `ncclGin` construction via `resourceSharingMode`, carried in `ncclGinCtx`; runtime switch dispatches to template-instantiated code; EFA-GDA currently only distinguishes CTA vs GPU (collapses Exclusive into GPU)

### efa-dp-direct primitives actually used by NCCL GIN:

| Primitive | Used? | Purpose |
|-----------|-------|---------|
| `efa_cuda_init_rdma_write_wr()` | ✅ | Build WQE with opcode + remote addr |
| `efa_cuda_wr_set_sge()` | ✅ | Set local buffer SGE |
| `efa_cuda_wr_set_remote()` | ✅ | Set (ah, qpn, qkey) destination |
| `efa_cuda_wr_set_processing_hints()` | ✅ | Set PPS burst hint |
| `EFA_SET(&wr.meta.ctrl2, PHASE, phase)` | ✅ | Stamp phase bit |
| `efa_cuda_start_sq_batch()` | ❌ | GIN does atomic `pc.fetch_add` instead |
| `efa_cuda_sq_batch_place_wr()` | ❌ | GIN does direct 64-byte ring write |
| `efa_cuda_flush_sq_wrs()` | ❌ | GIN does its own fence + doorbell + rendezvous |
| `efa_cuda_cq_poll()` / `cq_pop()` | ❌ | GIN uses HW counter, not CQ |
| `efa_cuda_post_recv_wr()` / `flush_rq_wrs()` | ❌ | GIN is write-only (no recv) |

### NCCL GIN Warp-Cooperative SQ Protocol (detailed)

```
postRdmaWrite<mode>(ep, ah, qpn, qkey, srcAddr, srcLkey, writeBytes, dstAddr, dstRkey, optFlags):

  ┌─ Warp Coalescing ───────────────────────────────────────────────────────┐
  │ active = cooperative_groups::coalesced_threads()                         │
  │ group = labeled_partition(active, (uintptr_t)qp)  ← lanes on same QP   │
  │ is_leader = (group.thread_rank() == 0)                                  │
  │ group_size = group.num_threads()                                        │
  └─────────────────────────────────────────────────────────────────────────┘

  ┌─ Atomic Slot Reservation ───────────────────────────────────────────────┐
  │ if (is_leader)                                                          │
  │   base = pc_ref.fetch_add(group_size, relaxed)  ← one atomic per group  │
  │ base = group.shfl(base, 0)  ← broadcast to all lanes                   │
  └─────────────────────────────────────────────────────────────────────────┘

  ┌─ Chunked Posting (for group_size > max_batch) ──────────────────────────┐
  │ for chunk_start in [0, group_size) step max_batch:                      │
  │                                                                         │
  │   ┌─ Leader: Backpressure (two checks) ────────────────────────────┐    │
  │   │ (a) Un-rung depth: chunk_next - db_rung ≤ max_batch            │    │
  │   │     If exceeded: force-ring deferred WQEs below us             │    │
  │   │ (b) Ring overflow: (chunk_next - *hw_cntr) & 0x7FFF ≤ sq_size  │    │
  │   │     Spin until NIC consumes enough WQEs                        │    │
  │   └────────────────────────────────────────────────────────────────┘    │
  │   group.sync()                                                          │
  │                                                                         │
  │   ┌─ All lanes: Parallel WQE Write ────────────────────────────────┐    │
  │   │ my_slot = chunk_base + (my_idx - chunk_start)                  │    │
  │   │ sq_idx = my_slot & queue_mask                                  │    │
  │   │ phase = (my_slot >> queue_size_shift) & 1                      │    │
  │   │ EFA_SET(&wr.meta.ctrl2, PHASE, phase)                         │    │
  │   │ memcpy_64B(qp->sq.wq.buf + sq_idx*64, &wr)                   │    │
  │   └────────────────────────────────────────────────────────────────┘    │
  │   group.sync()                                                          │
  │                                                                         │
  │   ┌─ Leader: Publish + Doorbell + Handoff ─────────────────────────┐    │
  │   │ __threadfence_system()   ← make WQEs visible to NIC            │    │
  │   │ while (wqes_completed != chunk_base) spin  ← rendezvous        │    │
  │   │                                                                │    │
  │   │ if (!aggregate || chunk_next - db_rung >= max_batch):          │    │
  │   │   *qp->sq.wq.db = chunk_next          ← ring doorbell         │    │
  │   │   __threadfence_system()               ← order MMIO            │    │
  │   │   submitted_count += (chunk_next - db_rung)                    │    │
  │   │   db_rung = chunk_next                                         │    │
  │   │                                                                │    │
  │   │ wqes_completed = chunk_next            ← hand off to next      │    │
  │   └────────────────────────────────────────────────────────────────┘    │
  │   group.sync()                                                          │
  └─────────────────────────────────────────────────────────────────────────┘
```

### NCCL GIN Endpoint Architecture

```
nccl_ofi_gin_gdaki_dev_handle (per-context, in GPU memory):
├── data: endpoint_handle          ← payload RDMA writes
│   ├── qp (efa_cuda_qp*)         ← raw QP struct, accessed directly
│   ├── cq (efa_cuda_cq*)         ← exists but NOT polled on data path
│   ├── target_address_handles[]  ← [total_slots × nranks]
│   ├── target_remote_qpns[]      ← [total_slots × nranks]
│   ├── target_qkey[]             ← [total_slots × nranks]
│   ├── sq_lock (unused by GIN — uses atomics instead)
│   ├── local_cntr_value*         ← FI_WRITE HW counter in GPU HBM
│   ├── submitted_count           ← bumped after doorbell
│   └── sq_size                   ← for ring-overflow backpressure
│
├── pvdata: endpoint_handle        ← PutValue staging writes
│   └── (same structure as data, own QP/counter)
│
├── counter_handles[nCounters]     ← counter-tracked puts (own QPs)
│   └── each has: base (endpoint) + cntr_value* + cntr_offset
│
├── signal_handles[nSignals]       ← signal delivery (remote target only)
│   └── each has: base (endpoint) + cntr_value* (FI_REMOTE_WRITE) + cntr_offset
│
├── scratch_{local_addr, lkey, remote_addrs[], remote_rkeys[]}
│                                  ← 0-byte writes for signal-only
├── putvalue_{lkey, slot_size}     ← PutValue slot pool metadata
├── nranks, rank, rail_id
└── nCounters, nSignals
```

### Target Addressing Table Layout

Each endpoint (data, pvdata, each counter EP) carries its own target table:
```
target_address_handles[total_slots * nranks]   (targetSlot-major)
target_remote_qpns[total_slots * nranks]
target_qkey[total_slots * nranks]

Index: targetSlot * nranks + peer
  slot 0       → peer's DATA endpoint (no FI_REMOTE_WRITE, plain put)
  slot 1 + s   → peer's sc endpoint s (FI_REMOTE_WRITE, signal delivery)
```

### Signal Add-by-N Emulation

EFA's FI_REMOTE_WRITE increments by exactly 1 per inbound write. To signal
Add-by-N, NCCL posts N separate 0-byte writes:

```c
// First write: payload (or 0-byte scratch if signal-only), on main_ep
postRdmaWrite<mode>(main_ep, main_ah, main_qpn, main_qkey,
                    srcAddr, srcLkey, writeBytes, dstAddr, dstRkey);

// Remaining N-1 signal increments: 0-byte writes on DATA ep
for (uint32_t k = 1; k < signalCount; k++) {
    postRdmaWrite<mode>(&dev->data, dataSigAh, dataSigQpn, dataSigQkey,
                        scratch_local_addr, scratch_lkey, 0,
                        scratch_remote_addrs[peer], scratch_remote_rkeys[peer]);
}
```

### Counter-Only Completion (Flush)

```c
// Wait for ALL endpoints to drain
auto wait_for_endpoint = [](endpoint_handle& ep) {
    uint64_t target = atomicLoad<scope, relaxed>(&ep.submitted_count);
    while (((uint32_t)target - (uint32_t)hwCounterLoad(ep.local_cntr_value))
           & 0x7FFFFFFF) != 0) {
        /* spin */
    }
};
wait_for_endpoint(dev->data);
wait_for_endpoint(dev->pvdata);
for (int i = 0; i < dev->nCounters; i++)
    wait_for_endpoint(dev->counter_handles[i]->base);
// Signal endpoints are NEVER drained (remote target only)
```

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

| Aspect | OFI Acc API Proposal | NCCL GIN (actual production) | perftest GDA | Gap |
|--------|---------------------|-------------------------------|--------------|-----|
| **Memory allocation** | `fi_acc_info.alloc/import` callbacks | `cuMemHostRegister(IOMEMORY)` for SQ/doorbell BAR + DMA-BUF for HW counters | DMA-BUF for CQ, `cuMemHostRegister(IOMEMORY)` for SQ/doorbell BAR | Proposal is more abstract; production needs both BAR-mapping and DMA-BUF |
| **Resource export** | `fi_ep_export_acc()` → opaque blob | `gda_ops->query_qp_wqs()` → raw struct fields (`buf`, `db`, `pc`, `queue_mask`, `max_batch`, etc.) directly accessed | `efadv_query_qp_wqs()` + manual `cuMemHostRegister` + `efa_cuda_create_qp()` | NCCL accesses QP fields directly today, but our opaque export works because the provider's inline `fi_acc_write()` accesses those same fields internally |
| **SQ management** | `fi_acc_write()` encapsulates full post | **Custom warp-cooperative protocol:** atomic `pc.fetch_add` → parallel WQE write → rendezvous → deferred doorbell | `start_sq_batch` → `sq_batch_place_wr` → `flush_sq_wrs` (linear single-thread) | NCCL's protocol CAN be encapsulated inside `fi_acc_write()` via `scope` + `FI_MORE` flags; provider implements cooperative posting internally |
| **WQE construction** | Hidden inside `fi_acc_write()` | `efa_cuda_init_rdma_write_wr` + `wr_set_sge` + `wr_set_remote` + `wr_set_processing_hints` + manual phase stamp | Same efa-dp-direct WQE builders | Proposal hides WQE format; NCCL uses efa-dp-direct as format library only |
| **Completion** | `fi_acc_cq_read()` (CQ polling) | **NO CQ polling** — counter-only: `hwCounterLoad(local_cntr_value)` with system-scope acquire; `(submitted - *cntr) & 0x7FFFFFFF` | CQ polling (`efa_cuda_cq_poll`) | Counter export is P0; CQ export is P2 (used by perftest, not NCCL) |
| **Backpressure** | Not elaborated | **Dual:** (a) un-rung depth ≤ max_batch (doorbell staging limit), (b) ring overflow via `(chunk_next - *hw_cntr) & 0x7FFF ≤ sq_size` | CQ-based: `scnt - ccnt < tx_depth` | Hidden inside `fi_acc_write()` — provider enforces both limits internally |
| **Doorbell control** | Not elaborated | **Deferred aggregation:** `ncclGinOptFlagsAggregateRequests` skips doorbell; later group drains all deferred WQEs with one ring | `flush_sq_wrs()` after batch of ≤16 WQEs | Hidden inside `fi_acc_write()` — `FI_MORE` flag defers doorbell; provider rings when max_batch reached or `FI_MORE` absent |
| **Concurrency model** | `FI_ACC_WORK_ITEM/SUBGROUP/WORK_GROUP/DEVICE` scope param | **Warp coalescing:** `cooperative_groups::labeled_partition(qp)` → leader reserves, all lanes write WQEs in parallel, strict slot-order rendezvous. **Resource sharing mode** (3 modes: Exclusive/CTA/GPU) selects atomic scope for coordination cursors | Fixed thread-block: `__syncthreads()` | `scope` parameter unifies both: `WORK_ITEM`=Exclusive (no atomics), `SUBGROUP`/`WORK_GROUP`=CTA (block-scope), `DEVICE`=GPU (device-scope); one runtime switch dispatches |
| **Counter support** | Not shown in proposal | **Central to everything:** HW counter in GPU HBM (FI_WRITE for local completion, FI_REMOTE_WRITE for signals), 31-bit wrap semantics | Not used (CQ-only) | **P0 gap** — counters ARE the completion mechanism in production |
| **Counter wrapping** | Not elaborated | 2^31 wrap: `(producer - consumer) & 0x7FFFFFFF`; in-flight bounded by sq_size (4096) « 2^31 | N/A | Already queryable via existing `domain_attr->max_cntr_value` / `max_err_cntr_value`; acc API just documents device-side modulo arithmetic |
| **Signal delivery** | Not elaborated | EFA FI_REMOTE_WRITE ticks +1 per write; Add-by-N emulated as N separate 0-byte writes to peer scratch | N/A | Signal semantics are transport-specific |
| **Multi-endpoint** | Not elaborated | data EP, pvdata EP (PutValue staging), counter EPs (per-counterId), signal EPs (remote target only) | Single QP or multi-QP | Production uses many specialized EPs per context |
| **Multi-rail** | Not elaborated | `rail_id = contextId % num_rails`; per-rail domains/EPs/MRs; window arrays indexed by rail_id | Multiple QPs sharing single CQ | Important for production bandwidth |
| **Per-QP serialization** | Not in proposal | Three modes: **Exclusive** (plain loads/stores, no atomics — one thread owns QP), **CTA** (block-scope atomics), **GPU** (device-scope atomics). Selected at construction time via `ctx.resourceSharingMode`. All three compile into the binary; runtime switch dispatches. | N/A | Unified into `scope` parameter: `WORK_ITEM`=Exclusive, `SUBGROUP`/`WORK_GROUP`=CTA, `DEVICE`=GPU; provider dispatches internally with one switch |
| **PutValue staging** | Not elaborated | Dedicated pvdata EP; per-EP slot pool (`pvSliceBase + slot_idx * pvSlotSize`); stages value then RDMA writes from pool | N/A | Application-level pattern, but API must support separate staging EP |
| **Recv posting on GPU** | Not elaborated | NOT used (NCCL is write-only) | `efa_cuda_post_recv_wr()` + `efa_cuda_flush_rq_wrs()` | perftest demonstrates it's viable; not needed by primary consumer |
| **GPU-side timing** | Not elaborated | N/A | `clock64()` before/after each op | Useful for benchmarking only |

---

## Recommendations for Improving the OFI Accelerator API

The primary consumer (NCCL GIN) uses efa-dp-direct only as a WQE format/construction
library and implements its own warp-cooperative SQ posting protocol. Our API
encapsulates this pattern inside `fi_acc_write()` via `scope` and `flags` parameters,
so the consumer gets the same performance without managing ring buffers directly.


### 1. The `fi_acc_info` Struct

`fi_acc_info` is the consumer's description of the accelerator, passed at object
creation (CQ/counter/EP with `FI_ACC`). It carries the GPU identity, the memory
handling mode, and the callbacks the provider invokes during creation and export.

```c
struct fi_acc_info {
    enum fi_hmem_iface   iface;      /* FI_HMEM_CUDA, FI_HMEM_ROCR, FI_HMEM_ZE */
    uint64_t             device;     /* GPU device ordinal */
    enum fi_acc_mem_type mem_type;   /* how memory is allocated/mapped */
    /* Callbacks (used when mem_type == FI_ACC_MEM_USER): */
    int  (*alloc)(uint64_t device, uint64_t size, uint64_t alignment,
                  uint64_t flags, void **addr, int *fd, uint64_t *offset);
    int  (*import)(uint64_t device, void *host_addr, uint64_t size,
                   uint64_t flags, void **dev_addr);
    void (*free)(uint64_t device, void *addr);
};
```

#### Memory Type Enum

Selects who allocates GPU memory and how the provider gets device pointers:

```c
enum fi_acc_mem_type {
    FI_ACC_MEM_USER,     /* Consumer handles memory via alloc/import/free
                          * callbacks — works for any GPU runtime */
    FI_ACC_MEM_PROVIDER, /* Provider handles memory internally (e.g., via
                          * libfabric HMEM interface) */
};
```

With `FI_ACC_MEM_USER`, the provider stays GPU-runtime-agnostic and the
consumer's callbacks translate to CUDA/HIP/Level Zero calls. DMA-BUF is
not a separate mode — it flows through the `alloc` callback (the consumer exports
the fd when `FI_ACC_ALLOC_DMABUF` is set).

#### Callback Flags — Libfabric-Defined, Not Platform-Specific

The `alloc` and `import` callbacks use **libfabric-defined flags** rather than
platform-specific ones (e.g., CUDA's `CU_MEMHOSTREGISTER_IOMEMORY`). The provider
expresses *what* it needs semantically; the consumer's callback translates to
platform-specific calls.

**Alloc flags** (allocate fresh GPU memory):

| Flag | Meaning |
|------|---------|
| `FI_ACC_ALLOC_DMABUF` | Consumer must export a DMA-BUF fd for the allocation (provider will pass the fd to the NIC driver for direct DMA access) |
| (none) | Plain GPU memory — no fd needed, consumer may return fd = -1 |

```c
// Case 1: DMA-BUF needed (HW counter, GPU-resident CQ buffer — NIC DMAs into it):
acc_info->alloc(device, 8, 8, FI_ACC_ALLOC_DMABUF,
                &gpu_ptr, &dmabuf_fd, &offset);
// Provider passes dmabuf_fd to NIC driver (efadv_create_comp_cntr)
// GPU kernel reads *gpu_ptr directly

// Case 2: Plain GPU memory (opaque EP blob, AV peer table, MR descriptor):
acc_info->alloc(device, sizeof(fi_acc_dev_ep), 8, 0,
                &gpu_ptr, &dmabuf_fd, &offset);
// Consumer can just cudaMalloc; fd stays -1, provider ignores it
// Provider H2D copies the built struct to gpu_ptr
```

**Why distinguish:** Exporting a DMA-BUF fd
(`cuMemGetDmaBufFd`) has real cost and constraints — memory must be allocated
with RDMA-capable properties (e.g., CUDA VMM with `gpuDirectRDMACapable`). The
blobs from `fi_ep_export_acc`, `fi_av_export_acc`, and `fi_mr_export_acc` never
need NIC access, so a plain `cudaMalloc` suffices.

**Import flags** (map provider-owned host memory into GPU address space):

| Flag | Meaning | CUDA equivalent | HIP equivalent |
|------|---------|-----------------|----------------|
| `FI_ACC_IMPORT_IOMEMORY` | Host address points to PCIe BAR MMIO (device I/O memory on the NIC) | `CU_MEMHOSTREGISTER_IOMEMORY` | `hipHostRegisterIoMemory` |
| `FI_ACC_IMPORT_DEVICEMAP` | Make memory visible in GPU device address space | `CU_MEMHOSTREGISTER_DEVICEMAP` | `hipHostRegisterMapped` |

```c
// Provider (inside fi_ep_export_acc):
//   SQ buffer is BAR MMIO → needs both flags
acc_info->import(device, sq_host_va, sq_size,
                 FI_ACC_IMPORT_IOMEMORY | FI_ACC_IMPORT_DEVICEMAP,
                 &sq_dev_ptr);

//   RQ buffer is regular host memory → only DEVICEMAP
acc_info->import(device, rq_host_va, rq_size,
                 FI_ACC_IMPORT_DEVICEMAP,
                 &rq_dev_ptr);
```

The consumer's CUDA callback translates:

```c
int my_import(uint64_t device, void *host_addr,
              uint64_t size, uint64_t flags, void **dev_addr)
{
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
```

**Why libfabric flags instead of passing CUDA flags directly:**
- Provider code never links CUDA/HIP/Level Zero — it's built with gcc
- A HIP consumer translates `FI_ACC_IMPORT_IOMEMORY` → `hipHostRegisterIoMemory`
- A Level Zero consumer translates differently (`zeMemOpenIpcHandle` or `zexDriverImportExternalPointer`)
- The provider expresses *what* (BAR MMIO vs host RAM) — the consumer expresses *how*



### 2. Export APIs

The host-side export returns opaque `void*` device handles. The provider builds
the device-side blob internally (populates ring geometry, doorbell pointers,
phase state, backpressure fields) using the memory callbacks from section 1.
The consumer never inspects or constructs these structs — it passes the opaque
handles directly to the device-side API (`fi_acc_write()`, `fi_acc_cntr_read()`, etc.).

The exports fall into two categories:
- **Object handle exports** (2a EP, 2b Counter, 2c CQ) — one object → one opaque handle
- **Table exports (batch-native)** (2d MR, 2e AV) — N items → one GPU-resident table

**No parallel `*_open_acc` API needed.** Objects are created with the standard
calls (`fi_cq_open()`, `fi_cntr_open()`, `fi_endpoint()`) — the `FI_ACC` flag
plus `acc_info` tell the provider the object will be exported. All accelerator-
specific setup happens inside the export call.

#### 2a. Endpoint Export

```c
int fi_ep_export_acc(struct fid_ep *ep, uint64_t flags,
                     void **acc_ep, size_t *acc_ep_size);
```

**What the provider does inside `fi_ep_export_acc()`:**
1. Calls `efadv_query_qp_wqs()` → gets host VAs of SQ buffer, doorbell, RQ
2. Calls `acc_info.import()` with `FI_ACC_IMPORT_IOMEMORY | FI_ACC_IMPORT_DEVICEMAP` → gets device pointers
3. Allocates GPU memory for the internal `fi_acc_dev_ep` struct (via `acc_info.alloc()`)
4. Fills the struct with device pointers, ring geometry, phase state, max_batch, sq_size
5. H2D copies → returns opaque `void*` to consumer

The resource sharing mode (atomic scope) is NOT declared at export time —
it is determined per-call by the `scope` parameter on `fi_acc_write()`.
The provider compiles all three template instantiations (Exclusive/CTA/GPU)
into its `.cuh` header; `fi_acc_write()` dispatches with a single runtime
switch on `scope`, matching the upstream NCCL pattern where `putImpl` switches
on `ctx.resourceSharingMode` into template-instantiated `putImplMode<MODE>()`.

The consumer only ever does:
```c
void *acc_ep;
fi_ep_export_acc(ep, 0, &acc_ep, &size);
// ... pass acc_ep to GPU kernel ...
fi_acc_write(acc_ep, buf, desc, size, 0, peer, raddr, rkey, NULL,
             FI_ACC_SUBGROUP, flags);  // scope selects atomic scope too
```

#### 2b. Counter Export

```c
int fi_cntr_export_acc(struct fid_cntr *cntr, uint64_t flags,
                       void **acc_cntr, size_t *acc_cntr_size);
```

**What the provider does inside `fi_cntr_export_acc()`:**
1. `acc_info.alloc(FI_ACC_ALLOC_DMABUF)` → ONE GPU HBM allocation + ONE DMA-BUF fd,
   sized to hold both the **completion counter** and (if the HW supports it) the
   **error counter** at different offsets (EFA: `comp_cntr_ext_mem` +
   `err_cntr_ext_mem` in `efadv_comp_cntr_init_attr` — same fd, distinct offsets)
2. Bind the fd to the NIC counter (e.g., `efadv_create_comp_cntr`) so
   the NIC DMAs both counter updates directly into GPU memory
3. Return ONE opaque handle wrapping both GPU pointers

The consumer never distinguishes comp vs err memory — both live behind the
single opaque handle. The device-side API exposes them as separate reads
(`fi_acc_cntr_read()` for the completion value, `fi_acc_cntr_readerr()` for
the error value — mirroring host-side `fi_cntr_read()` / `fi_cntr_readerr()`);
the provider resolves each to the right offset internally.
On hardware without a device-visible error counter, the provider sizes the
allocation for comp only and `fi_acc_cntr_readerr()` degrades gracefully
(returns 0 or a comp_mask bit indicates its absence).

**Counter semantics** (counters are THE completion mechanism in NCCL GIN — not CQ polling):

NCCL GIN uses counters for:
- **SQ backpressure (FI_WRITE)**: `(chunk_next - (uint32_t)hwCounterLoad(cntr)) & 0x7FFFFFFF ≤ sq_size`
- **Flush/completion (FI_WRITE)**: `(submitted - *cntr) & 0x7FFFFFFF == 0`
- **Signal delivery (FI_REMOTE_WRITE)**: peer polls counter to detect arrival
- **Counter-tracked puts**: counterId selects which EP's FI_WRITE to observe
- **Reset-without-zeroing**: software `cntr_offset` baseline, since NIC counter is read-only

**Wrap semantics are already covered by the existing cntr API:** the domain
attributes report `max_cntr_value` / `max_err_cntr_value`
(`fi_info->domain_attr`), so a consumer can query the wrap point generically
(EFA would report 2^31 - 1). No new API is needed — the accelerator API only
needs to document that:
- Device-side counter arithmetic must be modulo `max_cntr_value + 1`
  (e.g., `(a - b) & max_cntr_value` when it is a power-of-2 minus 1)
- Counter is NIC-owned; software cannot write it (offset-based reset only)

#### 2c. CQ Export

```c
int fi_cq_export_acc(struct fid_cq *cq, uint64_t flags,
                     void **acc_cq, size_t *acc_cq_size);
```

`fi_cq_export_acc()` can place the CQ ring in GPU HBM (alloc + DMA-BUF
→ NIC writes CQEs directly to GPU memory) or map the host ring via `import()` —
the provider picks per its hardware.

**HW creation timing — an implementation trade-off** (applies to both counter
and CQ): `fi_cq_open()` / `fi_cntr_open()` are abstractions; the underlying HW
resource can be created whenever the provider chooses. Since `acc_info` (with
the `alloc` callback) is available at open time, the provider has two options:

- **Allocate at open:** `fi_cntr_open(FI_ACC)` / `fi_cq_open(FI_ACC)` call
  `acc_info.alloc(FI_ACC_ALLOC_DMABUF)` immediately and create the HW resource
  (e.g., `efadv_create_comp_cntr(fd, offset)`,
  `efadv_create_cq(EXT_MEM_DMABUF)`) inside the open call. The export call then
  only does the remaining mapping work (BAR imports, opaque blob build, H2D copy).
- **Defer to export:** open returns the fid only; the provider creates the HW
  resource lazily at export time when the fd is produced.

Either way this is provider-internal and invisible to the consumer.

#### 2d. MR Export (Batch-Native)

Unlike the object handle exports in 2a–2c, MR export is a **table builder**,
not a single-object handle wrapper. It takes an array by default —
`count == 1` is the trivial case; there is no separate single-item API.

```c
/* Batch-native: exports local/remote keys for `count` MRs into one
 * GPU-resident descriptor table. acc_descs_size is the TOTAL table size
 * (count × per-entry stride). */
int fi_mr_export_acc(struct fid_mr **mrs, size_t count, uint64_t flags,
                     void **acc_descs, size_t *acc_descs_size);
```

**Why batch-native:** NCCL GIN registers per-rail MRs for payload
buffers, scratch buffers, and PutValue slot pools, and needs their lkeys on the
GPU for WQE construction. One call exports all descriptors into a single
GPU-resident table with one alloc + H2D copy.

#### 2e. AV Export (Batch-Native)

Like MR export, AV export is a table builder taking an array by default.

```c
/* Batch-native: resolves `count` fi_addrs into one GPU-resident peer table.
 * acc_peers_size is the TOTAL table size (count × per-entry stride). */
int fi_av_export_acc(struct fid_av *av, fi_addr_t *addrs, size_t count,
                     uint64_t flags, void **acc_peers, size_t *acc_peers_size);
```

**Why batch-native:** NCCL GIN builds `[total_slots × nranks]` target
tables of (AHN, QPN, QKEY) tuples — the GPU kernel indexes the table to select
the remote target per write. Passing the full `fi_addr_t` array in one call lets
the provider resolve all peers and build one GPU-resident table with a single
alloc + H2D copy, instead of `nranks × total_slots` round trips.

**Size and indexing (applies to both MR and AV tables):** the size output is
the **total table size** — consistent with the object handle exports in 2a–2c,
where the size output is always the whole blob. The per-entry stride is derived
as `size / count`, and the consumer indexes the table with plain pointer
arithmetic — no accessor functions needed. Entry *contents* remain opaque; only
the stride is derivable:

```c
// Host side:
void *acc_peers; size_t peers_size;
fi_av_export_acc(av, addrs, nranks, 0, &acc_peers, &peers_size);
size_t peer_stride = peers_size / nranks;   // per-entry stride

// Device side — select peer i and MR j:
void *peer = (char *)acc_peers + i * peer_stride;
void *desc = (char *)acc_descs + j * desc_stride;
fi_acc_write(acc_ep, buf, desc, size, 0, peer, raddr, rkey, NULL, scope, flags);
```

### 3. Device-Side Post API

The post API encapsulates NCCL GIN's warp-cooperative posting protocol inside
provider-inlined functions. The `scope` parameter controls how threads cooperate
on SQ submission; `FI_MORE` controls doorbell deferral.

#### Functions

The proposal (slides, 4/21/2026) defines the full accelerator-side surface:

```c
fi_acc_send(acc_ep, buf, size, desc, data, peer, ctxt, scope, flags)
fi_acc_recv(acc_ep, buf, desc, size, peer, ctxt, scope, flags)
fi_acc_tsend(acc_ep, buf, size, desc, data, peer, tag, ctxt, scope, flags)
fi_acc_trecv(acc_ep, buf, size, desc, peer, tag, ignore, ctxt, scope, flags)
fi_acc_write(acc_ep, buf, desc, size, data, peer, raddr, rkey, ctxt, scope, flags)
fi_acc_read(acc_ep, buf, desc, size, peer, raddr, rkey, ctxt, scope, flags)
fi_acc_atomic(acc_ep, …, scope, flags)
fi_acc_fetch_atomic(acc_ep, …, scope, flags)
fi_acc_compare_atomic(acc_ep, …, scope, flags)
fi_acc_flush(acc_ep)
```

Notes against production usage:
- **`fi_acc_write` covers the NCCL GIN data path** — the only post operation
  GIN uses. `data` maps to write-with-imm (perftest validates it); `ctxt` is
  the per-op context for CQ-based consumers (counter-only consumers pass NULL).
- **`fi_acc_flush(acc_ep)` is the TX doorbell drain** — rings the doorbell
  for all written-but-deferred (`FI_MORE`) WQEs. It does NOT wait for
  completion; see section 4 for the consumer-owned completion pattern.
- **`fi_acc_tsend`/`fi_acc_trecv`/atomics** — no current GDA consumer
  (NCCL GIN is write-only; perftest covers send/recv/write/read). EFA has no
  device-side tag matching or native atomics, so these would be unsupported
  (or emulated) there; portability across providers TBD.
- **`fi_acc_recv`** — validated by perftest (GPU-side RQ posting for
  send/recv and write+imm patterns).

#### Scope Parameter

The `scope` parameter declares the contention level on the EP — who else may
be posting to the same EP concurrently. The provider uses this to select the
atomic scope for internal coordination (slot reservation, rendezvous, doorbell
tracking). This maps directly to NCCL GIN's `ncclGinResourceSharingMode`
template parameter on `postRdmaWrite`.

The cooperation model (how threads coalesce within a post — e.g., warp-
cooperative `labeled_partition` in EFA-GDA) is provider-internal and not
exposed to the consumer. The provider always picks the optimal cooperation
strategy for its hardware; `scope` only tells it what synchronization
strength is needed.

| Scope | CUDA contention boundary | Internal atomic scope | NCCL GIN equivalent |
|-------|-------------------------|----------------------|---------------------|
| `FI_ACC_WORK_ITEM` | One thread owns this EP | None (plain loads/stores) | `NCCL_GIN_RESOURCE_SHARING_THREAD` / `DOCA_EXCLUSIVE` |
| `FI_ACC_SUBGROUP` | Warps within one CTA | `thread_scope_block` | `NCCL_GIN_RESOURCE_SHARING_CTA` |
| `FI_ACC_WORK_GROUP` | Threads within one CTA | `thread_scope_block` | `NCCL_GIN_RESOURCE_SHARING_CTA` |
| `FI_ACC_DEVICE` | Multiple CTAs on the GPU | `thread_scope_device` | `NCCL_GIN_RESOURCE_SHARING_GPU` |

`FI_ACC_SUBGROUP` and `FI_ACC_WORK_GROUP` both use block-scope atomics (a
warp is always within a CTA); they differ only in how the consumer organizes
its threads, not in what the provider does internally.

Rule of thumb: use the scope that matches the widest set of threads that
may concurrently post to the same EP handle.

#### Flags

| Flag | Effect |
|------|--------|
| `FI_MORE` | Defer doorbell — provider writes WQE but does not ring until a subsequent call without `FI_MORE`, a `fi_acc_flush()`, or max_batch reached |
| (none) | Ring doorbell immediately after this WQE batch |

`FI_MORE` works the same for both TX and RX. Provider-specific op flags (bits
60–63, e.g., EFA's `FI_EFA_WR_HIGH_PPS`) pass through unchanged, exactly as
they do for host-side calls like `fi_writemsg()`.

#### How NCCL GIN's Pattern Maps to the Post API

| NCCL GIN does manually | `fi_acc_write()` encapsulates via |
|---|---|
| `cooperative_groups::labeled_partition(qp)` | `scope = FI_ACC_SUBGROUP` — provider detects warp coalescing |
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
| `ncclGinScope` template (Exclusive/CTA/GPU atomic scope) | `scope` parameter — `WORK_ITEM`=Exclusive, `SUBGROUP`/`WORK_GROUP`=CTA (block-scope), `DEVICE`=GPU (device-scope); one switch dispatches |

#### Backpressure (Internal to Provider)

NCCL GIN has two independent checks, both inside `fi_acc_write()`:

```c
// (a) Un-rung depth (EFA staging limit):
//     chunk_next - db_rung ≤ max_batch
//     If exceeded: force-ring deferred WQEs to make room

// (b) Ring overflow (SQ overrun):
//     (chunk_next - *hw_cntr) & 0x7FFFFFFF ≤ sq_size
//     Spin until NIC consumes enough WQEs
```

The consumer never sees `sq_size`, `submitted_count`, or `max_batch`. The
provider owns all the state. The consumer observes backpressure only as
`fi_acc_write()` spinning when the SQ is full.

#### Example

```c
// Consumer's GPU kernel — replaces NCCL GIN's 200-line postRdmaWrite<mode>():
fi_acc_write(acc_ep, buf, desc, size, 0, peer, raddr, rkey, NULL,
             FI_ACC_SUBGROUP, FI_MORE);

// Provider internally does:
//   1. Detect subgroup → coalesce lanes targeting same EP
//   2. Leader: atomic reserve N slots
//   3. All lanes: build WQE, compute phase, write 64B to ring
//   4. FI_MORE → defer doorbell (or force-ring if max_batch reached)
//   5. Leader: fence, advance cursors, hand off in slot order
```


### 4. Device-Side Completion API

The completion API provides two mechanisms: counters (primary, used by NCCL GIN)
and CQ polling (secondary, used by perftest). No scope parameter needed — these
are simple reads/waits.

#### Functions

The proposal defines:

```c
fi_acc_cq_read(acc_cq, …)
fi_acc_cntr_read(acc_cntr, …)
fi_acc_cntr_readerr(acc_cntr, …)
```

Elaborated:

```c
// Counter — primary completion mechanism (NCCL GIN path)
uint64_t fi_acc_cntr_read(void *acc_cntr);
void     fi_acc_cntr_wait(void *acc_cntr, uint64_t target);

// Error counter — device-visible error detection, mirrors host-side
// fi_cntr_readerr(). Resolves to the err counter inside the same opaque
// handle (e.g., EFA's err_cntr_ext_mem — same DMA-BUF, distinct offset)
uint64_t fi_acc_cntr_readerr(void *acc_cntr);

// CQ — per-operation completion (perftest path)
void    *fi_acc_cq_read(void *acc_cq, uint32_t position);  // poll one entry
void     fi_acc_cq_pop(void *acc_cq, uint32_t amount);     // advance consumer

// Error detection (for CQ consumers)
uint32_t fi_acc_wc_read_vendor_err(void *cqe);
```

#### Completion Drain: fi_acc_flush + Consumer-Owned Baseline

`fi_acc_flush(acc_ep)` (section 3) only rings the doorbell for deferred WQEs —
it does not wait. Full completion drain (GIN's Flush) is the consumer-owned
baseline pattern; no provider-internal state needs exposing:

```c
uint64_t base = fi_acc_cntr_read(acc_cntr);   // baseline snapshot
// ... N posts (consumer counts N — it makes the calls) ...
fi_acc_flush(acc_ep);                          // ring db for deferred WQEs
fi_acc_cntr_wait(acc_cntr, base + N);          // modular compare internally
```

Contract requirements:
1. **1:1 tick** — each posted op increments the bound FI_WRITE counter by
   exactly 1 (normative; true on EFA)
2. **Flush before wait** — a `FI_MORE`-deferred WQE never completes until a
   doorbell covers it
3. **Multi-poster tally** — for an EP-wide quiet across threads/CTAs, the
   consumer aggregates its own N

#### Counter Completion (NCCL GIN Pattern)

NCCL GIN uses counters exclusively — no CQ polling on data path:

- **Flush (wait for local completion):**
  baseline pattern — `fi_acc_cntr_wait(cntr, base + N)` after `fi_acc_flush()`
  (see Completion Drain above)
- **Signal detection (wait for remote arrival):**
  `while (fi_acc_cntr_read(signal_cntr) - offset < expected) spin;`
- **Reset-without-zeroing:**
  Snapshot counter value as offset; subsequent reads subtract offset.

Counter semantics:
- NIC-owned — software cannot write it
- Wraps at 2^31 on EFA — all arithmetic uses `(a - b) & 0x7FFFFFFF`; wrap
  point is queryable via `domain_attr->max_cntr_value`
- Read via system-scope acquire (bypasses GPU caches, coherent with NIC PCIe writes)

#### CQ Completion (Perftest Pattern)

For consumers that need per-operation status (opcode, error, imm data):

- `fi_acc_cq_read(cq, position)` — position-based parallel polling
  (thread N polls position N for cooperative bandwidth kernels)
- `fi_acc_cq_pop(cq, amount)` — advance CQ consumer pointer after processing
- Phase-bit protocol handled internally by the provider

#### Error Handling

NCCL GIN detects errors via counter timeout (counter stops advancing).
`fi_acc_cntr_readerr()` improves on this where the HW exposes a device-visible
error counter (EFA does): the GPU kernel can distinguish "slow" from "failed"
without waiting for a timeout. `fi_acc_wc_read_vendor_err()` is available for
CQ-based consumers.
Host-side health monitoring is more practical for production error recovery.


### 5. The Abstraction Level Decision

NCCL GIN's warp-cooperative protocol is sophisticated, but its underlying
operations (reserve slots, write WQE, fence, ring doorbell, check counter)
can all be encapsulated inside `fi_acc_write()` with appropriate `scope`,
`flags`, and resource sharing mode. The provider has enough information to
implement the same optimizations.

The key insight: **NCCL's custom protocol exists because efa-dp-direct's
`start_sq_batch`/`place_wr`/`flush_sq_wrs` was too limiting** (single-threaded,
no deferred doorbells, no warp coalescing). Our API can do better by providing
a higher-level call that INTERNALLY implements the advanced protocol.

**Architecture:**

```
Layer 0 (Host-side export — both NCCL and simple consumers need this):
    fi_ep_export_acc() → opaque blob + provider .cuh
    fi_cntr_export_acc() → GPU HBM counter pointer (for signal/flush)
    fi_av_export_acc() → (AHN, QPN, QKEY) per peer
    fi_mr_export_acc() → lkey

Layer 1 (Device-side operations — provider encapsulates the hard stuff):
    fi_acc_write / fi_acc_send / fi_acc_read (+ tagged, atomics per proposal)
        ↳ scope param = cooperation grouping AND atomic scope (unified)
          WORK_ITEM=Exclusive, SUBGROUP/WORK_GROUP=CTA, DEVICE=GPU
    fi_acc_recv (with FI_MORE for batched posting)
    fi_acc_flush
    fi_acc_cntr_read / fi_acc_cntr_readerr / fi_acc_cntr_wait
    fi_acc_cq_read / fi_acc_cq_pop
```

**Raw resource export is NOT part of the proposed API.** It already exists in
production today as vendor-specific extension ops — EFA's `fi_efa_ops_gda`
exposes `query_qp_wqs()` (raw SQ/RQ buffer, doorbell, ring geometry) and
`query_cq()` via `fi_open_ops(FI_EFA_GDA_OPS)`, and this is exactly what
aws-ofi-nccl GDAKI consumes. The raw queue layout, WQE format, and doorbell
semantics are inherently vendor-specific, so standardizing such an interface
across providers would be meaningless — each provider's "raw" is different.

The escape-hatch story is therefore: consumers with custom posting protocols
beyond what `scope` + `flags` can express use the provider's own extension
ops (as NCCL GIN does today), not a generalized API. This coexists cleanly
with the accelerator API — both are reached from the same domain/EP objects.


### 6. Multi-Rail Support

```c
/* Per-rail: open separate domain/EP per rail, export each independently.
 * The consumer manages rail selection (rail_id = contextId % num_rails). */
```

NCCL GIN's pattern: `rail_id` is baked into the device handle at createContext time.
Each rail has its own domain → endpoint → QP/CQ/counter chain. The API doesn't need
explicit multi-rail — it works by creating N independent EP/CQ/counter sets.


### 7. Version/Compatibility Negotiation

The provider's device-side structs are compiled into the consumer's binary via
inlined `.cuh` headers. If the provider upgrades and changes struct layout, old
consumer binaries break. This requires a multi-level compatibility mechanism:

#### Level 1: Version Negotiation — Both Directions

Version exchange must work in **both directions**:

**Provider → Consumer** (via `fi_getinfo`): the consumer discovers what the
provider supports:

```c
hints->caps |= FI_ACC;
fi_getinfo(FI_VERSION(2,0), node, service, flags, hints, &info);

// Provider reports its accelerator API version:
info->acc_api_version = FI_ACC_VERSION(1, 0);  // major.minor
```

A consumer compiled against v1.1 headers can check `info->acc_api_version` and
avoid calling v1.1 functions if the provider only supports v1.0.

**Consumer → Provider** (via export flags or attrs): the consumer declares which
header version its device code was **compiled against**, so the provider
populates structs accordingly:

```c
// Consumer's binary has v1.0 inlined device code:
fi_ep_export_acc(ep, FI_ACC_VERSION(1, 0), &acc_ep, &size);
// Provider populates only v1.0 fields, sets only v1.0 comp_mask bits
```

This second direction matters for the **old-consumer-binary scenario**: e.g., an
application released with v1.0 device structs frozen into its binary later runs
against a v1.2 provider. Negotiation tells the provider "speak v1.0," but the
provider must also be ABLE to populate v1.0 structs. With the append-only rule
(Level 2/3 below), this is nearly free — a v1.0 struct is a prefix of a v1.2
struct, so the provider fills the prefix and sets only v1.0 comp_mask bits. One
population code path serves all versions. Without append-only discipline, the
provider would need separate struct builders per supported version.

#### Level 2: Host-Side Attrs — `comp_mask` for Extensibility

Exported attribute structs use `comp_mask` to indicate which optional fields are valid:

```c
struct fi_acc_ep_attr {
    uint64_t comp_mask;          // bits indicate which optional fields are valid
    struct fi_acc_wq_attr sq;    // always present (v1.0)
    struct fi_acc_wq_attr rq;    // always present (v1.0)
    uint32_t max_inline_data;    // always present (v1.0)
    uint32_t max_rdma_sges;      // always present (v1.0)
    // --- v1.1 additions (always at the end) ---
    uint32_t max_atomic_size;    // valid only if comp_mask & FI_ACC_EP_ATTR_ATOMIC
};

#define FI_ACC_EP_ATTR_ATOMIC      (1ULL << 0)
```

A v1.0 consumer ignores unknown bits. A v1.1 consumer checks `comp_mask`
before reading extension fields. A v1.0 provider leaves extension bits unset.

#### Level 3: Device-Side Structs — `comp_mask` for Inlined Code

The critical level. The `.cuh` header defines the struct that both the provider
(filling it on host) and the consumer's GPU kernel (reading it) share:

```c
struct fi_acc_dev_ep {
    uint64_t comp_mask;
    // v1.0 fields (always present):
    struct { uint8_t *buf; uint32_t *db; uint32_t pc; ... } sq;
    uint64_t submitted_count;
    volatile uint64_t *local_cntr;
    uint32_t sq_size;
    // --- v1.1 additions (at the end) ---
    uint32_t new_feature_field;  // only if comp_mask & FI_ACC_DEV_EP_V1_1
};
```

The provider's `fi_ep_export_acc()` zeroes the struct, fills known fields, sets
`comp_mask` bits for features it populated, then H2D copies to GPU memory.

The device-side `fi_acc_write()` checks `comp_mask` only for optional paths:

```cuda
FI_ACC_DEV static inline int fi_acc_write(void *acc_ep, ...) {
    struct fi_acc_dev_ep *ep = (struct fi_acc_dev_ep *)acc_ep;
    // v1.0 path — always safe:
    uint32_t slot = atomicAdd(&ep->sq.pc, 1);
    // ... write WQE, doorbell, backpressure ...

    // v1.1 optional behavior:
    if (ep->comp_mask & FI_ACC_DEV_EP_V1_1) {
        // use new_feature_field
    }
}
```

#### Compatibility Matrix

| Provider version | Consumer headers | Behavior |
|---|---|---|
| v1.0 | v1.0 | Normal operation |
| v1.1 | v1.0 | Works — consumer ignores v1.1 fields (at end of struct, never accessed) |
| v1.0 | v1.1 | Works — consumer checks `comp_mask & V1_1` → false, skips v1.1 path |
| v1.1 | v1.1 | Full v1.1 features active |

#### Rules

1. New fields always go at the **end** of structs — never reorder existing fields
2. New fields always guarded by a new `comp_mask` bit
3. Provider **zeroes the entire struct** before filling (unknown fields are 0)
4. `acc_ep_size` output from export tells consumer the actual blob size
5. Major version bump (breaking change) → consumer must recompile

---

## Summary of Priority Improvements

| Priority | Improvement | Rationale |
|----------|------------|-----------|
| **P0** | Hardware counter export (GPU HBM pointer) | THE completion/backpressure/signaling mechanism in NCCL; NOT CQ |
| **P0** | `fi_acc_write()` with `scope` + `FI_MORE` flags | `scope` unifies cooperation grouping AND atomic scope (WORK_ITEM/SUBGROUP/WORK_GROUP/DEVICE → Exclusive/CTA/CTA/GPU); `FI_MORE` defers doorbells; must support warp-cooperative posting internally |
| **P0** | Address resolution export + batch | NCCL builds [total_slots × nranks] target tables |
| **P0** | MR lkey/rkey export | WQE construction needs local + remote keys |
| **P1** | DMA-BUF support for counters | NIC writes counter directly to GPU HBM |
| **P1** | Import callbacks (BAR MMIO → GPU device pointer) | Provider must map SQ/doorbell for GPU access |
| **P1** | Internal warp-cooperative SQ management | Provider implements reservation + parallel write + rendezvous inside `fi_acc_write()` |
| **P1** | Internal dual backpressure (max_batch + counter) | Provider checks both limits before posting |
| **P2** | CQ export + polling API | perftest uses CQ; NCCL does not but other consumers may |
| **P2** | GPU-side recv posting | perftest uses it; NCCL does not |
| — | Raw ring export | NOT proposed as a general API — inherently vendor-specific; already served by provider extension ops (EFA: `query_qp_wqs`/`query_cq` via `FI_EFA_GDA_OPS`) |
| **P0** | Version/comp_mask in all exported structs | Forward compatibility — must be baked in from day one; impossible to retrofit once binaries ship |

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

**Note:** perftest uses the efa-dp-direct batch API (`start_sq_batch`/`place_wr`/`flush`)
which is a simpler single-threaded model. NCCL GIN implements its own warp-cooperative
protocol instead. perftest validates WQE format correctness across all operation types.

---

## Appendix: Mapping Between Systems

| OFI Acc API | efa-dp-direct | NCCL GIN (actual usage) | perftest GDA |
|------------|---------------|-------------------------|--------------|
| `fi_acc_info.alloc` | N/A (user provides) | Host plugin: `cuMemHostRegister(IOMEMORY)` for BAR; DMA-BUF for HW counters | `ctx->memory->allocate_buffer` (DMA-BUF) + `cuMemHostRegister` (BAR) |
| `fi_ep_export_acc` → ring geometry | `efa_cuda_create_qp(attrs)` | Host plugin: `gda_ops->query_qp_wqs()` → fills `efa_cuda_qp` → H2D copy; **Device: directly accesses `qp->sq.wq.*` fields** | `efadv_query_qp_wqs` + `cuMemHostRegister` + `efa_cuda_create_qp` |
| `fi_cntr_export_acc` | N/A | `gda_ops->cntr_open_ext(DMA-BUF)` → `ep.local_cntr_value` pointer in GPU HBM; read via `hwCounterLoad()` (system-scope acquire) | Not used (CQ-only) |
| `fi_av_export_acc` → (AHN,QPN,QKEY) | N/A | `gda_ops->query_addr()` → builds `target_address_handles[total_slots*nranks]`, `target_remote_qpns[]`, `target_qkey[]` | Host resolves, passes as kernel args |
| `fi_mr_export_acc` → lkey | N/A | `gda_ops->get_mr_lkey()` → per-rail `mr_handle.lkey`; allgather for remote `(addr, rkey)` | Direct `ibv_mr->lkey` |
| `fi_acc_write()` (high-level) | `init_rdma_write_wr` + `set_sge` + `set_remote` + `place` + `flush` | **NOT used as one call.** NCCL GIN calls WQE builders individually, then its own warp-cooperative SQ management: atomic `pc.fetch_add` → parallel 64B writes → rendezvous → deferred doorbell | Uses full batch API: `start_sq_batch` + `place_wr` + `flush_sq_wrs` |
| `fi_acc_cq_read()` | `efa_cuda_cq_poll` + `cq_pop` | **NOT used on data path** — counter-only completion. CQ struct exists but is never polled. | `efa_cuda_cq_poll(cq, tid)` + `cq_pop(batch)` |
| Backpressure | N/A (TODO in source) | **Dual:** (a) `chunk_next - db_rung ≤ max_batch` (EFA staging), (b) `(chunk_next - *hw_cntr) & 0x7FFFFFFF ≤ sq_size` (ring overflow) | CQ-based: `scnt - ccnt < tx_depth` |
| Doorbell control | `flush_sq_wrs()` rings immediately | **Deferred aggregation:** `aggregate` flag → write WQEs, hand off WITHOUT ringing; later group drains all deferred WQEs with one doorbell ring, bounded by `max_batch` | `flush_sq_wrs()` after each batch (immediate) |
| Concurrency | `FI_ACC_WORK_GROUP` scope | `cooperative_groups::labeled_partition(qp)` → dynamic warp groups; leader atomics on `pc`/`wqes_completed`/`wqes_posted`; strict slot-order rendezvous. Resource sharing mode (Exclusive/CTA/GPU) selects atomic scope via template dispatch | `__syncthreads()` block sync |
| Per-QP serialization | `scope` parameter (unified) | Three modes: **Exclusive** = plain loads/stores (no atomics); **CTA** = `thread_scope_block` atomics; **GPU** = `thread_scope_device` atomics. Runtime switch at entry dispatches to template-instantiated code. `scope` maps: `WORK_ITEM`→Exclusive, `SUBGROUP`/`WORK_GROUP`→CTA, `DEVICE`→GPU. EFA-GDA currently collapses Exclusive→GPU. | Single-thread (no contention) |
| Counter semantics | (missing) | 2^31 wrap; offset-based reset (NIC counter is read-only); FI_WRITE = local completion, FI_REMOTE_WRITE = remote signal | Not used |
| Multi-EP | (missing) | data + pvdata + counter_handles[N] + signal_handles[N]; different roles per endpoint | Single QP/CQ pair |

### Key Correction: What "uses efa-dp-direct" Actually Means for NCCL

NCCL GIN `#include`s `efa_cuda_dp_impl.cuh` but uses it **only as a WQE format library**:

```c
// USED (WQE construction helpers):
efa_cuda_init_rdma_write_wr(&wr, id, rkey, raddr);    // opcode + remote addr
efa_cuda_wr_set_sge(&wr, lkey, addr, len);            // local SGE
efa_cuda_wr_set_remote(&wr, ah, qpn, qkey);           // destination tuple
efa_cuda_wr_set_processing_hints(&wr, PPS_SENSITIVE); // NIC hint
EFA_SET(&wr.meta.ctrl2, PHASE, phase);                // phase bit stamp

// NOT USED (SQ management — NCCL has its own protocol):
// efa_cuda_start_sq_batch()      → replaced by pc.fetch_add
// efa_cuda_sq_batch_place_wr()   → replaced by direct 64B ring write
// efa_cuda_flush_sq_wrs()        → replaced by custom fence + doorbell + rendezvous

// NOT USED (CQ polling — NCCL uses counters):
// efa_cuda_cq_poll()             → replaced by hwCounterLoad()
// efa_cuda_cq_pop()              → not needed (no CQ state to advance)

// NOT USED (RQ — NCCL is write-only):
// efa_cuda_post_recv_wr()
// efa_cuda_flush_rq_wrs()
```

### NCCL GIN's efa_cuda_qp Field Usage

The `efa_cuda_qp` struct is treated as a **mutable state container** by GIN, not
a black box. Fields directly accessed on the GPU:

| Field | Access Pattern | Purpose |
|-------|---------------|---------|
| `sq.wq.pc` | `cuda::atomic_ref<uint32_t>.fetch_add()` | Slot reservation (monotonic) |
| `sq.wq.buf` | Direct 64-byte writes at `buf + idx*64` | WQE placement into BAR MMIO |
| `sq.wq.db` | `*db = target` (MMIO store) | Doorbell ring |
| `sq.wq.queue_mask` | `slot & queue_mask` | Ring index calculation |
| `sq.wq.queue_size_shift` | `(slot >> shift) & 1` | Phase bit computation |
| `sq.wq.max_batch` | Comparison vs un-rung depth | EFA staging limit enforcement |
| `sq.wq.wqes_completed` | `cuda::atomic_ref.load/store` | Rendezvous: slot-order handoff token |
| `sq.wq.wqes_posted` | `cuda::atomic_ref.load/store` | Tracks last doorbell position (db_rung) |
| `sq.wq.wqes_pending` | Not used (GIN tracks differently) | — |
| `sq.wq.phase` | Not used (computed from slot) | — |

---

## Device API Design Discussion (WIP)

Working notes from the device-side API deep dive, grounded in the actual
`postRdmaWrite<mode>()` implementation in NCCL GIN
(`upstream-to-nccl/src/include/nccl_device/gin/efa_gda/gin_efa_gda.h`).

### Can postRdmaWrite simply call fi_acc_write?

Yes — for the plain Put path it is nearly a drop-in replacement.

**Today (inside GIN's `putImplMode`, per lane):**

```c
// GIN picks the target tuple from its own table:
int idx = targetSlot * nranks + peer;
uint16_t ah   = ep->target_address_handles[idx];
uint16_t qpn  = ep->target_remote_qpns[idx];
uint32_t qkey = ep->target_qkey[idx];

postRdmaWrite<mode>(ep, ah, qpn, qkey,
                    absSrcAddr, srcLkey, writeBytes,
                    absDstAddr, dstRkey, optFlags);
```

**With our API:**

```c
// Same index math — but into the provider-exported AV table:
void *peer_h = (char *)dev->acc_peers + (targetSlot * nranks + peer) * peer_stride;
void *desc   = (char *)dev->acc_descs + rail_mr_idx * desc_stride;

fi_acc_write(dev->data_acc_ep,
             (void *)absSrcAddr, desc, writeBytes, 0, peer_h,
             absDstAddr, dstRkey, NULL,
             FI_ACC_SUBGROUP,
             FI_EFA_WR_HIGH_PPS | (aggregate ? FI_MORE : 0));
```

The mapping is natural because `postRdmaWrite` is already a per-lane call that
internally discovers its cooperation group — exactly the shape of
`fi_acc_write` with `FI_ACC_SUBGROUP`. The provider's internals become a
near-verbatim copy of GIN's protocol: `labeled_partition` on the EP, leader
`fetch_add` reservation, chunked ≤ max_batch windows, dual backpressure,
strict slot-order rendezvous, deferred doorbell for `FI_MORE`. The `scope`
parameter (`FI_ACC_SUBGROUP`) also tells the provider to use block-scope
atomics for the internal coordination — matching GIN's CTA sharing mode.
If the consumer uses `FI_ACC_WORK_ITEM` instead, the provider skips all
atomics entirely (plain loads/stores), matching GIN's Exclusive mode.
If multiple CTAs share an EP, the consumer uses `FI_ACC_DEVICE` for
device-scope atomics, matching GIN's GPU sharing mode.
The `(ah, qpn, qkey)` tuple becomes an opaque peer entry from the AV export;
`srcLkey` becomes the desc from the MR export. Signal Add-by-N stays an
application-level loop of N−1 zero-byte `fi_acc_write` calls.

### Gap tally from the mapping exercise

| Gap | Resolution |
|---|---|
| Doorbell drain for deferred WQEs | ✅ `fi_acc_flush(acc_ep)` — in the proposal; rings db for all written-but-un-rung WQEs, TX-side only |
| Completion drain (GIN Flush / quiet) | ✅ No new API — consumer-owned baseline pattern (below) |
| PPS processing hint | ✅ Existing `FI_EFA_WR_HIGH_PPS` (bit 60, `fi_ext_efa.h`) flows through `fi_acc_write` flags exactly as it does through `fi_writemsg()` today; provider-specific op flags (bits 60–63) pass through unchanged and fold away at compile time in inlined code |
| PutValue staging | ✅ Resolved — `FI_INJECT` flag on `fi_acc_write()`; provider copies data internally (mlx5: WQE inline, EFA: pool slot staging) |
| Sharing mode / atomic scope | ✅ Resolved — unified into `scope` parameter: `WORK_ITEM`=Exclusive, `SUBGROUP`/`WORK_GROUP`=CTA, `DEVICE`=GPU; one runtime switch dispatches |
| Return type | 💬 Discussable — void vs int (below) |

### Completion drain: consumer-owned baseline pattern

`fi_acc_flush()` only rings the doorbell — it does not wait for completion.
GIN's Flush additionally waits until the FI_WRITE counter catches up to its
internal `submitted_count`. Rather than exposing that provider-internal count
(or adding a second wait primitive), the consumer owns the arithmetic:

```c
// Baseline snapshot (before posting, or at any known-quiescent point):
uint64_t base = fi_acc_cntr_read(acc_cntr);

// ... N calls to fi_acc_write — consumer counts N itself ...

fi_acc_flush(acc_ep);   // ring db for any FI_MORE-deferred WQEs

// Wait: modular compare per domain_attr->max_cntr_value
while (((fi_acc_cntr_read(acc_cntr) - base) & max_cntr_value) < N) { /* spin */ }
// or: fi_acc_cntr_wait(acc_cntr, base + N)
```

This is GIN's exact pattern generalized — GIN's baseline is implicitly 0
(counter and submitted_count both start at zero); the explicit snapshot also
subsumes reset-without-zeroing (the baseline IS the offset), and the remote
side uses the identical pattern on its FI_REMOTE_WRITE counter for signal
detection, including Add-by-N.

Contract requirements the spec must state:
1. **1:1 tick guarantee** — every posted operation increments the bound
   FI_WRITE counter by exactly 1 (normative; true on EFA).
2. **Flush before wait** — a `FI_MORE`-deferred WQE never completes until a
   doorbell covers it; the wait must be preceded by `fi_acc_flush()` (or a
   non-`FI_MORE` post).
3. **Multi-poster tally** — for one EP-wide quiet across multiple
   threads/CTAs, the consumer aggregates its own N (its concurrency layout,
   its bookkeeping).

### Concurrency: scope unifies cooperation and atomic scope

GDAKI has two concurrency concerns that initially appear orthogonal but
collapse into our single `scope` parameter:

**Concern 1 — Cooperation grouping (who coalesces into one post):**
dynamic, discovered at runtime via `coalesced_threads()` +
`labeled_partition(qp)`. Groups form per-QP among currently-active warp lanes
(1 to 32 lanes; different lanes may simultaneously target different QPs and
form separate groups). Leader reserves the group's slots with one atomic;
all lanes write WQEs in parallel; leader rings once.

**Concern 2 — Resource sharing mode (what contention level on this EP):**

All three NCCL GIN backends (EFA-GDA, GDAKI/DOCA, GPI) implement three
resource sharing modes that control the scope of internal atomics/fences:

```c
// NCCL's unified enum (gin_device_common.h):
enum ncclGinResourceSharingMode : uint8_t {
  NCCL_GIN_RESOURCE_SHARING_GPU    = 0,  // any CTA on the GPU may post to this QP
  NCCL_GIN_RESOURCE_SHARING_CTA    = 1,  // only threads in one CTA post to this QP
  NCCL_GIN_RESOURCE_SHARING_THREAD = 2,  // exclusive — one thread owns this QP
};

// DOCA/NVIDIA equivalent (doca_gpunetio_verbs_def.h):
enum doca_gpu_dev_verbs_resource_sharing_mode {
  DOCA_GPUNETIO_VERBS_RESOURCE_SHARING_MODE_EXCLUSIVE = 0,  // one thread
  DOCA_GPUNETIO_VERBS_RESOURCE_SHARING_MODE_CTA       = 1,  // one CTA
  DOCA_GPUNETIO_VERBS_RESOURCE_SHARING_MODE_GPU       = 2,  // whole GPU
};

// GPI equivalent (gin_gpi_device_host_common.h):
enum gpi_resource_sharing_mode {
  GPI_RESOURCE_SHARING_MODE_EXCLUSIVE = 0,
  GPI_RESOURCE_SHARING_MODE_CTA       = 1,
  GPI_RESOURCE_SHARING_MODE_GPU       = 2,
};
```

Each mode determines what synchronization primitives the provider uses
internally on QP coordination state (producer index, ready index, cursors):

| Mode | Atomic scope | Atomic add | Lock | mark_wqes_ready |
|------|-------------|------------|------|-----------------|
| **Exclusive/Thread** | None | Plain load + store (no atomic instruction) | Plain `*lock = 1` | Direct store — no CAS, no fence, no spin |
| **CTA** | `thread_scope_block` | `cuda::atomic_ref<T, block>::fetch_add(relaxed)` | `atomicCAS_block` spin + block-scope acquire fence | Block-scope CAS spin (rendezvous) + block-scope fences |
| **GPU** | `thread_scope_device` | `cuda::atomic_ref<T, device>::fetch_add(relaxed)` | `atomicCAS` (global) spin + device-scope acquire fence | Device-scope CAS spin (rendezvous) + device-scope fences |

The performance impact is significant: Exclusive eliminates ALL atomic
instructions on the hot path (just plain memory loads/stores), CTA uses
cheaper block-scoped atomics, and GPU uses full device-scoped atomics.
The HW counter load is always system-scope acquire regardless of mode
(NIC writes over PCIe).

**How backends implement the dispatch:** All three backends use a runtime
`switch` at the top-level entry point that dispatches to template-instantiated
per-mode functions. All three template instantiations are compiled into the
same GPU binary; the switch selects which one runs. Within each instantiation,
the mode is a compile-time constant so all conditional logic
(`if (resource_sharing_mode == EXCLUSIVE)`) is constant-folded by the compiler
and optimal code is generated for each path. The cost is one branch at entry
plus code size (3 copies of the function body in the binary):

```c
// GDAKI pattern (gin_gdaki.h):
template <typename Coop>
NCCL_DEVICE_INLINE static void putImpl(ncclGinCtx ctx, Coop coop, ...) {
  switch ((ncclGinResourceSharingMode)ctx.resourceSharingMode) {
  case NCCL_GIN_RESOURCE_SHARING_THREAD:
    putImplMode<DOCA_GPUNETIO_VERBS_RESOURCE_SHARING_MODE_EXCLUSIVE>(...);
    break;
  case NCCL_GIN_RESOURCE_SHARING_CTA:
    putImplMode<DOCA_GPUNETIO_VERBS_RESOURCE_SHARING_MODE_CTA>(...);
    break;
  default:
    putImplMode<DOCA_GPUNETIO_VERBS_RESOURCE_SHARING_MODE_GPU>(...);
    break;
  }
}

// EFA-GDA pattern (gin_efa_gda.h) — currently only distinguishes two:
template <typename Coop>
NCCL_DEVICE_INLINE static void putImpl(ncclGinCtx ctx, Coop coop, ...) {
  switch ((ncclGinResourceSharingMode)ctx.resourceSharingMode) {
  case NCCL_GIN_RESOURCE_SHARING_CTA:
    putImplMode<NCCL_GIN_RESOURCE_SHARING_CTA>(...);
    break;
  default:  // GPU and THREAD both fall here → device scope
    putImplMode<NCCL_GIN_RESOURCE_SHARING_GPU>(...);
    break;
  }
}
```

**EFA-GDA only implements 2 of 3 modes:** It collapses THREAD/Exclusive into
GPU (device-scope atomics) because its warp-cooperative protocol
(`coalesced_threads` + `labeled_partition` + `pc.fetch_add`) inherently
uses atomics even for a group of size 1. A single exclusive thread still
enters the cooperative protocol — it just gets a group of 1 lane but still
does an atomic `fetch_add` on `pc`. GDAKI and GPI fully implement all three
because their protocol structure (lock + single-poster WQE build + unlock)
can trivially degrade to plain memory ops in exclusive mode.

**Unified mapping to our `scope` parameter:** These two concerns collapse
into a single parameter because the cooperation group directly implies the
contention level:

| `scope` | Contention boundary | Atomic scope |
|---------|-------------------|--------------|
| `FI_ACC_WORK_ITEM` | One thread owns this EP | None (plain loads/stores) |
| `FI_ACC_SUBGROUP` | Warps within one CTA | `thread_scope_block` |
| `FI_ACC_WORK_GROUP` | Threads within one CTA | `thread_scope_block` |
| `FI_ACC_DEVICE` | Multiple CTAs on the GPU | `thread_scope_device` |

The provider dispatches on `scope` with a single runtime switch (same
pattern as NCCL's switch on `ctx.resourceSharingMode`), entering template-
instantiated code where the atomic scope is a compile-time constant.

**Edge case — multiple CTAs, warp-cooperative:** If multiple CTAs each use
`FI_ACC_SUBGROUP` on the same EP simultaneously, the caller must use
`FI_ACC_DEVICE` instead to signal device-scope contention. The scope
declares the *maximum* contention level, not just the cooperation width.
Rule of thumb: use the scope that matches the widest set of threads that
may concurrently post to the same EP handle.

### PutValue staging (resolved)

GIN's PutValue stages the register value into a pool slot addressed by the
**reserved SQ slot index** (`my_slot % sq_size`), then points the WQE's SGE at
the staged copy. The slot index is only known after reservation — which
`fi_acc_write` hides.

**Resolution:** Use the existing `FI_INJECT` flag on `fi_acc_write()`:

```c
fi_acc_write(acc_ep, &value, NULL /*no desc*/, sizeof(value), 0, peer,
             raddr, rkey, NULL, scope, FI_INJECT | flags);
```

`FI_INJECT` already exists in libfabric with this semantic: the provider
copies the data from `buf` internally and the caller's buffer is reusable
immediately on return. No MR descriptor needed (pass NULL for `desc`).

- On mlx5/GDAKI: provider embeds the value directly in the WQE inline
  data segment (`doca_gpu_dev_verbs_p<T>` — no staging buffer needed)
- On EFA: provider stages the value into an internal pool slot indexed by
  the reserved SQ slot (`my_slot % sq_size`), then points the WQE's SGE
  at the staged copy (same as GIN's PutValue path today)

No separate `fi_acc_inject_write` function needed — one API, one flag.

### Return type: void vs int (discussable)

Walking every wait inside `postRdmaWrite` shows the post path has no
synchronous failure mode:

| Wait | Resolution |
|---|---|
| Un-rung depth > max_batch | Leader actively force-rings deferred WQEs — guaranteed progress |
| SQ ring overflow (31-bit masked diff vs HW counter) | Spins until NIC consumes |
| Doorbell-turn rendezvous | Spins until predecessor hands off — resolves by slot-order induction |

Backpressure, counter wraparound, and ordering are all absorbed internally —
GDAKI's `postRdmaWrite` returns void, and if `fi_acc_write` encapsulates the
same protocol (it must), there is nothing to report at post time. The
consumer-owned completion pattern above also removes the last hidden state a
return channel might have carried.

The counterweight for `int`:
- Libfabric convention (every host-side data op returns ssize_t/int);
  retrofitting a return type later is an API break the versioning rules
  cannot absorb.
- Future escape hatches: a non-blocking flag returning `-FI_EAGAIN` instead
  of spinning; debug-build argument validation.
- Cost is zero: provider-inlined `return FI_SUCCESS;` constant-folds away.
- If adopted, the spec must require **converged returns** for cooperative
  scopes (all threads in the scope receive the same value) so error paths
  never diverge the group.

Status: leaning void-semantics-today either way; whether to keep the `int`
shell as a forward-compatibility hedge is an open discussion point.
