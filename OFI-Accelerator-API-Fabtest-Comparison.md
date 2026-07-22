# OFI Accelerator API — Fabtest Comparison

## Overview

This document describes the new `fi_acc_gda` fabtest that exercises the OFI Accelerator API
and compares it side-by-side with the existing `efa_gda` fabtest (which uses provider-specific
`fi_efa_ops_gda` + efa-dp-direct) and the perftest GDA implementation.

---

## New Fabtest Files

| File | Purpose |
|------|---------|
| `fabtests/prov/efa/src/fi_acc_gda.c` | Host-side test using OFI Acc API |
| `fabtests/prov/efa/src/fi_acc/fi_acc_kernels.h` | CUDA kernel declarations |
| `fabtests/prov/efa/src/fi_acc/fi_acc_kernels.cu` | GPU kernels using `fi_acc_dev_*` |

---

## Host-Side Comparison: `fi_acc_gda.c` vs `efa_gda.c`

### Resource Setup

| Step | `efa_gda.c` (old, EFA-specific) | `fi_acc_gda.c` (new, portable) |
|------|------|------|
| **Get provider ops** | `fi_open_ops(&domain->fid, FI_EFA_GDA_OPS, 0, (void**)&efa_gda_ops, NULL)` | Not needed — `FI_ACC` in `hints->caps` signals accelerator intent |
| **CQ creation** | `gda_ops->cq_open_ext(domain, &cq_attr, &efa_cq_init_attr, &cq, NULL)` — consumer manually allocates DMA-BUF for CQ buffer | `fi_cq_open(domain, &cq_attr, &cq, NULL)` — standard API; provider knows FI_ACC |
| **Counter creation** | `ft_hmem_alloc()` + `ft_hmem_get_dmabuf_fd()` + `gda_ops->cntr_open_ext(domain, &attr, &cntr, NULL, &efa_attr)` | `fi_cntr_open(domain, &attr, &cntr, NULL)` with FI_ACC flag; provider calls `acc_info.alloc()` internally |
| **QP export** | `gda_ops->query_qp_wqs(ep, &sq_attr, &rq_attr)` then manual `cuMemHostRegister(IOMEMORY\|DEVICEMAP)` + `cuMemHostGetDevicePointer()` for each of: SQ buffer, SQ doorbell, RQ buffer, RQ doorbell (8 CUDA calls) | `fi_acc_ep_export(ep, 0, &ep_attr)` — **one call**, provider does all mapping internally |
| **CQ export** | `gda_ops->query_cq(cq, &cq_attr)` — returns host VA, consumer uses it directly | `fi_acc_cq_export(cq, 0, &cq_attr)` — returns device-accessible pointer |
| **MR lkey** | `gda_ops->get_mr_lkey(mr)` → uint64_t | `fi_acc_mr_export(mr, 0, &mr_attr)` → `mr_attr.lkey` (uint32_t) |
| **Peer address** | `gda_ops->query_addr(ep, fi_addr, &ahn, &qpn, &qkey)` | `fi_acc_av_lookup(av, fi_addr, 0, &peer_addr)` → struct with all 3 fields |
| **Build GPU QP** | `efa_cuda_create_qp(&qp_attrs, sizeof(qp_attrs))` — efa-dp-direct allocates on GPU | `build_gpu_qp(&ep_attr)` — fill `fi_acc_dev_qp` from export attrs, `cudaMemcpy` to GPU |
| **Build GPU CQ** | `efa_cuda_create_cq(&cq_attrs, sizeof(cq_attrs))` | `build_gpu_cq(&cq_attr, &d_cq)` — fill `fi_acc_dev_cq`, `cudaMemcpy` |

### Code Reduction

| Metric | `efa_gda.c` | `fi_acc_gda.c` |
|--------|-------------|----------------|
| Lines for QP setup | ~60 (query + 8 CUDA calls + struct fill) | ~20 (1 export call + struct fill) |
| External dependencies | `efa_cuda_dp.h`, `fi_ext_efa.h`, CUDA driver API | `fi_acc.h`, `fi_acc_device.h`, CUDA driver API |
| Provider-specific types | `fi_efa_wq_attr`, `fi_efa_cq_attr`, `fi_efa_comp_cntr_init_attr`, `fi_efa_cq_init_attr` | None — all types are in `rdma/fi_acc.h` |
| Portability | EFA only | Any provider implementing FI_ACC |

---

## Device-Side Comparison: GPU Kernels

### `fi_acc_kernels.cu` vs `efa_gda_kernels.cu`

| Aspect | `efa_gda_kernels.cu` (old) | `fi_acc_kernels.cu` (new) |
|--------|------|------|
| **Include** | `#include "efa_cuda_dp_impl.cuh"` | `#include <rdma/fi_acc_device.h>` |
| **QP type** | `efa_cuda_qp *qp` | `struct fi_acc_dev_qp *qp` |
| **CQ type** | `efa_cuda_cq *cq` | `struct fi_acc_dev_cq *cq` |
| **WQE type** | `struct efa_io_tx_wqe wr_buf` | `struct fi_acc_dev_wqe wr` |
| **Init write** | `efa_cuda_init_rdma_write_wr(&wr, id, rkey, raddr)` | `fi_acc_dev_write_prep(&wr, id, rkey, raddr, lkey, laddr, len)` |
| **Set SGE** | `efa_cuda_wr_set_sge(&wr, lkey, addr, len)` | Included in `fi_acc_dev_write_prep()` |
| **Set remote** | `efa_cuda_wr_set_remote(&wr, ah, qpn, qkey)` | `fi_acc_dev_wr_set_peer(&wr, &target)` |
| **Start batch** | `efa_cuda_start_sq_batch(&qp, 1)` | `fi_acc_dev_sq_start_batch(&qp, 1)` |
| **Place WQE** | `efa_cuda_sq_batch_place_wr(&qp, 0, &wr)` | `fi_acc_dev_sq_place(&qp, 0, &wr)` |
| **Flush** | `efa_cuda_flush_sq_wrs(&qp)` | `fi_acc_dev_sq_flush(&qp)` |
| **Poll CQ** | `efa_cuda_cq_poll(&cq, 0)` | `fi_acc_dev_cq_poll(&cq, 0)` |
| **Pop CQ** | `efa_cuda_cq_pop(&cq, 1)` | `fi_acc_dev_cq_pop(&cq, 1)` |
| **Post recv** | `efa_cuda_post_recv_wr(&qp, addr, len, lkey)` | `fi_acc_dev_post_recv(&qp, idx, addr, len, lkey)` |
| **Flush RQ** | `efa_cuda_flush_rq_wrs(&qp)` | `fi_acc_dev_rq_flush(&qp, count)` |
| **Shared mem pattern** | `__shared__ efa_cuda_qp local_qp = *qp` | `__shared__ fi_acc_dev_qp local_qp = *qp` |
| **Writeback** | `*qp = local_qp` | `*qp = local_qp` |

### Kernel Implementations Provided

| Kernel | Description | Old equivalent |
|--------|-------------|----------------|
| `fi_acc_lat_send_kernel` | Send/recv ping-pong latency (single thread) | `efagda_lat_send_kernel` |
| `fi_acc_bw_kernel` | RDMA write/read/send bandwidth (single thread) | `efagda_bw_kernel` |
| `fi_acc_bw_recv_kernel` | Recv-side for writedata/send BW | `efagda_bw_recv_kernel` |

---

## Comparison with perftest GDA Mode

| Aspect | perftest (`--use_dp_direct`) | `fi_acc_gda` (this fabtest) |
|--------|------|------|
| **QP creation** | `efadv_query_qp_wqs()` + `cuMemHostRegister()` directly | `fi_acc_ep_export()` (provider-internal) |
| **CQ creation** | `efadv_create_cq(EXT_MEM_DMABUF)` + `efa_cuda_create_cq()` | `fi_cq_open(FI_ACC)` + `fi_acc_cq_export()` |
| **Address resolution** | Host resolves, passes (ah, qpn, qkey) as kernel args | `fi_acc_av_lookup()` → same triple |
| **Counter usage** | Not used (CQ-only backpressure) | Optional via `fi_acc_cntr_export()` |
| **Device library** | efa-dp-direct (`efa_cuda_dp_impl.cuh`) | `fi_acc_device.h` (provider-neutral) |
| **Multi-QP** | Up to 32 QPs, per-thread assignment | Single QP (can be extended) |
| **Thread model** | `post_list × num_qps` threads for BW | Single thread (latency & BW) |
| **Portability** | EFA-only (efadv/ibv APIs) | Any OFI provider with FI_ACC support |
| **Build dependency** | `HAVE_EFAGDA` + `$(LIBEFAGDA)` | `fi_acc.h` + `fi_acc_device.h` (in-tree) |

---

## End-to-End Data Flow Comparison

### Old Path (efa_gda.c + efa-dp-direct)

```
Host setup:
  fi_open_ops(FI_EFA_GDA_OPS) → gda_ops vtable
  gda_ops->cntr_open_ext(domain, DMA-BUF) → HW counter in GPU HBM
  fi_endpoint() + fi_ep_bind(cntr) + fi_enable()
  gda_ops->query_qp_wqs() → host VA
  cuMemHostRegister(IOMEMORY|DEVICEMAP) × 4 → GPU device ptrs
  efa_cuda_create_qp(attrs) → GPU-resident descriptor
  gda_ops->query_cq() → host VA
  efa_cuda_create_cq(attrs) → GPU-resident descriptor
  gda_ops->query_addr() → (ahn, qpn, qkey)
  gda_ops->get_mr_lkey() → lkey

GPU kernel:
  efa_cuda_init_*_wr() → efa_cuda_wr_set_sge() → efa_cuda_wr_set_remote()
  efa_cuda_start_sq_batch() → efa_cuda_sq_batch_place_wr() → efa_cuda_flush_sq_wrs()
  efa_cuda_cq_poll() → efa_cuda_cq_pop()
```

### New Path (fi_acc_gda.c + fi_acc_device.h)

```
Host setup:
  fi_getinfo(caps = FI_ACC)
  fi_cq_open() + fi_cntr_open() + fi_endpoint() + fi_enable()  [standard API]
  fi_acc_ep_export(ep, &attr)      → device ptrs for SQ/RQ/doorbells
  fi_acc_cq_export(cq, &attr)      → device ptr for CQ ring
  fi_acc_cntr_export(cntr, &attr)  → GPU HBM counter ptr
  fi_acc_mr_export(mr, &attr)      → lkey
  fi_acc_av_lookup(av, addr, &peer)→ (ahn, qpn, qkey)
  Build fi_acc_dev_qp/cq from attrs → cudaMemcpy to GPU

GPU kernel:
  fi_acc_dev_write_prep() → fi_acc_dev_wr_set_peer()
  fi_acc_dev_sq_start_batch() → fi_acc_dev_sq_place() → fi_acc_dev_sq_flush()
  fi_acc_dev_cq_poll() → fi_acc_dev_cq_pop()
```

---

## Usage

```bash
# Build (requires CUDA toolkit + libfabric with FI_ACC)
cd fabtests && make

# Send latency ping-pong
# Server:
./fi_acc_gda
# Client:
./fi_acc_gda -o msg <server_ip>

# RDMA Write bandwidth
# Server:
./fi_acc_gda
# Client:
./fi_acc_gda -o write <server_ip>

# RDMA Read bandwidth
./fi_acc_gda -o read <server_ip>

# Write with immediate data
./fi_acc_gda -o writedata <server_ip>

# With data verification
./fi_acc_gda -v -o write <server_ip>
```

---

## Key Design Decisions

1. **No efa-dp-direct dependency** — The CUDA kernels use only `fi_acc_device.h` which is
   compiled from libfabric's include tree. No external GPU library needed.

2. **Same kernel structure** — The kernels follow the identical pattern as the original
   (shared memory QP/CQ copy, single-thread latency, writeback at end) to ensure
   performance parity.

3. **Provider handles mapping** — The `acc_info.import()` callback abstracts away
   `cuMemHostRegister`. The test provides CUDA-specific callbacks, but a SYCL or HIP
   test would provide different callbacks with the same interface.

4. **Structured exports** — `fi_acc_ep_attr` returns individual fields (buffer ptr,
   doorbell ptr, num_entries, entry_size, max_batch) rather than an opaque blob,
   enabling the consumer to build `fi_acc_dev_qp` directly.

5. **Counter polling** — Both old and new tests support optional HW counter polling
   as an alternative to CQ polling for send completion tracking.


---

## Update: aws-ofi-nccl GDAKI Coverage

After cross-referencing with the full `nccl_ofi_gin_gdaki_dev.h` and
`nccl_ofi_gin_gdaki_resources.h` from aws-ofi-nccl, here's how the
OFI Accelerator API maps to each GDAKI component:

### GDAKI `createContext` → OFI Acc API

| GDAKI createContext step | OFI Acc API equivalent |
|------|------|
| `fi_open_ops(FI_EFA_GDA_OPS)` | Not needed — `FI_ACC` in caps |
| `gdaki_hw_counter::create()` (VMM alloc + DMA-BUF + cntr_open_ext) | `efa_acc_cntr_open(domain, attr, acc_info, &cntr, ctx)` — one call |
| `gdaki_fi_endpoint::open()` + bind counters + enable | Standard libfabric: `fi_endpoint()` + `fi_ep_bind()` + `fi_enable()` |
| `gdaki_endpoint::populate()` (query_qp_wqs + MMIO mapping + GPU QP/CQ build) | `fi_acc_ep_export(ep, 0, &attr)` + consumer builds `fi_acc_dev_qp` from attrs |
| `gda_ops->query_cq()` → GPU CQ build | `fi_acc_cq_export(cq, 0, &attr)` + consumer builds `fi_acc_dev_cq` |
| `gdaki_target_addressing::populate()` (fi_av_insert + query_addr loop) | `fi_av_insert()` + `fi_acc_av_lookup_batch(av, addrs, count, 0, out)` |
| `gda_ops->get_mr_lkey(mr)` | `fi_acc_mr_get_info(mr, 0, &lkey, &addr, &rkey)` |
| Assemble `nccl_ofi_gin_gdaki_dev_handle` + H2D copy | Consumer fills `fi_acc_dev_*` structs from export results + `cudaMemcpy` |

### GDAKI Device Handle → fi_acc_dev_* Types

| GDAKI device type | fi_acc_device.h type |
|-------------------|---------------------|
| `nccl_ofi_gin_gdaki_qp` (cast to `efa_cuda_qp`) | `struct fi_acc_dev_qp` |
| `nccl_ofi_gin_gdaki_cq` (cast to `efa_cuda_cq`) | `struct fi_acc_dev_cq` |
| `volatile uint64_t *local_cntr_value` | `struct fi_acc_dev_cntr` → `.value` |
| `target_address_handles[]` / `target_remote_qpns[]` / `target_qkey[]` | Array of `struct fi_acc_dev_peer` (or split arrays) |
| `sq_lock` (uint32_t) | `fi_acc_dev_lock()` / `fi_acc_dev_unlock()` |
| `submitted_count` / `sq_size` | Consumer-maintained uint64_t + `fi_acc_ep_attr.sq.num_entries` |

### Multi-Endpoint Pattern

```
Per-context:
  data EP      → fi_acc_ep_export() → data.qp / data.cq
  pvdata EP    → fi_acc_ep_export() → pvdata.qp / pvdata.cq
  sc EP[0..N]  → fi_acc_ep_export() → sc[i].qp / sc[i].cq

Per-counter:
  FI_WRITE cntr     → fi_acc_cntr_export() → local_cntr_value (backpressure)
  FI_REMOTE_WRITE   → fi_acc_cntr_export() → cntr_value (signal detection)

Per-MR (regMrSym):
  fi_mr_reg() → fi_acc_mr_get_info() → (lkey, local_addr, rkey)
  Allgather rkey/addr → build GPU-resident fi_acc_mr_peer[nranks]
```

### What the Consumer Still Does (same as today)

- Allocates GPU memory for device handle, QP/CQ descriptors, target tables
- Fills `fi_acc_dev_qp` / `fi_acc_dev_cq` from exported `fi_acc_ep_attr` / `fi_acc_cq_attr`
- H2D copies all descriptors to GPU
- Manages `submitted_count`, `sq_lock`, `cntr_offset` in GPU memory
- Selects target slot per write (data EP = slot 0, signal EP = slot 1+s)
- Implements PutValue staging (write srcVal to local slot, then RDMA write)
