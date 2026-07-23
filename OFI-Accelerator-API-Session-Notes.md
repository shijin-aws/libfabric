# OFI Accelerator API — Project Session Notes

**Last updated:** 2026-07-23
**Branch:** `fi_accelerator` at `8afee8ab9`
**Workspace:** `/home/sjina/PortaFiducia/build/libraries/libfabric/direct_cq/source/libfabric`

---

## What We Built

A portable OFI Accelerator API that **replaces both `fi_efa_ops_gda` and `efa-dp-direct`**
with a single libfabric-native interface for GPU-initiated RDMA.

## Commits (oldest → newest)

1. `a90a9d65b` — Initial implementation (structured Layer 2 export, all exports returning typed structs)
2. `ca527d429` — Design docs (proposal comparison, GDAKI analysis, opaque direction document)
3. `afaaa314c` — Restructure to **opaque export model** (`void**` returns, high-level device functions)
4. `d9dbe4957` — Move EFA device impl to `prov/efa/src/acc_cuda/`
5. `e0f29b93e` — Rename to `.cuh`, install as header-only via Makefile
6. `8afee8ab9` — Rename to `fi_ext_efa_acc.cuh`, install in `rdma/` (convention)

## File Layout

```
include/rdma/
  fi_acc.h                    ← Public host API (opaque void** exports)
  fi_acc_device.h             ← Common macros (FI_ACC_DEV qualifier)
  fi_ext_efa_acc.cuh          ← [INSTALLED] EFA device impl (replaces efa-dp-direct)
  fabric.h                    ← Modified: added FI_ACC (1ULL << 44)

prov/efa/src/
  acc_cuda/
    fi_ext_efa_acc.cuh        ← Source of truth for the device header
  efa_acc.h                   ← Provider internal state (efa_acc_state)
  efa_acc.c                   ← Provider host-side impl (builds opaque GPU blobs)
  efa_base_ep.h               ← Modified: added acc_state field
  efa_cq.h                    ← Modified: added acc_state field
  efa_cntr.h                  ← Modified: added acc_state field

fabtests/prov/efa/src/
  fi_acc_gda.c                ← Fabtest host-side (opaque handles only)
  fi_acc/
    fi_acc_kernels.h          ← Kernel declarations
    fi_acc_kernels.cu         ← GPU kernels using fi_acc_write/send/cq_poll

Makefile.am                   ← Modified: installs fi_acc*.h + fi_ext_efa_acc.cuh
prov/efa/Makefile.include     ← Modified: added efa_acc.c to source list
```

## Architecture

```
Consumer (.cu file):
  #include <rdma/fi_ext_efa_acc.cuh>
  fi_acc_write(acc_ep, buf, len, desc, raddr, rkey, peer, flags)
  → internally: backpressure + WQE build + phase bit + MMIO write + doorbell

Host setup:
  #include <rdma/fi_acc.h>
  fi_acc_ep_export(ep, 0, &acc_ep, &size)    → opaque GPU blob
  fi_acc_cq_export(cq, 0, &acc_cq, &size)    → opaque GPU blob
  fi_acc_cntr_export(cntr, 0, &acc_cntr, &size)
  fi_acc_mr_export(mr, 0, &acc_desc, &size)
  fi_acc_av_export(av, addr, 0, &acc_peer, &size)
```

## Key Design Decisions

1. **Opaque exports** — Consumer gets `void*` GPU pointers, never sees struct internals
2. **Provider ships device code** as installed `.cuh` header (`fi_ext_efa_acc.cuh`)
3. **Header-only device library** — no nvcc in libfabric Makefile; consumer's nvcc inlines it
4. **Naming:** `fi_ext_efa_acc.cuh` follows `fi_ext_*` convention, installed in `rdma/`
5. **High-level device API:** `fi_acc_write()` encapsulates entire post path
6. **Counter read is opaque** — `fi_acc_cntr_read(acc_cntr)` inlines to single load
7. **Backpressure inside `fi_acc_write()`** — consumer never sees sq_size/submitted_count
8. **`fi_acc_ep_lock()`/`unlock()`** — exposed because multi-CTA scheduling is consumer's decision
9. **Import callbacks** — provider calls `acc_info.import()` internally during export (BAR MMIO mapping)
10. **`acc_info.alloc()`** — used for counter GPU HBM allocation (DMA-BUF + NIC direct write)

## What's Done ✅

- [x] Public API header (`fi_acc.h`) — opaque exports
- [x] Device API header (`fi_ext_efa_acc.cuh`) — EFA implementation
- [x] Common macros header (`fi_acc_device.h`)
- [x] EFA provider implementation (`efa_acc.c`) — all export functions
- [x] Provider state management (`efa_acc_state_create/destroy`)
- [x] `acc_state` field on EP, CQ, counter structs
- [x] Fabtest host-side (`fi_acc_gda.c`)
- [x] Fabtest GPU kernels (`fi_acc_kernels.cu`)
- [x] Makefile integration (compile efa_acc.c, install all headers)
- [x] `make -j install` passes (libfabric + fabtests)
- [x] nvcc compilation of .cu against installed headers passes
- [x] Design documentation (2 markdown files)
- [x] Covers full aws-ofi-nccl GDAKI workflow

## Remaining Work 🔲

- [ ] **Object creation hooks** — When `FI_ACC` flag detected in `fi_cq_open()`/`fi_cntr_open()`/`fi_endpoint()`, allocate `efa_acc_state` and store `fi_acc_info`
- [ ] **H2D copy in provider** — Current `acc_gpu_alloc_and_copy()` uses `memcpy` (works if GPU mem is host-mapped); need proper HMEM-based H2D for production
- [ ] **Register export functions** in provider ops dispatch (via `fi_open_ops` or fid ops table)
- [ ] **Cleanup on fi_close** — Call `efa_acc_state_destroy()` in EP/CQ/counter destructors
- [ ] **Integrate fabtest into fabtests Makefile** — Add nvcc rule for `fi_acc_kernels.cu`
- [ ] **Batch/cooperative posting** — `fi_acc_write` currently posts one WQE per call; add `FI_MORE`-style batching for warp-cooperative patterns
- [ ] **fi_acc_read()** — RDMA read opcode (0x05); same pattern as write
- [ ] **Run on real hardware** — Test on P5en with EFA
- [ ] **Second provider** — When CXI implements FI_ACC, split device headers properly

## Key References

- Original proposal: `OFI-Accelerator-API.md` (Jianxin Xiong slides)
- Gap analysis: `OFI-Accelerator-API-Analysis.md`
- Our design doc: `OFI-Accelerator-API-Libfabric-Changes.md`
- GDAKI workflow: `~/communication-libraries-notes/efa-gdaki/gdaki_workflow.md`
- aws-ofi-nccl GDAKI: `~/PortaFiducia/build/libraries/aws_ofi_nccl/.../nccl_ofi_gin_gdaki_dev.h`
- efa-dp-direct (what we replace): device functions in `efa_cuda_dp_impl.cuh`

## How to Resume

```bash
cd /home/sjina/PortaFiducia/build/libraries/libfabric/direct_cq/source/libfabric
git log --oneline -6   # verify state
make -j install        # rebuild
# For CUDA kernel compilation:
nvcc -c --gpu-architecture=compute_80 -I $(pwd)/../install/libfabric/include \
  -I fabtests/prov/efa/src -o /dev/null fabtests/prov/efa/src/fi_acc/fi_acc_kernels.cu
```
