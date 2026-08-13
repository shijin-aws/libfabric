# FI_XPU API Implementation Progress

## Date: 2026-08-12/13

## Branch: `fi_accelerator_api_impl` (cloned from `fi_accelerator_api`)

---

## Summary

Implemented the OFI XPU API based on PR #12620 review feedback from Sean Hefty
(shefty) and Jianxin Xiong (j-xiong), plus the EFA provider implementation
ported from the `fi_accelerator` branch.

---

## Review Feedback Applied (from PR #12620, Aug 12)

### From j-xiong:
- Removed descriptive ABI comment in `src/abi_1_0.c`
- Referred to capability as `FI_XPU` in man page OVERVIEW
- Updated version to `FI_VERSION(2,7)` for v2.7.0 release target
- Added XPU documentation to each resource's own man page (fi_av, fi_cq,
  fi_cntr, fi_mr, fi_endpoint)

### From shefty:
- Introduced typed `struct fid_xpu` base type (fclass + prov_id)
- Added `struct fid_xpu_ep`, `fid_xpu_cq`, `fid_xpu_cntr` typed exports
- Updated all `export_xpu` signatures to use typed pointers
- Moved `enum fi_xpu_provider` and `fid_xpu*` types to `fi_xpu.h`
  (canonical home), with `fi_xpu_device.h` including `fi_xpu.h` on host
- Documented `prov_id` assignment requirements in the Provider Dispatch
  Model section
- Removed FI_CHECK_OP from `fi_xpu_ctx_query` (provider must support it)

---

## Header Structure

```
include/rdma/
├── fi_xpu.h              # Host-side API: fi_xpu_ctx, fi_xpu_ctx_query,
│                         # enum fi_xpu_provider, struct fid_xpu/ep/cq/cntr,
│                         # fi_xpu_attr, fi_xpu_ops, fi_xpu_ctx_attr,
│                         # capability flags (FI_XPU_CAP_EP/CQ/CNTR)
├── fi_xpu_device.h       # Device-side dispatch: includes fi_xpu.h +
│                         # fi_xpu_device_efa.h, defines FI_XPU_FUNC,
│                         # scope enum, dispatch functions (fi_xpu_write,
│                         # fi_xpu_send, fi_xpu_recv, fi_xpu_read,
│                         # fi_xpu_cntr_read/wait, fi_xpu_cq_read, etc.)
├── fi_xpu_device_efa.h   # EFA provider device implementation: WQE/CQE
│                         # formats, fi_xpu_efa_ep/cq/cntr/peer/desc structs,
│                         # all fi_xpu_*_efa() inline functions
├── fabric.h              # Forward declarations for fid_xpu_ep/cq/cntr
├── fi_endpoint.h         # export_xpu uses struct fid_xpu_ep **
└── fi_eq.h               # export_xpu uses struct fid_xpu_cq/cntr **
```

---

## EFA Provider Implementation

### New Files:
- `prov/efa/src/efa_xpu.h` — State structs (efa_xpu_ctx, ep/cq/cntr state)
- `prov/efa/src/efa_xpu.c` — Full implementation:
  - `efa_xpu_ctx_open()` — creates XPU context
  - `efa_xpu_ctx_query()` — returns caps, av_addr_size, mr_desc_size
  - `efa_ep_export_xpu()` — exports EP (maps SQ/RQ/doorbells to GPU)
  - `efa_cq_export_xpu()` — exports CQ (maps CQ ring to GPU)
  - `efa_cntr_export_xpu()` — exports counter (GPU HBM allocation)
  - `efa_av_lookup2()` — returns per-entry raw peer address
  - `efa_mr_get_desc()` — returns lkey for XPU use
  - Memory helpers: `xpu_import_region()`, `xpu_gpu_alloc_and_copy()`
  - State lifecycle: create/destroy for ep/cq/cntr state

### Wired Into:
- `efa_domain.c` — `.xpu_ctx = efa_xpu_ctx_open`
- `efa_ep.c` — `.export_xpu = efa_ep_export_xpu`
- `efa_cq.c` — `.export_xpu = efa_cq_export_xpu`
- `efa_cntr.c` — `.export_xpu = efa_cntr_export_xpu`
- `efa_av.c` — `.lookup2 = efa_av_lookup2`
- `efa_mr.c` — `.get_desc = efa_mr_get_desc`

### Build:
- `prov/efa/Makefile.include` — efa_xpu.c added conditionally
  (HAVE_EFADV_QUERY_QP_WQS + HAVE_EFADV_QUERY_CQ)
- `prov/efa/configure.m4` — AM_CONDITIONALs already existed

---

## Man Page Reorganization

### fi_xpu.3.md (overview/workflow):
- OVERVIEW, XPU CONTEXT, fi_xpu_attr, fi_xpu_ctx_attr sections
- Per-object semantics: EP → CQ → Counters → AV → MR
- Brief cross-references to each resource's man page
- DEVICE-SIDE API: Provider Dispatch Model, Scope, cross-references
- Full end-to-end EXAMPLE

### Per-resource man pages (detailed API docs):
- `fi_endpoint.3.md` — fi_ep_export_xpu (NAME, SYNOPSIS, ## description),
  xpu_ctx in fi_ep_attr, XPU behavior in fi_endpoint2 section
- `fi_cq.3.md` — fi_cq_export_xpu, xpu_ctx in fi_cq_attr, XPU in
  fi_cq_open section
- `fi_cntr.3.md` — fi_cntr_export_xpu, xpu_ctx in fi_cntr_attr, XPU in
  fi_cntr_open section
- `fi_av.3.md` — fi_av_lookup2 (NAME, SYNOPSIS, ## description), XPU
  SUPPORT section
- `fi_mr.3.md` — fi_mr_get_desc (NAME, SYNOPSIS, ## description), XPU
  SUPPORT section

### Data transfer man pages (device-side APIs):
- `fi_msg.3.md` — fi_xpu_send, fi_xpu_recv + scope parameter
- `fi_tagged.3.md` — fi_xpu_tsend, fi_xpu_trecv + scope parameter
- `fi_rma.3.md` — fi_xpu_write, fi_xpu_read + scope parameter
- `fi_atomic.3.md` — fi_xpu_atomic, fi_xpu_fetch_atomic,
  fi_xpu_compare_atomic + scope parameter

---

## Fabtests

- `fabtests/prov/efa/src/fi_xpu_gda.c` — Host test program (send latency,
  RDMA write/read bandwidth, counter/CQ modes)
- `fabtests/prov/efa/src/fi_xpu/fi_xpu_kernels.h` — Kernel declarations
- `fabtests/prov/efa/src/fi_xpu/fi_xpu_kernels.cu` — CUDA kernels
- `fabtests/prov/efa/src/fi_xpu/Makefile` — Builds libfixpukernels.so
- `fabtests/prov/efa/Makefile.include` — fi_xpu_gda target (FI_XPU_GDA)
- `fabtests/prov/efa/configure.m4` — --enable-fi-xpu-gda option

---

## Commit Structure (9 commits on fi_accelerator_api_impl)

1. `core: Add FI_XPU capability flag`
2. `core: Add XPU attribute and ops structures`
3. `core: Add XPU memory callback flags`
4. `core: Add fid_xpu_ctx and domain creation/query`
5. `core: Add fid_xpu_ctx to EP/CQ/CNTR attrs` (+ ABI compat)
6. `core: Add EP/CQ/CNTR export_xpu functions` (+ enum fi_xpu_provider,
   fid_xpu types, typed signatures)
7. `core: Add fi_av_lookup2 and fi_mr_get_desc with XPU context`
8. `core: Add device-side XPU API header`
9. `man: Add fi_xpu man page and document XPU semantics`

**Not yet committed:** EFA provider implementation + fabtests + device header

---

## TODO / Known Issues

1. **EFA provider not committed yet** — efa_xpu.c/h, fi_xpu_device_efa.h,
   and all ops wiring changes are in the working tree but not committed.
   Should be a separate commit: "prov/efa: Implement XPU API"

2. **Fabtests not committed** — fi_xpu_gda.c and kernel files need a
   separate commit: "fabtests/efa: Add fi_xpu_gda test"

3. **Full build not verified** — Headers compile clean. Full build requires
   CUDA headers and EFA verbs devel (efadv) which are not on this dev box.
   Need to test on an EFA instance with CUDA.

4. **efa_xpu.c struct names** — The efa_xpu.c may reference old struct
   names from the initial subagent run (fi_xpu_efa_ep vs the new layout in
   fi_xpu_device_efa.h). Needs reconciliation before commit.

5. **fi_xpu_device_efa.h peer struct** — The peer struct uses
   (ahn, remote_qpn, remote_qkey) which is the minimal EFA addressing.
   The old code also had this layout. Verify against current EFA AV/conn
   internals.

6. **Missing device-side functions** — fi_xpu_tsend_efa, fi_xpu_trecv_efa
   (tagged), fi_xpu_atomic_efa (atomics) are not in the device header yet.
   The dispatch in fi_xpu_device.h references them but they don't exist.
   Either add stubs returning -FI_ENOSYS or implement them.

7. **fi_xpu_device.h scope enum** — When fi_xpu_device_efa.h is included
   from fi_xpu_device.h, the scope enum is already defined. But for
   standalone inclusion, the fallback #defines handle it. Verify no
   conflicts.

8. **autoreconf needed** — Makefile.include changes require running
   autoreconf to regenerate Makefile.in. The current build used the
   pre-existing Makefile.in so the new source wasn't compiled.
