# EFA Provider Refactoring Architecture Document

## Executive Summary

This document outlines the proposed architecture for refactoring the EFA provider using a **sharing-based approach**:
- **Eliminate Protocol Branching**: Remove `if (info_type == EFA_INFO_RDM)` branches in shared components
- **Maintain Separate APIs**: Keep EFA-direct and RDM APIs separate to avoid locking conflicts
- **Extract Lock-Agnostic Utilities**: Share common helper functions without imposing locking requirements
- **Preserve Performance**: Leverage existing common data path functions

## Design Principles

1. **Eliminate Protocol Branching**: Remove `if (info_type == EFA_INFO_RDM)` branches in shared components
2. **Maintain Separate APIs**: Keep EFA-direct and RDM endpoint/CQ APIs separate to avoid locking conflicts
3. **Extract Lock-Agnostic Utilities**: Share common helper functions that don't impose locking requirements
4. **Preserve Existing Architecture**: Don't disrupt well-designed separations in EP/CQ layers
5. **Avoid API Layering**: Don't force one fabric's API to call another's API

### Why API Layering is Problematic

Forcing RDM to call EFA-direct APIs creates serious locking and atomicity issues:

```c
/* PROBLEMATIC: RDM calling Direct API */
efa_rdm_ep_bind() {
    ofi_genlock_lock(&domain->srx_lock);  /* RDM needs this lock */
    
    ret = efa_ep_bind(...);  /* ❌ Direct API may acquire conflicting locks */
                             /* ❌ Lock ordering issues, potential deadlock */
    
    /* RDM-specific code that MUST be atomic with above */
    rdm_specific_setup();    /* ❌ Atomicity broken if Direct API fails/returns early */
    
    ofi_genlock_unlock(&domain->srx_lock);
}
```

**Problems with API Layering:**
- **Lock Ordering**: Different fabrics may acquire locks in different orders → deadlock
- **Atomicity**: RDM operations need to be atomic, but calling Direct APIs breaks atomicity
- **Lock Nesting**: Direct functions may acquire locks that conflict with RDM's locks
- **Different Lock Granularity**: RDM might need coarser locking than Direct
- **Future Deprecation**: If EFA-direct is eventually deprecated, layered dependencies make removal difficult

**Solution**: Keep APIs separate and share only lock-agnostic utilities.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    Libfabric API Layer                     │
└─────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────┐
│                    EFA Provider                            │
│  ┌─────────────────┐              ┌─────────────────────┐   │
│  │   EFA-RDM       │              │    EFA-Direct       │   │
│  │   Fabric        │              │    Fabric           │   │
│  │ (efa_rdm_*)     │              │    (efa_*)          │   │
│  └─────────────────┘              └─────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────┐
│              SHARED COMPONENTS (Branch-Free)               │
│  ┌─────────────────┐              ┌─────────────────────┐   │
│  │   RDM Uses      │              │  Direct Uses        │   │
│  │ • Function Ptrs │◄─────────────►│  • Function Ptrs    │   │
│  │ • Lock-Agnostic │  Common Impl │  • Lock-Agnostic    │   │
│  │   Utilities     │              │    Utilities        │   │
│  └─────────────────┘              └─────────────────────┘   │
│                    ┌─────────────────────┐                  │
│                    │ Shared Components   │                  │
│                    │ • efa_mr.c (no br.) │                  │
│                    │ • efa_av.c (no br.) │                  │
│                    │ • efa_conn.c        │                  │
│                    │ • efa_ep.c          │                  │
│                    │ • efa_qp_post_*()   │                  │
│                    └─────────────────────┘                  │
└─────────────────────────────────────────────────────────────┘
```

### Existing Code Structure and Sharing

```
efa/src/
├── efa_domain.c/h           # SHARED: Both fabrics use same domain API
├── efa_mr.c/h               # SHARED: Both fabrics use same MR API (with minor branching)
├── efa_av.c/h               # SHARED: Both fabrics use same AV API (with minor branching)
├── efa_cntr.c/h             # SHARED: Both fabrics use same counter API
├── efa_conn.c/h             # SHARED: Connection management (with protocol branching)
├── efa_ep.c/h               # SEPARATE: EFA-direct endpoint control
├── efa_cq.c/h               # SEPARATE: EFA-direct completion queue
├── efa_msg.c/h              # SEPARATE: EFA-direct data path (send/recv)
├── efa_rma.c/h              # SEPARATE: EFA-direct RMA operations
├── efa_base_ep.c/h          # SHARED: Base endpoint functionality
└── rdm/
    ├── efa_rdm_ep.h         # SEPARATE: RDM endpoint control
    ├── efa_rdm_cq.c/h       # SEPARATE: RDM completion processing
    ├── efa_rdm_msg.c/h      # SEPARATE: RDM messaging with protocol emulation
    ├── efa_rdm_rma.c/h      # SEPARATE: RDM RMA with software protocols
    └── efa_rdm_*.c/h        # SEPARATE: Other RDM protocol components
```

### Current Sharing Status

**Already Shared (Same API)**:
- **Domain**: `efa_domain.c` - Both fabrics use identical domain operations
- **Memory Registration**: `efa_mr.c` - Both fabrics use same MR API
- **Address Vector**: `efa_av.c` - Both fabrics use same AV API  
- **Counters**: `efa_cntr.c` - Both fabrics use same counter API
- **Base Endpoint**: `efa_ep.c` - Common endpoint functionality
- **Data Path Primitives**: `efa_qp_post_send()`, `efa_qp_post_recv()`, etc.

**Separate APIs**:
- **Endpoint Control**: `efa_ep.c` vs `efa_rdm_ep.c` - Different control interfaces
- **Completion Queue**: `efa_cq.c` vs `efa_rdm_cq.c` - Different CQ interfaces
- **Data Path**: `efa_msg.c` vs `efa_rdm_msg.c` - Different send/recv implementations

### Protocol Branching Issues

**Problem**: Some shared components have `if (info_type == EFA_INFO_RDM)` branches:

```c
/* Example from efa_conn.c */
if (av->domain->info_type == EFA_INFO_RDM && insert_shm_av) {
    err = efa_conn_rdm_insert_shm_av(av, conn);  // RDM-specific logic
}

/* Example from efa_mr.c */
if (efa_mr->domain->info_type == EFA_INFO_RDM && !(flags & FI_MR_DMABUF) && cuda_is_gdrcopy_enabled()) {
    /* RDM-specific GDRCopy registration */
}
```

**Target for Refactoring**: These branches should be eliminated through function pointers or separate implementations.

## Proposed New Code Structure

### New File Layout After Refactoring

```
efa/src/
├── efa_domain.c/h              # UNCHANGED: Already well shared
├── efa_cntr.c/h                # UNCHANGED: Already well shared
├── efa_mr.c/h                  # SHARED: Branch-free MR operations
├── efa_av.c/h                  # SHARED: Branch-free AV operations
├── efa_conn.c/h                # SHARED: Branch-free connection management
├── efa_utils.c/h               # SHARED: Common utility functions
├── efa_data_path_ops.c/h       # SHARED: Common data path operations
├── efa_ep.c/h                  # SHARED: Common EP control (replaces efa_base_ep.c)
├── efa_cq.c/h                  # SHARED: Common CQ control (branch-free)
├── direct/                     # NEW: EFA-direct specific implementations
│   ├── efa_direct_ep.c/h       # NEW: Direct-specific EP functions
│   ├── efa_direct_cq.c/h       # NEW: Direct-specific CQ functions
│   ├── efa_msg.c/h             # MOVED: From root (direct data path)
│   └── efa_rma.c/h             # MOVED: From root (direct RMA)
└── rdm/                        # EXISTING: RDM-specific implementations
    ├── efa_rdm_ep.c/h          # UNCHANGED: Existing RDM endpoint
    ├── efa_rdm_cq.c/h          # UNCHANGED: Existing RDM CQ
    ├── efa_rdm_msg.c/h         # UNCHANGED: Existing RDM messaging
    ├── efa_rdm_rma.c/h         # UNCHANGED: Existing RDM RMA
    └── efa_rdm_*.c/h           # UNCHANGED: Other RDM components
```

### New Sharing Rules

#### 1. Shared Components (Branch-Free)
**Location**: `efa/src/` (root level)
**Rule**: No protocol-specific branching allowed
**Usage**: Both fabrics use through function pointers

```c
/* efa_mr.c - Branch-free MR operations */
int efa_mr_reg(struct efa_mr *mr, const struct fi_mr_attr *attr, uint64_t flags)
{
    /* Common MR registration logic */
    ret = efa_mr_validate_params(mr, attr);
    if (ret) return ret;
    
    /* Use function pointer - no branching */
    ret = mr->domain->mr_ops->validate_access(mr, attr);
    if (ret) return ret;
    
    ret = mr->domain->mr_ops->setup_hmem(mr, attr, flags);
    if (ret) return ret;
    
    return efa_mr_register_ibv(mr, attr, flags);
}
```

#### 2. Fabric-Specific Components
**Location**: `efa/src/direct/` and `efa/src/rdm/`
**Rule**: Implement fabric-specific function pointers
**Usage**: Set function pointers during domain/AV creation

```c
/* efa_direct_ep.c - Direct-specific EP functions */
static int efa_direct_ep_enable_qp(struct efa_ep *ep)
{
    /* Direct-specific QP enable logic */
    return efa_ep_create_and_enable_qp(ep, false);
}

static int efa_direct_ep_setup_tx_cq(struct efa_ep *ep, struct efa_cq *cq)
{
    /* Direct fabric uses bypass CQ ops */
    cq->util_cq.cq_fid.ops = &efa_cq_bypass_util_cq_ops;
    return 0;
}

/* Function pointer table for direct fabric */
struct efa_ep_ops efa_direct_ep_ops = {
    .enable_qp = efa_direct_ep_enable_qp,
    .setup_tx_cq = efa_direct_ep_setup_tx_cq,
};
```

```c
/* efa_direct_cq.c - Direct-specific CQ functions */
static ssize_t efa_direct_cq_process_completion(struct efa_cq *cq, struct fi_cq_entry *entry)
{
    /* Direct completion processing - no protocol overhead */
    return efa_cq_read_entry_direct(cq, entry);
}

static void efa_direct_cq_progress(struct util_cq *cq)
{
    /* Direct CQ progress - single IBV CQ polling */
    efa_cq_poll_ibv_cq(cq);
}

/* Function pointer table for direct fabric */
struct efa_cq_ops efa_direct_cq_ops = {
    .process_completion = efa_direct_cq_process_completion,
    .progress = efa_direct_cq_progress,
};
```

#### 3. Domain Creation Sets Function Pointers

```c
/* efa_domain.c - Set function pointers during domain creation */
int efa_domain_open(struct fid_fabric *fabric_fid, struct fi_info *info,
                   struct fid_domain **domain_fid, void *context)
{
    struct efa_domain *domain = calloc(1, sizeof(*domain));
    
    /* Set fabric-specific function pointers */
    if (info->fabric_attr->api_version == EFA_INFO_DIRECT) {
        domain->mr_ops = &efa_direct_mr_ops;
        domain->av_ops = &efa_direct_av_ops;
        domain->conn_ops = &efa_direct_conn_ops;
        domain->ep_ops = &efa_direct_ep_ops;
        domain->cq_ops = &efa_direct_cq_ops;
    } else {
        domain->mr_ops = &efa_rdm_mr_ops;
        domain->av_ops = &efa_rdm_av_ops;
        domain->conn_ops = &efa_rdm_conn_ops;
        domain->ep_ops = &efa_rdm_ep_ops;
        domain->cq_ops = &efa_rdm_cq_ops;
    }
    
    /* Common domain setup */
    return efa_domain_init(domain, info);
}
```

### Code Organization Benefits

#### 1. Clear Separation of Concerns
- **Shared code**: Pure utilities with no protocol knowledge
- **Direct code**: EFA-direct specific optimizations
- **RDM code**: RDM protocol implementations

#### 2. Elimination of Protocol Branching
- No `if (info_type == EFA_INFO_RDM)` in shared code
- Function pointers provide clean dispatch
- Each fabric implements only what it needs

#### 3. Maintainability Improvements
- Bug fixes in shared code benefit both fabrics
- New features can be added to specific fabrics without affecting others
- Clear ownership of code sections

#### 4. Performance Preservation
- Function pointers resolved at domain creation (control path)
- Data path uses static inline functions with existing common implementations
- No runtime branching in hot paths

### Migration Strategy

#### Phase 1: Extract Shared Utilities
1. Refactor existing files to be branch-free
2. Move branch-free logic from existing files to common implementations
3. Add function pointer infrastructure

#### Phase 2: Reorganize Fabric-Specific Code
1. Create `efa/src/direct/` directory
2. Move EFA-direct specific code to `direct/`
3. Implement fabric-specific function pointer tables

#### Phase 3: Update Build System
1. Update Makefile.am to include new direct/ directory
2. Ensure proper linking of common shared files
3. Maintain backward compatibility

#### Phase 4: Validation
1. Verify no performance regression
2. Ensure all tests pass
3. Validate code size reduction

This new structure provides clear separation while maximizing code reuse and eliminating protocol branching.

## Detailed Component Architecture

### 1. Control Path: Layered Approach

#### RDM Control Path Calls EFA-Direct

```c
/* efa_rdm_ep.c - RDM endpoint uses EFA-direct control functions */
static int efa_rdm_ep_enable(struct fid_ep *ep_fid)
{
    struct efa_rdm_ep *rdm_ep = container_of(ep_fid, struct efa_rdm_ep, base_ep.util_ep.ep_fid);
    
    /* Call EFA-direct endpoint enable - layered approach */
    int ret = efa_ep_enable(&rdm_ep->base_ep.util_ep.ep_fid);
    if (ret)
        return ret;
    
    /* RDM-specific initialization */
    return efa_rdm_ep_post_internal_rx_pkts(rdm_ep);
}

static int efa_rdm_ep_bind(struct fid *fid, struct fid *bfid, uint64_t flags)
{
    struct efa_rdm_ep *rdm_ep = container_of(fid, struct efa_rdm_ep, base_ep.util_ep.ep_fid.fid);
    
    /* Call EFA-direct bind - layered approach */
    int ret = efa_ep_bind(&rdm_ep->base_ep.util_ep.ep_fid.fid, bfid, flags);
    if (ret)
        return ret;
    
    /* RDM-specific binding logic */
    return efa_rdm_ep_setup_peer_management(rdm_ep);
}
```

#### Address Vector Layering

```c
/* efa_rdm_av.c - RDM uses EFA-direct AV functions */
static int efa_rdm_av_insert(struct fid_av *av_fid, const void *addr, size_t count, fi_addr_t *fi_addr, uint64_t flags, void *context)
{
    /* Call EFA-direct AV insert - layered approach */
    int ret = efa_av_insert(av_fid, addr, count, fi_addr, flags, context);
    if (ret)
        return ret;
    
    /* RDM-specific peer management */
    return efa_rdm_av_setup_peers(av_fid, addr, count, fi_addr);
}
```

### 2. Data Path: Common Interface Approach

#### Common Data Path Interface

```c
/* efa_data_ops.h - Common interface for data path operations */
struct efa_data_ops {
    /* Send operations */
    ssize_t (*send)(struct efa_base_ep *ep, const struct iovec *iov, size_t iov_count,
                   fi_addr_t dest_addr, void *context, uint64_t flags);
    
    /* Receive operations */
    ssize_t (*recv)(struct efa_base_ep *ep, const struct iovec *iov, size_t iov_count,
                   void *context, uint64_t flags);
    
    /* RMA operations */
    ssize_t (*read)(struct efa_base_ep *ep, const struct iovec *iov, size_t iov_count,
                   fi_addr_t src_addr, uint64_t addr, uint64_t key, void *context);
    
    ssize_t (*write)(struct efa_base_ep *ep, const struct iovec *iov, size_t iov_count,
                    fi_addr_t dest_addr, uint64_t addr, uint64_t key, void *context);
    
    /* Completion operations */
    ssize_t (*cq_read)(struct efa_cq *cq, void *buf, size_t count);
};
```

#### Common Implementation with Specialization

```c
/* EXISTING: efa_qp_post_send already provides the common interface */
/* From efa_data_path_ops.h - this is the shared implementation */
static inline int
efa_qp_post_send(struct efa_qp *qp,
                 const struct ibv_sge *sge_list,
                 const struct ibv_data_buf *inline_data_list,
                 size_t data_count,
                 bool use_inline,
                 uintptr_t wr_id,
                 uint64_t data,
                 uint64_t flags,
                 struct efa_ah *ah,
                 uint32_t qpn,
                 uint32_t qkey)
{
    /* This already handles both IBV and direct paths */
#if HAVE_EFA_DATA_PATH_DIRECT
    if (qp->data_path_direct_enabled)
        return efa_data_path_direct_post_send(qp, sge_list, inline_data_list, data_count,
                                            use_inline, wr_id, data, flags, ah, qpn, qkey);
#endif
    return efa_ibv_post_send(qp, sge_list, inline_data_list, data_count,
                           use_inline, wr_id, data, flags, ah, qpn, qkey);
}
```

#### Fabric-Specific Wrappers Use Existing Common Interface

```c
/* efa_msg.c - EFA-direct uses existing efa_qp_post_send */
ssize_t efa_send(struct fid_ep *ep, const void *buf, size_t len, void *desc,
                fi_addr_t dest_addr, void *context)
{
    struct efa_base_ep *base_ep = container_of(ep, struct efa_base_ep, util_ep.ep_fid);
    
    /* Build SGE - common logic */
    struct ibv_sge sge = {
        .addr = (uintptr_t)buf,
        .length = len,
        .lkey = /* get lkey from desc */
    };
    
    struct efa_ah *ah = efa_av_addr_to_ah(base_ep->av, dest_addr);
    
    /* Use existing common interface - no duplication */
    return efa_qp_post_send(base_ep->qp, &sge, NULL, 1, false,
                           (uintptr_t)context, 0, 0, ah, ah->qpn, ah->qkey);
}, ah->qpn, ah->qkey);
}
```

#### Static Inline Wrappers Use Existing Common Interface

```c
/* efa_msg.c - EFA-direct messaging uses existing efa_qp_post_send */
static inline ssize_t
efa_send(struct fid_ep *ep, const void *buf, size_t len, void *desc,
        fi_addr_t dest_addr, void *context)
{
    struct efa_base_ep *base_ep = container_of(ep, struct efa_base_ep, util_ep.ep_fid);
    
    /* Build SGE */
    struct ibv_sge sge = {
        .addr = (uintptr_t)buf,
        .length = len,
        .lkey = /* get lkey from desc */
    };
    
    struct efa_ah *ah = efa_av_addr_to_ah(base_ep->av, dest_addr);
    
    /* Use existing common interface - compiler can inline */
    return efa_qp_post_send(base_ep->qp, &sge, NULL, 1, false,
                           (uintptr_t)context, 0, 0, ah, ah->qpn, ah->qkey);
}
```

```c
/* efa_rdm_msg.c - RDM messaging uses existing efa_qp_post_send */
static inline ssize_t
efa_rdm_send(struct fid_ep *ep, const void *buf, size_t len, void *desc,
            fi_addr_t dest_addr, void *context)
{
    struct efa_rdm_ep *rdm_ep = container_of(ep, struct efa_rdm_ep, base_ep.util_ep.ep_fid);
    
    /* RDM protocol: allocate and build packet */
    struct efa_rdm_ope *txe = efa_rdm_ep_alloc_txe(rdm_ep, peer, &msg, ofi_op_msg, 0, flags);
    struct efa_rdm_pke *pkt_entry = efa_rdm_pke_alloc_rtm(rdm_ep, txe, EFA_RDM_EAGER_MSGRTM_PKT);
    
    /* Build SGE for RDM packet */
    struct ibv_sge sge = {
        .addr = (uintptr_t)pkt_entry->wiredata,
        .length = pkt_entry->pkt_size,
        .lkey = pkt_entry->mr->lkey
    };
    
    /* Use existing common interface - compiler can inline */
    return efa_qp_post_send(rdm_ep->base_ep.qp, &sge, NULL, 1, false,
                           (uintptr_t)pkt_entry, 0, 0, ah, ah->qpn, ah->qkey);
}
```

### 3. Completion Queue: Hybrid Approach

#### Control Path: Layered (CQ Creation)

```c
/* efa_rdm_cq.c - RDM uses EFA-direct CQ creation */
int efa_rdm_cq_open(struct fid_domain *domain, struct fi_cq_attr *attr,
                   struct fid_cq **cq_fid, void *context)
{
    /* Use EFA-direct CQ creation - layered approach */
    int ret = efa_cq_open(domain, attr, cq_fid, context);
    if (ret)
        return ret;
    
    /* Set RDM-specific data path operations */
    struct efa_cq *cq = container_of(*cq_fid, struct efa_cq, util_cq.cq_fid);
    cq->data_ops = &efa_rdm_data_ops;
    
    return 0;
}
```

#### Data Path: Common Interface (CQ Processing)

```c
/* efa_data_ops.c - Common CQ processing */
ssize_t efa_common_cq_read_impl(struct efa_cq *cq, void *buf, size_t count, bool use_rdm_protocol)
{
    /* Common CQ polling logic */
    struct fi_cq_entry *entries = (struct fi_cq_entry *)buf;
    ssize_t ret = 0;
    
    efa_cq_start_poll(cq->ibv_cq);
    
    while (ret < count && efa_cq_wc_available(cq->ibv_cq)) {
        if (use_rdm_protocol) {
            /* RDM protocol-aware completion processing */
            ret += efa_rdm_process_completion(cq, &entries[ret]);
        } else {
            /* Direct completion processing */
            ret += efa_direct_process_completion(cq, &entries[ret]);
        }
        efa_cq_next_poll(cq->ibv_cq);
    }
    
    efa_cq_end_poll(cq->ibv_cq);
    return ret;
}
```

## Shared Components Refactoring Details

### Current State Analysis

Based on code examination, here's the current sharing status:

#### Already Well Shared (Minimal Changes Needed)
- **efa_domain.c**: Both fabrics use same domain API, only different ops tables
- **efa_cntr.c**: Both fabrics use same counter API, only different progress functions

#### Needs Refactoring (Has Protocol Branching)
- **efa_mr.c**: Has `if (efa_mr->domain->info_type == EFA_INFO_RDM)` branches
- **efa_av.c**: Has `if (av->domain->info_type == EFA_INFO_RDM)` branches
- **efa_conn.c**: Has significant RDM-specific logic mixed in

#### Additional Analysis Results

**CQ Components Analysis:**
- **efa_cq.c**: Well-structured with separate ops tables (`efa_cq_bypass_util_cq_ops` vs `efa_cq_ops`). Uses function pointers for different CQ formats (`read_entry` function pointer). Minimal refactoring needed.
- **efa_rdm_cq.c**: Separate implementation with different progress function (`efa_rdm_cq_progress`). Good separation already exists.

**Endpoint Components Analysis:**
- **efa_ep.c**: Clean EFA-direct endpoint implementation with separate ops tables. No protocol branching detected.
- **efa_base_ep.c**: Shared base functionality used by both fabrics. Well-designed common interface.
- **efa_rdm_ep_fiops.c**: RDM endpoint control operations. Contains layering opportunities - calls base_ep functions in several places.
- **efa_rdm_ep_utils.c**: RDM endpoint utilities. Contains some shared functionality that could be extracted.

**Key Findings:**
1. **CQ Layer**: Already well-separated with different ops tables and progress functions
2. **Base EP**: Good shared foundation, minimal changes needed
3. **RDM EP**: Some layering already exists (calls `efa_base_ep_*` functions), can be enhanced
4. **No Major Protocol Branching**: Unlike MR/AV/CONN, the EP and CQ components don't have significant `if (info_type == EFA_INFO_RDM)` branching

### Detailed Refactoring Proposals

#### 1. efa_mr.c Refactoring

**Current Problem**:
```c
/* efa_mr_reg_impl() has protocol-specific branching */
if (efa_mr->domain->info_type == EFA_INFO_DIRECT) {
    /* EFA-direct specific validation */
    if ((mr_attr->access & (FI_READ | FI_REMOTE_READ)) && !device_support_rdma_read) {
        return -FI_EOPNOTSUPP;
    }
}

/* efa_mr_hmem_setup() has RDM-specific logic */
if (efa_mr->domain->info_type == EFA_INFO_RDM && !(flags & FI_MR_DMABUF) && cuda_is_gdrcopy_enabled()) {
    /* RDM-specific GDRCopy registration */
}
```

**Proposed Solution: Function Pointer Dispatch**:
```c
/* efa_mr.h - Add function pointers to domain */
struct efa_domain {
    /* ... existing fields ... */
    
    /* MR operation function pointers - set at domain creation */
    int (*mr_validate_access)(struct efa_mr *efa_mr, const struct fi_mr_attr *attr);
    int (*mr_setup_hmem)(struct efa_mr *efa_mr, const struct fi_mr_attr *attr, uint64_t flags);
};

/* efa_mr.c - Separate implementations */
static int efa_mr_validate_access_direct(struct efa_mr *efa_mr, const struct fi_mr_attr *attr)
{
    /* EFA-direct specific validation - no branching */
    if ((attr->access & (FI_READ | FI_REMOTE_READ)) && !device_support_rdma_read) {
        return -FI_EOPNOTSUPP;
    }
    return 0;
}

static int efa_mr_validate_access_rdm(struct efa_mr *efa_mr, const struct fi_mr_attr *attr)
{
    /* RDM allows all access modes - no validation needed */
    return 0;
}

/* efa_mr_reg_impl() becomes branch-free */
static int efa_mr_reg_impl(struct efa_mr *efa_mr, uint64_t flags, const struct fi_mr_attr *mr_attr)
{
    /* ... common setup ... */
    
    /* Use function pointer - no branching */
    ret = efa_mr->domain->mr_validate_access(efa_mr, mr_attr);
    if (ret) return ret;
    
    ret = efa_mr->domain->mr_setup_hmem(efa_mr, mr_attr, flags);
    if (ret) return ret;
    
    /* ... rest of common logic ... */
}
```

#### 2. efa_av.c Refactoring

**Current Problem**:
```c
/* efa_av_insert_one() has RDM-specific branching */
if (av->domain->info_type == EFA_INFO_RDM)
    assert(ofi_genlock_held(&av->domain->srx_lock));

/* efa_conn_alloc() has RDM-specific logic */
if (av->domain->info_type == EFA_INFO_RDM && insert_shm_av) {
    err = efa_conn_rdm_insert_shm_av(av, conn);
}
```

**Proposed Solution: Separate AV Operations**:
```c
/* efa_av.h - Add AV operation function pointers */
struct efa_av {
    /* ... existing fields ... */
    
    /* AV operation function pointers - set at AV creation */
    int (*conn_setup)(struct efa_av *av, struct efa_conn *conn, bool insert_shm_av);
    void (*pre_insert_lock)(struct efa_av *av);
    void (*post_insert_unlock)(struct efa_av *av);
};

/* efa_av_insert_one() becomes branch-free */
int efa_av_insert_one(struct efa_av *av, struct efa_ep_addr *addr, ...)
{
    /* Use function pointer - no branching */
    av->pre_insert_lock(av);
    
    /* ... common insertion logic ... */
    
    conn = efa_conn_alloc(av, addr, flags, context, insert_shm_av, insert_implicit_av);
    if (!conn) {
        av->post_insert_unlock(av);
        return -FI_EADDRNOTAVAIL;
    }
    
    /* Use function pointer - no branching */
    ret = av->conn_setup(av, conn, insert_shm_av);
    
    av->post_insert_unlock(av);
    return ret;
}
```

#### 4. efa_cq.c and efa_rdm_cq.c Analysis

**Current State: Already Well-Designed**

The CQ components are already well-structured with good separation:

```c
/* efa_cq.c - EFA-direct CQ with separate ops tables */
struct fi_ops_cq efa_cq_bypass_util_cq_ops = {
    .readfrom = efa_cq_readfrom,     /* Direct hardware polling */
    .readerr = efa_cq_readerr,       /* Direct error handling */
};

struct fi_ops_cq efa_cq_ops = {
    .readfrom = ofi_cq_readfrom,     /* Util CQ with staging */
    .readerr = ofi_cq_readerr,       /* Util error handling */
};

/* efa_rdm_cq.c - RDM CQ with different progress function */
static struct fi_ops_cq efa_rdm_cq_ops = {
    .readfrom = efa_rdm_cq_readfrom, /* RDM-specific readfrom */
    .sreadfrom = efa_rdm_cq_sreadfrom, /* RDM blocking read */
};

static void efa_rdm_cq_progress(struct util_cq *cq) {
    /* RDM-specific progress with SHM handling */
    if (cq->shm_cq) {
        fi_cq_read(cq->shm_cq, NULL, 0);
    }
    /* Poll multiple IBV CQs for RDM */
    dlist_foreach(&efa_rdm_cq->ibv_cq_poll_list, item) {
        efa_rdm_cq_poll_ibv_cq(efa_env.efa_cq_read_size, poll_list_entry->cq);
    }
}
```

**Recommendation**: No major refactoring needed. The CQ layer already has good separation.

#### 5. efa_ep.c, efa_base_ep.c, and efa_rdm_ep_*.c Analysis

**Current State: Good Foundation with Enhancement Opportunities**

**efa_base_ep.c** provides excellent shared functionality:
```c
/* Shared base endpoint functions used by both fabrics */
int efa_base_ep_construct(struct efa_base_ep *base_ep, ...);  /* Common construction */
int efa_base_ep_create_and_enable_qp(struct efa_base_ep *ep, ...);  /* QP management */
int efa_base_ep_bind_av(struct efa_base_ep *base_ep, struct efa_av *av);  /* AV binding */
const char *efa_base_ep_getname(fid_t fid, void *addr, size_t *addrlen);  /* Address ops */
```

**efa_rdm_ep_fiops.c** already shows some layering:
```c
/* RDM endpoint bind calls base endpoint functions */
static int efa_rdm_ep_bind(struct fid *ep_fid, struct fid *bfid, uint64_t flags) {
    /* ... */
    case FI_CLASS_AV:
        ret = ofi_ep_bind_av(&efa_rdm_ep->base_ep.util_ep, &av->util_av);
        if (ret) return ret;
        
        ret = efa_base_ep_bind_av(&efa_rdm_ep->base_ep, av);  /* Layered call */
        if (ret) return ret;
        break;
    /* ... */
}

/* RDM endpoint enable calls base endpoint functions */
static int efa_rdm_ep_ctrl(struct fid *fid, int command, void *arg) {
    case FI_ENABLE:
        /* ... RDM-specific setup ... */
        ret = efa_base_ep_create_and_enable_qp(&ep->base_ep, create_user_recv_qp);  /* Layered call */
        if (ret) return ret;
        /* ... more RDM-specific setup ... */
}
```

**Enhancement Opportunities**:
1. **Extract Common Utilities**: Some functions in `efa_rdm_ep_utils.c` could be shared as utilities
2. **Maintain Separate APIs**: Keep RDM and direct endpoint APIs separate (no layering)
3. **Focus on Shared Base Functions**: Use `efa_base_ep_*` as utility functions, not API layers

## Implementation Strategy

### Phase 1: Eliminate Protocol Branching

1. **MR Refactoring**
   - Add function pointers to `efa_domain` for MR operations
   - Separate direct and RDM implementations
   - Remove `if (info_type == EFA_INFO_RDM)` branches

2. **AV Refactoring**
   - Add function pointers to `efa_av` for protocol-specific operations
   - Separate connection setup logic
   - Remove protocol branching from insertion path

3. **Connection Management**
   - Extract common connection allocation
   - Move RDM-specific logic to RDM modules
   - Use function pointer dispatch for protocol-specific setup

### Phase 2: Maintain Separate EP/CQ APIs

1. **Keep Existing Separation**
   - EFA-direct and RDM endpoints have different APIs (no layering)
   - CQ implementations remain separate with different ops tables
   - Maintain existing `efa_base_ep.c` as shared utilities only

2. **Focus on Common Utilities**
   - Extract shared helper functions where appropriate
   - Keep `efa_base_ep_*` functions as utility functions, not API layers
   - Avoid forcing one endpoint type to call another's APIs

### Phase 3: Leverage Existing Common Interfaces

1. **Identify Existing Common Functions**
   - `efa_qp_post_send()` - already shared between fabrics
   - `efa_qp_post_recv()` - already shared
   - `efa_qp_post_read/write()` - already shared
   - `efa_ibv_cq_*()` functions - already shared

2. **Eliminate Duplicated Wrapper Logic**
   - Remove duplicated SGE building code
   - Remove duplicated address resolution
   - Remove duplicated error handling
   - Consolidate common parameter validation

### Phase 4: Validation & Optimization

1. **Performance Testing**
   - Ensure zero regression in data path performance
   - Validate control path functionality
   - Measure code size reduction

2. **Code Cleanup**
   - Remove duplicated implementations
   - Optimize shared function interfaces
   - Update documentation

## Expected Benefits

### Code Reduction
- **Shared Components**: 20-30% reduction through branch elimination in MR/AV/CONN
- **Data Path**: 30-40% reduction through common interface (existing `efa_qp_post_*` functions)
- **Utility Functions**: 10-15% reduction through shared base endpoint utilities
- **Overall**: 25-35% reduction in duplicated code

### Performance Preservation
- **Control Path**: Minimal impact (infrequent operations)
- **Data Path**: Zero impact (static inline + existing common implementation)
- **Shared Components**: Improved performance through branch elimination
- **Endpoint APIs**: No performance impact (separate APIs maintained)
- **Compiler Optimization**: Better inlining opportunities

### Maintainability
- **Single Implementation**: Shared logic in one place for MR/AV/CONN
- **Bug Fixes**: Fixed once, benefits both fabrics
- **Separate APIs**: Each fabric maintains its optimal API design
- **Branch-Free Code**: Easier to understand and maintain

## Success Metrics

### Performance
1. **Data Path**: Zero regression in latency/throughput
2. **Control Path**: <5% overhead acceptable
3. **Binary Size**: 20-30% reduction overall

### Code Quality
1. **Duplication**: >35% reduction in duplicated code
2. **Maintainability**: Single source for shared functionality
3. **Branch Elimination**: Remove protocol-specific branching from shared components
4. **Test Coverage**: Maintain >90% coverage

## Conclusion

The revised architecture provides:

1. **Eliminate Protocol Branching**: Remove `if (info_type == EFA_INFO_RDM)` branches in MR/AV/CONN components
2. **Maintain Separate APIs**: Preserve existing EP/CQ separation to avoid locking conflicts
3. **Extract Lock-Agnostic Utilities**: Share common helper functions without imposing locking requirements
4. **Significant Code Reduction**: 25-35% reduction in duplicated code while preserving performance
5. **Preserve Working Architecture**: Don't disrupt well-designed EP/CQ layers

This approach achieves substantial code reuse while avoiding the **locking conflicts**, **atomicity issues**, **API impedance**, and **future deprecation complexity** that would arise from forcing API layering between fabrics.

### Future Evolution Path

The sharing-based approach (vs layering) provides a clean evolution path:

**If EFA-direct is eventually deprecated:**
- ✅ **With Sharing**: Simply remove EFA-direct files, keep shared utilities
- ❌ **With Layering**: Must refactor all RDM code that calls Direct APIs, complex dependency untangling

**Benefits of Sharing Approach:**
- **Clean Removal**: Each fabric is self-contained
- **No Dependency Chains**: RDM doesn't depend on Direct APIs
- **Preserved Utilities**: Shared helper functions remain useful
- **Simplified Migration**: Applications can migrate from Direct to RDM without provider-level dependencies

```c
/* efa_rdm_msg.c - RDM also uses existing efa_qp_post_send */
ssize_t efa_rdm_send_eager(struct efa_rdm_ep *ep, struct efa_rdm_ope *txe)
{
    /* RDM protocol logic to build packet */
    struct efa_rdm_pke *pkt_entry = efa_rdm_pke_alloc(ep, ep->efa_tx_pkt_pool,
                                                      EFA_RDM_EAGER_MSGRTM_PKT);
    
    /* Build SGE for packet */
    struct ibv_sge sge = {
        .addr = (uintptr_t)pkt_entry->wiredata,
        .length = pkt_entry->pkt_size,
        .lkey = pkt_entry->mr->lkey
    };
    
    /* Use existing common interface - no duplication */
    return efa_qp_post_send(ep->base_ep.qp, &sge, NULL, 1, false,
                           (uintptr_t)pkt_entry, 0, 0, ah, ah->qpn, ah->qkey);
}
```

#### Static Inline Wrappers Use Existing Common Interface

```c
/* efa_msg.c - EFA-direct messaging uses existing efa_qp_post_send */
static inline ssize_t
efa_send(struct fid_ep *ep, const void *buf, size_t len, void *desc,
        fi_addr_t dest_addr, void *context)
{
    struct efa_base_ep *base_ep = container_of(ep, struct efa_base_ep, util_ep.ep_fid);
    
    /* Build SGE */
    struct ibv_sge sge = {
        .addr = (uintptr_t)buf,
        .length = len,
        .lkey = /* get lkey from desc */
    };
    
    struct efa_ah *ah = efa_av_addr_to_ah(base_ep->av, dest_addr);
    
    /* Use existing common interface - compiler can inline */
    return efa_qp_post_send(base_ep->qp, &sge, NULL, 1, false,
                           (uintptr_t)context, 0, 0, ah, ah->qpn, ah->qkey);
}
```

```c
/* efa_rdm_msg.c - RDM messaging uses existing efa_qp_post_send */
static inline ssize_t
efa_rdm_send(struct fid_ep *ep, const void *buf, size_t len, void *desc,
            fi_addr_t dest_addr, void *context)
{
    struct efa_rdm_ep *rdm_ep = container_of(ep, struct efa_rdm_ep, base_ep.util_ep.ep_fid);
    
    /* RDM protocol: allocate and build packet */
    struct efa_rdm_ope *txe = efa_rdm_ep_alloc_txe(rdm_ep, peer, &msg, ofi_op_msg, 0, flags);
    struct efa_rdm_pke *pkt_entry = efa_rdm_pke_alloc_rtm(rdm_ep, txe, EFA_RDM_EAGER_MSGRTM_PKT);
    
    /* Build SGE for RDM packet */
    struct ibv_sge sge = {
        .addr = (uintptr_t)pkt_entry->wiredata,
        .length = pkt_entry->pkt_size,
        .lkey = pkt_entry->mr->lkey
    };
    
    /* Use existing common interface - compiler can inline */
    return efa_qp_post_send(rdm_ep->base_ep.qp, &sge, NULL, 1, false,
                           (uintptr_t)pkt_entry, 0, 0, ah, ah->qpn, ah->qkey);
}
```

### 3. Completion Queue: Hybrid Approach

#### Control Path: Layered (CQ Creation)

```c
/* efa_rdm_cq.c - RDM uses EFA-direct CQ creation */
int efa_rdm_cq_open(struct fid_domain *domain, struct fi_cq_attr *attr,
                   struct fid_cq **cq_fid, void *context)
{
    /* Use EFA-direct CQ creation - layered approach */
    int ret = efa_cq_open(domain, attr, cq_fid, context);
    if (ret)
        return ret;
    
    /* Set RDM-specific data path operations */
    struct efa_cq *cq = container_of(*cq_fid, struct efa_cq, util_cq.cq_fid);
    cq->data_ops = &efa_rdm_data_ops;
    
    return 0;
}
```

#### Data Path: Common Interface (CQ Processing)

```c
/* efa_data_ops.c - Common CQ processing */
ssize_t efa_common_cq_read_impl(struct efa_cq *cq, void *buf, size_t count, bool use_rdm_protocol)
{
    /* Common CQ polling logic */
    struct fi_cq_entry *entries = (struct fi_cq_entry *)buf;
    ssize_t ret = 0;
    
    efa_cq_start_poll(cq->ibv_cq);
    
    while (ret < count && efa_cq_wc_available(cq->ibv_cq)) {
        if (use_rdm_protocol) {
            /* RDM protocol-aware completion processing */
            ret += efa_rdm_process_completion(cq, &entries[ret]);
        } else {
            /* Direct completion processing */
            ret += efa_direct_process_completion(cq, &entries[ret]);
        }
        efa_cq_next_poll(cq->ibv_cq);
    }
    
    efa_cq_end_poll(cq->ibv_cq);
    return ret;
}
```

## Shared Components Refactoring Details

### Current State Analysis

Based on code examination, here's the current sharing status:

#### Already Well Shared (Minimal Changes Needed)
- **efa_domain.c**: Both fabrics use same domain API, only different ops tables
- **efa_cntr.c**: Both fabrics use same counter API, only different progress functions

#### Needs Refactoring (Has Protocol Branching)
- **efa_mr.c**: Has `if (efa_mr->domain->info_type == EFA_INFO_RDM)` branches
- **efa_av.c**: Has `if (av->domain->info_type == EFA_INFO_RDM)` branches
- **efa_conn.c**: Has significant RDM-specific logic mixed in

#### Additional Analysis Results

**CQ Components Analysis:**
- **efa_cq.c**: Well-structured with separate ops tables (`efa_cq_bypass_util_cq_ops` vs `efa_cq_ops`). Uses function pointers for different CQ formats (`read_entry` function pointer). Minimal refactoring needed.
- **efa_rdm_cq.c**: Separate implementation with different progress function (`efa_rdm_cq_progress`). Good separation already exists.

**Endpoint Components Analysis:**
- **efa_ep.c**: Clean EFA-direct endpoint implementation with separate ops tables. No protocol branching detected.
- **efa_base_ep.c**: Shared base functionality used by both fabrics. Well-designed common interface.
- **efa_rdm_ep_fiops.c**: RDM endpoint control operations. Contains layering opportunities - calls base_ep functions in several places.
- **efa_rdm_ep_utils.c**: RDM endpoint utilities. Contains some shared functionality that could be extracted.

**Key Findings:**
1. **CQ Layer**: Already well-separated with different ops tables and progress functions
2. **Base EP**: Good shared foundation, minimal changes needed
3. **RDM EP**: Some layering already exists (calls `efa_base_ep_*` functions), can be enhanced
4. **No Major Protocol Branching**: Unlike MR/AV/CONN, the EP and CQ components don't have significant `if (info_type == EFA_INFO_RDM)` branching

### Detailed Refactoring Proposals

#### 1. efa_mr.c Refactoring

**Current Problem**:
```c
/* efa_mr_reg_impl() has protocol-specific branching */
if (efa_mr->domain->info_type == EFA_INFO_DIRECT) {
    /* EFA-direct specific validation */
    if ((mr_attr->access & (FI_READ | FI_REMOTE_READ)) && !device_support_rdma_read) {
        return -FI_EOPNOTSUPP;
    }
}

/* efa_mr_hmem_setup() has RDM-specific logic */
if (efa_mr->domain->info_type == EFA_INFO_RDM && !(flags & FI_MR_DMABUF) && cuda_is_gdrcopy_enabled()) {
    /* RDM-specific GDRCopy registration */
}
```

**Proposed Solution: Function Pointer Dispatch**:
```c
/* efa_mr.h - Add function pointers to domain */
struct efa_domain {
    /* ... existing fields ... */
    
    /* MR operation function pointers - set at domain creation */
    int (*mr_validate_access)(struct efa_mr *efa_mr, const struct fi_mr_attr *attr);
    int (*mr_setup_hmem)(struct efa_mr *efa_mr, const struct fi_mr_attr *attr, uint64_t flags);
};

/* efa_mr.c - Separate implementations */
static int efa_mr_validate_access_direct(struct efa_mr *efa_mr, const struct fi_mr_attr *attr)
{
    /* EFA-direct specific validation - no branching */
    if ((attr->access & (FI_READ | FI_REMOTE_READ)) && !device_support_rdma_read) {
        return -FI_EOPNOTSUPP;
    }
    return 0;
}

static int efa_mr_validate_access_rdm(struct efa_mr *efa_mr, const struct fi_mr_attr *attr)
{
    /* RDM allows all access modes - no validation needed */
    return 0;
}

/* efa_mr_reg_impl() becomes branch-free */
static int efa_mr_reg_impl(struct efa_mr *efa_mr, uint64_t flags, const struct fi_mr_attr *mr_attr)
{
    /* ... common setup ... */
    
    /* Use function pointer - no branching */
    ret = efa_mr->domain->mr_validate_access(efa_mr, mr_attr);
    if (ret) return ret;
    
    ret = efa_mr->domain->mr_setup_hmem(efa_mr, mr_attr, flags);
    if (ret) return ret;
    
    /* ... rest of common logic ... */
}
```

#### 2. efa_av.c Refactoring

**Current Problem**:
```c
/* efa_av_insert_one() has RDM-specific branching */
if (av->domain->info_type == EFA_INFO_RDM)
    assert(ofi_genlock_held(&av->domain->srx_lock));

/* efa_conn_alloc() has RDM-specific logic */
if (av->domain->info_type == EFA_INFO_RDM && insert_shm_av) {
    err = efa_conn_rdm_insert_shm_av(av, conn);
}
```

**Proposed Solution: Separate AV Operations**:
```c
/* efa_av.h - Add AV operation function pointers */
struct efa_av {
    /* ... existing fields ... */
    
    /* AV operation function pointers - set at AV creation */
    int (*conn_setup)(struct efa_av *av, struct efa_conn *conn, bool insert_shm_av);
    void (*pre_insert_lock)(struct efa_av *av);
    void (*post_insert_unlock)(struct efa_av *av);
};

/* efa_av_insert_one() becomes branch-free */
int efa_av_insert_one(struct efa_av *av, struct efa_ep_addr *addr, ...)
{
    /* Use function pointer - no branching */
    av->pre_insert_lock(av);
    
    /* ... common insertion logic ... */
    
    conn = efa_conn_alloc(av, addr, flags, context, insert_shm_av, insert_implicit_av);
    if (!conn) {
        av->post_insert_unlock(av);
        return -FI_EADDRNOTAVAIL;
    }
    
    /* Use function pointer - no branching */
    ret = av->conn_setup(av, conn, insert_shm_av);
    
    av->post_insert_unlock(av);
    return ret;
}
```

#### 4. efa_cq.c and efa_rdm_cq.c Analysis

**Current State: Already Well-Designed**

The CQ components are already well-structured with good separation:

```c
/* efa_cq.c - EFA-direct CQ with separate ops tables */
struct fi_ops_cq efa_cq_bypass_util_cq_ops = {
    .readfrom = efa_cq_readfrom,     /* Direct hardware polling */
    .readerr = efa_cq_readerr,       /* Direct error handling */
};

struct fi_ops_cq efa_cq_ops = {
    .readfrom = ofi_cq_readfrom,     /* Util CQ with staging */
    .readerr = ofi_cq_readerr,       /* Util error handling */
};

/* efa_rdm_cq.c - RDM CQ with different progress function */
static struct fi_ops_cq efa_rdm_cq_ops = {
    .readfrom = efa_rdm_cq_readfrom, /* RDM-specific readfrom */
    .sreadfrom = efa_rdm_cq_sreadfrom, /* RDM blocking read */
};

static void efa_rdm_cq_progress(struct util_cq *cq) {
    /* RDM-specific progress with SHM handling */
    if (cq->shm_cq) {
        fi_cq_read(cq->shm_cq, NULL, 0);
    }
    /* Poll multiple IBV CQs for RDM */
    dlist_foreach(&efa_rdm_cq->ibv_cq_poll_list, item) {
        efa_rdm_cq_poll_ibv_cq(efa_env.efa_cq_read_size, poll_list_entry->cq);
    }
}
```

**Recommendation**: No major refactoring needed. The CQ layer already has good separation.

#### 5. efa_ep.c, efa_base_ep.c, and efa_rdm_ep_*.c Analysis

**Current State: Good Foundation with Enhancement Opportunities**

**efa_base_ep.c** provides excellent shared functionality:
```c
/* Shared base endpoint functions used by both fabrics */
int efa_base_ep_construct(struct efa_base_ep *base_ep, ...);  /* Common construction */
int efa_base_ep_create_and_enable_qp(struct efa_base_ep *ep, ...);  /* QP management */
int efa_base_ep_bind_av(struct efa_base_ep *base_ep, struct efa_av *av);  /* AV binding */
const char *efa_base_ep_getname(fid_t fid, void *addr, size_t *addrlen);  /* Address ops */
```

**efa_rdm_ep_fiops.c** already shows some layering:
```c
/* RDM endpoint bind calls base endpoint functions */
static int efa_rdm_ep_bind(struct fid *ep_fid, struct fid *bfid, uint64_t flags) {
    /* ... */
    case FI_CLASS_AV:
        ret = ofi_ep_bind_av(&efa_rdm_ep->base_ep.util_ep, &av->util_av);
        if (ret) return ret;
        
        ret = efa_base_ep_bind_av(&efa_rdm_ep->base_ep, av);  /* Layered call */
        if (ret) return ret;
        break;
    /* ... */
}

/* RDM endpoint enable calls base endpoint functions */
static int efa_rdm_ep_ctrl(struct fid *fid, int command, void *arg) {
    case FI_ENABLE:
        /* ... RDM-specific setup ... */
        ret = efa_base_ep_create_and_enable_qp(&ep->base_ep, create_user_recv_qp);  /* Layered call */
        if (ret) return ret;
        /* ... more RDM-specific setup ... */
}
```

**Enhancement Opportunities**:
1. **Extract Common Utilities**: Some functions in `efa_rdm_ep_utils.c` could be shared as utilities
2. **Maintain Separate APIs**: Keep RDM and direct endpoint APIs separate (no layering)
3. **Focus on Shared Base Functions**: Use `efa_base_ep_*` as utility functions, not API layers

## Implementation Strategy

### Phase 1: Eliminate Protocol Branching

1. **MR Refactoring**
   - Add function pointers to `efa_domain` for MR operations
   - Separate direct and RDM implementations
   - Remove `if (info_type == EFA_INFO_RDM)` branches

2. **AV Refactoring**
   - Add function pointers to `efa_av` for protocol-specific operations
   - Separate connection setup logic
   - Remove protocol branching from insertion path

3. **Connection Management**
   - Extract common connection allocation
   - Move RDM-specific logic to RDM modules
   - Use function pointer dispatch for protocol-specific setup

### Phase 2: Maintain Separate EP/CQ APIs

1. **Keep Existing Separation**
   - EFA-direct and RDM endpoints have different APIs (no layering)
   - CQ implementations remain separate with different ops tables
   - Maintain existing `efa_base_ep.c` as shared utilities only

2. **Focus on Common Utilities**
   - Extract shared helper functions where appropriate
   - Keep `efa_base_ep_*` functions as utility functions, not API layers
   - Avoid forcing one endpoint type to call another's APIs

### Phase 3: Leverage Existing Common Interfaces

1. **Identify Existing Common Functions**
   - `efa_qp_post_send()` - already shared between fabrics
   - `efa_qp_post_recv()` - already shared
   - `efa_qp_post_read/write()` - already shared
   - `efa_ibv_cq_*()` functions - already shared

2. **Eliminate Duplicated Wrapper Logic**
   - Remove duplicated SGE building code
   - Remove duplicated address resolution
   - Remove duplicated error handling
   - Consolidate common parameter validation

### Phase 4: Validation & Optimization

1. **Performance Testing**
   - Ensure zero regression in data path performance
   - Validate control path functionality
   - Measure code size reduction

2. **Code Cleanup**
   - Remove duplicated implementations
   - Optimize shared function interfaces
   - Update documentation

## Expected Benefits

### Code Reduction
- **Shared Components**: 20-30% reduction through branch elimination in MR/AV/CONN
- **Data Path**: 30-40% reduction through common interface (existing `efa_qp_post_*` functions)
- **Utility Functions**: 10-15% reduction through shared base endpoint utilities
- **Overall**: 25-35% reduction in duplicated code

### Performance Preservation
- **Control Path**: Minimal impact (infrequent operations)
- **Data Path**: Zero impact (static inline + existing common implementation)
- **Shared Components**: Improved performance through branch elimination
- **Endpoint APIs**: No performance impact (separate APIs maintained)
- **Compiler Optimization**: Better inlining opportunities

### Maintainability
- **Single Implementation**: Shared logic in one place for MR/AV/CONN
- **Bug Fixes**: Fixed once, benefits both fabrics
- **Separate APIs**: Each fabric maintains its optimal API design
- **Branch-Free Code**: Easier to understand and maintain

## Success Metrics

### Performance
1. **Data Path**: Zero regression in latency/throughput
2. **Control Path**: <5% overhead acceptable
3. **Binary Size**: 20-30% reduction overall

### Code Quality
1. **Duplication**: >35% reduction in duplicated code
2. **Maintainability**: Single source for shared functionality
3. **Branch Elimination**: Remove protocol-specific branching from shared components
4. **Test Coverage**: Maintain >90% coverage

## Conclusion

The revised architecture provides:

1. **Eliminate Protocol Branching**: Remove `if (info_type == EFA_INFO_RDM)` branches in MR/AV/CONN components
2. **Maintain Separate APIs**: Preserve existing EP/CQ separation to avoid locking conflicts
3. **Extract Lock-Agnostic Utilities**: Share common helper functions without imposing locking requirements
4. **Significant Code Reduction**: 25-35% reduction in duplicated code while preserving performance
5. **Preserve Working Architecture**: Don't disrupt well-designed EP/CQ layers

This approach achieves substantial code reuse while avoiding the **locking conflicts**, **atomicity issues**, **API impedance**, and **future deprecation complexity** that would arise from forcing API layering between fabrics.

### Future Evolution Path

The sharing-based approach (vs layering) provides a clean evolution path:

**If EFA-direct is eventually deprecated:**
- ✅ **With Sharing**: Simply remove EFA-direct files, keep shared utilities
- ❌ **With Layering**: Must refactor all RDM code that calls Direct APIs, complex dependency untangling

**Benefits of Sharing Approach:**
- **Clean Removal**: Each fabric is self-contained
- **No Dependency Chains**: RDM doesn't depend on Direct APIs
- **Preserved Utilities**: Shared helper functions remain useful
- **Simplified Migration**: Applications can migrate from Direct to RDM without provider-level dependencies