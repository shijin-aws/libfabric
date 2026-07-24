# OFI Accelerator API — Host-Side Setup Examples

This document shows how applications currently call the host-side API to setup
Work Queues, Completion Queues, and doorbell access via EFA-specific domain ops
(`efa_domain.c`), and proposes how the generic OFI Accelerator API should look.

---

## Table of Contents

1. [Current EFA-Specific Flow (Production)](#1-current-efa-specific-flow)
2. [Detailed Walkthrough: efa_domain.c ops](#2-detailed-walkthrough-efa_domainc-ops)
3. [How aws-ofi-nccl GDAKI Calls These Ops](#3-how-aws-ofi-nccl-gdaki-calls-these-ops)
4. [Proposed Generic OFI Accelerator API Equivalent](#4-proposed-generic-ofi-accelerator-api)

---

## 1. Current EFA-Specific Flow

Today, the EFA provider exposes accelerator datapath resources through a
**provider-specific ops table** obtained via `fi_open_ops()`:

```c
/* In prov/efa/src/efa_domain.c */
static struct fi_efa_ops_gda efa_ops_gda = {
    .query_addr     = efa_domain_query_addr,
    .query_qp_wqs   = efa_domain_query_qp_wqs,
    .query_cq       = efa_domain_query_cq,
    .cq_open_ext    = efa_domain_cq_open_ext,
    .get_mr_lkey    = efa_domain_get_mr_lkey,
    .cntr_open_ext  = efa_domain_cntr_open_ext,
};
```

An application obtains this table by calling:

```c
struct fi_efa_ops_gda *gda_ops = NULL;
int ret = fi_open_ops(&domain->fid, FI_EFA_GDA_OPS, 0, (void **)&gda_ops, NULL);
// Only succeeds on efa-direct provider (EFA_INFO_DIRECT)
```

---

## 2. Detailed Walkthrough: efa_domain.c Ops

### 2.1 Query Work Queue Attributes (`query_qp_wqs`)

Returns the **raw hardware queue buffer addresses and doorbell MMIO pointers**
for a given endpoint's send and receive queues.

```c
/* efa_domain.c implementation */
static int efa_domain_query_qp_wqs(struct fid_ep *ep_fid,
                                   struct fi_efa_wq_attr *sq_attr,
                                   struct fi_efa_wq_attr *rq_attr)
{
    struct efa_base_ep *base_ep = container_of(ep_fid, struct efa_base_ep,
                                              util_ep.ep_fid);
    struct efadv_wq_attr qp_sq_attr = {0};
    struct efadv_wq_attr qp_rq_attr = {0};

    /* Calls into rdma-core EFA device-specific verbs */
    int ret = efadv_query_qp_wqs(base_ep->qp->ibv_qp,
                                 &qp_sq_attr, &qp_rq_attr,
                                 sizeof(qp_sq_attr));
    if (ret) return -FI_EINVAL;

    /* Expose the hardware queue buffer pointers */
    sq_attr->buffer      = qp_sq_attr.buffer;      /* SQ ring buffer (BAR MMIO) */
    sq_attr->entry_size  = qp_sq_attr.entry_size;   /* 64 bytes per WQE */
    sq_attr->num_entries = qp_sq_attr.num_entries;   /* e.g., 512 or 1024 */
    sq_attr->doorbell    = qp_sq_attr.doorbell;      /* Doorbell MMIO register */
    sq_attr->max_batch   = qp_sq_attr.max_batch;    /* Max WQEs before flush */

    rq_attr->buffer      = qp_rq_attr.buffer;
    rq_attr->entry_size  = qp_rq_attr.entry_size;
    rq_attr->num_entries = qp_rq_attr.num_entries;
    rq_attr->doorbell    = qp_rq_attr.doorbell;
    rq_attr->max_batch   = qp_rq_attr.max_batch;

    return FI_SUCCESS;
}
```

**Key output structure:**
```c
struct fi_efa_wq_attr {
    uint8_t  *buffer;       /* Host VA of the queue ring buffer (BAR-mapped) */
    uint32_t  entry_size;   /* Size of each WQE in bytes */
    uint32_t  num_entries;  /* Number of slots in the ring */
    uint32_t *doorbell;     /* Host VA of the doorbell MMIO register */
    uint32_t  max_batch;    /* Max WQEs that can be batched before doorbell */
};
```

### 2.2 Query CQ Attributes (`query_cq`)

Returns the hardware completion queue buffer where the NIC writes CQEs:

```c
static int efa_domain_query_cq(struct fid_cq *cq_fid,
                               struct fi_efa_cq_attr *cq_attr)
{
    struct efa_cq *efa_cq = container_of(cq_fid, struct efa_cq,
                                         util_cq.cq_fid);
    struct efadv_cq_attr attr = {0};

    int ret = efadv_query_cq(ibv_cq_ex_to_cq(efa_cq->ibv_cq.ibv_cq_ex),
                             &attr, sizeof(attr));
    if (ret) return -FI_EINVAL;

    cq_attr->buffer      = attr.buffer;       /* CQ ring buffer */
    cq_attr->entry_size  = attr.entry_size;    /* CQE size in bytes */
    cq_attr->num_entries = attr.num_entries;    /* Number of CQ slots */

    return FI_SUCCESS;
}
```

### 2.3 Query Peer Address (`query_addr`)

Resolves an `fi_addr_t` into hardware-level addressing needed for WQE construction:

```c
static int efa_domain_query_addr(struct fid_ep *ep_fid, fi_addr_t addr,
                                 uint16_t *ahn, uint16_t *remote_qpn,
                                 uint32_t *remote_qkey)
{
    struct efa_base_ep *base_ep = container_of(ep_fid, struct efa_base_ep,
                                              util_ep.ep_fid);
    struct efa_conn *conn = efa_av_addr_to_conn(base_ep->av, addr);

    *ahn         = conn->ah->ahn;           /* Address Handle Number (NIC routing) */
    *remote_qpn  = conn->ep_addr->qpn;      /* Remote Queue Pair Number */
    *remote_qkey = conn->ep_addr->qkey;      /* Queue Key (access control) */

    return FI_SUCCESS;
}
```

### 2.4 Create CQ with External Memory (`cq_open_ext`)

Creates a CQ whose buffer resides in GPU memory (via DMA-BUF):

```c
static int efa_domain_cq_open_ext(struct fid_domain *domain_fid,
                                  struct fi_cq_attr *attr,
                                  struct fi_efa_cq_init_attr *efa_cq_init_attr,
                                  struct fid_cq **cq_fid, void *context)
{
    /* Validate: GPU cannot do blocking wait */
    if (attr->wait_obj != FI_WAIT_NONE)
        return -FI_ENOSYS;

    if (!(efa_cq_init_attr->flags & FI_EFA_CQ_INIT_FLAGS_EXT_MEM_DMABUF))
        return -FI_EINVAL;

    /* Create CQ backed by caller's DMA-BUF memory */
    // efa_cq_init_attr->ext_mem_dmabuf = { .buffer, .length, .offset, .fd }
    // The NIC will write CQEs directly into this GPU-resident buffer
    ...
}
```

### 2.5 Create Hardware Counter with External Memory (`cntr_open_ext`)

Creates a hardware counter whose value is written directly to GPU memory:

```c
static int efa_domain_cntr_open_ext(struct fid_domain *domain,
                                    struct fi_cntr_attr *attr,
                                    struct fid_cntr **cntr_fid,
                                    void *context,
                                    struct fi_efa_comp_cntr_init_attr *fi_efa_attr)
{
    struct efadv_comp_cntr_init_attr efa_cc_attr = {0};

    /* Convert fi_efa memory location to efadv format */
    if (fi_efa_attr->flags & FI_EFA_COMP_CNTR_INIT_WITH_COMP_EXTERNAL_MEM) {
        efa_cc_attr.flags |= EFADV_COMP_CNTR_INIT_WITH_COMP_EXTERNAL_MEM;
        /* fi_efa_attr->comp_cntr_ext_mem specifies:
         *   .type = FI_EFA_MEMORY_LOCATION_DMABUF
         *   .dmabuf.fd = <DMA-BUF fd from GPU VMM alloc>
         *   .dmabuf.offset = <offset within the DMA-BUF>
         * The NIC will DMA counter updates directly to this GPU address */
    }

    /* Create the counter via rdma-core */
    ret = efa_hw_cntr_open(domain, attr, cntr, cntr_fid, context, &efa_cc_attr);
    ...
}
```

### 2.6 Get MR Local Key (`get_mr_lkey`)

Retrieves the local key needed for SQ WQE scatter-gather entries:

```c
static uint64_t efa_domain_get_mr_lkey(struct fid_mr *mr)
{
    struct efa_mr *efa_mr = container_of(mr, struct efa_mr, mr_fid);
    return efa_mr->ibv_mr->lkey;
}
```

---

## 3. How aws-ofi-nccl GDAKI Calls These Ops

The complete host-side setup in aws-ofi-nccl's GDAKI mode:

```cpp
// =========================================================================
// STEP 1: Obtain EFA GDA ops table from the domain
// =========================================================================
struct fi_efa_ops_gda *gda_ops = nullptr;
int ret = fi_open_ops(&domain->fid, FI_EFA_GDA_OPS, 0,
                      (void **)&gda_ops, nullptr);
// Fails if domain is not efa-direct

// =========================================================================
// STEP 2: Open EP + CQ + AV using standard libfabric API
// =========================================================================
struct fi_cq_attr cq_attr = {};
cq_attr.format = FI_CQ_FORMAT_DATA;
cq_attr.size = 1024;  // configurable
ret = fi_cq_open(domain, &cq_attr, &cq, nullptr);

struct fi_av_attr av_attr = {};
av_attr.type = FI_AV_TABLE;
ret = fi_av_open(domain, &av_attr, &av, nullptr);

ret = fi_endpoint(domain, info, &ep, nullptr);
ret = fi_ep_bind(ep, &cq->fid, FI_TRANSMIT | FI_RECV);
ret = fi_ep_bind(ep, &av->fid, 0);

// =========================================================================
// STEP 2b: Create hardware counter with GPU-resident external memory
// =========================================================================
// Allocate GPU memory via CUDA VMM (gpuDirectRDMACapable)
void *gpu_cntr_mem = nullptr;
size_t actual_size = 0;
nccl_net_ofi_gpu_vmm_alloc(&gpu_cntr_mem, sizeof(uint64_t), &actual_size);

// Export DMA-BUF fd for the GPU allocation
int dmabuf_fd = -1;
size_t dmabuf_offset = 0;
nccl_net_ofi_gpu_get_dma_buf_fd(gpu_cntr_mem, actual_size,
                                &dmabuf_fd, &dmabuf_offset);

// Create counter backed by that GPU memory
struct fi_cntr_attr cntr_attr = {};
cntr_attr.events = FI_CNTR_EVENTS_COMP;

struct fi_efa_comp_cntr_init_attr efa_cntr_attr = {};
efa_cntr_attr.flags = FI_EFA_COMP_CNTR_INIT_WITH_COMP_EXTERNAL_MEM;
efa_cntr_attr.comp_cntr_ext_mem.type = FI_EFA_MEMORY_LOCATION_DMABUF;
efa_cntr_attr.comp_cntr_ext_mem.dmabuf.fd = dmabuf_fd;
efa_cntr_attr.comp_cntr_ext_mem.dmabuf.offset = dmabuf_offset;

struct fid_cntr *write_cntr = nullptr;
gda_ops->cntr_open_ext(domain, &cntr_attr, &write_cntr, nullptr, &efa_cntr_attr);

// Bind counter to EP BEFORE enabling
ret = fi_ep_bind(ep, &write_cntr->fid, FI_WRITE);

// =========================================================================
// STEP 3: Enable the endpoint
// =========================================================================
ret = fi_enable(ep);

// =========================================================================
// STEP 4: Query WQ attributes (SQ buffer, doorbell, sizes)
// =========================================================================
struct fi_efa_wq_attr sq_attr = {}, rq_attr = {};
gda_ops->query_qp_wqs(ep, &sq_attr, &rq_attr);
// sq_attr now contains:
//   .buffer      = 0x7f...  (host VA of SQ ring buffer in BAR)
//   .entry_size  = 64       (bytes per WQE)
//   .num_entries = 512      (ring depth)
//   .doorbell    = 0x7f...  (host VA of doorbell MMIO)
//   .max_batch   = 16       (max WQEs before must ring DB)

// =========================================================================
// STEP 5: Map SQ buffer BAR region for GPU access
// =========================================================================
size_t sq_buf_size = sq_attr.num_entries * sq_attr.entry_size;

// Register the BAR memory as IOMEMORY for GPU access
cuMemHostRegister(sq_attr.buffer, sq_buf_size,
                  CU_MEMHOSTREGISTER_IOMEMORY | CU_MEMHOSTREGISTER_DEVICEMAP);

// Get the GPU-visible device pointer
void *sq_buffer_dev = nullptr;
cuMemHostGetDevicePointer(&sq_buffer_dev, sq_attr.buffer, 0);

// =========================================================================
// STEP 6: Map doorbell MMIO register for GPU access
// =========================================================================
size_t page_size = sysconf(_SC_PAGESIZE);  // rdma-core maps at page granularity

cuMemHostRegister(sq_attr.doorbell, page_size,
                  CU_MEMHOSTREGISTER_IOMEMORY | CU_MEMHOSTREGISTER_DEVICEMAP);

void *sq_doorbell_dev = nullptr;
cuMemHostGetDevicePointer(&sq_doorbell_dev, sq_attr.doorbell, 0);

// =========================================================================
// STEP 7: Query CQ attributes
// =========================================================================
struct fi_efa_cq_attr efa_cq_attr = {};
gda_ops->query_cq(cq, &efa_cq_attr);
// efa_cq_attr now contains:
//   .buffer      = 0x7f...  (host VA of CQ ring buffer)
//   .entry_size  = 8 or 16  (bytes per CQE)
//   .num_entries = 1024     (ring depth)

// =========================================================================
// STEP 8: Build GPU-resident QP descriptor (for efa-dp-direct)
// =========================================================================
// Allocate the descriptor struct in GPU memory
struct efa_cuda_qp *gpu_qp;
cudaMalloc(&gpu_qp, sizeof(struct efa_cuda_qp));

// Build on host, then copy to GPU
struct efa_cuda_qp host_qp = {};
host_qp.sq.wq.buf             = (uint8_t *)sq_buffer_dev;
host_qp.sq.wq.db              = (uint32_t *)sq_doorbell_dev;
host_qp.sq.wq.max_wqes        = sq_attr.num_entries;
host_qp.sq.wq.queue_mask      = sq_attr.num_entries - 1;
host_qp.sq.wq.queue_size_shift = __builtin_ctz(sq_attr.num_entries);
host_qp.sq.wq.max_batch       = sq_attr.max_batch;
host_qp.sq.wq.phase           = 0;  // SQ initial phase
host_qp.sq.max_inline_data    = 32;
host_qp.sq.max_rdma_sges      = 2;
host_qp.rq.wq.buf             = rq_attr.buffer;   // RQ buffer
host_qp.rq.wq.db              = rq_attr.doorbell;  // RQ doorbell
host_qp.rq.wq.max_wqes        = rq_attr.num_entries;
host_qp.rq.wq.queue_mask      = rq_attr.num_entries - 1;
host_qp.rq.wq.queue_size_shift = __builtin_ctz(rq_attr.num_entries);
host_qp.rq.wq.max_batch       = rq_attr.num_entries;
host_qp.rq.wq.phase           = 1;  // RQ initial phase

cudaMemcpy(gpu_qp, &host_qp, sizeof(host_qp), cudaMemcpyHostToDevice);

// =========================================================================
// STEP 9: Build GPU-resident CQ descriptor
// =========================================================================
struct efa_cuda_cq *gpu_cq;
cudaMalloc(&gpu_cq, sizeof(struct efa_cuda_cq));

struct efa_cuda_cq host_cq = {};
host_cq.buf              = efa_cq_attr.buffer;
host_cq.entry_size       = efa_cq_attr.entry_size;
host_cq.num_entries      = efa_cq_attr.num_entries;
host_cq.queue_mask       = efa_cq_attr.num_entries - 1;
host_cq.queue_size_shift = __builtin_ctz(efa_cq_attr.num_entries);
host_cq.phase            = 1;  // CQ initial phase

cudaMemcpy(gpu_cq, &host_cq, sizeof(host_cq), cudaMemcpyHostToDevice);

// =========================================================================
// STEP 10: Resolve peer addresses for GPU-side WQE construction
// =========================================================================
fi_addr_t peer_fi_addr;
fi_av_insert(av, peer_raw_addr, 1, &peer_fi_addr, 0, NULL);

uint16_t ahn, remote_qpn;
uint32_t remote_qkey;
gda_ops->query_addr(ep, peer_fi_addr, &ahn, &remote_qpn, &remote_qkey);
// ahn        = NIC-level address handle (routing)
// remote_qpn = destination queue pair number
// remote_qkey = queue key for access control

// Copy to GPU-resident target table for kernel use
// ... (see gdaki_target_addressing::populate)
```

---

## 4. Proposed Generic OFI Accelerator API

The following shows how the same setup should look with a **provider-portable**
OFI Accelerator API, eliminating the EFA-specific `fi_open_ops` / `fi_efa_ops_gda`
pattern.

### 4.1 Design Principles

1. **Structured export, not opaque blobs** — the API returns typed structs
   with queue buffer pointers, sizes, doorbells, so any device library can consume them.
2. **Memory allocation via callbacks or DMA-BUF** — supports both BAR MMIO mapping
   (for SQ/doorbell) and DMA-BUF (for CQ/counters in GPU HBM).
3. **Provider does the heavy lifting** — memory mapping, address resolution, etc.
   are provider responsibilities, not application responsibilities.
4. **Counter support is first-class** — not an afterthought.

### 4.2 Proposed Structures

```c
/* ===== Accelerator memory specification ===== */

enum fi_acc_mem_type {
    FI_ACC_MEM_USER,     /* App handles memory via alloc/import callbacks (primary) */
    FI_ACC_MEM_PROVIDER, /* Provider handles memory internally (e.g., HMEM) */
};

struct fi_acc_info {
    enum fi_hmem_iface   iface;       /* FI_HMEM_CUDA, FI_HMEM_ZE, etc. */
    uint64_t             device;      /* GPU device ordinal */
    enum fi_acc_mem_type mem_type;
    union {
        struct {
            int (*alloc)(uint64_t device, uint64_t size,
                         uint64_t alignment, uint64_t flags,
                         void **addr, int *fd, uint64_t *offset);
            int (*import)(uint64_t device, int fd,
                          uint64_t offset, uint64_t size,
                          uint64_t flags, void **addr);
        } callbacks;
        struct {
            int      fd;        /* DMA-BUF file descriptor */
            uint64_t offset;    /* Offset within DMA-BUF */
            uint64_t size;      /* Size of the DMA-BUF region */
        } dmabuf;
    } mem;
};

/* ===== Work Queue export attributes ===== */

struct fi_acc_wq_attr {
    void     *buffer;        /* Accelerator-visible pointer to ring buffer */
    void     *doorbell;      /* Accelerator-visible pointer to doorbell register */
    uint32_t  entry_size;    /* Bytes per WQE/RQE */
    uint32_t  num_entries;   /* Ring depth (power of 2) */
    uint32_t  max_batch;     /* Max entries before mandatory doorbell */
    uint32_t  initial_phase; /* Initial phase bit value */
};

/* ===== CQ export attributes ===== */

struct fi_acc_cq_attr {
    void     *buffer;        /* Accelerator-visible pointer to CQ buffer */
    uint32_t  entry_size;    /* Bytes per CQE */
    uint32_t  num_entries;   /* Ring depth (power of 2) */
    uint32_t  initial_phase; /* Initial expected phase bit */
};

/* ===== Counter export attributes ===== */

struct fi_acc_cntr_attr {
    volatile uint64_t *value;  /* Accelerator-visible pointer to counter value */
    /* NIC updates this directly; accelerator reads without host round-trip */
};

/* ===== Peer address export (for WQE construction) ===== */

struct fi_acc_peer_addr {
    uint16_t address_handle;  /* NIC routing handle */
    uint16_t remote_qpn;      /* Remote queue pair number */
    uint32_t remote_qkey;     /* Queue access key */
};

/* ===== Full endpoint export ===== */

struct fi_acc_ep_export {
    struct fi_acc_wq_attr sq;     /* Send queue */
    struct fi_acc_wq_attr rq;     /* Receive queue */
    struct fi_acc_cq_attr cq;     /* Completion queue */
    uint32_t max_inline_data;     /* Max bytes for inline sends */
    uint32_t max_rdma_sges;       /* Max scatter-gather entries for RDMA */
    uint32_t max_send_sges;       /* Max SGEs for send */
};
```

### 4.3 Proposed API Functions

```c
/* ===== Resource creation with accelerator awareness ===== */

/* Open CQ with accelerator-accessible memory */
int fi_cq_open_acc(struct fid_domain *domain,
                   struct fi_cq_attr *attr,
                   struct fi_acc_info *acc_info,
                   struct fid_cq **cq, void *context);

/* Open counter with accelerator-accessible external memory */
int fi_cntr_open_acc(struct fid_domain *domain,
                     struct fi_cntr_attr *attr,
                     struct fi_acc_info *acc_info,
                     uint64_t bind_flags,           /* FI_WRITE, FI_REMOTE_WRITE */
                     struct fid_cntr **cntr, void *context);

/* Open endpoint with accelerator capability */
int fi_endpoint_acc(struct fid_domain *domain,
                    struct fi_info *info,
                    struct fi_acc_info *acc_info,
                    struct fid_ep **ep, void *context);

/* ===== Resource export to accelerator ===== */

/* Export the full endpoint (SQ + RQ + CQ) for accelerator access */
int fi_ep_export_acc(struct fid_ep *ep, uint64_t flags,
                     struct fi_acc_ep_export *export_attrs);

/* Export counter value pointer for accelerator polling */
int fi_cntr_export_acc(struct fid_cntr *cntr, uint64_t flags,
                       struct fi_acc_cntr_attr *export_attrs);

/* Resolve peer address for accelerator WQE construction */
int fi_av_resolve_acc(struct fid_av *av, fi_addr_t addr,
                      struct fi_acc_peer_addr *peer_addr);

/* Get MR local key for accelerator SGE construction */
int fi_mr_export_acc(struct fid_mr *mr, uint64_t *lkey);
```

### 4.4 Complete Example: Proposed Generic API

```c
/* =========================================================================
 * STEP 1: Discovery — request accelerator capability
 * ========================================================================= */
struct fi_info *hints = fi_allocinfo();
hints->caps = FI_MSG | FI_RMA | FI_HMEM | FI_ACC;
hints->ep_attr->type = FI_EP_RDM;

struct fi_info *info = NULL;
fi_getinfo(FI_VERSION(2, 0), NULL, NULL, 0, hints, &info);
fi_freeinfo(hints);

/* =========================================================================
 * STEP 2: Open fabric and domain (standard)
 * ========================================================================= */
struct fid_fabric *fabric;
struct fid_domain *domain;
fi_fabric(info->fabric_attr, &fabric, NULL);
fi_domain(fabric, info, &domain, NULL);

/* =========================================================================
 * STEP 3: Setup accelerator info (describes the GPU)
 * ========================================================================= */
struct fi_acc_info acc_info = {};
acc_info.iface = FI_HMEM_CUDA;
acc_info.device = 0;  /* GPU 0 */
acc_info.mem_type = FI_ACC_MEM_PROVIDER;  /* Let provider handle mapping */

/* =========================================================================
 * STEP 4: Open CQ with accelerator awareness
 *
 * The provider creates the CQ and ensures its buffer is accessible
 * from the accelerator (either via DMA-BUF into GPU HBM, or by
 * preparing the host buffer for MMIO mapping).
 * ========================================================================= */
struct fi_cq_attr cq_attr = {};
cq_attr.format = FI_CQ_FORMAT_DATA;
cq_attr.size = 1024;
cq_attr.wait_obj = FI_WAIT_NONE;  /* GPU cannot block */

struct fid_cq *cq;
fi_cq_open_acc(domain, &cq_attr, &acc_info, &cq, NULL);

/* =========================================================================
 * STEP 5: Open hardware counter with GPU-resident value
 *
 * The NIC will DMA counter updates directly into GPU memory.
 * Used for SQ backpressure (FI_WRITE counter) and arrival
 * notification (FI_REMOTE_WRITE counter).
 * ========================================================================= */
struct fi_cntr_attr cntr_attr = {};
cntr_attr.events = FI_CNTR_EVENTS_COMP;

struct fid_cntr *write_cntr;
fi_cntr_open_acc(domain, &cntr_attr, &acc_info, FI_WRITE, &write_cntr, NULL);

struct fid_cntr *remote_write_cntr;
fi_cntr_open_acc(domain, &cntr_attr, &acc_info, FI_REMOTE_WRITE,
                 &remote_write_cntr, NULL);

/* =========================================================================
 * STEP 6: Open AV (standard)
 * ========================================================================= */
struct fi_av_attr av_attr = {};
av_attr.type = FI_AV_TABLE;
struct fid_av *av;
fi_av_open(domain, &av_attr, &av, NULL);

/* =========================================================================
 * STEP 7: Open endpoint with accelerator support, bind resources
 *
 * The provider knows this EP's queues need accelerator access and
 * allocates them accordingly (e.g., in BAR-mappable memory).
 * ========================================================================= */
struct fid_ep *ep;
fi_endpoint_acc(domain, info, &acc_info, &ep, NULL);

fi_ep_bind(ep, &cq->fid, FI_TRANSMIT | FI_RECV);
fi_ep_bind(ep, &av->fid, 0);
fi_ep_bind(ep, &write_cntr->fid, FI_WRITE);
fi_ep_bind(ep, &remote_write_cntr->fid, FI_REMOTE_WRITE);
fi_enable(ep);

/* =========================================================================
 * STEP 8: Export endpoint resources for accelerator
 *
 * This is where the magic happens. The provider returns
 * accelerator-visible pointers for all queue resources.
 * No manual cuMemHostRegister needed — provider did it.
 * ========================================================================= */
struct fi_acc_ep_export ep_export = {};
fi_ep_export_acc(ep, 0, &ep_export);

/* ep_export now contains:
 *   .sq.buffer        = <GPU-visible ptr to SQ ring>
 *   .sq.doorbell      = <GPU-visible ptr to SQ doorbell>
 *   .sq.entry_size    = 64
 *   .sq.num_entries   = 512
 *   .sq.max_batch     = 16
 *   .sq.initial_phase = 0
 *   .rq.buffer        = <GPU-visible ptr to RQ ring>
 *   .rq.doorbell      = <GPU-visible ptr to RQ doorbell>
 *   ...
 *   .cq.buffer        = <GPU-visible ptr to CQ ring>
 *   .cq.entry_size    = 8
 *   .cq.num_entries   = 1024
 *   .cq.initial_phase = 1
 *   .max_inline_data  = 32
 *   .max_rdma_sges    = 2
 */

/* =========================================================================
 * STEP 9: Export counter for GPU polling
 * ========================================================================= */
struct fi_acc_cntr_attr write_cntr_export = {};
fi_cntr_export_acc(write_cntr, 0, &write_cntr_export);
/* write_cntr_export.value = <GPU-visible ptr to counter> */

struct fi_acc_cntr_attr remote_cntr_export = {};
fi_cntr_export_acc(remote_write_cntr, 0, &remote_cntr_export);

/* =========================================================================
 * STEP 10: Resolve peer addresses
 * ========================================================================= */
fi_addr_t peer;
fi_av_insert(av, peer_raw_addr, 1, &peer, 0, NULL);

struct fi_acc_peer_addr peer_hw_addr = {};
fi_av_resolve_acc(av, peer, &peer_hw_addr);
/* peer_hw_addr = { .address_handle=5, .remote_qpn=17, .remote_qkey=0x11111111 } */

/* =========================================================================
 * STEP 11: Get MR lkey for GPU-side SGE construction
 * ========================================================================= */
uint64_t lkey;
fi_mr_export_acc(mr, &lkey);

/* =========================================================================
 * STEP 12: Pass all exported info to GPU kernel
 *
 * Build a device-side handle struct and copy to GPU memory.
 * The GPU kernel uses these directly with the device-side API
 * (fi_acc_send, fi_acc_write, fi_acc_cq_read, etc.)
 * ========================================================================= */
struct my_gpu_handle {
    struct fi_acc_ep_export   ep;
    struct fi_acc_cntr_attr   write_cntr;
    struct fi_acc_cntr_attr   remote_cntr;
    struct fi_acc_peer_addr  *peers;     /* [nranks] */
    uint64_t                  lkey;
    uint32_t                  sq_submitted;  /* for backpressure */
};
// ... cudaMalloc + cudaMemcpy to GPU ...
```

### 4.5 Comparison: Before vs. After

| Step | Current (EFA-specific) | Proposed (Generic OFI Acc API) |
|------|----------------------|-------------------------------|
| Get ops table | `fi_open_ops(domain, "efa gda ops")` | Not needed — built into API |
| Open CQ | `fi_cq_open()` + later `query_cq()` | `fi_cq_open_acc(domain, attr, acc_info, ...)` |
| Open counter | `gda_ops->cntr_open_ext(domain, ..., efa_attr)` | `fi_cntr_open_acc(domain, attr, acc_info, ...)` |
| Open EP | `fi_endpoint()` | `fi_endpoint_acc(domain, info, acc_info, ...)` |
| Get SQ buffer/DB | `gda_ops->query_qp_wqs(ep, &sq, &rq)` | `fi_ep_export_acc(ep, 0, &export)` |
| Map BAR for GPU | `cuMemHostRegister(IOMEMORY\|DEVICEMAP)` + `cuMemHostGetDevicePointer()` | Provider does this internally |
| Get CQ buffer | `gda_ops->query_cq(cq, &attr)` | Included in `fi_ep_export_acc()` |
| Resolve peer | `fi_av_insert()` + `gda_ops->query_addr(ep, fi_addr, ...)` | `fi_av_insert()` + `fi_av_resolve_acc(av, addr, ...)` |
| Get MR lkey | `gda_ops->get_mr_lkey(mr)` | `fi_mr_export_acc(mr, &lkey)` |
| Get counter ptr | Manual: `cuMemCreate` + DMA-BUF fd + pass to `cntr_open_ext` | `fi_cntr_export_acc(cntr, 0, &attr)` returns GPU ptr |

### 4.6 Key Advantage: Provider Handles Memory Mapping

The biggest complexity reduction is that the **provider** (not the application)
is responsible for making queue buffers GPU-accessible:

**Current (application does everything):**
```c
// App must know: EFA SQ is BAR-mapped, needs IOMEMORY registration
gda_ops->query_qp_wqs(ep, &sq_attr, &rq_attr);
cuMemHostRegister(sq_attr.buffer, size, CU_MEMHOSTREGISTER_IOMEMORY | CU_MEMHOSTREGISTER_DEVICEMAP);
cuMemHostGetDevicePointer(&dev_ptr, sq_attr.buffer, 0);
```

**Proposed (provider does it):**
```c
// Provider already returned GPU-visible pointers
fi_ep_export_acc(ep, 0, &export);
// export.sq.buffer is already the GPU device pointer
```

This means:
- CXI provider can use its own mechanism to expose queues
- Verbs provider could use a different BAR mapping approach
- Application code is **identical** regardless of provider

---

## Summary

The current production flow requires **6 EFA-specific calls** plus **manual CUDA
memory mapping** that only works with EFA hardware. The proposed generic API:

1. Eliminates provider-specific ops tables
2. Makes the provider responsible for memory mapping (portability)
3. Returns structured, typed exports (not opaque blobs)
4. Treats counters as first-class citizens
5. Includes peer address resolution for WQE construction
6. Supports the same underlying hardware capabilities without abstraction overhead
