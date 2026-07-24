# OFI Accelerator API — Memory Callback Design

## Overview

The `fi_acc_info` structure carries two memory callbacks (`alloc` and `import`)
that the **provider** calls internally during object creation and export. The
consumer implements them with platform-specific GPU APIs (CUDA, HIP, Level Zero).

The consumer never calls these directly after initial setup — they are invoked
by the provider at the appropriate time during `fi_cq_open(FI_ACC)`,
`fi_cntr_open(FI_ACC)`, `fi_acc_ep_export()`, etc.

---

## The Two Callbacks

### `import` — Map provider-owned host memory into GPU address space

```c
int (*import)(uint64_t device, void *host_addr,
              uint64_t size, uint64_t flags,
              void **dev_addr);
```

**Purpose:** The provider already owns a host virtual address (from the NIC
driver). The GPU can't see it yet. `import` registers that host memory with the
GPU runtime and returns a device pointer to the same physical memory.

**Parameters:**
| Param | Direction | Description |
|-------|-----------|-------------|
| `device` | in | GPU device ordinal |
| `host_addr` | in | Provider-owned host VA (BAR MMIO or host RAM) |
| `size` | in | Size of the region in bytes |
| `flags` | in | `FI_ACC_IMPORT_IOMEMORY` and/or `FI_ACC_IMPORT_DEVICEMAP` |
| `dev_addr` | out | Resulting device pointer (GPU can access this) |

**Flags:**
- `FI_ACC_IMPORT_IOMEMORY` — The host_addr points to PCIe BAR MMIO (device memory
  on the NIC). Required for SQ buffers and doorbells.
- `FI_ACC_IMPORT_DEVICEMAP` — Make the memory visible in GPU device address space.
  Always set.

**When the provider calls it:**

| During | Resource being mapped | Flags |
|--------|----------------------|-------|
| `fi_acc_ep_export()` | SQ ring buffer (BAR MMIO) | `IOMEMORY \| DEVICEMAP` |
| `fi_acc_ep_export()` | SQ doorbell (BAR MMIO) | `IOMEMORY \| DEVICEMAP` |
| `fi_acc_ep_export()` | RQ ring buffer (host RAM) | `DEVICEMAP` |
| `fi_acc_ep_export()` | RQ doorbell (BAR MMIO) | `IOMEMORY \| DEVICEMAP` |
| `fi_acc_cq_export()` | CQ ring buffer (host RAM) | `DEVICEMAP` |

**CUDA implementation:**
```c
int my_import(uint64_t device, void *host_addr,
              uint64_t size, uint64_t flags, void **dev_addr)
{
    unsigned int cuda_flags = CU_MEMHOSTREGISTER_DEVICEMAP;
    if (flags & FI_ACC_IMPORT_IOMEMORY)
        cuda_flags |= CU_MEMHOSTREGISTER_IOMEMORY;

    // Register host memory so GPU can see it
    cuMemHostRegister(host_addr, size, cuda_flags);

    // Get the GPU-side pointer for the same physical memory
    CUdeviceptr ptr;
    cuMemHostGetDevicePointer(&ptr, host_addr, 0);

    *dev_addr = (void *)ptr;
    return 0;
}
```

---

### `alloc` — Allocate fresh GPU memory accessible by the NIC

```c
int (*alloc)(uint64_t device, uint64_t size,
             uint64_t alignment, uint64_t flags,
             void **addr, int *fd, uint64_t *offset);
```

**Purpose:** The provider needs memory in GPU HBM that the NIC can write to via
DMA. The consumer allocates GPU memory and exports it as a DMA-BUF file
descriptor, which the provider passes to the NIC driver.

**Parameters:**
| Param | Direction | Description |
|-------|-----------|-------------|
| `device` | in | GPU device ordinal |
| `size` | in | Requested size in bytes |
| `alignment` | in | Required alignment (0 = default) |
| `flags` | in | `FI_ACC_ALLOC_DMABUF` |
| `addr` | out | GPU device pointer to the allocated memory |
| `fd` | out | DMA-BUF file descriptor (provider gives this to NIC) |
| `offset` | out | Offset within the DMA-BUF |

**When the provider calls it:**

| During | What's being allocated | What provider does with fd |
|--------|----------------------|---------------------------|
| `fi_cntr_open(FI_ACC)` | 8 bytes for HW counter value | Passes to `efadv_create_comp_cntr()` → NIC DMAs counter writes here |
| `fi_cq_open(FI_ACC)` (optional) | CQ buffer in GPU HBM | Passes to `efadv_create_cq(EXT_MEM_DMABUF)` → NIC DMAs completions here |
| Export functions | Small structs (fi_acc_dev_ep, etc.) | fd closed immediately (H2D copy only) |

**CUDA implementation:**
```c
int my_alloc(uint64_t device, uint64_t size, uint64_t alignment,
             uint64_t flags, void **addr, int *fd, uint64_t *offset)
{
    // Allocate GPU memory
    void *buf;
    cudaMalloc(&buf, size);

    // Export as DMA-BUF so the NIC can DMA to it
    cuMemGetDmaBufFd(buf, size, fd, offset);

    *addr = buf;
    return 0;
}
```

---

### `free` — Release GPU memory from `alloc`

```c
void (*free)(uint64_t device, void *addr);
```

Called by the provider during `fi_close()` cleanup for any memory it allocated
via `alloc`. The `addr` parameter matches what was returned in `*addr` from
`alloc`.

---

## Data Flow Diagrams

### Counter Creation (alloc path)

```
fi_cntr_open(domain, attr={flags=FI_ACC, acc_info=&ai}, &cntr):

  Provider internally:
    ┌─────────────────────────────────────────────────────────┐
    │ 1. ai->alloc(device, 8, 8, FI_ACC_ALLOC_DMABUF,       │
    │              &gpu_ptr, &fd, &offset)                    │
    │                                                         │
    │    Consumer does:                                        │
    │      cudaMalloc → gpu_ptr (GPU HBM)                     │
    │      cuMemGetDmaBufFd → fd, offset                      │
    │      return gpu_ptr, fd, offset                         │
    │                                                         │
    │ 2. efadv_create_comp_cntr(fd, offset)                   │
    │    → NIC HW configured to DMA counter writes to gpu_ptr │
    │                                                         │
    │ 3. close(fd)                                            │
    │    → fd no longer needed (NIC has its own reference)    │
    │                                                         │
    │ 4. Store gpu_ptr in acc_state->cntr_value_dev           │
    └─────────────────────────────────────────────────────────┘

  Later, fi_acc_cntr_export(cntr, &acc_cntr):
    → Returns opaque handle containing gpu_ptr
    → Device kernel: fi_acc_cntr_read(acc_cntr)
      = single volatile load from GPU HBM (one instruction)

  On fi_close(cntr):
    → Provider calls ai->free(gpu_ptr)
    → Consumer does cudaFree(gpu_ptr)
```

### EP Export (import path)

```
fi_acc_ep_export(ep, 0, &acc_ep, &size):

  Provider internally:
    ┌─────────────────────────────────────────────────────────┐
    │ 1. efadv_query_qp_wqs(qp) → sq_host_va, sq_doorbell_va │
    │                                                         │
    │ 2. ai->import(device, sq_host_va, sq_size,              │
    │               IOMEMORY|DEVICEMAP, &sq_dev_ptr)          │
    │                                                         │
    │    Consumer does:                                        │
    │      cuMemHostRegister(sq_host_va, IOMEMORY|DEVICEMAP)  │
    │      cuMemHostGetDevicePointer → sq_dev_ptr             │
    │      return sq_dev_ptr                                  │
    │                                                         │
    │ 3. ai->import(device, sq_doorbell_va, page_size,        │
    │               IOMEMORY|DEVICEMAP, &db_dev_ptr)          │
    │                                                         │
    │ 4. Build fi_acc_efa_ep struct on host stack:            │
    │      .sq.buf = sq_dev_ptr                               │
    │      .sq.db  = db_dev_ptr                               │
    │      .sq.queue_mask = num_entries - 1                    │
    │      ...                                                │
    │                                                         │
    │ 5. ai->alloc(sizeof(fi_acc_efa_ep)) → gpu_blob          │
    │    H2D copy struct → gpu_blob                           │
    │                                                         │
    │ 6. *acc_ep = gpu_blob                                   │
    └─────────────────────────────────────────────────────────┘

  Device kernel:
    fi_acc_write(acc_ep, buf, len, desc, raddr, rkey, peer, scope, 0)
    → internally dereferences acc_ep as fi_acc_efa_ep*
    → writes WQE to sq_dev_ptr (BAR MMIO → NIC sees it immediately)
    → rings db_dev_ptr (doorbell, triggers NIC processing)
```

---

## Why Callbacks Instead of Provider Doing It Directly

1. **Provider doesn't link CUDA** — libfabric is built with gcc, not nvcc.
   It cannot call `cuMemHostRegister` or `cudaMalloc` directly.

2. **Runtime portability** — A HIP consumer provides `hipHostRegister` +
   `hipHostGetDevicePointer`. A Level Zero consumer provides `zeMemAllocDevice`
   + `zeMemGetIpcHandle`. Same provider code works for all.

3. **Consumer controls allocation policy** — The consumer might use CUDA VMM
   with specific granularity, a pool allocator, or a different alignment
   strategy. The provider shouldn't dictate this.

4. **DMA-BUF is the bridge** — The `alloc` callback returns a DMA-BUF fd which
   is a kernel-level standard for cross-device memory sharing. The NIC driver
   understands DMA-BUF regardless of whether it came from CUDA, HIP, or Level
   Zero.

---

## Summary Table

| Callback | Direction of data | Who owns the memory | NIC involvement | GPU involvement |
|----------|------------------|--------------------:|:---------------:|:---------------:|
| `import` | Provider → Consumer → Provider | Provider (NIC BAR or host RAM) | Already has access | Gets new device pointer |
| `alloc` | Consumer → Provider | Consumer (GPU HBM) | Gets DMA-BUF fd | Already has access |
| `free` | Provider → Consumer | Consumer | N/A | Frees GPU memory |

---

## Platform-Specific Implementations

### CUDA

```c
struct fi_acc_info acc_info = {
    .iface = FI_HMEM_CUDA,
    .device = 0,
    .mem_type = FI_ACC_MEM_USER,
    .alloc  = cuda_acc_alloc,   // cudaMalloc + cuMemGetDmaBufFd
    .import = cuda_acc_import,  // cuMemHostRegister + cuMemHostGetDevicePointer
    .free   = cuda_acc_free,    // cudaFree
};
```

### HIP (AMD)

```c
struct fi_acc_info acc_info = {
    .iface = FI_HMEM_ROCR,
    .device = 0,
    .mem_type = FI_ACC_MEM_USER,
    .alloc  = hip_acc_alloc,    // hipMalloc + hipMemGetDmaBufFd (ROCm 6.2+)
    .import = hip_acc_import,   // hipHostRegister + hipHostGetDevicePointer
    .free   = hip_acc_free,     // hipFree
};
```

### Level Zero (Intel)

```c
struct fi_acc_info acc_info = {
    .iface = FI_HMEM_ZE,
    .device = 0,
    .mem_type = FI_ACC_MEM_USER,
    .alloc  = ze_acc_alloc,     // zeMemAllocDevice + zeMemGetIpcHandle(DMA_BUF)
    .import = ze_acc_import,    // zeMemOpenIpcHandle or zexDriverImportExternalPointer
    .free   = ze_acc_free,      // zeMemFree
};
```
