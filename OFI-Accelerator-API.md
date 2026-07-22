# OFI Accelerator API

**Jianxin Xiong**
**4/21/2026**

---

## Introduction

- For accelerator-initiated communication
  - a.k.a. GPU Direct Async – Kernel Initiated
  - Bypass CPU on the data path
- History
  - Started as a draft specification under UEC Software WG in July 2024
  - Reached technical ready milestone (v0.75) in Dec 2025
  - UEC Software WG voted to formally dispose the spec and transfer the ownership to OFA in Jan 2026

---

## Theory of Operations

- **CPU:**
  - Setup the queues shared by the accelerator and the NIC
  - Setup doorbell access
- **Accelerator:**
  - Construct the WQE
  - Write to WQ
  - Ring the doorbell
  - Check the CQ
- Counters are not shown in the picture, but are simpler than CQ

> *Note: The accelerator & NIC specific details are implementation-dependent.*

---

## API Overview

- **Host side API**
  - A set of functions to setup the communication resources
    - fabric, domain, endpoint, …
  - Most are extensions to existing Libfabric API
  - A few new functions to export the resources to accelerator accessible objects
- **Accelerator side API**
  - A set of functions that can be called from a compute kernel
  - Can be similar to the existing host side communication calls
    - message, rma, atomics, etc.
  - But a set of simplified calls may be more desirable

---

## Acceleration Information

To be passed as part of the attrs for creating objects:

```c
struct fi_acc_info {
    enum fi_hmem_iface  iface;
    uint64_t            device;
    int (*alloc)(uint64_t device, uint64_t size,
                 uint64_t alignment, uint64_t flags,
                 void **addr, int *fd, uint64_t *offset);
    int (*import)(uint64_t device, int fd,
                  uint64_t offset, uint64_t size,
                  uint64_t flags, void **addr);
};
```

> *Alternatives:*
> - Alt 1: HMEM method
> - Alt 2: User allocate

---

## Create Objects

Add `acc_info` to `fi_cq_attr`:

```c
struct fi_cq_attr {
    size_t              size;
    uint64_t            flags;
    enum fi_cq_format   format;
    enum fi_wait_obj    wait_obj;
    int                 signaling_vector;
    enum fi_cq_wait_cond wait_cond;
    void                *wait_set;
    struct fi_acc_info   *acc_info;
};
```

- Call `fi_cq_open` with the new `FI_ACC` flag
- Endpoints, AVs, and counters are similarly handled

---

## Exporting Objects to Accelerator

Exporting an endpoint:

```c
int fi_ep_export_acc(
    struct fid_ep   *ep,
    uint64_t        flags,
    void            **acc_ep,
    size_t          *acc_ep_size);
```

- `acc_ep` points to a memory block that can be accessed from the accelerator
- CQs, counters, AVs, MRs are handled similarly

---

## Example

### Host-side setup (part 1)

```c
hints = fi_allocinfo();
hints->caps |= FI_ACC;
ret = fi_getinfo(version, node, service, flags, hints, &info);

ret = fi_fabric(info->fabric_attr, &fabric, context);
ret = fi_domain(fabric, info, domain, context);

my_acc_info.alloc = my_acc_alloc;
my_acc_info.import = my_acc_import;

av_attr.flags = FI_ACC;
av_attr.acc_info = &my_acc_info;
ret = fi_av_open(domain, &av_attr, &av);

cq_attr.flags = FI_ACC;
cq_attr.acc_info = &my_acc_info;
ret = fi_cq_open(domain, &cq_attr, &cq, context);
```

### Host-side setup (part 2)

```c
cntr_attr.flags = FI_ACC;
cntr_attr.acc_info = &my_acc_info;
ret = fi_cntr_open(domain, &cntr_attr, &cntr, context);

info->ep_attr->acc_info = &my_acc_info;
ret = fi_endpoint2(domain, info, &ep, FI_ACC, context);

ret = fi_ep_bind(ep, cq, flags);
ret = fi_ep_bind(ep, cntr, flags);
ret = fi_ep_bind(ep, av, flags);
ret = fi_enable(ep);

ret = fi_ep_export_acc(ep, flags, &acc_ep, &acc_ep_size);
ret = fi_cq_export_acc(cq, flags, &acc_cq, &acc_cq_size);
ret = fi_cntr_export_acc(cntr, flags, &acc_cntr, &acc_cntr_size);
```

---

## Accelerator Side API

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
fi_acc_cq_read(acc_cq, …)
fi_acc_cntr_read(acc_cntr, …)
fi_acc_cntr_readerr(acc_cntr, …)
```

---

## Scope

Specify the concurrency of the operation. All the threads in the scope are required to issue the same operation. This allows the implementation to optimize.

| Scope | CUDA | SYCL |
|-------|------|------|
| `FI_ACC_WORK_ITEM` | Thread | Work item |
| `FI_ACC_SUBGROUP` | Warp | Subgroup |
| `FI_ACC_WORK_GROUP` | Thread block | Work group |

### Implementation Strategies

| GDA | Proxy |
|-----|-------|
| A block of WQEs are reserved. Threads construct WQEs concurrently. A single commit at the end (ring the doorbell). | Threads submit reqs to the proxy concurrently. The proxy constructs WQEs and submits as a batch. |
