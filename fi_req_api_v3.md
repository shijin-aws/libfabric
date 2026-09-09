# OFI Work Request API

## 1. Overview

Libfabric's data transfer post operations (`fi_send`, `fi_write`, `fi_read`,
etc.) are monolithic: a single call constructs the hardware work queue entry
(WQE), copies it to the NIC's submission queue, and rings the doorbell. This
coupling blocks three capabilities that emerging data paths require:

- **Staged posting** — building a WQE at one time or place and submitting it
  (copy-to-NIC and doorbell ring) at another. Data paths that drive the NIC
  without host involvement need this — e.g., *Neuron NetLink*, where
  NeuronRuntime prepares all WQEs at model load time on the host and, at
  execution time, Neuron's TOP_SP DMA engine copies them to EFA's IPP SQ BAR
  and rings the doorbell — no host involvement in the data path.
- **Provider-specific WQE metadata** — injecting extra per-WQE fields beyond the
  standard parameters (addr, desc, rkey, data). Provider-specific flags cover
  single-value hints, but not features that need several additional per-WQE
  fields (e.g., per-WQE signal IDs, action parameters, or other extended
  completion metadata).
- **Explicit doorbell control** — with the existing `FI_MORE` flag a provider
  may defer a transfer to batch it with later ones, but today that deferred work
  is only flushed when a subsequent non-`FI_MORE` `fi_write` (or similar) is
  posted. There is no explicit flush call, which makes the flag awkward to
  adopt: an application can leave a deferred request dangling simply by
  forgetting to post a trailing non-`FI_MORE` operation. Applications need a
  single, well-defined flush point.

This document specifies a Work Request (WR) API that addresses these by
decomposing the post lifecycle into three discrete stages — **prepare**,
**submit**, and **flush** — allowing WQE construction, provider-specific metadata
injection, and submission to be separated in time and place, with batched
submission and automatic doorbell coalescing. The flush stage also rings the
doorbell for work deferred under `FI_MORE`, unifying the flush point.

## 2. API Specification

The WR API is proposed here as a **general** endpoint API — available on any
endpoint, host- or device-driven. It reuses the `struct fi_op_*` operation
descriptors that libfabric already defines for `struct fi_deferred_work`
(discriminated by `enum fi_op_type`, see
[`fi_trigger`(3)](https://ofiwg.github.io/libfabric/main/man/fi_trigger.3.html))
to describe the operation. It adds three endpoint calls — `fi_prepare_wr`,
`fi_submit_wr`, and `fi_flush_wr` — plus a small work-request descriptor
`struct fi_wr_attr`. (Section 3 records the review outcome that this generality
is not warranted and that the API should be scoped to XPU use, which renames
these symbols; see §3.)

The API works in three stages. **Prepare** formats the operation into a
hardware WQE, writing it into a caller-owned buffer (`wr_desc`); this is pure
construction — no submission-queue resources are consumed and the data buffers
are not touched. **Submit** places that WQE into the endpoint's submission
queue. Submit is *not* a verbatim copy: a few WQE fields depend on the
submission slot and the queue's current state and cannot be known at prepare
time, so submit mutates them into the WQE as it places it (see §2.2). **Flush**
rings the doorbell so the NIC begins processing the submitted work. Separating
the
three lets WQE construction, optional provider-specific metadata injection, and
submission happen at different times and places (including from different
agents, e.g. a device that places the prepared WQE into the queue itself,
applying the same submit-time mutation). A work request descriptor is a plain
struct — deliberately **not** a fid, and therefore not subject to `fi_close` or
any object lifecycle.

### 2.1 Work Request Descriptor

A work request is described by `struct fi_wr_attr`, which reuses the `fi_op_*`
union (the same descriptors used by `struct fi_deferred_work`). It carries only
the operation description; the caller-owned buffer that receives the formatted
WQE is passed to the calls directly (see §2.2). It is defined in
`rdma/fi_trigger.h` alongside the existing `fi_op_*` structures.

```c
struct fi_wr_attr {
    enum fi_op_type                 op_type;

    union {
        struct fi_op_msg            *msg;
        struct fi_op_tagged         *tagged;
        struct fi_op_rma            *rma;
        struct fi_op_atomic         *atomic;
        struct fi_op_fetch_atomic   *fetch_atomic;
        struct fi_op_compare_atomic *compare_atomic;
    } op;
};
```

Each `fi_op_*` descriptor carries the target endpoint, the operation's message
descriptor, and its flags, e.g.:

```c
struct fi_op_rma {
    struct fid_ep       *ep;      /* target endpoint */
    struct fi_msg_rma   msg;      /* iov, desc, addr, rma_iov, context, data */
    uint64_t            flags;
};
```

The endpoint in the operation descriptor must match the endpoint the calls are
issued on.

The buffer that receives the hardware-formatted WQE is separate from the
descriptor: the caller passes `wr_desc` (buffer) and `wr_len` (capacity in /
actual size out) to `fi_prepare_wr`, so one `fi_wr_attr` can be reused to
format into different buffers. The required buffer size is an endpoint property
(the WQE format is specific to the endpoint's queue pair) and is queried with
`fi_getopt` using new `FI_OPT_ENDPOINT` option names:

```c
enum {
    ...
    FI_OPT_TX_REQ_SIZE,     /* size_t — TX work request buffer size in bytes */
    FI_OPT_RX_REQ_SIZE,     /* size_t — RX work request buffer size in bytes */
};
```

`fi_getopt(FI_OPT_TX_REQ_SIZE)` returns the buffer size to allocate for a TX
work request (`FI_OPT_RX_REQ_SIZE` for RX). WR API support itself is detected
via the `FI_WR` capability (see §6), not this option.

### 2.2 The Three Calls

The staged lifecycle is expressed as three endpoint calls, declared in
`rdma/fi_endpoint.h`:

```c
/* Build the WQE for wr into wr_desc (wr_len: [in] capacity, [out] WQE size). */
int fi_prepare_wr(struct fid_ep *ep, struct fi_wr_attr *wr,
                  void *wr_desc, size_t *wr_len);

/* Submit the prepared WQE to the submission queue (flags reserved, pass 0). */
int fi_submit_wr(struct fid_ep *ep, void *wr_desc, uint64_t flags);

/* Ring the doorbell for all submitted work. */
int fi_flush_wr(struct fid_ep *ep);
```

#### fi_prepare_wr

```c
struct fi_op_rma rma = { .ep = ep, .msg = ..., .flags = 0 };
struct fi_wr_attr wr = { .op_type = FI_OP_WRITE, .op.rma = &rma };

size_t wr_len = tx_req_size;      /* buffer capacity on input */
int ret = fi_prepare_wr(ep, &wr, wr_desc, &wr_len);
/* on success, wr_len holds the actual WQE size */
```

The provider validates the inputs and writes a hardware-formatted WQE into
`wr_desc`, using the endpoint the call was issued on (which must match
`wr->op.rma->ep`), and updates `*wr_len` to the actual WQE size. The buffer
content is opaque to the application; it remains valid until the application
reuses or frees it. Prepare neither submits the request nor consumes SQ
resources, and the referenced data buffers are not accessed at prepare time.

Between prepare and submit, the application may need to attach
provider-specific per-WQE input beyond the standard parameters (addr, desc,
rkey, data) — the "provider-specific WQE metadata" motivation of §1. For
example, under Neuron NetLink the EFA provider needs to insert per-WQE signal
IDs into the WQE metadata so the device can correlate each transfer with a
signal. Single-value hints are carried in the operation descriptor's `flags`
field passed to prepare.

Multi-field provider-specific WQE metadata is **out of scope for this
document.** Earlier drafts explored two mechanisms — provider-specific setter
functions that patch the prepared WQE, and reinterpreting the message
descriptor's `context` field under a new common flag — but neither is adopted
here. A dedicated solution that is not based on the `context` field will be
specified separately; the WR calls in this document intentionally do not depend
on any particular metadata mechanism.

#### fi_submit_wr

```c
int ret = fi_submit_wr(ep, wr_desc, flags);
```

The call places the prepared WQE (`wr_desc`) into the endpoint's submission
queue. It is **not** a verbatim copy: the provider may need to mutate a few
fields of the prepared WQE before it can go on the hardware queue, because their
correct values depend on the work queue's current state and are not known at
prepare time. For example, EFA's TX WQE format carries a `phase` bit and a
request id that depend on the queue's producer counter (`pc`) and completion
tracking; the provider fills these in as it submits. Message ordering
(`msg_order`) follows submit order — the order in which WQEs are submitted, not
the order in which they were prepared. `flags` is currently reserved for future
use (pass 0). `fi_submit_wr` does not
ring the doorbell — the application does that with `fi_flush_wr` — except when
the hardware batch limit is reached, in which case the provider MUST auto-flush
(ring the doorbell) before placing this WQE. If the SQ is full, the provider
MUST flush any pending WQEs before returning `-FI_EAGAIN` so previously
submitted WQEs make progress; on `-FI_EAGAIN` the `wr_desc` buffer remains valid
for retry.

#### fi_flush_wr

```c
int ret = fi_flush_wr(ep);
```

The call rings the doorbell for all submitted-but-not-yet-flushed WQEs on this
endpoint, after which the NIC begins processing them. If nothing is pending
(already auto-flushed), it is a no-op. It also rings the doorbell for operations
posted earlier on the same endpoint that the provider deferred under the
existing `FI_MORE` flag, so a single `fi_flush_wr` flushes both WR-API requests
and `FI_MORE`-batched transfers.

### 2.3 Usage Examples

#### Basic RDMA Write

```c
/* Query request buffer size (WR API support detected via FI_WR, see 6) */
size_t tx_req_size, len = sizeof(tx_req_size);
fi_getopt(&ep->fid, FI_OPT_ENDPOINT, FI_OPT_TX_REQ_SIZE, &tx_req_size, &len);

void *wr_desc = malloc(tx_req_size);

/* Describe the operation using the existing fi_op_rma / fi_msg_rma structs */
struct fi_rma_iov rma_iov = { .addr = remote_addr, .len = data_len,
                              .key = remote_key };
struct iovec iov = { .iov_base = buf, .iov_len = data_len };
struct fi_op_rma rma = {
    .ep    = ep,
    .msg   = {
        .msg_iov   = &iov,     .iov_count   = 1,
        .desc      = &desc,
        .addr      = dest_addr,
        .rma_iov   = &rma_iov, .rma_iov_count = 1,
        .context   = context,
    },
    .flags = 0,
};

struct fi_wr_attr wr = { .op_type = FI_OP_WRITE, .op.rma = &rma };

/* Prepare -> submit -> flush */
size_t wr_len = tx_req_size;
fi_prepare_wr(ep, &wr, wr_desc, &wr_len);
fi_submit_wr(ep, wr_desc, flags);
fi_flush_wr(ep);
```

#### RDMA Write with Provider-Specific WQE Metadata

Provider-specific per-WQE metadata is out of scope for this document (§2.2). If
a future mechanism defines how such metadata is attached to a prepared WQE, it
would slot into the lifecycle between prepare and submit:

```c
size_t wr_len = tx_req_size;
fi_prepare_wr(ep, &wr, wr_desc, &wr_len);

/* A future, separately specified mechanism would attach provider-specific
 * per-WQE metadata (e.g. Neuron NetLink signal IDs) here. Not defined by
 * this document. */

fi_submit_wr(ep, wr_desc, flags);
fi_flush_wr(ep);
```

#### Batch Submission

```c
for (int i = 0; i < N; i++) {
    struct fi_wr_attr wr = { .op_type = FI_OP_WRITE, .op.rma = &rmas[i] };
    size_t wr_len = tx_req_size;
    fi_prepare_wr(ep, &wr, wr_descs[i], &wr_len);
}

for (int i = 0; i < N; i++)
    fi_submit_wr(ep, wr_descs[i], flags);   /* auto-flush at batch limit */

fi_flush_wr(ep);                       /* ring doorbell once */
```

### 2.4 Batching Semantics

The provider manages batching internally, tracking the number of pending
(submitted but not yet flushed) requests per endpoint. `fi_submit_wr` never rings
the doorbell on its own; the application accumulates requests and rings the
doorbell once with `fi_flush_wr`. The one exception is the hardware batch limit:
when the pending count reaches `max_batch`, the provider MUST auto-flush (ring
the doorbell) before placing the next request. This auto-flush is a provider
obligation, not optional, and it is transparent to the application — it never
surfaces as an error.

The `max_batch` limit is intentionally NOT exposed as a general Libfabric API
for now — the application may call `fi_submit_wr` any number of times followed by
a single `fi_flush_wr`, and the provider guarantees correct behavior (including
auto-flush) regardless of how many requests are submitted. Where an application
does want the value, a provider may expose it through a provider-specific
endpoint option — for EFA, via `fi_getopt` on the endpoint (mirroring the
`max_batch` reported by `efadv_query_qp_wqs` in `struct efadv_wq_attr`).

### 2.5 Error Handling

The three calls return 0 on success and a negative libfabric error code
(`-FI_*`) on failure:

- **`fi_prepare_wr`** — 0 on success (and `*wr_len` is set to the actual WQE
  size). Errors: `-FI_EINVAL` for invalid inputs (bad `op_type`, mismatched
  endpoint, etc.), `-FI_ETOOSMALL` if the supplied `wr_desc`/`wr_len` is smaller
  than the WQE the provider needs to write, and `-FI_ENOSYS`/`-FI_EOPNOTSUPP` if
  the operation is not supported.
- **`fi_submit_wr`** — 0 on success. `-FI_EAGAIN` if the SQ is full: this is a
  transient, retryable condition (the provider has already flushed pending WQEs
  before returning), and `wr_desc` remains valid, so the application should
  progress the endpoint to reap completions and retry the same request. Any
  other negative code is fatal (e.g., `-FI_EINVAL` if the endpoint is not
  enabled).
- **`fi_flush_wr`** — 0 on success (including the no-op case where nothing is
  pending); a negative code indicates the doorbell write failed and is
  provider-specific to recover from.
- **`-FI_ENOSYS`** from any call means the provider does not implement the WR
  API; the application should fall back to `fi_write`/`fi_send`/etc.

The request buffer (`wr_desc`) remains valid and reusable after a failed
`fi_submit_wr`. The application does not need to re-prepare the request.

### 2.6 Capability Detection

WR API support is advertised through a new endpoint capability bit, `FI_WR`.
An application requests it in `fi_info` hints (`caps`), and a provider that
supports the WR API reports it in the returned `fi_info`.

```c
hints->caps |= FI_WR;
fi_getinfo(version, node, service, flags, hints, &info);
if (info->caps & FI_WR) {
    /* WR API supported; size buffers via FI_OPT_TX_REQ_SIZE */
} else {
    /* Not supported — fall back to fi_write/fi_send/etc. */
}
```

## 3. Community Feedback and XPU Extension

The Work Request API can be extended to XPU (accelerator) initiated networking,
where an accelerator such as a GPU drives data transfers directly while the host
CPU keeps ownership of control-path setup — the model defined by the OFI XPU API
([`fi_xpu`(3)](https://ofiwg.github.io/libfabric/main/man/fi_xpu.3.html)).

The same PR that proposed the Work Request API
([#12695](https://github.com/ofiwg/libfabric/pull/12695)) also proposed
extending it to the device side, by defining `fi_xpu_prepare_wr` /
`fi_xpu_submit_wr` / `fi_xpu_flush_wr` as direct device-side equivalents of the
host `fi_prepare_wr` / `fi_submit_wr` / `fi_flush_wr` calls (§2), so a device
kernel could run the same prepare/submit/flush lifecycle. Community feedback
reshaped that design.

A major comment from
the community is that a host-side **submit** call is likely not needed. For
a CPU-accessible endpoint, separating `prepare` from `submit` adds little over
the existing `FI_MORE` flag: with a provider-managed batch limit, `submit` +
`flush` behaves much like posting with `FI_MORE` and then a trailing
non-`FI_MORE` operation. The compelling case for staging is the *device* one —
format the WQE on the CPU (control path) and submit it from a GPU/DMA engine
(data path), which aligns with the OFI XPU model. The
recommendation is
therefore to **not** offer host-side prepare/submit generally, but to scope the
staged construct/submit path to `FI_XPU` endpoints.

An explicit **flush**, by contrast, does have value independent of the staging
question — it gives applications a single, well-defined flush point for work
deferred under `FI_MORE`, the motivation tracked in issue
[#12041](https://github.com/ofiwg/libfabric/issues/12041) — and can remain a
generally useful call.

Following the feedback, the staged construct/submit path is scoped to endpoints
configured with `FI_XPU` rather than offered as a general
endpoint API: the CPU builds the WQE (control path) and the device submits it to
the hardware queue (data path). The XPU-scoped API mirrors the staged calls of
§2 — same descriptor content, same lifecycle — as a host-side export call and
device-side submit/flush calls:

```c
/* Descriptor: the fi_op_* operation description (§2.1). */
struct fi_xpu_wr_attr {
    enum fi_op_type op_type;
    union {
        struct fi_op_msg            *msg;
        struct fi_op_tagged         *tagged;
        struct fi_op_rma            *rma;
        struct fi_op_atomic         *atomic;
        struct fi_op_fetch_atomic   *fetch_atomic;
        struct fi_op_compare_atomic *compare_atomic;
    } op;
};

/* Host: build the WQE for wr into a device-visible wr_desc. */
int fi_ep_export_xpu_wr(struct fid_ep *ep, struct fi_xpu_wr_attr *wr,
                        void *wr_desc, size_t *wr_len);

/* Device: submit a prepared WQE, then ring the doorbell. */
FI_XPU_FUNC int fi_xpu_submit_wr(struct fid_xpu_ep *ep, void *wr_desc,
                                 uint64_t flags, int scope);
FI_XPU_FUNC int fi_xpu_flush_wr(struct fid_xpu_ep *ep, int scope);
```

The device-side `fi_xpu_submit_wr` / `fi_xpu_flush_wr` take a trailing
cooperative `int scope`, matching the rest of the XPU device API, and operate on
the endpoint handle exported to the device with `fi_ep_export_xpu`. Provider-specific
per-WQE metadata remains out of scope (§2.2); whatever mechanism is later defined
applies equally to the `fi_op_*` descriptor passed to `fi_ep_export_xpu_wr`.

Buffer-size discovery and capability detection use the XPU context rather than
the standalone `FI_OPT_*_REQ_SIZE` options and `FI_WR` capability of §2: the
maximum work-request descriptor sizes are reported as
`fi_xpu_ctx_attr.tx_wr_desc_size` / `rx_wr_desc_size` from `fi_xpu_ctx_query`,
and support is indicated by the XPU context rather than a separate capability
bit.

Another comment from the community is to also provide a device-side
`fi_xpu_prepare_wr`, so that a device kernel can build the WQE itself rather than
relying on the host to export it. This would let the whole prepare/submit/flush
lifecycle run on the device — the kernel prepares a WQE into a device buffer,
submits it, and flushes. The exact
device-side prepare semantics (in particular how the `fi_op_*` operation is
described from device code) remain to be worked out. A related
`fi_xpu_modify_wr` was also proposed: it would let the device populate many WQE
buffers from one common WR template, modifying only the per-WQE fields that
differ (e.g. `remote_addr`, `desc`, `addr`).

In a typical workflow the host exports each WQE into a device-visible buffer and
exports the endpoint handle for device use; a device kernel then submits the
WQEs, flushes the doorbell, and waits for completion:

```c
/* Host: export each WQE into a device-visible buffer, and export the EP. */
struct fid_xpu_ep xpu_ep;
fi_ep_export_xpu(ep, 0, &xpu_ep);

for (int i = 0; i < num_ops; i++) {
    struct fi_xpu_wr_attr wr = { .op_type = FI_OP_WRITE, .op.rma = &rmas[i] };
    size_t wr_len = tx_wr_desc_size;
    fi_ep_export_xpu_wr(ep, &wr, dev_wqe[i], &wr_len);
}
/* copy xpu_ep and the dev_wqe[] pointers to device-accessible memory */

/* Device kernel: submit the exported WQEs, flush, then wait on the counter. */
__global__ void submit_kernel(struct fid_xpu_ep *ep,
                              struct fid_xpu_cntr *cntr,
                              void **dev_wqe, int n)
{
    uint64_t prev = fi_xpu_cntr_read(cntr, FI_XPU_WORK_ITEM);

    for (int i = 0; i < n; i++)
        fi_xpu_submit_wr(ep, dev_wqe[i], 0, FI_XPU_WORK_ITEM);
    fi_xpu_flush_wr(ep, FI_XPU_WORK_ITEM);

    fi_xpu_cntr_wait(cntr, prev + n, -1, FI_XPU_WORK_ITEM);
}
```

The host side only builds WQEs; the device side drives submission on the data
path, with the provider applying the submit-time fields (§2.2) as each WQE is
placed on the hardware queue.

## References

- RFC PR and review: https://github.com/ofiwg/libfabric/pull/12695
- Explicit flush of outstanding work requests: https://github.com/ofiwg/libfabric/issues/12041
- OFI XPU API (`fi_xpu`(3)): https://ofiwg.github.io/libfabric/main/man/fi_xpu.3.html
- Triggered ops / Deferred Work (`fi_trigger`(3)): https://ofiwg.github.io/libfabric/main/man/fi_trigger.3.html
- rdma-core WR pattern (`ibv_wr_start` / `ibv_wr_complete`): https://man7.org/linux/man-pages/man3/ibv_wr_post.3.html
