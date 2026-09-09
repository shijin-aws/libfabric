# OFI Completion with Signal

## 1. Introduction

EFA completion with signal allows an EFA NIC to execute a registered action
(memory write or counter increment) at a device-accessible address upon work
request completion, enabling direct accelerator notification without host CPU
involvement. Its motivation, use cases (Neuron NetLink, INF5, ECT/DeepEP),
hardware design, and rdma-core level semantics are covered by the
[EFA Extended Completion Signaling HLD](https://chorus.aws.dev/doc/D1s6WVeppTU1/EFA-Extended-Completion-Signaling-ECS-HLD).

This document focuses on the Libfabric interface that exposes completion with
signal to applications: signal registration (control path), enabling signal
support on the endpoint, and per-WR signal attachment (data path).

## 2. API

The completion with signal interface has three parts: signal registration (control
path), enabling signal support on the endpoint, and signal
attachment to work requests (data path). Together they map the rdma-core
completion with signal primitives into Libfabric's provider-specific extension
model.

### 2.1 Signal Registration (Control Path)

Before a signal can be used on the data path, the application registers it with
the provider. Mirroring the EFA ECS HLD, registration is a **two-step** control
path so that the target resource (a memory-write target, or a counter) is
created first and then wrapped in a signal:

1. Create the completion resource — either a *completion memory operation* that
   writes a value to a target address (MEMSET), or reuse a pre-created event
   counter.
2. Create a *signal* over that resource. The provider issues an admin command to
   the NIC, which allocates an action-table entry and returns an opaque
   `signal_id` that is then referenced in work requests.

For remote signals (triggered at the receiver), the `signal_id` must be
communicated out-of-band from the receiver to the sender.

### Signal ops table

These are provider-specific control-plane calls, so they are exposed as a
domain-level ops table obtained with `fi_open_ops`, the same way the EFA
provider exposes its GDA ops (`FI_EFA_GDA_OPS`) and domain ops
(`FI_EFA_DOMAIN_OPS`) — see `efa_domain_ops_open()` in `efa_domain.c`:

```c
/* rdma/fi_ext_efa.h */
#define FI_EFA_SIGNAL_OPS "efa signal ops"

struct fi_efa_ops_signal {
    int (*create_comp_mem_op)(struct fid_domain *domain,
                              struct fi_efa_comp_mem_op_attr *attr,
                              uint32_t *comp_mem_id);
    int (*destroy_comp_mem_op)(struct fid_domain *domain, uint32_t comp_mem_id);
    int (*register_signal)(struct fid_domain *domain,
                           struct fi_efa_comp_signal_attr *attr,
                           uint32_t *signal_id);
    int (*deregister_signal)(struct fid_domain *domain, uint32_t signal_id);
    int (*query_max_comp_mem_ops)(struct fid_domain *domain,
                                  uint32_t *max_comp_mem_ops);
};

/* Obtained via:
 *   struct fi_efa_ops_signal *ops;
 *   fi_open_ops(&domain->fid, FI_EFA_SIGNAL_OPS, 0, (void **)&ops, NULL);
 */
```

`query_max_comp_mem_ops` reports how many completion memory operations
(MEMSET-backed signals) the device supports; a value of 0 means completion with
signal is unsupported. It is a device capability sourced from the rdma-core
`efadv_query_device` verb, and lets an application size its signal pool before
registering. Counter-backed signals (`FI_EFA_COMP_SIGNAL_CNTR_INC`) are bounded
separately by the device's event-counter capacity.

### Memory location (VA or dmabuf/HMEM)

The MEMSET target may live in host memory or in device memory (GPU/Neuron HBM).
It is described by the provider's existing `struct fi_efa_memory_location`
(already defined in `fi_ext_efa.h`, mirroring `efadv_memory_location`), which
carries either a VA (`ptr`) or a dmabuf `fd`/`offset`, rather than a bare
`void *`:

```c
/* rdma/fi_ext_efa.h — existing */
enum fi_efa_memory_location_type {
    FI_EFA_MEMORY_LOCATION_VA,
    FI_EFA_MEMORY_LOCATION_DMABUF,
};

struct fi_efa_memory_location {
    uint8_t     *ptr;                    /* FI_EFA_MEMORY_LOCATION_VA */
    struct {
        uint64_t offset;
        int32_t  fd;                     /* FI_EFA_MEMORY_LOCATION_DMABUF */
        uint32_t reserved;
    } dmabuf;
    uint8_t      type;                   /* enum fi_efa_memory_location_type */
    uint8_t      reserved[7];
};
```

### Step 1 — completion memory operation

```c
/* Width of the value written by a MEMSET completion memory operation. */
enum fi_efa_comp_mem_op {
    FI_EFA_COMP_MEM_OP_SET_SIGNAL_VAL_8,
    FI_EFA_COMP_MEM_OP_SET_SIGNAL_VAL_16,
    FI_EFA_COMP_MEM_OP_SET_SIGNAL_VAL_32,
};

struct fi_efa_comp_mem_op_attr {
    uint64_t                        comp_mask;
    enum fi_efa_comp_mem_op         op;         /* value width to write */
    struct fi_efa_memory_location   location;   /* target: VA or dmabuf/HMEM */
    uint64_t                        length;     /* target region length */
};

/* ops->create_comp_mem_op(domain, &attr, &comp_mem_id);
 * ops->destroy_comp_mem_op(domain, comp_mem_id); */
```

### Step 2 — signal registration

A signal is created over either a completion memory op (from step 1) or a
pre-created event counter, and returns the opaque `signal_id`:

```c
enum fi_efa_comp_signal_type {
    FI_EFA_COMP_SIGNAL_MEM_OP,    /* backed by a completion memory operation */
    FI_EFA_COMP_SIGNAL_CNTR_INC,  /* backed by an event counter */
};

struct fi_efa_comp_signal_attr {
    uint64_t                        comp_mask;
    enum fi_efa_comp_signal_type    type;
    union {
        uint32_t            comp_mem_id;  /* FI_EFA_COMP_SIGNAL_MEM_OP */
        struct fid_cntr    *cntr;         /* FI_EFA_COMP_SIGNAL_CNTR_INC */
    };
};

/* ops->register_signal(domain, &attr, &signal_id);
 * ops->deregister_signal(domain, signal_id); */
```

Semantics:

- Registration is a control-path operation (admin command to NIC), grouped under
  the `FI_EFA_SIGNAL_OPS` domain ops table.
- A MEMSET signal takes two steps (create the completion memory op, then the
  signal); a counter signal instead passes an existing libfabric counter
  (`struct fid_cntr *`), from which the provider retrieves the underlying
  counter ID, so only step 2 is needed.
- Device-memory (HMEM) targets are expressed through
  `FI_EFA_MEMORY_LOCATION_DMABUF` in `struct fi_efa_memory_location`.
- The returned `signal_id` is opaque; the application treats it as a plain
  number (its internal structure is defined by the EFA Extended Completion
  Signaling HLD).
- PD of the signal must match PD of the QP that will use it.

### 2.2 Endpoint Signal Support

Signal support must be enabled explicitly at endpoint setup, before the endpoint
is enabled, because it governs how the endpoint's send queue is allocated: the
provider uses wide (128-byte) WQE blocks so the signal descriptor fields can be
carried per work request. Enabling it also reduces the inline data available in
a WQE; the exact amount depends on which signal fields a given work request
carries and is a device property defined by the EFA Extended Completion
Signaling HLD, so it is not a fixed endpoint-level value.

The application opts in via `fi_setopt` on the endpoint:

```c
bool enable = true;
fi_setopt(&ep->fid, FI_OPT_ENDPOINT, FI_OPT_EFA_COMP_SIGNAL, &enable, sizeof(enable));
```

When set, the provider creates the QP with the EFA-direct verbs work-request
capability bits `EFADV_WR_EX_WITH_COMP_SIGNAL` and
`EFADV_WR_EX_WITH_COMP_SIGNAL_WITH_DATA`. These bits do double duty: they enable
the corresponding WQE feature blocks (the signal-ID block and the signal-data
block; see the appendix) at QP creation, which is what causes the send queue to
be allocated with wide WQEs and the inline data region to shrink. A single
option sets both, so the endpoint can carry signals with or without per-WR
operand data: the WQE is already sized for the with-data case, and whether
operand data is present is chosen per work request on the data path via the
`FI_EFA_*_SIGNAL_DATA` flags (§2.3).

Because enabling signals reduces the inline data a WQE can hold, the device-level
inline size (`inline_buf_size_ex`) may not be achievable once signals are on. The
available inline size is therefore queried per endpoint: libfabric's `fi_getopt`
at EP level reports the actual inline size for an already-created endpoint (backed
by the new `efadv_get_max_inline_size()` verb), while a device-capability query
still reports the nominal `inline_buf_size_ex`. Applications that enable signals
should size inline sends from the EP-level value.

### 2.3 Signal Attachment (Data Path)

Once a signal is registered, the application attaches it to individual work
requests by passing the signal descriptor in a provider-specific message
structure. Instead of patching a prepared WQE with setter calls, completion
signaling defines EFA-specific message structs that are layout-compatible with
the core libfabric
message descriptors: the core struct is the first member, so a pointer to the
EFA struct can be passed anywhere the core descriptor is expected, and the
provider recovers the extra fields by casting back.

```c
/* rdma/fi_ext_efa.h */

/* Selects which EFA metadata fields the fi_efa_msg[_rma] struct carries. Each
 * bit gates exactly one field, so new EFA per-WR metadata can be added over
 * time without consuming bits in the common fi_writemsg/fi_sendmsg flags word. */
enum {
    FI_EFA_LOCAL_SIGNAL_ID    = 1 << 0,  /* local_signal_id is valid */
    FI_EFA_REMOTE_SIGNAL_ID   = 1 << 1,  /* remote_signal_id is valid */
    FI_EFA_LOCAL_SIGNAL_DATA  = 1 << 2,  /* local_signal_data is valid */
    FI_EFA_REMOTE_SIGNAL_DATA = 1 << 3,  /* remote_signal_data is valid */
    /* future EFA metadata fields add bits here */
};

/* EFA-specific message descriptors. The core descriptor is the first member,
 * so (struct fi_msg_rma *)&efa_msg is valid and vice versa. The feature_bits word
 * selects which of the fields below the provider should read; a field with its
 * bit unset is ignored regardless of its contents. */
struct fi_efa_msg_rma {
    struct fi_msg_rma   msg;                /* MUST be first — castable to fi_msg_rma */
    uint64_t            feature_bits;          /* which fields below are valid (FI_EFA_*) */
    uint32_t            local_signal_id;    /* opaque ID from fi_efa_register_comp_signal */
    uint32_t            remote_signal_id;
    uint32_t            local_signal_data;  /* per-WR operand for the local signal */
    uint32_t            remote_signal_data; /* per-WR operand for the remote signal */
};

struct fi_efa_msg {
    struct fi_msg       msg;                /* MUST be first — castable to fi_msg */
    uint64_t            feature_bits;          /* which fields below are valid (FI_EFA_*) */
    uint32_t            local_signal_id;
    uint32_t            remote_signal_id;
    uint32_t            local_signal_data;
    uint32_t            remote_signal_data;
};
```

The reinterpretation is selected by a new EFA-specific operation flag passed in
the `flags` argument of the ordinary data transfer calls (`fi_writemsg`,
`fi_sendmsg`, ...):

```c
/* rdma/fi_ext_efa.h — EFA-specific operation flag */
#define FI_EFA_EXTENDED_MSG      /* msg pointer is an fi_efa_msg[_rma] struct */
```

The mechanism is two-level. The outer `FI_EFA_EXTENDED_MSG` operation flag, set in
the `flags` word of the ordinary call, tells the provider to reinterpret the
descriptor pointer as the corresponding EFA struct (e.g. the
`struct fi_msg_rma *` argument of `fi_writemsg` as `struct fi_efa_msg_rma *`).
It is an EFA-specific flag occupying one of the high, provider-reserved bits of
that word (the exact bit is an implementation detail chosen not to collide with
the core operation flags). The inner `feature_bits` word, inside the struct, then
selects which EFA metadata fields the provider consumes.

Each `feature_bits` bit gates exactly one field. This two-level split matters
because the common operation-flags word is shared across all of libfabric and
nearly exhausted: the whole EFA metadata scheme costs just one bit there
(`FI_EFA_EXTENDED_MSG`), and every future field is added as a new `FI_EFA_*` bit
in `feature_bits` rather than a new common flag.

Completion with signal is the first such feature. A work request can carry up to
two signals — a local one (triggered on sender-side TX completion) and a remote
one (triggered on receiver-side RX completion) — each identified by a signal ID
obtained from `fi_efa_register_comp_signal`. The ID and its per-WR operand are
independently gated:

- `FI_EFA_LOCAL_SIGNAL_ID` / `FI_EFA_REMOTE_SIGNAL_ID` attach the local / remote
  signal, naming which registered action fires.
- `FI_EFA_LOCAL_SIGNAL_DATA` / `FI_EFA_REMOTE_SIGNAL_DATA` supply that signal's
  per-WR operand (`*_signal_data`) — for a MEMSET signal the value written, for
  a counter signal the increment amount. A signal may be attached without data
  (leave the data bit unset), which the device treats as its default operand.

```c
int fi_writemsg(struct fid_ep *ep, const struct fi_msg_rma *msg, uint64_t flags);
```

Constraints:

- The endpoint must have signal support enabled (§2.2); otherwise
  `FI_EFA_EXTENDED_MSG` and the signal fields are rejected.
- `FI_EFA_EXTENDED_MSG` is only accepted on the message-form data transfer calls
  that take a descriptor pointer — `fi_sendmsg` and `fi_writemsg`. It is not
  supported on the other data transfer variants (`fi_send`, `fi_write`,
  `fi_inject`, `fi_writedata`, ...), which have no descriptor to extend; passing
  it there is rejected with `-FI_EINVAL`.
- `FI_EFA_EXTENDED_MSG` must be set in the call's `flags` for the provider to read the
  struct; without it the pointer is treated as a plain core descriptor and all
  EFA fields are ignored.
- Within the struct, the provider reads only the fields whose flag is set in
  `feature_bits`; fields whose bit is unset are ignored and need not be
  initialized.
- Local and remote signals are independent: attach either or both by setting the
  corresponding `FI_EFA_*_SIGNAL_ID` bit(s). A signal's data bit
  (`FI_EFA_*_SIGNAL_DATA`) may only be set when its ID bit is also set.


## 3. End-to-End Flow

### 3.1 Receiver Setup

```c
/* Obtain the signal ops table from the domain. */
struct fi_efa_ops_signal *sig_ops;
fi_open_ops(&domain->fid, FI_EFA_SIGNAL_OPS, 0, (void **)&sig_ops, NULL);

/* 1. Create the completion memory op targeting the receiver's semaphore.
 *    Here the semaphore lives in device (HBM) memory, addressed by dmabuf. */
struct fi_efa_comp_mem_op_attr mem_attr = {
    .op       = FI_EFA_COMP_MEM_OP_SET_SIGNAL_VAL_32,
    .location = { .type   = FI_EFA_MEMORY_LOCATION_DMABUF,
                  .dmabuf = { .fd = sem_dmabuf_fd, .offset = sem_offset } },
    .length   = 4,
};
uint32_t comp_mem_id;
sig_ops->create_comp_mem_op(domain, &mem_attr, &comp_mem_id);

/* 2. Create a signal over that completion memory op. */
struct fi_efa_comp_signal_attr sig_attr = {
    .type        = FI_EFA_COMP_SIGNAL_MEM_OP,
    .comp_mem_id = comp_mem_id,
};
uint32_t signal_id;
sig_ops->register_signal(domain, &sig_attr, &signal_id);

/* 3. Communicate signal_id to sender out-of-band */
send_signal_id_to_peer(peer, signal_id);
```

### 3.2 Sender Data Path

```c
/* 1. Receive remote signal_id from peer */
uint32_t remote_sig_id = receive_signal_id_from_peer(peer);

/* 2. Build an RDMA write descriptor with an attached remote completion signal */
struct fi_rma_iov rma_iov = { .addr = remote_addr, .len = len, .key = rkey };
struct iovec iov = { .iov_base = buf, .iov_len = len };
struct fi_efa_msg_rma emsg = {
    .msg = {
        .msg_iov       = &iov,      .iov_count     = 1,
        .desc          = &desc,     .addr          = dest_addr,
        .rma_iov       = &rma_iov,  .rma_iov_count = 1,
        .context       = context,
    },
    .feature_bits          = FI_EFA_REMOTE_SIGNAL_ID | FI_EFA_REMOTE_SIGNAL_DATA,
    .remote_signal_id   = remote_sig_id,
    .remote_signal_data = sem_value,
    /* local signal omitted: FI_EFA_LOCAL_SIGNAL_ID not set */
};

/* 3. Post the write; FI_EFA_EXTENDED_MSG tells the provider to read emsg as fi_efa_msg_rma */
fi_writemsg(ep, (struct fi_msg_rma *)&emsg, FI_EFA_EXTENDED_MSG);
```

Completion semantics (ordering, visibility, trigger guarantees, PD validation,
lifecycle), resource limits, and the set of supported operations and rollout
phases are device behavior defined by the EFA Extended Completion Signaling HLD
and are not restated here.

## 4. Extension to FI_XPU (accelerator) API

The interface above is host-driven: the CPU builds the message descriptor and
posts it with `fi_writemsg` / `fi_sendmsg`. Completion with signal is also
intended for accelerator-initiated networking, where a device (GPU, Neuron)
drives data transfers directly while the host keeps ownership of control-path
setup — the model defined by the OFI `FI_XPU` API. An extension of that API
([design](https://chorus.aws.dev/doc/uEcfexqeXh04/OFI-Work-Request-API)) lets an
application build WQEs on the host that are later submitted to the NIC — driven
by the XPU on the data path — and the rest of this section is framed in terms of
that extension.

It breaks a post into staged steps — format a hardware work-queue entry (WQE)
into a caller buffer, submit it to the queue, and ring the doorbell — so the
stages can run on different agents: the WQE may be formatted on the host or on
the device itself, and submitted from the device. An operation is described with
a small work-request descriptor rather than the flat post arguments:

```c
/* From the FI_XPU extension design (see References), abridged. */
struct fi_wr_attr {
    enum fi_op_type op_type;          /* FI_OP_WRITE, FI_OP_SEND, ... */
    union {                           /* the fi_op_* structs libfabric already
                                       * defines for deferred work */
        struct fi_op_msg    *msg;
        struct fi_op_rma    *rma;     /* carries a struct fi_msg_rma + flags */
        /* tagged / atomic / ... */
    } op;
};
```

The `fi_op_*` structs embed the same message descriptors used on the host path
(`fi_op_rma` carries a `fi_msg_rma`), so completion with signal plugs in the
same way regardless of where the WQE is built: the caller supplies the extended
`fi_efa_msg[_rma]` as that message descriptor and sets `FI_EFA_EXTENDED_MSG` in
the operation flags, and the formatted WQE carries the signal fields.

One `FI_XPU` flow is host-formatted: the host formats each work request into a
device-visible buffer with the export call and hands the buffer to a device
kernel, which submits it and rings the doorbell. (The device may also build the
WQE itself; either way the same descriptor and flags carry the signal metadata.)
Signal registration and endpoint capability (§2.1, §2.2) remain host-side
control-path operations regardless of who drives the data path.

```c
/* Host (control path): format the WQE, carrying the signal metadata. */
struct fi_efa_msg_rma emsg = {
    .msg           = { /* iov, desc, addr, rma_iov, context */ },
    .feature_bits     = FI_EFA_REMOTE_SIGNAL_ID | FI_EFA_REMOTE_SIGNAL_DATA,
    .remote_signal_id   = remote_sig_id,
    .remote_signal_data = sem_value,
};
/* Wrap the extended descriptor in the operation descriptor; FI_EFA_EXTENDED_MSG
 * in the op flags tells the provider to read it as fi_efa_msg_rma. */
struct fi_op_rma  op = { .ep = ep, .msg = emsg.msg, .flags = FI_EFA_EXTENDED_MSG };
struct fi_wr_attr wr = { .op_type = FI_OP_WRITE, .op.rma = &op };

fi_ep_export_xpu_wr(ep, &wr, dev_wqe, &wr_len);

/* Device (data path): submit the pre-formatted WQE and flush. */
fi_xpu_submit_wr(xpu_ep, dev_wqe, 0, FI_XPU_WORK_ITEM);
fi_xpu_flush_wr(xpu_ep, FI_XPU_WORK_ITEM);
```

The signal metadata is baked into the WQE at host format time, so the device
submit path needs no signaling-specific step. The exact descriptor wrapping and
XPU calls follow the `FI_XPU` extension design (see References); the point here
is that the completion with signal metadata model (registered signal IDs plus
per-WR gated fields) is defined so it applies unchanged to both the host and the
XPU data paths.

## References

- EFA Extended Completion Signaling HLD:
  https://chorus.aws.dev/doc/D1s6WVeppTU1/EFA-Extended-Completion-Signaling-ECS-HLD
- OFI `FI_XPU` staged work-request extension design:
  https://chorus.aws.dev/doc/uEcfexqeXh04/OFI-Work-Request-API
- Neuron NetLink:
  https://quip-amazon.com/DQ4DA9l2aOy2/Neuron-NetLink-Neuron-Direct-Async


## Appendix: WQE Layout (implementation detail)

This appendix summarizes how the signal fields are carried in the hardware WQE.
It is provider/device implementation detail — not part of the libfabric API — and
is included only as background for the inline-size behavior in §2.2. The
authoritative description is in the EFA Host-Configurable WQE and EFA Extended
Completion Signaling HLDs.

A WQE has a fixed meta descriptor and a data section (remote/local memory
descriptors and/or inline data). Optional per-WR features are carried in
**feature blocks** stacked from the end of the WQE inward; enabling a feature
reduces the inline data region by that block's size. Because the blocks compete
with inline data, each feature is enabled explicitly at QP creation (the
`fi_setopt` opt-in in §2.2), and the resulting inline size is queried per
endpoint rather than assumed (§2.2).

Completion with signal uses two feature blocks:

```c
/* Signal IDs block — enabled by FI_EFA_*_SIGNAL_ID (via the signal capability). */
struct efa_io_tx_wqe_comp_signals {
    uint32_t local_signal_id;
    uint32_t remote_signal_id;
};

/* Signal data block — enabled by FI_EFA_*_SIGNAL_DATA (with-data capability). */
struct efa_io_tx_wqe_comp_signals_data {
    uint32_t local_data;
    uint32_t remote_data;
};
```

Notes:

- Feature blocks require the wide (128-byte) WQE format.
- Block ordering, offsets, and any alignment padding are an internal contract
  between the provider, driver, and firmware; they are not visible through the
  libfabric API. The public surface is only the `fi_efa_msg[_rma]` fields (§2.3)
  and the per-endpoint inline-size query (§2.2).
