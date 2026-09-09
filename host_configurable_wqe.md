Host configurable WQE structure

Motivation

Meta descriptor in send queue entry is limited to 32 bytes when only 7 unused bytes left as of today. We would like to:





reserve the remaining bits for describing the WQE structure and giving processing instructions



support features that require more space than available (e.g. signals)



in general be frugal on WQE space and reduce static allocation for optional features that might be disabled or even unavailable is some configurations or devices

High level idea

Today a WQE consists of two parts:





Meta descriptor - a header that contains mainly common information used by hardware or firmware for processing of the request



Data section - contains local and remote memory locations and/or inline data when applicable

We want to introduce a third part that can contain optional features data. 

Since all of the 128 bytes are in use in some of the WQE formats and we currently can't increase the WQE size any further, the idea is to dynamically partition the current data section creating space for new optional features by reducing the maximum supported inline data size, when such features are enabled.

The plan is using a concept similar to stack-heap allocation in process virtual memory, when stack grows into the heap region. By defining each feature data as a separate structure, and stacking only such that belong to enabled features one on another from the end of the WQE and reducing inline data size only by that amount, we can achieve optimal utilization.

The flexible part of the WQE structure will be configured by host during QP creation according to an agreed contract with firmware. Future extension can add support for dynamically configuring the structure for each WQE but this isn't required at this stage (see Future extensions paragraph).

Suggested solution

The following diagrams explain the suggested WQE structure.

RDMA Write inline with feature1, feature2 and feature 3 enabled:

Byte offset
  0 ┌─────────────────────────────────────┐
    │                                     │
    │         Meta Descriptor             │
    │       (efa_io_tx_meta_desc)         │
    │             32 bytes                │
    │                                     │
 32 ├─────────────────────────────────────┤
    │       Remote Memory Address         │
    │      (efa_io_remote_mem_addr)       │
    │     length, rkey, buf_addr_lo/hi    │
    │             16 bytes                │
 48 ├─────────────────────────────────────┤ ◄─ inline region start
    │                                     │
    │           Inline Data               │  ▲
    │            (56 bytes)               │  │ grows
    │                                     │  │ downward
    │                                     │  │
104 ├- ─ ─ ─ ─ ─ ─ ─ ─ ─ - ─ ─ ─ ─ ─ ─ ─ ─┤ ◄─ inline / features boundary
    │      Feature Block 3 (12 bytes)     │  │
116 ├─────────────────────────────────────┤  │ grows
    │      Feature Block 2 (8 bytes)      │  │ upward
124 ├─────────────────────────────────────┤  │
    │      Feature Block 1 (4 bytes)      │  ▼
128 └─────────────────────────────────────┘



RDMA Write SGL with feature1 and feature3 enabled:

Byte offset
  0 ┌─────────────────────────────────────┐
    │                                     │
    │         Meta Descriptor             │
    │       (efa_io_tx_meta_desc)         │
    │             32 bytes                │
    │                                     │
 32 ├─────────────────────────────────────┤
    │       Remote Memory Address         │
    │      (efa_io_remote_mem_addr)       │
    │  length, rkey, buf_addr_lo/hi       │
    │             16 bytes                │
 48 ├─────────────────────────────────────┤
    │       Local Memory Descriptor       │
    │        (efa_io_tx_buf_desc)         │
    │  length, lkey, buf_addr_lo/hi       │
    │             16 bytes                │
 64 ├─────────────────────────────────────┤
    │                                     │
    │           (available)               │
    │             48 bytes                │
    │                                     │
112 ├─────────────────────────────────────┤  ▲
    │      Feature Block 3 (12 bytes)     │  │
124 ├─────────────────────────────────────┤  │ grows
    │      Feature Block 1 (4 bytes)      │  │ upward
128 └─────────────────────────────────────┘



There are few options we can consider for communicating the configuration to firmware:

Configurable offset of each feature block

Pass the offset in the WQE of each enabled feature from rdma-core to driver and then to firmware during QP creation. Inline data maximal size is defined by the smallest offset of any of the feature blocks.

Pros





explicit interface that doesn't have any hidden meaning



feature blocks can be later extended with additional optional fields

Cons





the list of offsets needs to be moved across the software stack



if we ever decide to support configuration at WQE level, it will have to use a different solution as there is no space in meta descriptor for all the offsets



requires more complex validation in firmware to catch overlaps



more options to test

Features bitmap

Define a features enablement bitmap when bits order dictates the order of feature blocks in the WQE. Each enabled feature is pushing the following blocks locations towards beginning of the WQE by the related feature block size.

Pros





simple interface that allows easy sync across firmware, driver, rdma-core, libfabric and efa-dp-direct



can be naturally extended to WQE level control using same concept

Cons





feature block definition is final once it's published and it can't be extended

Features bitmap despite its limitations seems like a better approach that that allows to define simple APIs across out software stack and doesn't add more freedom than needed. Block extension limitation can be addressed by simply defining another extended struct and adding a new flag in the bitmap, although to use this path we would need to wait for the new block support in firmware to be fully deployed or to communicate its support as an additional capability bit. Another option is later extending the method into a hybrid approach that allows setting feature block sizes to device.

Update: Following design review we will use the "offsets" approach which enables having a single source of truth for WQE used WQE structure.

Host

Each new feature that relies on the WQE feature blocks mechanism has to have an explicit enablement flag set by upper layers as it competes with inline data.

The main impact of this new approach on user experience is that the value in inline_buf_size_ex field returned by efadv_query_device() might not be supported when combined with other features.

We will introduce a new API to query the inline size that is actually available:

enum {
        EFADV_INLINE_SIZE_FLAGS_COMP_SIGNALS = 1 << 0,
        EFADV_INLINE_SIZE_FLAGS_COMP_SIGNALS_WITH_DATA = 1 << 1,
};

struct efadv_inline_size_attr {
	uint64_t comp_mask;
	uint32_t flags;
        uint32_t reserved;
};

int efadv_get_max_inline_size(struct ibv_context *ibvctx,
                              struct efadv_inline_size_attr *attr,
                              uint32_t inlen);

Libfabric will incorporate this in their fi_getopt implementation at EP level so that it will report inline_buf_size_ex when application queries for device level capabilities and the output of efadv_get_max_inline_size() at EP level, for already created EP.

Additionally efadv_query_qp_wqs() output need to be extended to return the list of enabled WQE feature blocks for use in external datapath implementations.

Firmware

On QP creation firmware is required to calculate the max inline size according to enabled features configuration (we might want to send inline size from host to make sure both sides are aligned) and configure IPP / CSO RPV accordingly (TODO: do we need HAL changes?). For each feature block, its offset needs to be stored in its QP object for accessing feature data on datapath or for configuring hardware engines for offloaded features.

efa-dp-direct

CUDA QP inItialization params will be extended to notify efa-dp-direct on enabled features using the existing sq_wq_caps field that is already being checked for having only supported flags. This means that old efa-dp-direct versions will fail when new unsupported feature is enabled, what is the expected behavior as such features need to be explicitly enabled by OFI plugin.

Signals - First feature to use WQE Feature Blocks method

For signals support we will define 2 WQE feature blocks:

One for basic signals

struct efa_io_tx_wqe_comp_signals {
        uint32_t local_signal_id;
        uint32_t remote_signal_id;
};

And another for signal data

struct efa_io_tx_wqe_comp_signals_data {
        uint32_t local_data;
        uint32_t remote_data;
};



WQE feature blocks bitmap need to be added in efa_admin_create_qp_cmd:

/*
 * 0 : comp_signals - If set, WQE will contain signals block
 * 1 : comp_signals_data - If set, WQE will contain signals data block
 */
uint16_t wqe_feature_blocks_en;



At verbs level it would be natural to rely on work request setter enablement flags we have already defined for enabling WQE feature block (wr_flags):

enum {
        EFADV_WR_EX_WITH_PROCESSING_HINTS = 1 << 0,
        EFADV_WR_EX_WITH_COMP_SIGNAL = 1 << 1,
        EFADV_WR_EX_WITH_COMP_SIGNAL_WITH_DATA = 1 << 2,
};



Limitations and open questions





Dynamic WQE features are enabled uniformly for all ops meaning that it can be enabled only when there is sufficient space in all WQE variations - so basic requirement is use of 128-byte WQE



Should we pad feature blocks to align to 8 bytes?

Testing

The mechanism will be tested as part of Completion Signals testing using Perftest and TE. The separation into two blocks one for signal ids and another for signal data should enable testing of most of the general init flows. 

Future extensions

Possible extension for this mechanism is enabling control over used feature block at WQE level so that inline size will be reduced only for WQEs that use a feature that competes with it. HW can support 16 WQE parsing profiles for each op - a feature blocks bitmap in WQE meta data can be used to select the correct preconfigured profile.

At host APIs level it will require finding a sane way of exposing all those options and limitations.