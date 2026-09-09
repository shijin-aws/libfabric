EFA Extended Completion Signaling (ECS) HLD

Overview

The need to reduce latency and processing overhead in GPU/Neuron initiated workloads requires EFA to support extended, non CQ based, completion signaling. IB NICs provide such mechanism by using atomic WRs and relying on RC QP ordering. EFA's unordered nature requires us to build a new mechanism to provide a per-WR extended signaling. 

Requirements 

A few internal teams and customers have requested support for ECS. Requirements we collected to this date:






 TRN NeuronNetLink (Neuron NetLink HLD):





The full NeuronNetLink design describes many features. In this doc we discuss only those related to completion signaling. 



After completion of certain WRITE WRs, execute a 32bit write to a semaphore register on initiator and target. The data is usually a single bit indicating the buffer that was written to. TRN HW sums the writes so the semaphore register acts as 32 bit buffer completion indication.



The semaphore value should be set on WR to enable writing different data to same semaphore address.



Ideally should allow to write different values to target and initiator semaphores.



The same requirements were recently requested by A\ as well.



INF5





Similar concept to NeuronNetLink but destination lives in accelerator memory, not registers.



Would like support for writing only 8 or 16 bit to reduce space of signaling buffer.



Need somewhere between hundreds and few thousands of target addresses. Counting events will not be sufficient in terms of scale



ECT - DeepEP unordered kernels





Currently using counting events bound to QP. Requires allocating QP just to split the counting of different streams on different counters which causes a QP waste



Would like to control which counter each WRITE WR increments so they can split different streams, using the same QP, to different counters. 



Are not able to utilize memory based signaling due to processing and API constraints (see Doc)

Design concept

The idea is to extend the completion signaling beyond CQE generation to other completion signaling mechanism. In that sense a completion signal can have different implementations like a CQE, a memset operation (e.g. for semaphores) or a counter increment. We could potentially evolve the feature in the future to support other completion signaling types (counter_add, counter_set, atomics, etc). For the current scoped work our plan is to support ECS via memset and counter increment. 

Programming model

To use ECS the user must first register a signal on the target, the initiator or both. Based on the signal type (counter, memset, etc) the user will need to provide additional resources such as counter id or memory location. A register signal command will return a unique id. To use ECS when submitting the WRs will require specifying:





Remote/local signal id. 



Remote/local operand. For example in MEMSET operations the operand is the MEMSET value. 


Notes





 We have considered implementing the MEMSET signal with an additional SGE (VA + RKEY). However, our HW up-to and including AL13 can't perform HW translation post completion so we must rely on pre-registration of the addresses on the target side and use target known IDs. 



The signal ID will convey the signal type, the resource id (cntr-id, memset-id) and the generation bits of the resources. However all that information is opaque to the user that treats the signal-id as a simple number. 

Verbs API

We plan to expose the new Completion Signals feature as part of EFA Direct Verbs interface since we don't anticipate other providers interest in this API at this stage which is also expected to expedite community review times.

Capabilities

Completion Signals capability needs to be available on both initiator and receiver sides

@@ -24,6 +24,7 @@ enum {
        EFADV_DEVICE_ATTR_CAPS_UNSOLICITED_WRITE_RECV = 1 << 4,
        EFADV_DEVICE_ATTR_CAPS_CQ_WITH_EXT_MEM_DMABUF = 1 << 5,
        EFADV_DEVICE_ATTR_CAPS_COMP_CNTR = 1 << 6,
+       EFADV_DEVICE_ATTR_CAPS_COMP_MEM_OP = 1 << 7,
+       EFADV_DEVICE_ATTR_CAPS_COMP_SIGNAL = 1 << 8,
 };



Max supported Completion Memory Operations will be reported using EFADV query device verb - 0 value means unsupported.

@@ -36,6 +36,7 @@ struct efadv_device_attr {
        uint16_t inline_buf_size_ex;
        uint32_t device_caps;
        uint32_t max_rdma_size;
+       uint32_t max_comp_mem_ops;
 };



Init time calls -  receiver side (or initiator for TX completion signaling)

Existing API for creating Completion Counters with external memory

enum {
	EFADV_MEMORY_LOCATION_VA,
	EFADV_MEMORY_LOCATION_DMABUF,
};

struct efadv_memory_location {
	uint8_t *ptr;
	struct {
		uint64_t offset;
		int32_t fd;
		uint32_t reserved;
	} dmabuf;
	uint8_t type;
	uint8_t reserved[7];
};

enum {
	EFADV_COMP_CNTR_INIT_WITH_COMP_EXTERNAL_MEM = 1 << 0,
	EFADV_COMP_CNTR_INIT_WITH_ERR_EXTERNAL_MEM = 1 << 1,
};

struct efadv_comp_cntr_init_attr {
	uint64_t comp_mask;
	uint32_t flags;
	uint32_t reserved;
	struct efadv_memory_location comp_cntr_ext_mem;
	struct efadv_memory_location err_cntr_ext_mem;
};

struct ibv_comp_cntr *efadv_create_comp_cntr(struct ibv_context *ibvctx,
					     struct ibv_comp_cntr_init_attr *attr,
					     struct efadv_comp_cntr_init_attr *efa_attr,
					     uint32_t inlen);



Proposed API for creating objects of the new Completion Memory Operation type. Error completion operation was added for completeness as a standalone completion notification mechanism but its usage is optional and we can choose to not support it at first stage or even drop it from the API and add later if needed.

struct efadv_comp_mem_op {
	struct ibv_context *context;
	uint32_t handle;
};

enum {
	EFADV_COMP_MEM_OP_WITH_COMP_EXTERNAL_MEM = 1 << 0,
	EFADV_COMP_MEM_OP_WITH_ERR_EXTERNAL_MEM = 1 << 1,
};

enum {
	EFADV_COMP_MEM_OP_NONE,
	EFADV_COMP_MEM_OP_SET_SIGNAL_VAL_8,
	EFADV_COMP_MEM_OP_SET_SIGNAL_VAL_16,
	EFADV_COMP_MEM_OP_SET_SIGNAL_VAL_32,
};

struct efadv_comp_mem_op_init_attr {
	uint64_t comp_mask;
	uint32_t flags;
	uint16_t comp_op;
	uint16_t err_op;
	struct efadv_memory_location comp_op_ext_mem;
	struct efadv_memory_location err_op_ext_mem; // Optional
	uint64_t comp_op_ext_mem_length;
	uint64_t err_op_ext_mem_length;
};

struct efadv_comp_mem_op *efadv_create_comp_mem_op(struct ibv_context *context,
                                                   struct efadv_comp_mem_op_init_attr *attr,
						   uint32_t inlen);

int efadv_destroy_comp_mem_op(struct efadv_comp_mem_op *comp_mem_op);


Proposed API for creating a Completion Signal out of Completion counter or Completion Memory Operation

struct efadv_comp_signal {
	struct ibv_context *context;
	struct ibv_pd *pd;
	uint32_t handle;
	uint32_t id;
};

enum {
	EFADV_COMP_SIGNAL_INIT_TYPE_CNTR_INC,
	EFADV_COMP_SIGNAL_INIT_TYPE_MEM_OP,
};

struct efadv_comp_signal_init_attr {
	uint64_t comp_mask;
	struct ibv_pd *pd;
	union {
		struct ibv_comp_cntr *comp_cntr;
		struct efadv_comp_mem_op *comp_mem_op;
	};
	uint16_t type;
	uint16_t reserved[6];
};

struct efadv_comp_signal *efadv_create_comp_signal(struct ibv_context *context,
						   struct efadv_comp_signal_init_attr *attr,
						   uint32_t inlen);

int efadv_destroy_comp_signal(struct efadv_comp_signal *comp_signal);



The id field in efadv_comp_signal needs to be communicated out-of-band to initiator side for later use in its work requests.

QP creation with Completion Signals support - initiator side

Enable signal in work requests when creating a QP. Enabling it will enforce using 128-byte WQE and reduce max inline data to 72/56 bytes (signal w/o or w/ data) - we can consider enabling local/remote signals separately to get more inline but not sure if it worth additional complexity. We can consider introducing another helper for querying maximum supported inline data size in combination with other features.

 enum {
        EFADV_WR_EX_WITH_PROCESSING_HINTS = 1 << 0,
+       EFADV_WR_EX_WITH_COMP_SIGNAL = 1 << 1,
+       EFADV_WR_EX_WITH_COMP_SIGNAL_WITH_DATA = 1 << 2,
 };



Datapath calls - initiator side

Called to set signal id and optionally data to currently constructed work request similar to other WR setters (e.g ibv_wr_set_inline_data, efadv_wr_set_processing_hints)

void efadv_wr_set_local_comp_signal(struct efadv_qp *efadv_qp, uint32_t signal_id);

void efadv_wr_set_remote_comp_signal(struct efadv_qp *efadv_qp, uint32_t signal_id);

void efadv_wr_set_local_comp_signal_with_data(struct efadv_qp *efadv_qp,
				              uint32_t signal_id, uint32_t data);

void efadv_wr_set_remote_comp_signal_with_data(struct efadv_qp *efadv_qp,
				               uint32_t signal_id, uint32_t data);

Device ABI

Registering signals and resources


Event counter - already supported.

  struct efa_admin_create_event_counter_cmd {     
          /* UAR number */     
          uint16_t uar;     
       
          /* MBZ */     
          uint16_t reserved;     
       
          /* Counter physical address */     
          uint64_t paddr;     
  } __attribute__((__packed__));     
       
  struct efa_admin_create_event_counter_resp {     
          struct efa_admin_acq_common_desc acq_common_desc;     
       
          /* Counter handle */     
          uint32_t cntr_handle;     
       
          /* MBZ */     
         uint32_t reserved;     
  };     
       
  struct efa_admin_destroy_event_counter_cmd {     
          /* Counter handle */     
          uint32_t cntr_handle;     
  } __attribute__((__packed__));     
       
  struct efa_admin_destroy_event_counter_resp {     
          struct efa_admin_acq_common_desc acq_common_desc;     
  };     

Completion memory  registration

enum efa_admin_comp_mem_type {
	/* Write a constant value to target address */
	EFA_ADMIN_COMP_MEM_TYPE_MEMSET              = 0,
};
struct efa_admin_register_comp_mem_cmd {
	uint16_t pd;
	/* type as defined in enum efa_admin_comp_mem_type */
	uint8_t type;
	/* Size of write transaction. Either 1, 2, or 4 bytes */
	uint8_t length;
	uint64_t paddr;
} __attribute__((__packed__));

struct efa_admin_register_comp_mem_resp {
	/* Common Admin Queue completion descriptor */
	struct efa_admin_acq_common_desc acq_common_desc;
	/* Completion memory operation ID */
	uint32_t comp_mem_id;
	/* MBZ */
	uint32_t reserved;
};

struct efa_admin_deregister_comp_mem_cmd {
	/* Completion memory operation ID */
	uint32_t comp_mem_id;
} __attribute__((__packed__));

struct efa_admin_deregister_comp_mem_resp {
	/* Common Admin Queue completion descriptor */
	struct efa_admin_acq_common_desc acq_common_desc;
};

Signal registration.

enum efa_admin_signal_type {
	/* Signal backed by a completion memory operation */
	EFA_ADMIN_SIGNAL_TYPE_COMP_MEM              = 0,
};

struct efa_admin_register_signal_cmd {
	uint16_t pd;
	/* type as defined in enum efa_admin_signal_type */
	uint16_t type;
	/* Resource ID (comp_mem_id for COMP_MEM type) */
        union {
	    uint32_t comp_mem_id;
            uint32_t counter_id;
        }
} __attribute__((__packed__));

struct efa_admin_register_signal_resp {
	/* Common Admin Queue completion descriptor */
	struct efa_admin_acq_common_desc acq_common_desc;
	/* Signal ID */
	uint32_t signal_id;
	/* MBZ */
	uint32_t reserved;
};

struct efa_admin_deregister_signal_cmd {
	uint32_t signal_id;
} __attribute__((__packed__));

struct efa_admin_deregister_signal_resp {
	/* Common Admin Queue completion descriptor */
	struct efa_admin_acq_common_desc acq_common_desc;
};

WQE format

Meta descriptor gets 2 new bits in ctrl2

struct efa_io_tx_meta_desc {
          /* Verbs-generated Request ID */
        uint16_t req_id;
        uint8_t ctrl1;

  /*
           * control flags
           * 0 : phase
           * 1 : reserved25 - MBZ
           * 2 : first - Indicates first descriptor in
           *    transaction. Must be set.
           * 3 : last - Indicates last descriptor in
           *    transaction. Must be set.
           * 4 : comp_req - Indicates whether completion should
           *    be posted, after packet is transmitted. Valid only
           *    for the first descriptor
           * 5 : p2p_flush - Indicates whether a p2p flush
           *    should be performed before posting rdma read
           *    completion. Ignored if destination is not a PCIe
           *    peer device.
           * 6 : local_signal - Indicates local signal should be 
           *     triggered post local WR completion.
           * 7 : remote_signal - Indicates remote signal should be 
           *     triggered post remote WR completion.
           */
          uint8_t ctrl2;
   
         ...... 
}



A new signal descriptor struct is defined. It will be placed on inline space since meta_desc only has 6 bytes left. One struct per remote and local signal. 

struct efa_io_signal_desc {
      uint32_t signal_id;
      uint64_t signal_data;
}

Updated device capability 

  struct efa_admin_feature_queue_attr_desc_2 {     
          /* Maximum size of data that can be sent inline in a Send WQE */     
        uint16_t inline_buf_size_ex;     
       
        uint16_t max_signals   // New field to advertise total comp_mem
        
        uint16_t max_comp_mem // New field to advertise total comp_mem

          /* MBZ */     
        uint8_t reserved[2];    // reduced from 6 to 2
.......


Updated QP flags

struct efa_admin_create_qp_cmd {     
          /* Protection Domain associated with this QP */     
        uint16_t pd;     
       
          /* QP type */     
        uint8_t qp_type;     
       
          /*     
           * 0 : sq_virt - If set, SQ ring base address is     
           *    virtual (IOVA returned by MR registration)     
           * 1 : rq_virt - If set, RQ ring base address is     
           *    virtual (IOVA returned by MR registration)     
           * 2 : unsolicited_write_recv - If set, work requests                                                                                                                                                                                                                                                                                                         
           *    will not be consumed for incoming RDMA write with                                                                                                                                                                                                                                                                                                       
           *    immediate                                                                                                                                                                                                                                                                                                                                               
           * 3 : sq_64_bit_req_id - If set, requests posted on                                                                                                                                                                                                                                                                                                          
           *    SQ will use 64-bit ids. The corresponding CQ must                                                                                                                                                                                                                                                                                                       
           *    also have 64-bit ids enabled. 
           * 4: signals: if set, QP supports using WR signals.
           *    affects inline size.                                                                                                                                                                                                                                                                                                                          
           * 7:5 : reserved - MBZ // was 7:4                                                                                                                                                                                                                                                                                                                                      
           */                                                                                                                                                                                                                                                                                                                                                           
        uint8_t flags; 
.... 



Notes: 





Since event_counters can also be used for completion counting, registering a CNTR_INC signal requires first registering an event_counter and then registering a signal with the counter_id.  For memset target we use a single step approach. 

Semantics





The signal will be visible only after the data in the WR it's attached to becomes visible.



The above is guaranteed only when the data and signal use the same path. For example in TRN2, data written to sidelink and signal written to HBM via PCIe switch does not guarantee signal/data ordering.



Using local or remote invalid resource ids will results in completion with error in initiator (target completion error is debatable)



Trigger once: a signal must be triggered only once even if the WR or parts of it were re-transmitted. Signals execute post WR completion, so this is guaranteed by PSN checks which blocks us from completing the same WR twice. 





Targets that do not support remote signaling will return ack-with-error which will propagate as a unique error to initiator. DDP of data may still occur.



The signal only executes for successful WR completion, both locally and remote. Adding signals for completion with error is open issue.



The order of signal/CQE visibility is not yet defined. We can choose whatever order makes sense both in FW and HW implementation.





Signals can co-exist with completion counters. For example if a WR carries a CNTR_INC signal and targets a destination QP that is bound to different event counter, both the QP completion counter and the signal counter will increment. However, the same event counter can't be used for both completion and signal counting. 



The PD of the local/remote signal must match the PD of the source/destination QP. Mismatched PD will result in completion with error.



De-registering signals under traffic is racy by nature, just like de-registering an MR. Some signaled WRs will complete okay while others will fail.



mem-op that use less than the 64 bit signal data will use the LSB bits first.

Limitations





The device will support up to 4K mem-op signals per VF to match the size of HW action table in AL12 and AL13 HW



The amount of counters supported per VF is 512 for AL10, AL11, and AL12. 



While the API and HW implementations allow supporting signals for SEND and READ, phases 1 to 3 will only support signals for WRITE opcode. 



The signal information (24 bytes) is too large to be contained in the meta descriptor and also in the normal WQE format. Therefore signaling will only be supported in wide WQE format and will reduce the inline space from 80 bytes to 56 bytes.

FW support - high level

local signaling

Local signaling is pretty straight forward in FW. When we receive a TX completion, at the same place where we post a CQE, we generate a PUPA command to either update an MSI-x counter (CNTR_INC) or a command to write a value to the registered address (MEMSET). We allocate a different PUPA Q for different PCIe paths (sidelink) since PUPA has the high bits hardcoded. 

Initial validity checks on signal properties can be done on submissions and also repeated prior to signal execution in case the state has changed since submission.

Remote Signaling

To support signaling on the remote end we must pass the signal id and optionally an operand (for MEMSET) on the EFA WRITE packet header. On the remote end we perform validity checks and execute the signal in the write completion handler.

Validation

We will perform the following validation checks on signals: 





The PD of the source/destination QP matches the PD of the local/remote signal



The signal type embedded in the ID is a valid type



The resource id (cntr-id, memset-id) points to a valid resource id



The generation of the resource id matches.

Any validation failure will results in ack-with-error and eventually a completion with error to the initiator. 

HW offloads

AL11

AL11 supports auto completion for single segment unsolicited writes. We can configure a post auto-completion operation that will issue a command to PUPA engine to execute an MSI-X increment and mirror the value to MSI-x address. This will reduce significant time (1/2 poll loop) compared to FW trigger, especially under load. Counter-id, generation, and PD validation will require maintaining a table for HW to check against. 

AL11 doesn't have action table so we can only offload counter increment operations. 

AL12

AL12 supports auto completions for larger writes (ASB) and added support for action table. Action table allows to register an address, pd, generation, and optionally data (not used) to write to that address. On completion the ETH unit will extract the action-id, generation, and value from the EFA WRITE header and performing validity check on the action-id, generation, and pd. If all passes it will forward a command to the PUPA to execute the write. 

CNTR_INC signal will keep using the MSI-x counter mode like AL11. 

AL12 currently runs in no-track mode, meaning FW is not aware of auto completed WRs. Therefore to perform post completions signaling we can either: 





Add HW offload as first step



Switch to track mode to enable FW signal triggering. 



Bypass ASB for Signaled WRs

AL13

AL13 adds auto TX completion feature. For non signaled WRs, the auto TX completion triggers the PUPA engine to generate a CQE for the WRs. For signaled WRs it will pull the required information from the WR (type, id, value) and forward the required command to the PUPA engine that will execute the signaling.

AL13 added PCIe atomic operations support which could be useful for signaling in case the memory targets support it. We could extend the signal API to register addresses as atomic and issue a PCIe atomic operation instead of a standard write to leverage that feature. 

Feature activation

The feature will be activated on driver reset when all resources are clear. Activation will only be possible once the previous deployed (downgrade) version of the FW supports the feature. 

Implementation phases

Phase 1 - MEMSET only, No offloads





Support for AL8 to AL11.



Support for WRITE w/o immediate only



Support only for MEMSET signal type



No HW offload in auto completion/ASB - FW will trigger MEMSET signal



Complete Test plan (see below)



IPA will be disabled for QPs supporting signaling.  will be re-enabled on later drops.

Phase 2 - Counter support





Add support for counter based signaling with HW offload to trigger from AL11 auto-completion and AL12 ASB.

Phase 3 - AL12 support with HW offload





Add support for MEMSET HW offload by utilizing the action table added in AL12 together with ASB.



Support for WRITE with immediate


Note - step 2 and 3 are independent and can be flipped/parallelized based on prioritization from ECT/TRN.

Metrics

The following FW metrics will be added to monitor usage: 





local_signals_executed



local_signals_errors



remote_signals_executed



remote_signals_errors


Host sysfs counters can also be added for host tracking of signal execution. 

Additionally, a signals capability bit will be added to allow tracking deployed instances in the EFA Capabilities dashboard.

High level test plan 





TE: Adding basic functionality, abort, and errors tests to TE to cover FW code



Pyverbs: Adding basic functionality tests to additionally cover the verbs and kernel support code



Perftest: Add signal based completion polling and run:





High PPS stress tests



Latency tests to validate timing.



high incast tests (multiple perftest processes)



Signal target in CPU/TRN/GPU



Fuzzer: Add fuzz testing for new API.



libfabric: basic functionality tests. 



End to end TRN testing. 





Design docs - https://quip-amazon.com/gHWVA8m8rHUc/ECS-Phase-1-Detailed-Design-Host-Side#TUT9CAK7Au8 

Timeline - https://chorus.aws.dev/doc/CLzwNu1SKNOM/Neureon-direct-EFA-timeline--Trn2





Additions

During review of the features the following requests were made. 

Cumulative signal

 TRN collective teams have requested to support a more complex signaling mode. TRN2 and TRN3 have a limited inflight queue for incoming PCIe transactions that the neuron device marks as flushing which in our context is writes to semaphore registers. Therefore in some collective algorithms such as A2A mesh the rate of incoming semaphore writes when using simple comp_mem signals can exceed the inflight limit and push back on PCIe. The request from TRN team is to trigger a signal only after a set of N previous WRs with the same signal ID have completed.

The plan is to implement this feature using a new signal type and an existing MSI-x HW capability. When creating the signal we will specify :





completion memory



event counter



count threhsold (upto 64)



immediate to write on trigger

In FW we will configure an MSI-x trigger register that compares the counter value to one of 64 pre-configured thresholds. Once the counter value reaches the threshold, the counter zeros and the immediate value is written to the completion memory.  The signal id will hold the counter-id and when we receive the TX/RX completion we will issue a pupa counter increment command, similar to completion counters.  This will increment the counter and eventually trigger the immediate write to memory.  The implementation is very similar to counter signal but requires an extra step at setup time. 


Notes: 





The counter will not function like a regular completion counter at this mode. it's value will not reflect to the memory it was registered with and it will reset on every threshold match. It is fine from API perspective since we bound it to a special type of signal. However in that sense allocating an address for the counter seem redundant.



The exact same HW offload can be used in AL12/AL13. in RX, ETH HW needs to extract the counter-id from the packet and trigger the pupa cmd. the rest will happen the same way. in TX AL13 TX completion offload can do the same. 



Threshold is limited to 64 because we only have 64 threshold registers that we pre-configure to [1,64]. When a threshold is selected we just point to the matching threshold register. 



This signal will have no signal data. we can't configure the MSI-x trigger value from ETH HW so the signal will use a pre-configured value.



Vector signal allocation

TRN3-SR team requested to allocate a single range of completion memory and pass the offset into that array on the WR. this saves expensive buffer-to-signal-id lookup tables in accelerator memory. We assume it will be useful for TRN as well. 

We will need to implement: 





Registering a completion memory array instead of a single address. simple expansion of the API to list element size and total elements



Registering a EFADV_COMP_SIGNAL_INIT_TYPE_MEM_OP_VEC signal.



Adding an offset to the base address:





in AL10/11 we will do this in SW. The user will encode the offset in the top 32 bit of the signal data. FW will extract that and calculate the final address as signal_addr = base_address + element_size * signal_offset.



In AL12/AL13 the HW will perform that operation. the base address and element size will be read from the action table and the offset from the write packet. ETH HW will also validate that the offset is within the range of comp_mem_vector


The bonus of this feature is that it allows to register way more addresses than action table entries. Essentially in AL12 we can support 4K vectors instead of 4K addresses. 

Signal ID from application

 A\ would like that buffer X on all peers will always be assigned signal-id Y. There are a few challenges with this approach: 





we always add the generation bits to the resource id, which makes the initial request impossible as generations can be completely different across devices. We could in theory allow the user to control the generation bits as well, and pass the responsibility for re-use to their end, but that would lead to hard to debug customer issues. 



The signal-id today encodes the signal type so we can't really accept a clean-id from the user without appending the type to it when we return it


We don't plan to support this request. With batched signal allocation, the mapping problem reduces to a simple linear conversion per peer so the extra mapping overhead is not huge. 







Timeline

















