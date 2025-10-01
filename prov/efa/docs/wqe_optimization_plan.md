# EFA WQE Preparation Optimization Plan

## Overview
Optimize EFA Work Queue Entry (WQE) preparation by eliminating the intermediate staging buffer (`sq->curr_tx_wqe`) and directly constructing WQEs in write-combined memory word-by-word (64-bit at a time).

## Current Implementation Problems

### Current Flow:
1. Multiple `efa_qp_*` functions modify `sq->curr_tx_wqe` (staging buffer)
2. `efa_data_path_direct_send_wr_post_working()` calls `mmio_memcpy_x64()` to copy entire WQE to write-combined memory
3. This involves extra memory bandwidth, cache pollution, and latency

### Key Functions in Current Flow:

**MSG Operations (efa_msg.c):**
- `efa_qp_wr_start(qp)` - Starts work request
- `efa_qp_wr_send(qp)` or `efa_qp_wr_send_imm(qp, data)` - Sets send operation
- `efa_qp_wr_set_inline_data_list()` or `efa_qp_wr_set_sge_list()` - Sets data buffers
- `efa_qp_wr_set_ud_addr()` - Sets UD addressing
- `efa_qp_wr_complete(qp)` - Completes and posts work request

**RMA Operations (efa_rma.c):**
- `efa_qp_wr_start(qp)` - Starts work request
- `efa_qp_wr_rdma_read(qp, key, addr)` - Sets RDMA READ operation
- `efa_qp_wr_rdma_write(qp, key, addr)` or `efa_qp_wr_rdma_write_imm(qp, key, addr, data)` - Sets RDMA WRITE operation
- `efa_qp_wr_set_sge_list(qp, count, sge_list)` - Sets local data buffers
- `efa_qp_wr_set_ud_addr()` - Sets UD addressing
- `efa_qp_wr_complete(qp)` - Completes and posts work request

### Current Inefficiencies:
- Multiple `EFA_SET()` calls doing read-modify-write operations on staging buffer
- `mmio_memcpy_x64()` copies entire WQE (extra memory operation)
- Cache pollution from staging buffer writes

## Optimization Strategy

### Target Flow:
1. Build 64-bit words in CPU registers containing packed bit fields
2. Write each 64-bit word directly to write-combined memory **EXACTLY ONCE**
3. Eliminate intermediate staging buffer and memcpy

### Critical Constraint:
**WRITE-COMBINED MEMORY SINGLE-WRITE REQUIREMENT**: Each 64-bit word in the write-combined region can only be written ONCE. Multiple writes to the same WC memory location can cause undefined behavior or performance degradation.

### Key Benefits:
- **Eliminates memcpy overhead** - No intermediate copy operation
- **Better cache efficiency** - Direct writes to WC memory
- **Reduced memory bandwidth** - Single write per 64-bit word
- **Lower latency** - Fewer memory operations in critical path
- **Hardware compliance** - Respects WC memory write-once semantics

## Implementation Approach

### Phase 1: Analyze WQE Structure and Current Functions
- Map out `struct efa_io_tx_wqe` layout and 64-bit word boundaries
- Identify which fields can be packed into single 64-bit writes
- Document bit field layouts for common operations
- Analyze current `efa_qp_*` function field overlap

### Phase 2: Create Consolidated WQE Builder Functions (Based on CUDA Reference)

**Strategy**: Follow the CUDA kernel pattern but eliminate staging buffer and memcpy.

**Current Multi-Function Pattern**:
```c
// MSG operations (efa_msg.c)
efa_qp_wr_start(qp);
efa_qp_wr_send(qp) or efa_qp_wr_send_imm(qp, data);
efa_qp_wr_set_sge_list(qp, count, sge_list);
efa_qp_wr_set_ud_addr(qp, ah, qpn, qkey);
efa_qp_wr_complete(qp);

// RMA operations (efa_rma.c)
efa_qp_wr_start(qp);
efa_qp_wr_rdma_read/write(qp, key, addr);
efa_qp_wr_set_sge_list(qp, count, sge_list);
efa_qp_wr_set_ud_addr(qp, ah, qpn, qkey);
efa_qp_wr_complete(qp);
```

**New Consolidated Pattern**:
```c
// Single consolidated function per operation type
efa_post_send_direct(qp, op_type, sge_list, count, ah, qpn, qkey, imm_data);
efa_post_rdma_read_direct(qp, local_sge_list, count, remote_key, remote_addr, ah, qpn, qkey);
efa_post_rdma_write_direct(qp, local_sge_list, count, remote_key, remote_addr, ah, qpn, qkey, imm_data);
```

**Implementation Strategy**:
1. **Collect all parameters** needed for complete WQE in function signature
2. **Calculate WC memory target address** directly: `(struct efa_io_tx_wqe *)sq->desc + sq_desc_idx`
3. **Build 64-bit words** in CPU registers with all required bit fields
4. **Write each 64-bit word once** to WC memory location
5. **Update queue state** (pc, phase, posted count)
6. **Ring doorbell** if needed

### Function Merging Strategy:

**Problem**: Current `efa_qp_*` functions may write to overlapping bit fields within the same 64-bit word:
- `efa_qp_wr_send()` sets operation type bits
- `efa_qp_wr_send_imm()` sets immediate data flag in same control word
- `efa_set_common_ctrl_flags()` sets multiple control bits

**Solution**: Create consolidated functions that:
1. **Collect all parameters** needed for a complete 64-bit word
2. **Build the entire word** in a CPU register with all bit fields
3. **Write once** to the WC memory location

**Example Consolidation**:
```c
// Instead of multiple functions touching ctrl1:
efa_qp_wr_send(qp);                    // Sets OP_TYPE bits
efa_qp_wr_send_imm(qp, imm_data);      // Sets HAS_IMM bit + imm_data
efa_set_common_ctrl_flags(...);        // Sets META_DESC bit

// Use single consolidated function:
efa_build_meta_ctrl1_word(op_type, has_imm, imm_data, meta_desc_flag);
```

### Reference Implementation Analysis:

**CUDA Kernel Example** (`fabtests/prov/efa/src/efagda/cuda_kernel.cu`):
The `efa_post_send_kernel()` function provides an excellent reference for consolidated WQE preparation:

```c
__global__ void efa_post_send_kernel(efa_qp *qp, uint16_t ah,
                                     uint16_t remote_qpn, uint32_t remote_qkey,
                                     uint64_t addr, uint32_t length,
                                     uint32_t lkey, int *result)
{
    __shared__ uint8_t wqe_buf[sizeof(struct efa_io_tx_wqe) + 64];
    struct efa_io_tx_wqe *wqe = (struct efa_io_tx_wqe *) ((uint64_t) (wqe_buf + 64 - 1) & ~(64 - 1));
    
    // Set all metadata fields in one place
    wqe->meta.dest_qp_num = remote_qpn;
    wqe->meta.ah = ah;
    wqe->meta.qkey = remote_qkey;
    wqe->meta.req_id = 0;
    
    // Set control fields using EFA_SET (still uses staging buffer)
    EFA_SET(&wqe->meta.ctrl1, EFA_IO_TX_META_DESC_META_DESC, 1);
    EFA_SET(&wqe->meta.ctrl1, EFA_IO_TX_META_DESC_OP_TYPE, EFA_IO_SEND);
    EFA_SET(&wqe->meta.ctrl2, EFA_IO_TX_META_DESC_PHASE, qp->sq.wq.phase);
    EFA_SET(&wqe->meta.ctrl2, EFA_IO_TX_META_DESC_FIRST, 1);
    EFA_SET(&wqe->meta.ctrl2, EFA_IO_TX_META_DESC_LAST, 1);
    EFA_SET(&wqe->meta.ctrl2, EFA_IO_TX_META_DESC_COMP_REQ, 1);
    
    // Set SGL data
    wqe->meta.length = 1;
    EFA_SET(&wqe->data.sgl[0].lkey, EFA_IO_TX_BUF_DESC_LKEY, lkey);
    wqe->data.sgl[0].length = length;
    wqe->data.sgl[0].buf_addr_lo = addr & 0xffffffff;
    wqe->data.sgl[0].buf_addr_hi = addr >> 32;
    
    // Still uses memcpy (what we want to eliminate)
    sq_desc_offset = (qp->sq.wq.pc & qp->sq.wq.queue_mask) * sizeof(*wqe);
    memcpy(qp->sq.buf + sq_desc_offset, wqe, sizeof(*wqe));
    
    // Update queue state
    qp->sq.wq.wqes_posted++;
    qp->sq.wq.pc++;
    if (!(qp->sq.wq.pc & qp->sq.wq.queue_mask))
        qp->sq.wq.phase++;
    
    __threadfence_system();
    *qp->sq.wq.db = qp->sq.wq.pc;
}
```

**Key Insights from CUDA Reference**:
1. **Single function approach** - All WQE preparation in one place
2. **Still uses staging buffer** - Creates WQE in local memory first
3. **Still uses memcpy** - Copies complete WQE to hardware queue
4. **Consolidated field setting** - All related fields set together
5. **Shows complete WQE structure** - Demonstrates all required fields

**Our Optimization Goal**: Take this consolidated approach but eliminate the staging buffer and memcpy by writing directly to write-combined memory word-by-word.

### Phase 3: Replace Current Functions with Direct Writers

**Replace `efa_data_path_direct_send_wr_post_working()`**:
```c
// Current (what we want to eliminate):
void efa_data_path_direct_send_wr_post_working(struct efa_data_path_direct_sq *sq, bool force_doorbell)
{
    uint32_t sq_desc_idx = (sq->wq.pc - 1) & sq->wq.desc_mask;
    mmio_memcpy_x64((struct efa_io_tx_wqe *)sq->desc + sq_desc_idx,
                    &sq->curr_tx_wqe, sizeof(struct efa_io_tx_wqe));  // ELIMINATE THIS
    // doorbell logic...
}

// New approach - no staging buffer, no memcpy:
void efa_write_wqe_direct(struct efa_data_path_direct_sq *sq, 
                         struct efa_wqe_params *params)
{
    uint32_t sq_desc_idx = (sq->wq.pc - 1) & sq->wq.desc_mask;
    struct efa_io_tx_wqe *wc_wqe = (struct efa_io_tx_wqe *)sq->desc + sq_desc_idx;
    
    // Write 64-bit words directly to WC memory
    efa_write_meta_words(wc_wqe, params);
    efa_write_sgl_words(wc_wqe, params);
    // doorbell logic...
}
```

**Modify High-Level Functions**:
- Update `efa_post_send()` in `efa_msg.c` to use consolidated direct writers
- Update `efa_rma_post_read()` and `efa_rma_post_write()` in `efa_rma.c`
- Ensure proper write-combined memory barriers

### Phase 4: Testing and Validation
- Performance benchmarking vs current implementation
- Functional testing across different WQE types (SEND, RDMA_READ, RDMA_WRITE)
- Stress testing for correctness
- Verify write-combined memory compliance (single write per word)

## Technical Details

### EFA_SET Macro Analysis:
```c
#define EFA_SET(ptr, mask, value)                       \
	({                                              \
		typeof(ptr) _ptr = ptr;                 \
		*_ptr = (*_ptr & ~(mask##_MASK)) |      \
			FIELD_PREP(mask##_MASK, value); \
	})
```

**Problem with EFA_SET for WC Memory**: This macro does read-modify-write, which violates the single-write constraint for write-combined memory.

**Solution**: Replace with direct bit field construction:
```c
// Instead of multiple EFA_SET calls:
EFA_SET(&desc->ctrl1, EFA_IO_TX_META_DESC_META_DESC, 1);
EFA_SET(&desc->ctrl1, EFA_IO_TX_META_DESC_OP_TYPE, op_type);
EFA_SET(&desc->ctrl1, EFA_IO_TX_META_DESC_HAS_IMM, has_imm);

// Use single word construction:
uint64_t ctrl1_word = FIELD_PREP(EFA_IO_TX_META_DESC_META_DESC_MASK, 1) |
                      FIELD_PREP(EFA_IO_TX_META_DESC_OP_TYPE_MASK, op_type) |
                      FIELD_PREP(EFA_IO_TX_META_DESC_HAS_IMM_MASK, has_imm);
*((uint64_t*)&wc_wqe->meta.ctrl1) = ctrl1_word;  // Single write
```

### Key Bit Fields to Optimize:
- `EFA_IO_TX_META_DESC_OP_TYPE_MASK` - GENMASK(3, 0) - bits 3:0
- `EFA_IO_TX_META_DESC_HAS_IMM_MASK` - BIT(4)
- `EFA_IO_TX_META_DESC_PHASE_MASK` - BIT(0)
- `EFA_IO_TX_META_DESC_FIRST_MASK` - BIT(2)
- `EFA_IO_TX_META_DESC_LAST_MASK` - BIT(3)
- `EFA_IO_TX_META_DESC_COMP_REQ_MASK` - BIT(4)

### Target Code Location:
- File: `prov/efa/src/efa_data_path_direct_internal.h`
- Function: `efa_data_path_direct_send_wr_post_working()` lines 270-271
- Current memcpy: `mmio_memcpy_x64((struct efa_io_tx_wqe *)sq->desc + sq_desc_idx, &sq->curr_tx_wqe, sizeof(struct efa_io_tx_wqe));`

## RDMA Operations Analysis

### RDMA READ Flow (`efa_rma_post_read`):
1. `efa_qp_wr_start(qp)` - Initialize WQE
2. `efa_qp_wr_rdma_read(qp, msg->rma_iov[0].key, msg->rma_iov[0].addr)` - Set remote memory info
3. `efa_qp_wr_set_sge_list(qp, msg->iov_count, sge_list)` - Set local buffers
4. `efa_qp_wr_set_ud_addr()` - Set addressing
5. `efa_qp_wr_complete(qp)` - Post WQE

### RDMA WRITE Flow (`efa_rma_post_write`):
1. `efa_qp_wr_start(qp)` - Initialize WQE
2. `efa_qp_wr_rdma_write(qp, key, addr)` or `efa_qp_wr_rdma_write_imm(qp, key, addr, data)` - Set remote memory info
3. `efa_qp_wr_set_sge_list(qp, msg->iov_count, sge_list)` - Set local buffers
4. `efa_qp_wr_set_ud_addr()` - Set addressing
5. `efa_qp_wr_complete(qp)` - Post WQE

### RDMA-Specific WQE Fields:
- Remote memory key (rkey)
- Remote memory address (64-bit, split into high/low)
- Operation type (RDMA_READ vs RDMA_WRITE)
- Immediate data (for RDMA_WRITE_IMM)

## Next Steps

### Immediate Actions:
1. **Examine `struct efa_io_tx_wqe` layout and alignment** - Map 64-bit word boundaries
2. **Create WQE parameter structure** - Design `struct efa_wqe_params` to hold all needed data
3. **Implement first consolidated function** - `efa_post_send_direct()` based on CUDA pattern
4. **Create word-building helpers** - Functions to construct 64-bit words with packed bit fields

### Implementation Sequence:
1. **SEND operations** - Start with basic send (simplest case)
2. **SEND_IMM operations** - Add immediate data handling
3. **RDMA_READ operations** - Add remote memory addressing
4. **RDMA_WRITE operations** - Complete RDMA support
5. **RDMA_WRITE_IMM operations** - Final operation type

### Validation Steps:
1. **Functional correctness** - Ensure all WQE fields are set correctly
2. **Performance benchmarking** - Measure improvement vs current implementation
3. **Write-combined memory compliance** - Verify single write per 64-bit word
4. **Integration testing** - Test with real applications and workloads

### Success Criteria:
- Eliminate `mmio_memcpy_x64()` call completely
- Reduce CPU cycles per WQE preparation
- Maintain functional correctness across all operation types
- Demonstrate measurable performance improvement

## Files to Modify
- `prov/efa/src/efa_data_path_direct_internal.h` - Core optimization functions
- `prov/efa/src/efa_msg.c` - Integration with MSG send path
- `prov/efa/src/efa_rma.c` - Integration with RDMA read/write paths
- `prov/efa/src/efa_io_defs.h` - Bit field definitions (reference)

## WQE Types to Optimize (All Equally Important)

### Core Operations (Implementation Order for Development):
1. **SEND** - Basic message send operations (start here - simplest to implement)
2. **SEND_IMM** - Send with immediate data (adds HAS_IMM bit + imm_data field)
3. **RDMA_READ** - Remote memory read operations
4. **RDMA_WRITE** - Remote memory write operations
5. **RDMA_WRITE_IMM** - Remote memory write with immediate data

### Common WQE Structure Elements:
- **Metadata**: dest_qp_num, ah, qkey, req_id, length
- **Control fields**: ctrl1 (META_DESC, OP_TYPE, HAS_IMM), ctrl2 (PHASE, FIRST, LAST, COMP_REQ)
- **SGL data**: lkey, length, buf_addr_lo, buf_addr_hi (for each SGE)
- **RDMA-specific**: remote_mem.rkey, remote_mem.buf_addr_lo, remote_mem.buf_addr_hi
- **Immediate data**: immediate_data field (when HAS_IMM=1)

## Success Metrics

### Performance Improvements:
- **Reduced CPU cycles per WQE preparation** - Eliminate memcpy overhead
- **Lower memory bandwidth utilization** - Single write per 64-bit word vs staging buffer + memcpy
- **Improved send operation latency** - Direct WC writes vs indirect staging
- **Better cache efficiency** - No staging buffer pollution

### Technical Compliance:
- **Write-combined memory compliance** - Each WC word written exactly once
- **Functional correctness** - All WQE fields set correctly across all operation types
- **Hardware compatibility** - Proper WC memory barriers and ordering

### Code Quality:
- **Function consolidation success** - Replace multiple `efa_qp_*` calls with single consolidated functions
- **Maintainability** - Clear, understandable direct-write functions
- **Extensibility** - Easy to add new operation types following the same pattern

### Measurable Targets:
- **Eliminate 100% of `mmio_memcpy_x64()` calls** in WQE posting path
- **Reduce memory operations by ~50%** (staging writes + memcpy → direct writes)
- **Maintain or improve throughput** for high-frequency send operations
- **Zero functional regressions** across all supported WQE types