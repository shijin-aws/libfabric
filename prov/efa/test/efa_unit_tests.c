/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/* SPDX-FileCopyrightText: Copyright Amazon.com, Inc. or its affiliates. All rights reserved. */

#include "efa_unit_tests.h"

struct efa_env orig_efa_env = {0};
struct efa_hmem_info g_efa_hmem_info_backup[OFI_HMEM_MAX];

/* Runs once before all tests */
static int efa_unit_test_mocks_group_setup(void **state)
{
	struct efa_resource *resource;
	struct fi_info *info;
	resource = calloc(1, sizeof(struct efa_resource));
	*state = resource;

	orig_efa_env = efa_env;

	/* run fi_getinfo to populate g_efa_hmem_info and copy it */
	fi_getinfo(FI_VERSION(2, 0), NULL, NULL, 0, NULL, &info);
	memcpy(g_efa_hmem_info_backup, g_efa_hmem_info, sizeof(g_efa_hmem_info));

	return 0;
}

/* Runs once after all tests */
static int efa_unit_test_mocks_group_teardown(void **state)
{
	struct efa_resource *resource = *state;
	free(resource);

	return 0;
}

/* Runs before every test */
static int efa_unit_test_mocks_setup(void **state)
{
	/* Zero out *resource */
	struct efa_resource *resource = *state;
	memset(resource, 0, sizeof(struct efa_resource));

	return 0;
}

/* Runs after every test */
static int efa_unit_test_mocks_teardown(void **state)
{
	struct efa_resource *resource = *state;

	/* Reset the contents of g_efa_hmem_info from backup */
	memcpy(g_efa_hmem_info, g_efa_hmem_info_backup, sizeof(g_efa_hmem_info));

	//efa_unit_test_resource_destruct(resource);

	efa_ibv_submitted_wr_id_vec_clear();

	g_efa_unit_test_mocks = (struct efa_unit_test_mocks) {
		.local_host_id = 0,
		.peer_host_id = 0,
		.ibv_create_ah = __real_ibv_create_ah,
		.efadv_query_device = __real_efadv_query_device,
#if HAVE_EFADV_CQ_EX
		.efadv_create_cq = __real_efadv_create_cq,
#endif
#if HAVE_NEURON
		.neuron_alloc = __real_neuron_alloc,
#endif
#if HAVE_CUDA
		.ofi_cudaMalloc = __real_ofi_cudaMalloc,
#endif
		.ofi_copy_from_hmem_iov = __real_ofi_copy_from_hmem_iov,
		.efa_rdm_pke_read = __real_efa_rdm_pke_read,
		.efa_rdm_pke_proc_matched_rtm = __real_efa_rdm_pke_proc_matched_rtm,
		.efa_rdm_ope_post_send = __real_efa_rdm_ope_post_send,
		.efa_device_support_unsolicited_write_recv = __real_efa_device_support_unsolicited_write_recv,
		.ibv_is_fork_initialized = __real_ibv_is_fork_initialized,
#if HAVE_EFADV_QUERY_MR
		.efadv_query_mr = __real_efadv_query_mr,
#endif
#if HAVE_EFA_DATA_IN_ORDER_ALIGNED_128_BYTES
		.ibv_query_qp_data_in_order = __real_ibv_query_qp_data_in_order,
#endif
#if HAVE_EFADV_QUERY_QP_WQS
		.efadv_query_qp_wqs = __real_efadv_query_qp_wqs,
#endif
#if HAVE_EFADV_QUERY_CQ
		.efadv_query_cq = __real_efadv_query_cq,
#endif
		.efa_qp_post_recv = __real_efa_qp_post_recv,
		.efa_qp_wr_complete = __real_efa_qp_wr_complete,
		.efa_qp_wr_rdma_read = __real_efa_qp_wr_rdma_read,
		.efa_qp_wr_rdma_write = __real_efa_qp_wr_rdma_write,
		.efa_qp_wr_rdma_write_imm = __real_efa_qp_wr_rdma_write_imm,
		.efa_qp_wr_send = __real_efa_qp_wr_send,
		.efa_qp_wr_send_imm = __real_efa_qp_wr_send_imm,
		.efa_qp_wr_set_inline_data_list = __real_efa_qp_wr_set_inline_data_list,
		.efa_qp_wr_set_sge_list = __real_efa_qp_wr_set_sge_list,
		.efa_qp_wr_set_ud_addr = __real_efa_qp_wr_set_ud_addr,
		.efa_qp_wr_start = __real_efa_qp_wr_start,
		.efa_ibv_cq_start_poll = __real_efa_ibv_cq_start_poll,
		.efa_ibv_cq_next_poll = __real_efa_ibv_cq_next_poll,
		.efa_ibv_cq_read_opcode = __real_efa_ibv_cq_read_opcode,
		.efa_ibv_cq_end_poll = __real_efa_ibv_cq_end_poll,
		.efa_ibv_cq_read_qp_num = __real_efa_ibv_cq_read_qp_num,
		.efa_ibv_cq_read_vendor_err = __real_efa_ibv_cq_read_vendor_err,
		.efa_ibv_cq_read_src_qp = __real_efa_ibv_cq_read_src_qp,
		.efa_ibv_cq_read_slid = __real_efa_ibv_cq_read_slid,
		.efa_ibv_cq_read_byte_len = __real_efa_ibv_cq_read_byte_len,
		.efa_ibv_cq_read_wc_flags = __real_efa_ibv_cq_read_wc_flags,
		.efa_ibv_cq_read_imm_data = __real_efa_ibv_cq_read_imm_data,
		.efa_ibv_cq_wc_is_unsolicited = __real_efa_ibv_cq_wc_is_unsolicited,
		.efa_ibv_cq_read_sgid = __real_efa_ibv_cq_read_sgid,
	};

	/* Reset environment */
	efa_env = orig_efa_env;
	unsetenv("FI_EFA_FORK_SAFE");
	unsetenv("FI_EFA_USE_DEVICE_RDMA");

	return 0;
}

int main(void)
{
	int ret;
	/* Requires an EFA device to work */
	const struct CMUnitTest efa_unit_tests[] = {
		

		cmocka_unit_test_setup_teardown(test_efa_cq_read_no_completion, efa_unit_test_mocks_setup, efa_unit_test_mocks_teardown),
		cmocka_unit_test_setup_teardown(test_efa_cq_read_send_success, efa_unit_test_mocks_setup, efa_unit_test_mocks_teardown),
		cmocka_unit_test_setup_teardown(test_efa_cq_read_senddata_success, efa_unit_test_mocks_setup, efa_unit_test_mocks_teardown),
		cmocka_unit_test_setup_teardown(test_efa_cq_read_write_success, efa_unit_test_mocks_setup, efa_unit_test_mocks_teardown),
		cmocka_unit_test_setup_teardown(test_efa_cq_read_writedata_success, efa_unit_test_mocks_setup, efa_unit_test_mocks_teardown),
		cmocka_unit_test_setup_teardown(test_efa_cq_read_read_success, efa_unit_test_mocks_setup, efa_unit_test_mocks_teardown),
		cmocka_unit_test_setup_teardown(test_efa_cq_read_recv_success, efa_unit_test_mocks_setup, efa_unit_test_mocks_teardown),
		cmocka_unit_test_setup_teardown(test_efa_cq_read_recv_rdma_with_imm_success, efa_unit_test_mocks_setup, efa_unit_test_mocks_teardown),



		
	};

	cmocka_set_message_output(CM_OUTPUT_XML);

	ret = cmocka_run_group_tests_name("efa unit tests", efa_unit_tests, efa_unit_test_mocks_group_setup, efa_unit_test_mocks_group_teardown);

	return ret;
}
