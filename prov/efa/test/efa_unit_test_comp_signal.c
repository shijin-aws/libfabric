/* SPDX-FileCopyrightText: Copyright Amazon.com, Inc. or its affiliates. All rights reserved. */
/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */

#include "efa_unit_tests.h"
#include "rdma/fi_ext.h"

/**
 * @brief Open the EFA signal ops on an efa-direct domain (EP not enabled).
 *
 * Returns the ops pointer; the endpoint is left un-enabled so that setopt-based
 * tests can still configure the endpoint.
 */
static struct fi_efa_ops_signal *
efa_unit_test_comp_signal_open_signal_ops(struct efa_resource *resource)
{
	struct fi_efa_ops_signal *efa_signal_ops = NULL;
	int ret;

	efa_unit_test_resource_construct_ep_not_enabled(resource, FI_EP_RDM,
							EFA_DIRECT_FABRIC_NAME);

	ret = fi_open_ops(&resource->domain->fid, FI_EFA_SIGNAL_OPS, 0,
			  (void **) &efa_signal_ops, NULL);
	assert_int_equal(ret, 0);
	assert_non_null(efa_signal_ops);

	return efa_signal_ops;
}

/**
 * @brief The signal ops table exposes the completion-with-signal control path.
 */
void test_efa_comp_signal_gda_ops_present(void **state)
{
	struct efa_resource *resource = *state;
	struct fi_efa_ops_signal *efa_signal_ops;

	efa_signal_ops = efa_unit_test_comp_signal_open_signal_ops(resource);

	assert_non_null(efa_signal_ops->create_comp_mem_op);
	assert_non_null(efa_signal_ops->destroy_comp_mem_op);
	assert_non_null(efa_signal_ops->register_signal);
	assert_non_null(efa_signal_ops->deregister_signal);
	assert_non_null(efa_signal_ops->query_max_comp_mem_ops);
}

/**
 * @brief query_max_comp_mem_ops rejects NULL and, when supported, returns a value.
 */
void test_efa_comp_signal_query_limits(void **state)
{
	struct efa_resource *resource = *state;
	struct fi_efa_ops_signal *efa_signal_ops;
	uint32_t max_comp_mem_ops = 0;
	int ret;

	efa_signal_ops = efa_unit_test_comp_signal_open_signal_ops(resource);

	/* NULL out param rejected. */
	ret = efa_signal_ops->query_max_comp_mem_ops(resource->domain, NULL);
	assert_int_equal(ret, -FI_EINVAL);

	/* Valid query succeeds (value may be 0 on unsupported HW). */
	ret = efa_signal_ops->query_max_comp_mem_ops(resource->domain,
						     &max_comp_mem_ops);
	assert_int_equal(ret, FI_SUCCESS);
}

/**
 * @brief create_comp_mem_op rejects NULL arguments regardless of hardware.
 */
void test_efa_comp_signal_create_mem_op_invalid_args(void **state)
{
	struct efa_resource *resource = *state;
	struct fi_efa_ops_signal *efa_signal_ops;
	struct fi_efa_comp_mem_op_attr attr = {0};
	uint32_t comp_mem_id = 0;
	int ret;

	efa_signal_ops = efa_unit_test_comp_signal_open_signal_ops(resource);

	/* NULL attr */
	ret = efa_signal_ops->create_comp_mem_op(resource->domain, NULL,
						 &comp_mem_id);
	assert_int_equal(ret, -FI_EINVAL);

	/* NULL out id */
	ret = efa_signal_ops->create_comp_mem_op(resource->domain, &attr, NULL);
	assert_int_equal(ret, -FI_EINVAL);
}

/**
 * @brief register_signal rejects NULL arguments regardless of hardware.
 */
void test_efa_comp_signal_register_invalid_args(void **state)
{
	struct efa_resource *resource = *state;
	struct fi_efa_ops_signal *efa_signal_ops;
	struct fi_efa_comp_signal_attr attr = {0};
	uint32_t signal_id = 0;
	int ret;

	efa_signal_ops = efa_unit_test_comp_signal_open_signal_ops(resource);

	ret = efa_signal_ops->register_signal(resource->domain, NULL,
					      &signal_id);
	assert_int_equal(ret, -FI_EINVAL);

	ret = efa_signal_ops->register_signal(resource->domain, &attr, NULL);
	assert_int_equal(ret, -FI_EINVAL);
}

/**
 * @brief deregister_signal / destroy_comp_mem_op reject unknown IDs.
 */
void test_efa_comp_signal_deregister_unknown_id(void **state)
{
	struct efa_resource *resource = *state;
	struct fi_efa_ops_signal *efa_signal_ops;
	int ret;

	efa_signal_ops = efa_unit_test_comp_signal_open_signal_ops(resource);

	ret = efa_signal_ops->deregister_signal(resource->domain, 0xdeadbeef);
	assert_int_equal(ret, -FI_EINVAL);

	ret = efa_signal_ops->destroy_comp_mem_op(resource->domain, 0xdeadbeef);
	assert_int_equal(ret, -FI_EINVAL);
}

/**
 * @brief FI_OPT_EFA_COMP_SIGNAL rejects a wrong optlen.
 */
void test_efa_comp_signal_setopt_bad_optlen(void **state)
{
	struct efa_resource *resource = *state;
	int intval = 1;
	int ret;

	efa_unit_test_resource_construct_ep_not_enabled(resource, FI_EP_RDM,
							EFA_DIRECT_FABRIC_NAME);

	ret = fi_setopt(&resource->ep->fid, FI_OPT_ENDPOINT,
			FI_OPT_EFA_COMP_SIGNAL, &intval, sizeof(intval));
	assert_int_equal(ret, -FI_EINVAL);
}

/**
 * @brief Disabling FI_OPT_EFA_COMP_SIGNAL (optval=false) always succeeds and
 * leaves the endpoint's signal support off.
 */
void test_efa_comp_signal_setopt_disable(void **state)
{
	struct efa_resource *resource = *state;
	struct efa_base_ep *base_ep;
	bool optval = false;
	int ret;

	efa_unit_test_resource_construct_ep_not_enabled(resource, FI_EP_RDM,
							EFA_DIRECT_FABRIC_NAME);

	base_ep = container_of(resource->ep, struct efa_base_ep,
			       util_ep.ep_fid);
	assert_false(base_ep->comp_signal_enabled);

	ret = fi_setopt(&resource->ep->fid, FI_OPT_ENDPOINT,
			FI_OPT_EFA_COMP_SIGNAL, &optval, sizeof(optval));
	assert_int_equal(ret, FI_SUCCESS);
	assert_false(base_ep->comp_signal_enabled);
}

/**
 * @brief FI_EFA_EXTENDED_MSG on fi_writemsg is rejected when the endpoint has
 * not enabled signal support.
 */
void test_efa_comp_signal_writemsg_requires_enable(void **state)
{
	struct efa_resource *resource = *state;
	struct efa_base_ep *base_ep;
	struct fi_efa_msg_rma emsg = {0};
	struct iovec iov = {0};
	struct fi_rma_iov rma_iov = {0};
	uint8_t buf[8] = {0};
	void *desc = NULL;
	ssize_t ret;

	efa_unit_test_resource_construct(resource, FI_EP_RDM,
					 EFA_DIRECT_FABRIC_NAME);

	base_ep = container_of(resource->ep, struct efa_base_ep,
			       util_ep.ep_fid);
	assert_false(base_ep->comp_signal_enabled);

	iov.iov_base = buf;
	iov.iov_len = sizeof(buf);
	rma_iov.addr = 0x1000;
	rma_iov.len = sizeof(buf);
	rma_iov.key = 0x1;

	emsg.msg.msg_iov = &iov;
	emsg.msg.iov_count = 1;
	emsg.msg.desc = &desc;
	emsg.msg.addr = 0;
	emsg.msg.rma_iov = &rma_iov;
	emsg.msg.rma_iov_count = 1;
	emsg.feature_bits = FI_EFA_REMOTE_SIGNAL_ID;
	emsg.remote_signal_id = 7;

	ret = fi_writemsg(resource->ep, (struct fi_msg_rma *) &emsg,
			  FI_EFA_EXTENDED_MSG);
	assert_int_equal(ret, -FI_EINVAL);
}
