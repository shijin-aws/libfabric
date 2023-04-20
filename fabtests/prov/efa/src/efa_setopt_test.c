/*
 * Copyright (c) Amazon Inc.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#include <stdio.h>
#include <rdma/fi_domain.h>
#include <rdma/fi_errno.h>
#include <rdma/fi_ext.h>

#include "unit_common.h"
#include "hmem.h"
#include "shared.h"

char err_buf[512];

int test_setopt(int optname)
{
	bool optval = true;
	int err, ret;

	err = fi_getinfo(FT_FIVERSION, NULL,
			 0, 0, hints, &fi);
	if (err) {
		ret = FAIL;
		FT_PRINTERR("fi_getinfo failed!",
				err);
		goto out;
	}

	err = ft_open_fabric_res();
	if (err) {
		ret = FAIL;
		FT_PRINTERR("open fabric resource failed!",
			       err);
		goto out;
	}

	err = fi_endpoint(domain, fi, &ep, NULL);
	if (err) {
		ret = FAIL;
		FT_PRINTERR("open endpoint failed!",
			       err);
		goto out;
	}

	err = fi_setopt(&ep->fid, FI_OPT_ENDPOINT,
			optname,
			&optval, sizeof(optval) );
	if (err) {
		fprintf(stderr, "fi_setopt failed! optname: %d, err: %d\n", optname, err);
		ret = FAIL;
	}

out:
	ft_close_fids(); /* close ep, eq, domain, fabric */
	return ret;
}

int main(int argc, char **argv)
{
	int op;
	int ret;
	int err;

	hints = fi_allocinfo();
	if (!hints) {
		FT_UNIT_STRERR(err_buf,
			       "hints allocationed failed!",
			       -FI_ENOMEM);
		return FAIL;
	}

	while ((op = getopt(argc, argv, FAB_OPTS HMEM_OPTS "h")) != -1) {
		switch (op) {
		default:
			ft_parseinfo(op, optarg, hints, &opts);
			break;
		case '?':
		case 'h':
			ft_usage(argv[0], "efa setopt test.");
			return EXIT_FAILURE;
		}
	}

	hints->mode = ~0;
	hints->domain_attr->mode = ~0;
	hints->domain_attr->mr_mode = ~(FI_MR_BASIC | FI_MR_SCALABLE);
	hints->caps |= FI_MSG;
	hints->fabric_attr->prov_name = strdup("efa");

	ret = 0;

	printf("testing setopt for FI_OPT_EFA_SENDRECV_IN_ORDER_ALIGNED_128_BYTES\n");
	err = test_setopt(FI_OPT_EFA_SENDRECV_IN_ORDER_ALIGNED_128_BYTES);
	if (err)
		ret = 1;

	printf("testing setopt for FI_OPT_EFA_WRITE_IN_ORDER_ALIGNED_128_BYTES\n");
	err = test_setopt(FI_OPT_EFA_WRITE_IN_ORDER_ALIGNED_128_BYTES);
	if (err)
		ret = 1;

	ft_free_res();
	return ret;
}
