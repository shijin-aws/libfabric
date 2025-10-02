/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/* SPDX-FileCopyrightText: Copyright Amazon.com, Inc. or its affiliates. All rights reserved. */

#include "config.h"

#if HAVE_EFA_DATA_PATH_DIRECT

#include "efa_data_path_direct_internal.h"
#include "efa_mmio.h"

void
efa_data_path_direct_send_wr_post_working(struct efa_data_path_direct_sq *sq,
					  bool force_doorbell)
{
	uint32_t sq_desc_idx;
	uint64_t *src, *dst;

	sq_desc_idx = (sq->wq.pc - 1) & sq->wq.desc_mask;
	src = (uint64_t *)&sq->curr_tx_wqe;
	dst = (uint64_t *)((struct efa_io_tx_wqe *)sq->desc + sq_desc_idx);

	/* Copy 64-byte WQE using 8 uint64_t stores */
	for (int i = 0; i < 8; i++)
		dst[i] = src[i];

	/* this routine only rings the doorbell if it must. */
	if (force_doorbell) {
		mmio_flush_writes();
		efa_sq_ring_doorbell(sq, sq->wq.pc);
		mmio_wc_start();
		sq->num_wqe_pending = 0;
	}
}

#endif /* HAVE_EFA_DATA_PATH_DIRECT */