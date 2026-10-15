/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/* SPDX-FileCopyrightText: Copyright Amazon.com, Inc. or its affiliates. All
 * rights reserved. */

/*
 * fi_efa_rdm_rq_double_consume
 * ============================
 *
 * Option-A integration reproducer for "EFA Signature A": the EFA device
 * completing a single RQ work request twice under an RNR-retry storm when
 * several QPs share one NIC, which libfabric's efa-rdm provider then turns
 * into an RX free-list double-release (-> SIGSEGV, "tail" case) or a
 * self-looping free list (-> "zombie rail", non-tail case).
 *
 * This test does NOT inject anything into the provider. It only drives the
 * trigger conditions described in the analysis (section 3.1) on real
 * hardware and reports what it observes.
 *
 * Trigger conditions recreated (receiver side):
 *   1. FI_EFA_USE_UNSOLICITED_WRITE_RECV = off  (fi_setopt per endpoint), so
 *      every write-with-immediate consumes one provider RX-pool entry.
 *   2. Several busy QPs on one NIC: --qps-per-nic K endpoints per NIC, each
 *      fed by exactly one writer QP on the peer. --shared-cq binds all K
 *      endpoints of a NIC to one CQ (one ibv_cq), otherwise one CQ each.
 *   3. A small RX pool (FI_EFA_RX_SIZE, default 64) so the RQ drains to empty
 *      quickly and the writers enter hardware RNR retry.
 *   4. Periodic receiver poll stalls (--stall-ms every --stall-period-ms) so
 *      the RQ stays empty for seconds while the writers keep their window of
 *      writes in RNR retry -- the window the duplicate CQE appears in.
 *
 * Trigger conditions recreated (sender side):
 *   - A --window-deep (default 64) window of outstanding
 *     fi_writemsg(FI_REMOTE_CQ_DATA | FI_COMPLETION) per QP, alternating
 *     --size (default 1 MiB) and --size-small (default 30412 B) payloads,
 *     landing in host memory or, with --gpu-target, CUDA memory.
 *     Each immediate is unique: [slot:6][seq:26].
 *   - Writer QP churn (--churn-period-ms): every period each sender NIC
 *     thread closes one of its endpoints with writes still in flight (like
 *     the SIGKILL in the report), opens a new one, and hands the new address
 *     to the receiver, which fi_av_remove()s the old peer and inserts the new.
 *
 * What the receiver detects and reports:
 *   - "Received packet from wrong generation!" from efa-rdm. The test imports
 *     a libfabric log handler and counts it directly, so no FI_LOG_LEVEL is
 *     needed. This is the provider-side fingerprint of a duplicate RQ CQE.
 *     With a --enable-debug libfabric the provider's assert fires on the
 *     first one instead (SIGABRT, caught below).
 *   - SIGSEGV/SIGABRT while polling the CQ (tail case).
 *   - LOCAL_ERROR_QP_INTERNAL_ERROR (status 2) RX errors, on the CQ and on
 *     the EQ (where efa-rdm reports errors on provider RX-pool packets).
 *   - Duplicate immediates (a re-emitted completion), immediates delivered
 *     on a CQ that does not own their QP (misrouted), and acked writes that
 *     never produced a completion (lost).
 *   - A completion stall (zombie rail): no user completion for 30 s.
 *
 * The receiver exits non-zero if any of wrong-generation, duplicate,
 * misrouted, lost or a crash was observed.
 *
 * Run (two nodes, 8 NICs x 8 QPs):
 *   # receiver
 *   ./fi_efa_rdm_rq_double_consume --nics 8 --qps-per-nic 8 \
 *       --rx-size 64 --stall-ms 5000 --stall-period-ms 20000 \
 *       --churn-period-ms 10000 --run-seconds 720
 *   # sender (same --nics / --qps-per-nic)
 *   ./fi_efa_rdm_rq_double_consume <receiver-ip> --nics 8 --qps-per-nic 8 \
 *       --churn-period-ms 10000 --run-seconds 720
 */

#include <getopt.h>
#include <inttypes.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <rdma/fabric.h>
#include <rdma/fi_cm.h>
#include <rdma/fi_domain.h>
#include <rdma/fi_endpoint.h>
#include <rdma/fi_errno.h>
#include <rdma/fi_ext.h>
#include <rdma/fi_rma.h>

#include "hmem.h"
#include "shared.h"
#include "efa_shared.h"

#define MAX_NICS 16
#define MAX_QPS_PER_NIC 16
#define SLOT_BITS 6
#define SEQ_BITS 26
#define MAX_SLOTS (1 << SLOT_BITS)
#define SEQ_MAX ((1u << SEQ_BITS) - 1)
#define IMM(slot, seq) (((uint32_t) (slot) << SEQ_BITS) | (uint32_t) (seq))
#define IMM_SLOT(imm) ((uint32_t) (imm) >> SEQ_BITS)
#define IMM_SEQ(imm) ((uint32_t) (imm) & SEQ_MAX)

/* EFA_IO_COMP_STATUS_LOCAL_ERROR_QP_INTERNAL_ERROR, see prov/efa efa_errno.h */
#define EFA_STATUS_QP_INTERNAL_ERROR 2

#define ZOMBIE_SEC 30.0
#define DRAIN_SEC 5.0

struct test_opts {
	int nics;		/* NICs (domains) */
	int qps_per_nic;	/* endpoints == QPs per NIC */
	bool shared_cq;		/* receiver: one CQ per NIC for all its QPs */
	bool gpu_target;	/* receiver: writes land in CUDA memory */
	int rx_size;		/* FI_EFA_RX_SIZE: provider RX pool size */
	int window_deep;	/* outstanding writes per QP */
	size_t size_big;	/* large write payload */
	size_t size_small;	/* small write payload */
	int stall_ms;		/* receiver poller stall duration */
	int stall_period_ms;	/* receiver poller stall period */
	int churn_period_ms;	/* sender QP churn period per NIC, 0 = off */
	int run_seconds;	/* total run time budget */
	int stats_sec;		/* hw counter sampling period, 0 = off */
};

static struct test_opts topts = {
	.nics = 8,
	.qps_per_nic = 1,
	.shared_cq = false,
	.gpu_target = false,
	.rx_size = 64,
	.window_deep = 64,
	.size_big = 1048576,
	.size_small = 30412,
	.stall_ms = 5000,
	.stall_period_ms = 20000,
	.churn_period_ms = 0,
	.run_seconds = 720,
	.stats_sec = 5,
};

enum {
	OPT_NICS = 512,
	OPT_QPS_PER_NIC,
	OPT_SHARED_CQ,
	OPT_GPU_TARGET,
	OPT_RX_SIZE,
	OPT_WINDOW_DEEP,
	OPT_SIZE_SMALL,
	OPT_STALL_MS,
	OPT_STALL_PERIOD_MS,
	OPT_CHURN_PERIOD_MS,
	OPT_RUN_SECONDS,
	OPT_STATS_SEC,
};

static struct option rq_long_opts[] = {
	{"nics", required_argument, NULL, OPT_NICS},
	{"qps-per-nic", required_argument, NULL, OPT_QPS_PER_NIC},
	{"shared-cq", no_argument, NULL, OPT_SHARED_CQ},
	{"gpu-target", no_argument, NULL, OPT_GPU_TARGET},
	{"rx-size", required_argument, NULL, OPT_RX_SIZE},
	{"window-deep", required_argument, NULL, OPT_WINDOW_DEEP},
	{"size", required_argument, NULL, 'S'},
	{"size-small", required_argument, NULL, OPT_SIZE_SMALL},
	{"stall-ms", required_argument, NULL, OPT_STALL_MS},
	{"stall-period-ms", required_argument, NULL, OPT_STALL_PERIOD_MS},
	{"churn-period-ms", required_argument, NULL, OPT_CHURN_PERIOD_MS},
	{"run-seconds", required_argument, NULL, OPT_RUN_SECONDS},
	{"stats-sec", required_argument, NULL, OPT_STATS_SEC},
	{0, 0, 0, 0}
};

/* RMA target info the receiver advertises to the sender, per NIC. */
struct rma_target {
	uint64_t addr;
	uint64_t key;
};

/* Run-time control messages, sender -> receiver over the OOB socket. */
enum {
	CTRL_CHURN = 1,	/* payload: new raw address of slot */
	CTRL_END,	/* payload: uint64_t acked[nslots] */
};

struct ctrl_hdr {
	uint32_t type;
	uint32_t slot;
};

/* One endpoint (QP). slot = nic * qps_per_nic + q, identical on both sides. */
struct ep_slot {
	int slot;
	struct nic *nic;
	struct fid_ep *ep;
	struct fid_cq *cq;	/* own CQ, or the NIC's shared CQ */
	struct fid_av *av;
	fi_addr_t peer;
	char peer_raw[FT_MAX_CTRL_MSG];

	/* sender */
	uint32_t seq;
	uint64_t outstanding;
	uint64_t off;
	uint64_t acked;		/* writes with a successful tx completion */
	uint64_t tx_err;
	uint64_t churns;

	/* receiver */
	uint8_t *seen;		/* bitmap over seq */
	uint64_t good;
	uint64_t dup;
	uint64_t misrouted;
	uint64_t qp_internal_err;
	uint64_t other_err;
	uint64_t peer_acked;	/* from CTRL_END */
};

/* Per-NIC fabric resources. */
struct nic {
	int idx;
	char dev[64];		/* ibv device name, for hw_counters */
	struct fi_info *info;
	struct fid_fabric *fabric;
	struct fid_domain *domain;
	struct fid_eq *eq;
	struct fid_cq *shared_cq;
	struct fid_mr *mr;
	void *buf;		/* MR region (write target on rx, src on tx) */
	enum fi_hmem_iface iface;
	size_t buf_len;
	struct rma_target tgt;	/* sender: the receiver's target on this NIC */
	struct ep_slot slots[MAX_QPS_PER_NIC];
	uint64_t zombies;
	uint64_t eq_qp_internal_err;	/* RX errors on non-RX packets */
	uint64_t eq_other_err;
};

static struct nic nics[MAX_NICS];
static int nslots;
static bool is_sender;
static pthread_mutex_t oob_lock = PTHREAD_MUTEX_INITIALIZER;
static volatile sig_atomic_t g_in_cq_poll;
static volatile sig_atomic_t g_crashed;
static volatile int g_end_seen;
static double g_end_time;
static uint64_t g_wrong_gen;

static struct ep_slot *slot_of(int s)
{
	return &nics[s / topts.qps_per_nic].slots[s % topts.qps_per_nic];
}

static double now_sec(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec + ts.tv_nsec / 1e9;
}

/* Wall clock, so receiver and sender logs line up across nodes. */
static double wall_sec(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
	return ts.tv_sec + ts.tv_nsec / 1e9;
}

/* ---- EFA hw counters ----------------------------------------------------- */

/*
 * efa-rdm handles RNR internally under FI_RM_ENABLED and only logs it at
 * debug level (compiled out in release builds). Each write WR the device
 * fails after its RNR retries is counted in the sender NIC's
 * rdma_write_wr_err, so sample that (and a few receiver-side counters)
 * instead of touching the provider.
 */
static const char *tx_counters[] = {
	"rdma_write_wr_err", "retrans_pkts", "retrans_timeout_events",
};
static const char *rx_counters[] = {
	"rx_drops", "impaired_remote_conn_events", "unresponsive_remote_events",
};
#define NUM_HW_COUNTERS 3

static uint64_t hw_counter(const char *dev, const char *name)
{
	char path[256];
	unsigned long long v = 0;
	FILE *f;

	snprintf(path, sizeof(path),
		 "/sys/class/infiniband/%s/ports/1/hw_counters/%s", dev, name);
	f = fopen(path, "r");
	if (!f)
		return 0;
	if (fscanf(f, "%llu", &v) != 1)
		v = 0;
	fclose(f);
	return v;
}

static volatile int g_stats_stop;

/*
 * efa-rdm RNR backoff log lines (warn level only with the local provider
 * patch that lifts them from EFA_DBG), counted by log_msg().
 */
enum { RNR_BACKOFF_INIT, RNR_BACKOFF_INC, RNR_BACKOFF_RESET, RNR_KINDS };
static const struct {
	const char *match;
	const char *name;
} rnr_kinds[RNR_KINDS] = {
	{ "initializing backoff timeout", "backoff_init" },
	{ "increasing backoff timeout", "backoff_inc" },
	{ "reset backoff timer", "backoff_reset" },
};
static uint64_t g_rnr[RNR_KINDS];

static void *stats_thread(void *arg)
{
	const char **names = is_sender ? tx_counters : rx_counters;
	uint64_t base[MAX_NICS][NUM_HW_COUNTERS];
	uint64_t prev[MAX_NICS][NUM_HW_COUNTERS];
	uint64_t cur, total, rnr_prev[RNR_KINDS] = {0}, rnr_cur[RNR_KINDS];
	char line[1024];
	int i, c, k, len, waited;

	for (i = 0; i < topts.nics; i++)
		for (c = 0; c < NUM_HW_COUNTERS; c++)
			base[i][c] = prev[i][c] = hw_counter(nics[i].dev, names[c]);

	while (!g_stats_stop) {
		for (waited = 0; waited < topts.stats_sec * 10 && !g_stats_stop;
		     waited++)
			usleep(100000);

		for (c = 0; c < NUM_HW_COUNTERS; c++) {
			len = snprintf(line, sizeof(line), "%.3f hw %s:",
				       wall_sec(), names[c]);
			total = 0;
			for (i = 0; i < topts.nics; i++) {
				cur = hw_counter(nics[i].dev, names[c]);
				total += cur - prev[i][c];
				len += snprintf(line + len, sizeof(line) - len,
						" %" PRIu64, cur - prev[i][c]);
				prev[i][c] = cur;
			}
			/* Quiet periods stay out of the log. */
			if (total || g_stats_stop)
				fprintf(stderr, "%s%s\n", line,
					g_stats_stop ? " (final)" : "");
		}

		total = 0;
		for (k = 0; k < RNR_KINDS; k++) {
			rnr_cur[k] = __atomic_load_n(&g_rnr[k], __ATOMIC_RELAXED);
			total += rnr_cur[k] - rnr_prev[k];
		}
		if (total)
			fprintf(stderr, "%.3f prov rnr: %s +%" PRIu64
				" %s +%" PRIu64 " %s +%" PRIu64 "\n", wall_sec(),
				rnr_kinds[0].name, rnr_cur[0] - rnr_prev[0],
				rnr_kinds[1].name, rnr_cur[1] - rnr_prev[1],
				rnr_kinds[2].name, rnr_cur[2] - rnr_prev[2]);
		memcpy(rnr_prev, rnr_cur, sizeof(rnr_prev));
	}

	for (k = 0; k < RNR_KINDS; k++)
		printf("prov rnr %s over run: %" PRIu64 "\n", rnr_kinds[k].name,
		       __atomic_load_n(&g_rnr[k], __ATOMIC_RELAXED));

	for (c = 0; c < NUM_HW_COUNTERS; c++) {
		total = 0;
		for (i = 0; i < topts.nics; i++)
			total += prev[i][c] - base[i][c];
		printf("hw %s over run: %" PRIu64 "\n", names[c], total);
	}
	return NULL;
}

/* ---- provider log hook --------------------------------------------------- */

/*
 * efa-rdm only warns (assert compiled out in release builds) when a CQE
 * resolves to a packet entry of a different generation. Import a log handler
 * so the test counts those directly instead of relying on a later crash.
 */
static int log_enabled(const struct fi_provider *prov, enum fi_log_level level,
		       enum fi_log_subsys subsys, uint64_t flags)
{
	return level <= FI_LOG_WARN;
}

static int log_ready(const struct fi_provider *prov, enum fi_log_level level,
		     enum fi_log_subsys subsys, uint64_t flags,
		     uint64_t *showtime)
{
	return log_enabled(prov, level, subsys, flags);
}

static void log_msg(const struct fi_provider *prov, enum fi_log_level level,
		    enum fi_log_subsys subsys, const char *func, int line,
		    const char *msg)
{
	uint64_t n;
	int k;

	for (k = 0; k < RNR_KINDS; k++) {
		if (!strstr(msg, rnr_kinds[k].match))
			continue;
		/* Can fire per retransmitted packet: count, print a sample. */
		n = __atomic_add_fetch(&g_rnr[k], 1, __ATOMIC_RELAXED);
		if (n <= 3)
			fprintf(stderr, "%.3f libfabric:%s:%s():%d %s",
				wall_sec(), prov->name, func, line, msg);
		return;
	}

	if (strstr(msg, "wrong generation")) {
		n = __atomic_add_fetch(&g_wrong_gen, 1, __ATOMIC_RELAXED);
		if (n > 10 && (n % 1000) != 0)
			return;
		fprintf(stderr, "%.3f *** WRONG GENERATION #%" PRIu64 " %s:%d %s",
			wall_sec(), n, func, line, msg);
		return;
	}
	fprintf(stderr, "%.3f libfabric:%s:%s():%d %s", wall_sec(), prov->name,
		func, line, msg);
}

static struct fi_ops_log rq_log_ops = {
	.enabled = log_enabled,
	.ready = log_ready,
	.log = log_msg,
};

static struct fid_logging rq_log_fid = {
	.ops = &rq_log_ops,
};

/* ---- crash classification ------------------------------------------------ */

static void crash_handler(int sig)
{
	static const char msg1[] =
		"\n*** rq_double_consume: fatal signal WHILE polling CQ ***\n"
		"*** Signature-A crash: a duplicate RQ completion on a live QP\n"
		"*** collapsed the efa-rdm RX free list (or a debug build's\n"
		"*** generation assert fired).\n";
	static const char msg2[] =
		"\n*** rq_double_consume: fatal signal OUTSIDE CQ poll ***\n";

	if (g_in_cq_poll)
		(void) !write(STDERR_FILENO, msg1, sizeof(msg1) - 1);
	else
		(void) !write(STDERR_FILENO, msg2, sizeof(msg2) - 1);

	g_crashed = 1;
	signal(sig, SIG_DFL);
	raise(sig);
}

static void install_crash_handlers(void)
{
	struct sigaction sa = {0};
	sa.sa_handler = crash_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_NODEFER;
	sigaction(SIGSEGV, &sa, NULL);
	sigaction(SIGABRT, &sa, NULL);
	sigaction(SIGBUS, &sa, NULL);
}

/* ---- per-NIC / per-QP setup ---------------------------------------------- */

static int cq_open(struct nic *n, struct fid_cq **cq, int neps)
{
	struct fi_cq_attr cqattr = {0};
	int ret;

	cqattr.format = FI_CQ_FORMAT_DATA;
	cqattr.wait_obj = FI_WAIT_NONE;
	cqattr.size = (n->info->rx_attr->size + n->info->tx_attr->size) * neps;
	/* A CQ shared by many QPs can exceed the device's max CQ depth. */
	while ((ret = fi_cq_open(n->domain, &cqattr, cq, NULL)) == -FI_EINVAL &&
	       neps > 1 && cqattr.size > n->info->rx_attr->size)
		cqattr.size /= 2;
	if (ret)
		FT_PRINTERR("fi_cq_open", ret);
	else if (neps > 1 && n->idx == 0)
		printf("shared CQ size %zu for %d QPs\n", cqattr.size, neps);
	return ret;
}

static int nic_open(struct nic *n, const char *domain_name)
{
	struct fi_info *hints;
	struct fi_eq_attr eqattr = {0};
	uint64_t access;
	int ret;

	hints = fi_allocinfo();
	if (!hints)
		return -FI_ENOMEM;

	hints->caps = FI_MSG | FI_RMA;
	hints->mode = 0;
	hints->ep_attr->type = FI_EP_RDM;
	hints->domain_attr->mr_mode = FI_MR_LOCAL | FI_MR_ALLOCATED |
				      FI_MR_VIRT_ADDR | FI_MR_PROV_KEY;
	hints->domain_attr->resource_mgmt = FI_RM_ENABLED;
	if (n->iface != FI_HMEM_SYSTEM) {
		hints->caps |= FI_HMEM;
		hints->domain_attr->mr_mode |= FI_MR_HMEM;
	}
	/* The receiver's control thread mutates AVs while rails poll. */
	hints->domain_attr->threading = FI_THREAD_SAFE;
	hints->fabric_attr->prov_name = strdup("efa");
	hints->domain_attr->name = strdup(domain_name);

	ret = fi_getinfo(FI_VERSION(1, 20), NULL, NULL, 0, hints, &n->info);
	fi_freeinfo(hints);
	if (ret) {
		FT_PRINTERR("fi_getinfo", ret);
		return ret;
	}
	if (n->info->domain_attr->cq_data_size < sizeof(uint32_t)) {
		fprintf(stderr, "cq_data_size %zu < 4\n",
			n->info->domain_attr->cq_data_size);
		return -FI_EINVAL;
	}

	ret = fi_fabric(n->info->fabric_attr, &n->fabric, NULL);
	if (ret) { FT_PRINTERR("fi_fabric", ret); return ret; }

	ret = fi_domain(n->fabric, n->info, &n->domain, NULL);
	if (ret) { FT_PRINTERR("fi_domain", ret); return ret; }

	eqattr.wait_obj = FI_WAIT_NONE;
	ret = fi_eq_open(n->fabric, &eqattr, &n->eq, NULL);
	if (ret) { FT_PRINTERR("fi_eq_open", ret); return ret; }

	if (!is_sender && topts.shared_cq) {
		ret = cq_open(n, &n->shared_cq, topts.qps_per_nic);
		if (ret)
			return ret;
	}

	/* MR: receiver is the remote write target; sender uses it as source.
	 * All QPs of a NIC share it; payload contents are not checked. */
	n->buf_len = topts.size_big * (size_t) (topts.window_deep + 1);
	if (n->iface == FI_HMEM_SYSTEM) {
		n->buf = calloc(1, n->buf_len);
		if (!n->buf)
			return -FI_ENOMEM;
	} else {
		ret = ft_hmem_alloc(n->iface, n->idx % 8, &n->buf, n->buf_len);
		if (ret) { FT_PRINTERR("ft_hmem_alloc", ret); return ret; }
	}

	access = is_sender ? (FI_WRITE | FI_SEND) : (FI_REMOTE_WRITE | FI_RECV);
	ret = ft_reg_mr_dom(n->domain, NULL, n->info, n->buf, n->buf_len,
			    access, 0, n->iface, n->idx % 8, &n->mr, NULL);
	if (ret) { FT_PRINTERR("ft_reg_mr_dom", ret); return ret; }

	return 0;
}

static int slot_open(struct ep_slot *s)
{
	struct nic *n = s->nic;
	struct fi_av_attr avattr = {0};
	bool off = false, homo = true;
	int ret;

	if (n->shared_cq) {
		s->cq = n->shared_cq;
	} else {
		ret = cq_open(n, &s->cq, 1);
		if (ret)
			return ret;
	}

	avattr.type = FI_AV_TABLE;
	avattr.count = 4;
	ret = fi_av_open(n->domain, &avattr, &s->av, NULL);
	if (ret) { FT_PRINTERR("fi_av_open", ret); return ret; }

	ret = fi_endpoint(n->domain, n->info, &s->ep, NULL);
	if (ret) { FT_PRINTERR("fi_endpoint", ret); return ret; }

	/* Core of the trigger: turn unsolicited write recv OFF so every
	 * write-with-immediate consumes a provider RX pool entry. */
	ret = fi_setopt(&s->ep->fid, FI_OPT_ENDPOINT,
			FI_OPT_EFA_USE_UNSOLICITED_WRITE_RECV, &off,
			sizeof(off));
	if (ret) {
		FT_PRINTERR("fi_setopt(USE_UNSOLICITED_WRITE_RECV=off)", ret);
		return ret;
	}

	/* Treat all peers as homogeneous so efa-rdm skips the handshake gate
	 * and uses RDMA write-with-immediate from the first write (the path the
	 * trigger depends on). */
	ret = fi_setopt(&s->ep->fid, FI_OPT_ENDPOINT,
			FI_OPT_EFA_HOMOGENEOUS_PEERS, &homo, sizeof(homo));
	if (ret) {
		FT_PRINTERR("fi_setopt(HOMOGENEOUS_PEERS=on)", ret);
		return ret;
	}

	ret = fi_ep_bind(s->ep, &n->eq->fid, 0);
	if (ret) { FT_PRINTERR("fi_ep_bind(eq)", ret); return ret; }
	ret = fi_ep_bind(s->ep, &s->cq->fid, FI_SEND | FI_RECV);
	if (ret) { FT_PRINTERR("fi_ep_bind(cq)", ret); return ret; }
	ret = fi_ep_bind(s->ep, &s->av->fid, 0);
	if (ret) { FT_PRINTERR("fi_ep_bind(av)", ret); return ret; }
	ret = fi_enable(s->ep);
	if (ret) { FT_PRINTERR("fi_enable", ret); return ret; }

	return 0;
}

static void slot_close(struct ep_slot *s)
{
	if (s->ep) fi_close(&s->ep->fid);
	if (s->cq && s->cq != s->nic->shared_cq) fi_close(&s->cq->fid);
	if (s->av) fi_close(&s->av->fid);
	s->ep = NULL;
	s->cq = NULL;
	s->av = NULL;
}

static void nic_close(struct nic *n)
{
	int q;

	for (q = 0; q < topts.qps_per_nic; q++) {
		slot_close(&n->slots[q]);
		free(n->slots[q].seen);
	}
	if (n->mr) fi_close(&n->mr->fid);
	if (n->shared_cq) fi_close(&n->shared_cq->fid);
	if (n->eq) fi_close(&n->eq->fid);
	if (n->domain) fi_close(&n->domain->fid);
	if (n->fabric) fi_close(&n->fabric->fid);
	if (n->info) fi_freeinfo(n->info);
	if (n->iface == FI_HMEM_SYSTEM)
		free(n->buf);
	else if (n->buf)
		ft_hmem_free(n->iface, n->buf);
	memset(n, 0, sizeof(*n));
}

static int slot_insert_peer(struct ep_slot *s)
{
	return ft_av_insert(s->av, s->peer_raw, 1, &s->peer, 0, NULL);
}

/* ---- OOB bring-up -------------------------------------------------------- */

static int exchange(void)
{
	struct fid_ep *eps[MAX_SLOTS];
	struct rma_target tgt[MAX_NICS];
	int32_t cfg[2] = { topts.nics, topts.qps_per_nic }, peer_cfg[2];
	char *remote_addrs;
	int i, ret;

	/* Both sides must agree on the slot layout. */
	ret = ft_sock_send(oob_sock, cfg, sizeof(cfg));
	if (ret) return ret;
	ret = ft_sock_recv(oob_sock, peer_cfg, sizeof(peer_cfg));
	if (ret) return ret;
	if (memcmp(cfg, peer_cfg, sizeof(cfg))) {
		fprintf(stderr, "layout mismatch: local %dx%d, peer %dx%d\n",
			cfg[0], cfg[1], peer_cfg[0], peer_cfg[1]);
		return -FI_EINVAL;
	}

	for (i = 0; i < nslots; i++)
		eps[i] = slot_of(i)->ep;

	remote_addrs = calloc(nslots, FT_MAX_CTRL_MSG);
	if (!remote_addrs)
		return -FI_ENOMEM;

	ret = efa_exchange_raw_addrs_oob(oob_sock, is_sender, eps, nslots,
					 remote_addrs, nslots);
	if (ret)
		goto out;

	for (i = 0; i < nslots; i++) {
		struct ep_slot *s = slot_of(i);

		memcpy(s->peer_raw, remote_addrs + (size_t) i * FT_MAX_CTRL_MSG,
		       FT_MAX_CTRL_MSG);
		ret = slot_insert_peer(s);
		if (ret)
			goto out;
	}

	/* Receiver advertises its write landing zone per NIC. */
	if (is_sender) {
		ret = ft_sock_recv(oob_sock, tgt, topts.nics * sizeof(*tgt));
		for (i = 0; !ret && i < topts.nics; i++)
			nics[i].tgt = tgt[i];
	} else {
		for (i = 0; i < topts.nics; i++) {
			tgt[i].addr = (uint64_t) (uintptr_t) nics[i].buf;
			tgt[i].key = fi_mr_key(nics[i].mr);
		}
		ret = ft_sock_send(oob_sock, tgt, topts.nics * sizeof(*tgt));
	}
out:
	free(remote_addrs);
	return ret;
}

/* ---- receiver ------------------------------------------------------------ */

static void handle_rx_comp(struct ep_slot *owner, uint32_t imm)
{
	uint32_t slot = IMM_SLOT(imm), seq = IMM_SEQ(imm);
	struct ep_slot *s;
	uint8_t bit, old;

	if (slot >= (uint32_t) nslots) {
		if (owner) owner->misrouted++;
		fprintf(stderr, "*** completion with bogus imm 0x%08x\n", imm);
		return;
	}
	s = slot_of(slot);
	/* With one CQ per QP, an immediate of another QP is misrouted. */
	if (owner && owner != s) {
		owner->misrouted++;
		if (owner->misrouted <= 5)
			fprintf(stderr, "*** MISROUTED: imm slot %u seq %u on "
				"CQ of slot %d\n", slot, seq, owner->slot);
	}

	bit = 1u << (seq & 7);
	old = __atomic_fetch_or(&s->seen[seq >> 3], bit, __ATOMIC_RELAXED);
	if (old & bit) {
		s->dup++;
		if (s->dup <= 5)
			fprintf(stderr, "*** DUPLICATE imm: slot %u seq %u\n",
				slot, seq);
		return;
	}
	s->good++;
}

static void handle_rx_err(struct fid_cq *cq, struct ep_slot *owner)
{
	struct fi_cq_err_entry e = {0};
	struct ep_slot *s;
	uint64_t n;

	if (fi_cq_readerr(cq, &e, 0) <= 0)
		return;

	/* Attribute to the QP if the provider gave us its immediate. */
	s = (e.flags & FI_REMOTE_CQ_DATA) && IMM_SLOT(e.data) < (uint32_t) nslots ?
		slot_of(IMM_SLOT(e.data)) : (owner ? owner : slot_of(0));
	if (e.prov_errno == EFA_STATUS_QP_INTERNAL_ERROR)
		n = ++s->qp_internal_err;
	else
		n = ++s->other_err;
	if (n <= 5)
		fprintf(stderr, "slot %d: CQ error: %s (err %d prov_errno %d)\n",
			s->slot,
			fi_cq_strerror(cq, e.prov_errno, e.err_data, NULL, 0),
			e.err, e.prov_errno);
}

/*
 * efa-rdm reports RX errors it cannot tie to a user operation (e.g. on a
 * provider RX-pool packet) on the EQ, not the CQ. Status 2 here is the
 * report's QP_INTERNAL_ERROR precursor.
 */
static void drain_eq(struct nic *n)
{
	struct fi_eq_err_entry e;
	uint32_t ev;
	uint64_t cnt;

	while (fi_eq_read(n->eq, &ev, NULL, 0, 0) == -FI_EAVAIL) {
		memset(&e, 0, sizeof(e));
		if (fi_eq_readerr(n->eq, &e, 0) <= 0)
			return;
		if (e.prov_errno == EFA_STATUS_QP_INTERNAL_ERROR)
			cnt = ++n->eq_qp_internal_err;
		else
			cnt = ++n->eq_other_err;
		if (cnt <= 5)
			fprintf(stderr, "%.3f nic %d: EQ error: %s "
				"(prov_errno %d)\n", wall_sec(), n->idx,
				fi_strerror(e.err), e.prov_errno);
	}
}

static bool rx_done(double start)
{
	double t = now_sec();

	if (g_crashed)
		return true;
	if (__atomic_load_n(&g_end_seen, __ATOMIC_ACQUIRE))
		return t >= g_end_time;
	/* Sender vanished without CTRL_END: give it a generous margin. */
	return t - start >= topts.run_seconds + 60;
}

static void *rx_nic_thread(void *arg)
{
	struct nic *n = arg;
	struct fi_cq_data_entry comp[16];
	struct fid_cq *cqs[MAX_QPS_PER_NIC];
	struct ep_slot *owners[MAX_QPS_PER_NIC];
	double start = now_sec(), last_good = start;
	double next_stall = start + topts.stall_period_ms / 1000.0;
	bool any_good = false, progressed;
	int ncq, c, i, ret;

	if (n->shared_cq) {
		ncq = 1;
		cqs[0] = n->shared_cq;
		owners[0] = NULL;	/* cannot attribute; skip misroute check */
	} else {
		ncq = topts.qps_per_nic;
		for (c = 0; c < ncq; c++) {
			cqs[c] = n->slots[c].cq;
			owners[c] = &n->slots[c];
		}
	}

	while (!rx_done(start)) {
		/* Periodic poll stall: stop polling so the provider stops
		 * reposting, the RQ drains to empty and writers enter RNR. */
		if (topts.stall_ms > 0 && now_sec() >= next_stall &&
		    !g_end_seen) {
			fprintf(stderr, "%.3f nic %d: stalling poller %d ms "
				"(force RQ empty -> RNR)\n", wall_sec(), n->idx,
				topts.stall_ms);
			usleep(topts.stall_ms * 1000);
			next_stall = now_sec() + topts.stall_period_ms / 1000.0;
			last_good = now_sec();
		}

		progressed = false;
		for (c = 0; c < ncq; c++) {
			g_in_cq_poll = 1;
			ret = fi_cq_read(cqs[c], comp, 16);	/* crash site */
			g_in_cq_poll = 0;

			if (ret > 0) {
				for (i = 0; i < ret; i++) {
					if (!(comp[i].flags & FI_REMOTE_CQ_DATA))
						continue;
					handle_rx_comp(owners[c],
						       (uint32_t) comp[i].data);
				}
				progressed = true;
			} else if (ret == -FI_EAVAIL) {
				handle_rx_err(cqs[c], owners[c]);
				progressed = true;
			}
		}

		drain_eq(n);
		if (progressed) {
			any_good = true;
			last_good = now_sec();
			continue;
		}

		if (any_good && now_sec() - last_good > ZOMBIE_SEC &&
		    !g_end_seen) {
			n->zombies++;
			fprintf(stderr, "nic %d: ZOMBIE suspected: no completion "
				"for %.0f s\n", n->idx, now_sec() - last_good);
			last_good = now_sec();	/* throttle */
		}
		sched_yield();
	}
	return NULL;
}

/* Applies sender churn to the receiver's AVs and records CTRL_END. */
static void *rx_ctrl_thread(void *arg)
{
	struct ctrl_hdr h;
	struct ep_slot *s;
	uint64_t *acked;
	char raw[FT_MAX_CTRL_MSG];
	uint8_t ack = 1;
	int i, ret;

	acked = calloc(nslots, sizeof(*acked));
	if (!acked)
		return NULL;

	for (;;) {
		if (ft_sock_recv(oob_sock, &h, sizeof(h)))
			break;

		if (h.type == CTRL_CHURN && h.slot < (uint32_t) nslots) {
			if (ft_sock_recv(oob_sock, raw, sizeof(raw)))
				break;
			s = slot_of(h.slot);
			/* The application's EOF path: drop the dead writer,
			 * then admit its replacement. */
			ret = fi_av_remove(s->av, &s->peer, 1, 0);
			if (ret)
				FT_PRINTERR("fi_av_remove", ret);
			memcpy(s->peer_raw, raw, sizeof(raw));
			ret = slot_insert_peer(s);
			if (ret)
				FT_PRINTERR("fi_av_insert(churn)", ret);
			if (ft_sock_send(oob_sock, &ack, sizeof(ack)))
				break;
		} else if (h.type == CTRL_END) {
			if (ft_sock_recv(oob_sock, acked,
					 nslots * sizeof(*acked)))
				break;
			for (i = 0; i < nslots; i++)
				slot_of(i)->peer_acked = acked[i];
			/* Outlast a poller stall that may be in progress. */
			g_end_time = now_sec() + DRAIN_SEC +
				     topts.stall_ms / 1000.0;
			__atomic_store_n(&g_end_seen, 1, __ATOMIC_RELEASE);
			(void) ft_sock_send(oob_sock, &ack, sizeof(ack));
			break;
		} else {
			fprintf(stderr, "bad ctrl message type %u slot %u\n",
				h.type, h.slot);
			break;
		}
	}
	free(acked);
	return NULL;
}

static int rx_report(void)
{
	uint64_t t_good = 0, t_dup = 0, t_mis = 0, t_lost = 0, t_qie = 0,
		 t_oerr = 0, t_zombie = 0, t_eq_qie = 0, t_eq_oerr = 0, lost;
	struct ep_slot *s;
	int i;

	printf("\n%-5s %-4s %12s %12s %8s %8s %8s %8s %8s\n", "slot", "nic",
	       "peer_acked", "unique", "dup", "misrt", "lost", "qp_int", "oerr");
	for (i = 0; i < nslots; i++) {
		s = slot_of(i);
		lost = s->peer_acked > s->good ? s->peer_acked - s->good : 0;
		printf("%-5d %-4d %12" PRIu64 " %12" PRIu64 " %8" PRIu64
		       " %8" PRIu64 " %8" PRIu64 " %8" PRIu64 " %8" PRIu64 "\n",
		       i, s->nic->idx, s->peer_acked, s->good, s->dup,
		       s->misrouted, lost, s->qp_internal_err, s->other_err);
		t_good += s->good;
		t_dup += s->dup;
		t_mis += s->misrouted;
		t_lost += lost;
		t_qie += s->qp_internal_err;
		t_oerr += s->other_err;
	}
	for (i = 0; i < topts.nics; i++) {
		t_zombie += nics[i].zombies;
		t_eq_qie += nics[i].eq_qp_internal_err;
		t_eq_oerr += nics[i].eq_other_err;
	}

	printf("\nSUMMARY: wrong_generation=%" PRIu64 " duplicate=%" PRIu64
	       " misrouted=%" PRIu64 " lost=%" PRIu64
	       " qp_internal_err=%" PRIu64 " other_err=%" PRIu64
	       " eq_qp_internal_err=%" PRIu64 " eq_other_err=%" PRIu64
	       " zombie=%" PRIu64 " unique=%" PRIu64 "%s\n",
	       __atomic_load_n(&g_wrong_gen, __ATOMIC_RELAXED), t_dup, t_mis,
	       t_lost, t_qie, t_oerr, t_eq_qie, t_eq_oerr, t_zombie, t_good,
	       g_end_seen ? "" : " (no CTRL_END from sender: lost is unknown)");

	if (__atomic_load_n(&g_wrong_gen, __ATOMIC_RELAXED) || t_dup ||
	    t_mis || t_lost) {
		printf("RESULT: REPRODUCED (duplicate/misdelivered RQ "
		       "completion observed)\n");
		return 1;
	}
	printf("RESULT: not reproduced\n");
	return 0;
}

static int run_receiver(void)
{
	pthread_t threads[MAX_NICS], ctrl;
	int i, ret;

	for (i = 0; i < nslots; i++) {
		slot_of(i)->seen = calloc(1, (SEQ_MAX + 1) / 8);
		if (!slot_of(i)->seen)
			return -FI_ENOMEM;
	}

	printf("receiver: %d nics x %d qps, %s CQ, unsolicited-write-recv OFF, "
	       "rx pool %d, stalling %d ms every %d ms\n",
	       topts.nics, topts.qps_per_nic,
	       topts.shared_cq ? "shared" : "per-QP", topts.rx_size,
	       topts.stall_ms, topts.stall_period_ms);

	ret = pthread_create(&ctrl, NULL, rx_ctrl_thread, NULL);
	if (ret)
		return -FI_EOTHER;
	for (i = 0; i < topts.nics; i++) {
		ret = pthread_create(&threads[i], NULL, rx_nic_thread, &nics[i]);
		if (ret) {
			fprintf(stderr, "pthread_create rx %d: %d\n", i, ret);
			return -FI_EOTHER;
		}
	}
	for (i = 0; i < topts.nics; i++)
		pthread_join(threads[i], NULL);

	/* Unblock the control thread if the sender never sent CTRL_END. */
	shutdown(oob_sock, SHUT_RDWR);
	pthread_join(ctrl, NULL);

	return rx_report() ? -FI_EOTHER : 0;
}

/* ---- sender -------------------------------------------------------------- */

static void tx_fill(struct ep_slot *s)
{
	struct nic *n = s->nic;
	void *desc = fi_mr_desc(n->mr);
	int ret;

	while (s->outstanding < (uint64_t) topts.window_deep &&
	       s->seq < SEQ_MAX) {
		size_t len = (s->seq & 1) ? topts.size_big : topts.size_small;
		uint32_t imm = IMM(s->slot, s->seq);
		struct iovec iov = { .iov_base = n->buf, .iov_len = len };
		struct fi_rma_iov rma = {
			.addr = n->tgt.addr + s->off,
			.len = len,
			.key = n->tgt.key,
		};
		struct fi_msg_rma msg = {
			.msg_iov = &iov,
			.desc = &desc,
			.iov_count = 1,
			.addr = s->peer,
			.rma_iov = &rma,
			.rma_iov_count = 1,
			.context = (void *) (uintptr_t) imm,
			.data = imm,
		};

		ret = fi_writemsg(s->ep, &msg,
				  FI_REMOTE_CQ_DATA | FI_COMPLETION);
		if (ret == -FI_EAGAIN)
			break;
		if (ret) {
			fprintf(stderr, "slot %d: fi_writemsg: %s\n", s->slot,
				fi_strerror(-ret));
			break;
		}
		s->outstanding++;
		s->seq++;
		s->off += len;
		if (s->off + topts.size_big >= n->buf_len)
			s->off = 0;
	}
}

static void tx_poll(struct ep_slot *s)
{
	struct fi_cq_data_entry comp[16];
	struct fi_cq_err_entry e;
	int ret;

	ret = fi_cq_read(s->cq, comp, 16);
	if (ret > 0) {
		s->outstanding -= ret;
		s->acked += ret;
	} else if (ret == -FI_EAVAIL) {
		memset(&e, 0, sizeof(e));
		if (fi_cq_readerr(s->cq, &e, 0) > 0) {
			s->outstanding--;	/* RNR etc; keep window moving */
			if (++s->tx_err <= 5)
				fprintf(stderr, "slot %d: tx error: %s "
					"(prov_errno %d)\n", s->slot,
					fi_cq_strerror(s->cq, e.prov_errno,
						       e.err_data, NULL, 0),
					e.prov_errno);
		}
	}
}

/*
 * Emulates the report's SIGKILL of a writer: the QP goes away with its
 * window still in flight, a fresh QP replaces it, and the receiver is told
 * to fi_av_remove the old address and insert the new one.
 */
static int tx_churn(struct ep_slot *s)
{
	struct ctrl_hdr h = { .type = CTRL_CHURN, .slot = s->slot };
	char raw[FT_MAX_CTRL_MSG] = {0};
	size_t addrlen = sizeof(raw);
	uint8_t ack;
	int ret;

	slot_close(s);
	s->outstanding = 0;

	ret = slot_open(s);
	if (ret)
		return ret;
	ret = slot_insert_peer(s);
	if (ret)
		return ret;
	ret = fi_getname(&s->ep->fid, raw, &addrlen);
	if (ret) { FT_PRINTERR("fi_getname", ret); return ret; }

	pthread_mutex_lock(&oob_lock);
	ret = ft_sock_send(oob_sock, &h, sizeof(h));
	if (!ret)
		ret = ft_sock_send(oob_sock, raw, sizeof(raw));
	if (!ret)
		ret = ft_sock_recv(oob_sock, &ack, sizeof(ack));
	pthread_mutex_unlock(&oob_lock);

	s->churns++;
	return ret;
}

static void *tx_nic_thread(void *arg)
{
	struct nic *n = arg;
	double start = now_sec();
	double next_churn = start + topts.churn_period_ms / 1000.0;
	int q, victim = 0;

	while (now_sec() - start < topts.run_seconds && !g_crashed) {
		if (topts.churn_period_ms > 0 && now_sec() >= next_churn) {
			if (tx_churn(&n->slots[victim])) {
				fprintf(stderr, "nic %d: churn failed\n",
					n->idx);
				return NULL;
			}
			victim = (victim + 1) % topts.qps_per_nic;
			next_churn = now_sec() + topts.churn_period_ms / 1000.0;
		}

		for (q = 0; q < topts.qps_per_nic; q++) {
			tx_fill(&n->slots[q]);
			tx_poll(&n->slots[q]);
		}
	}

	/* Collect what is still in flight so acked is as complete as it can
	 * be before it is reported. */
	start = now_sec();
	while (now_sec() - start < DRAIN_SEC) {
		uint64_t left = 0;

		for (q = 0; q < topts.qps_per_nic; q++) {
			tx_poll(&n->slots[q]);
			left += n->slots[q].outstanding;
		}
		if (!left)
			break;
	}
	return NULL;
}

static int run_sender(void)
{
	pthread_t threads[MAX_NICS];
	struct ctrl_hdr h = { .type = CTRL_END };
	uint64_t *acked;
	uint64_t t_acked = 0, t_err = 0, t_churn = 0;
	uint8_t ack;
	int i, ret;

	printf("sender: %d nics x %d qps, window %d, sizes %zu/%zu, "
	       "churn every %d ms, run %d s\n",
	       topts.nics, topts.qps_per_nic, topts.window_deep,
	       topts.size_big, topts.size_small, topts.churn_period_ms,
	       topts.run_seconds);

	for (i = 0; i < topts.nics; i++) {
		ret = pthread_create(&threads[i], NULL, tx_nic_thread, &nics[i]);
		if (ret) {
			fprintf(stderr, "pthread_create tx %d: %d\n", i, ret);
			return -FI_EOTHER;
		}
	}
	for (i = 0; i < topts.nics; i++)
		pthread_join(threads[i], NULL);

	acked = calloc(nslots, sizeof(*acked));
	if (!acked)
		return -FI_ENOMEM;
	for (i = 0; i < nslots; i++) {
		struct ep_slot *s = slot_of(i);

		acked[i] = s->acked;
		t_acked += s->acked;
		t_err += s->tx_err;
		t_churn += s->churns;
		if (s->seq >= SEQ_MAX)
			fprintf(stderr, "slot %d: hit the %u-write immediate "
				"space and stopped early\n", i, SEQ_MAX);
	}
	printf("sender: acked=%" PRIu64 " tx_err=%" PRIu64 " churns=%" PRIu64
	       "\n", t_acked, t_err, t_churn);

	ret = ft_sock_send(oob_sock, &h, sizeof(h));
	if (!ret)
		ret = ft_sock_send(oob_sock, acked, nslots * sizeof(*acked));
	if (!ret)
		ret = ft_sock_recv(oob_sock, &ack, sizeof(ack));
	free(acked);
	return ret;
}

/* ---- main ---------------------------------------------------------------- */

static void usage(const char *name)
{
	fprintf(stderr,
		"Usage: %s [options] [<server_addr>]\n"
		"  (no server_addr => receiver; with => sender)\n"
		"  --nics N             NICs, one domain each (default 8)\n"
		"  --qps-per-nic K      endpoints/QPs per NIC (default 1)\n"
		"  --shared-cq          receiver: one CQ per NIC for its QPs\n"
		"  --gpu-target         receiver: land writes in CUDA memory\n"
		"                       (NIC i uses GPU i %% 8)\n"
		"  --rx-size N          FI_EFA_RX_SIZE provider pool (default 64)\n"
		"  --window-deep N      outstanding writes/QP (default 64)\n"
		"  -S, --size N         large write size (default 1048576)\n"
		"  --size-small N       small write size (default 30412)\n"
		"  --stall-ms N         receiver poller stall ms (default 5000)\n"
		"  --stall-period-ms N  stall period ms (default 20000)\n"
		"  --churn-period-ms N  sender: replace one QP per NIC every N ms\n"
		"                       (default 0 = off)\n"
		"  --run-seconds N      total run time (default 720)\n"
		"  --stats-sec N        print EFA hw counter deltas every N s\n"
		"                       (default 5, 0 = off)\n"
		"  -b <port>            OOB port\n"
		"  EFA_DOMAINS=csv      explicit domain list (optional)\n",
		name);
}

int main(int argc, char **argv)
{
	char **domain_names = NULL;
	struct fi_info *dhints;
	char *server_addr = NULL;
	pthread_t stats_tid;
	bool stats_started = false;
	int op, i, q, ret;
	int longidx;

	opts = INIT_OPTS;
	opts.options |= FT_OPT_OOB_CTRL;

	while ((op = getopt_long(argc, argv, "S:b:p:h",
				 rq_long_opts, &longidx)) != -1) {
		switch (op) {
		case OPT_NICS: topts.nics = atoi(optarg); break;
		case OPT_QPS_PER_NIC: topts.qps_per_nic = atoi(optarg); break;
		case OPT_SHARED_CQ: topts.shared_cq = true; break;
		case OPT_GPU_TARGET: topts.gpu_target = true; break;
		case OPT_RX_SIZE: topts.rx_size = atoi(optarg); break;
		case OPT_WINDOW_DEEP: topts.window_deep = atoi(optarg); break;
		case 'S': topts.size_big = strtoull(optarg, NULL, 0); break;
		case OPT_SIZE_SMALL:
			topts.size_small = strtoull(optarg, NULL, 0); break;
		case OPT_STALL_MS: topts.stall_ms = atoi(optarg); break;
		case OPT_STALL_PERIOD_MS:
			topts.stall_period_ms = atoi(optarg); break;
		case OPT_CHURN_PERIOD_MS:
			topts.churn_period_ms = atoi(optarg); break;
		case OPT_RUN_SECONDS: topts.run_seconds = atoi(optarg); break;
		case OPT_STATS_SEC: topts.stats_sec = atoi(optarg); break;
		case 'b': opts.oob_port = optarg; break;
		case 'p': break; /* provider is always efa; accepted for parity */
		case 'h':
		default:
			usage(argv[0]);
			return EXIT_FAILURE;
		}
	}
	if (optind < argc)
		server_addr = argv[optind];
	is_sender = (server_addr != NULL);
	opts.dst_addr = server_addr;

	if (topts.nics < 1 || topts.nics > MAX_NICS ||
	    topts.qps_per_nic < 1 || topts.qps_per_nic > MAX_QPS_PER_NIC ||
	    topts.nics * topts.qps_per_nic > MAX_SLOTS) {
		fprintf(stderr, "need 1..%d nics, 1..%d qps/nic, <= %d total\n",
			MAX_NICS, MAX_QPS_PER_NIC, MAX_SLOTS);
		return EXIT_FAILURE;
	}
	nslots = topts.nics * topts.qps_per_nic;

	install_crash_handlers();

	/* Route provider logs through log_msg() before anything initializes. */
	ret = fi_import_log(FI_VERSION(1, 20), 0, &rq_log_fid);
	if (ret)
		fprintf(stderr, "fi_import_log: %s; wrong-generation warnings "
			"will not be counted\n", fi_strerror(-ret));

	/* Small RX pool makes the RQ drain fast. Set before any domain opens. */
	{
		char rx[32];
		snprintf(rx, sizeof(rx), "%d", topts.rx_size);
		setenv("FI_EFA_RX_SIZE", rx, 1);
	}
	/* RNR errors must come from the EFA device, not shm. */
	setenv("FI_EFA_ENABLE_SHM_TRANSFER", "0", 1);

	/* Pick N distinct efa domains (NICs). */
	dhints = fi_allocinfo();
	if (!dhints)
		return EXIT_FAILURE;
	dhints->fabric_attr->prov_name = strdup("efa");
	dhints->ep_attr->type = FI_EP_RDM;
	ret = efa_select_domains(dhints, topts.nics, getenv("EFA_DOMAINS"),
				 &domain_names);
	fi_freeinfo(dhints);
	if (ret) {
		FT_PRINTERR("efa_select_domains", ret);
		return EXIT_FAILURE;
	}

	if (!is_sender && topts.gpu_target) {
		ret = ft_hmem_init(FI_HMEM_CUDA);
		if (ret) {
			FT_PRINTERR("ft_hmem_init(CUDA)", ret);
			goto out;
		}
	}

	for (i = 0; i < topts.nics; i++) {
		char *sfx;

		nics[i].idx = i;
		snprintf(nics[i].dev, sizeof(nics[i].dev), "%s", domain_names[i]);
		sfx = strstr(nics[i].dev, "-rdm");
		if (sfx)
			*sfx = '\0';
		nics[i].iface = (!is_sender && topts.gpu_target) ?
				FI_HMEM_CUDA : FI_HMEM_SYSTEM;
		ret = nic_open(&nics[i], domain_names[i]);
		if (ret) {
			fprintf(stderr, "nic_open %d (%s) failed\n", i,
				domain_names[i]);
			goto out;
		}
		for (q = 0; q < topts.qps_per_nic; q++) {
			struct ep_slot *s = &nics[i].slots[q];

			s->slot = i * topts.qps_per_nic + q;
			s->nic = &nics[i];
			ret = slot_open(s);
			if (ret) {
				fprintf(stderr, "slot_open %d failed\n",
					s->slot);
				goto out;
			}
		}
	}

	/* OOB bring-up (reuses fabtests oob machinery). */
	ret = ft_init_oob();
	if (ret) { FT_PRINTERR("ft_init_oob", ret); goto out; }

	ret = exchange();
	if (ret) { FT_PRINTERR("exchange", ret); goto out; }

	if (topts.stats_sec > 0 &&
	    pthread_create(&stats_tid, NULL, stats_thread, NULL) == 0)
		stats_started = true;

	if (is_sender)
		ret = run_sender();
	else
		ret = run_receiver();

	if (stats_started) {
		g_stats_stop = 1;
		pthread_join(stats_tid, NULL);
	}

out:
	for (i = 0; i < topts.nics; i++)
		nic_close(&nics[i]);
	efa_free_domain_names(domain_names);
	if (!is_sender && topts.gpu_target)
		ft_hmem_cleanup(FI_HMEM_CUDA);
	ft_close_oob();
	if (g_crashed)
		return 137;
	return ret ? EXIT_FAILURE : EXIT_SUCCESS;
}
