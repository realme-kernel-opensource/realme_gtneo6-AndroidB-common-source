/* SPDX-License-Identifier: GPL-2.0 */
/*
 * BPF extensible scheduler class: Documentation/scheduler/sched-ext.rst
 *
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2022 Tejun Heo <tj@kernel.org>
 * Copyright (c) 2022 David Vernet <dvernet@meta.com>
 */

#include "slim.h"
#define CREATE_TRACE_POINTS
#include <trace/events/hmbird.h>
#undef CREATE_TRACE_POINTS

#define CLUSTER_SEPARATE

enum task_event {
	PUT_PREV_TASK   = 0,
	PICK_NEXT_TASK  = 1,
	TASK_WAKE       = 2,
	TASK_MIGRATE    = 3,
	TASK_UPDATE     = 4,
	IRQ_UPDATE      = 5,
};

enum scx_internal_consts {
	SCX_WATCHDOG_MAX_TIMEOUT = 30 * HZ,
};

enum scx_ops_enable_state {
	SCX_OPS_PREPPING,
	SCX_OPS_ENABLING,
	SCX_OPS_ENABLED,
	SCX_OPS_DISABLING,
	SCX_OPS_DISABLED,
};

static inline struct task_group *css_tg(struct cgroup_subsys_state *css)
{
	return css ? container_of(css, struct task_group, css) : NULL;
}

static inline void check_class_changed(struct rq *rq, struct task_struct *p,
                         const struct sched_class *prev_class,
                         int oldprio)
{
	if (prev_class != p->sched_class) {
		if (prev_class->switched_from)
			prev_class->switched_from(rq, p);

		p->sched_class->switched_to(rq, p);
	} else if (oldprio != p->prio || dl_task(p))
		p->sched_class->prio_changed(rq, p, oldprio);
}

/*
 * sched_ext_entity->ops_state
 *
 * Used to track the task ownership between the SCX core and the BPF scheduler.
 * State transitions look as follows:
 *
 * NONE -> QUEUEING -> QUEUED -> DISPATCHING
 *   ^              |                 |
 *   |              v                 v
 *   \-------------------------------/
 *
 * QUEUEING and DISPATCHING states can be waited upon. See wait_ops_state() call
 * sites for explanations on the conditions being waited upon and why they are
 * safe. Transitions out of them into NONE or QUEUED must store_release and the
 * waiters should load_acquire.
 *
 * Tracking scx_ops_state enables sched_ext core to reliably determine whether
 * any given task can be dispatched by the BPF scheduler at all times and thus
 * relaxes the requirements on the BPF scheduler. This allows the BPF scheduler
 * to try to dispatch any task anytime regardless of its state as the SCX core
 * can safely reject invalid dispatches.
 */
enum scx_ops_state {
	SCX_OPSS_NONE,		/* owned by the SCX core */
	SCX_OPSS_QUEUEING,	/* in transit to the BPF scheduler */
	SCX_OPSS_QUEUED,	/* owned by the BPF scheduler */
	SCX_OPSS_DISPATCHING,	/* in transit back to the SCX core */

	/*
	 * QSEQ brands each QUEUED instance so that, when dispatch races
	 * dequeue/requeue, the dispatcher can tell whether it still has a claim
	 * on the task being dispatched.
	 */
	SCX_OPSS_QSEQ_SHIFT	= 2,
	SCX_OPSS_STATE_MASK	= (1LLU << SCX_OPSS_QSEQ_SHIFT) - 1,
	SCX_OPSS_QSEQ_MASK	= ~SCX_OPSS_STATE_MASK,
};

enum switch_stat {
	SCX_DISABLED,
	SCX_SWITCH_PREP,
	SCX_RQ_SWITCH_BEGIN,
	SCX_RQ_SWITCH_DONE,
	SCX_ENABLED,
};
enum switch_stat curr_ss;

/*
 * During exit, a task may schedule after losing its PIDs. When disabling the
 * BPF scheduler, we need to be able to iterate tasks in every state to
 * guarantee system safety. Maintain a dedicated task list which contains every
 * task between its fork and eventual free.
 */
DEFINE_SPINLOCK(scx_tasks_lock);
static LIST_HEAD(scx_tasks);

/* ops enable/disable */
static struct kthread_worker *scx_ops_helper;
static DEFINE_MUTEX(scx_ops_enable_mutex);
DEFINE_STATIC_PERCPU_RWSEM(scx_fork_rwsem);
static atomic_t scx_ops_enable_state_var = ATOMIC_INIT(SCX_OPS_DISABLED);
static atomic_t set_sched_clock_prepare;

static bool scx_warned_zero_slice;
enum scx_switch_type sw_type;

DEFINE_STATIC_KEY_FALSE(scx_ops_cpu_preempt);

static atomic64_t scx_nr_rejected = ATOMIC64_INIT(0);

/*
 * The maximum amount of time in jiffies that a task may be runnable without
 * being scheduled on a CPU. If this timeout is exceeded, it will trigger
 * scx_ops_error().
 */
unsigned long scx_watchdog_timeout;

/*
 * The last time the delayed work was run. This delayed work relies on
 * ksoftirqd being able to run to service timer interrupts, so it's possible
 * that this work itself could get wedged. To account for this, we check that
 * it's not stalled in the timer tick, and trigger an error if it is.
 */
unsigned long scx_watchdog_timestamp = INITIAL_JIFFIES;

static struct delayed_work scx_watchdog_work;
static struct work_struct scx_err_exit_work;

/* idle tracking */
#ifdef CONFIG_SMP
#ifdef CONFIG_CPUMASK_OFFSTACK
#define CL_ALIGNED_IF_ONSTACK
#else
#define CL_ALIGNED_IF_ONSTACK __cacheline_aligned_in_smp
#endif

static struct {
	cpumask_var_t cpu;
	cpumask_var_t smt;
} idle_masks CL_ALIGNED_IF_ONSTACK;

static bool __cacheline_aligned_in_smp scx_has_idle_cpus;
#endif	/* CONFIG_SMP */

/* dispatch queues */
static struct scx_dispatch_q __cacheline_aligned_in_smp scx_dsq_global;

u32 SCX_BPF_DSQS_DEADLINE[MAX_GLOBAL_DSQS] = {0, 1, 2, 4, 6, 8, 16, 32, 64, 128};
u32 pcp_dsq_deadline = 20;
static struct scx_dispatch_q __cacheline_aligned_in_smp gdsqs[MAX_GLOBAL_DSQS];
static DEFINE_PER_CPU(struct scx_dispatch_q, pcp_ldsq);

static u64 max_ext_dsq_internal_id;

/* a dsq idx, whether task push to little domain cpu or bit domain cpu*/
#define CLUSTER_SEPARATE_IDX	(8)
#define GDSQS_ID_BASE		(3)
#define NON_PERIOD_START	(5)
#define NON_PERIOD_END		(MAX_GLOBAL_DSQS)
#define CREATE_DSQ_LEVEL_WITHIN	(1)

struct hmbird_sched_info {
	spinlock_t lock;
	int curr_idx[2];
	int rtime[MAX_GLOBAL_DSQS];
};

struct pcp_sched_info {
	s64 pcp_seq;
	int rtime;
	bool pcp_round;
};

/*
 * pcp_info may rw by another cpu.
 * protected by rq->lock.
 */
atomic64_t pcp_dsq_round;
static DEFINE_PER_CPU(struct pcp_sched_info, pcp_info);

struct md_info_t *md_info;

static struct hmbird_sched_info sinfo;

static unsigned long pcp_dsq_quota __read_mostly = 3 * NSEC_PER_MSEC;
static unsigned long dsq_quota[MAX_GLOBAL_DSQS] = {
					0, 0, 0, 0, 0,
					32 * NSEC_PER_MSEC,
					20 * NSEC_PER_MSEC,
					14 * NSEC_PER_MSEC,
					8 * NSEC_PER_MSEC,
					6 * NSEC_PER_MSEC
};

struct cluster_ctx {
        /* cpu-dsq map must within [lower, upper) */
	int upper;
	int lower;
	int tidx;
};

enum stat_items {
	GLOBAL_STAT,
	CPU_ALLOW_FAIL,
	RT_CNT,
	KEY_TASK_CNT,
	SWITCH_IDX,
	TIMEOUT_CNT,

	TOTAL_DSP_CNT,
	MOVE_RQ_CNT,
	SELECT_CPU,

	DWORD_STAT_END = SELECT_CPU,

	GDSQ_CNT,
	ERR_IDX,
	PCP_TIMEOUT_CNT,
	PCP_LDSQ_CNT,
	PCP_ENQL_CNT,

	MAX_ITEMS,
};
static DEFINE_SPINLOCK(stats_lock);
static char *stats_str[MAX_ITEMS] = {
	"global stat", "cpu_allow_fail", "rt_cnt", "key_task_cnt",
	"switch_idx", "timeout_cnt", "total_dsp_cnt", "move_rq_cnt",
	"select_cpu",
	"gdsq_cnt", "err_idx", "pcp_timeout_cnt", "pcp_ldsq_cnt",
	"pcp_enql_cnt"
};


struct stats_struct {
	u64 global_stat[2];
	u64 cpu_allow_fail[2];
	u64 rt_cnt[2];
	u64 key_task_cnt[2];
	u64 switch_idx[2];
	u64 timeout_cnt[2];
	u64 total_dsp_cnt[2];
	u64 move_rq_cnt[2];
	u64 select_cpu[2];

	u64 gdsq_count[MAX_GLOBAL_DSQS][2];
	u64 err_idx[5];
	u64 pcp_timeout_cnt[NR_CPUS];
	u64 pcp_ldsq_count[NR_CPUS][2];
	u64 pcp_enql_cnt[NR_CPUS];
} stats_data;


/*
 * Need more synchronization for these two variables?
 * I choose not to.
 */
static int l_need_rescue, b_need_rescue;

#define SCX_FATAL_INFO_FN(type, fmt, args...)					\
{										\
	char buf[MAX_FATAL_INFO];						\
										\
	scnprintf(buf, MAX_FATAL_INFO, fmt, ##args);				\
	scx_deferred_err(SCX_OPS_ERR, "type(%d) %s\n", type, buf);		\
	trace_scx_fatal_info((unsigned int)type, READ_ONCE(partial_enable),	\
		READ_ONCE(l_need_rescue), READ_ONCE(b_need_rescue), buf);	\
	queue_work(system_unbound_wq, &scx_err_exit_work);			\
}										\

static bool cpu_same_cluster_stat(struct task_struct *p, struct rq *rq1, struct rq *rq2)
{
	int c1, c2;
	struct cpumask mask = {.bits = {0}};
	struct cpumask tmp = {.bits = {0}};

	if (!slim_stats)
		return false;

	if (!rq1 || !rq2)
		return false;

	c1 = cpu_of(rq1);
	c2 = cpu_of(rq2);
	cpumask_set_cpu(c1, &mask);
	cpumask_set_cpu(c2, &mask);

	if (cpumask_and(&tmp, iso_masks.little, &mask))
		if (cpumask_equal(&tmp, &mask))
			return true;

	if (cpumask_and(&tmp, iso_masks.big, &mask))
		if (cpumask_equal(&tmp, &mask))
			return true;

	if (cpumask_and(&tmp, iso_masks.partial, &mask))
		if (cpumask_equal(&tmp, &mask))
			return true;

	scx_info_trace("<move>:task-%s, gdsq idx = %d, move from cpu%d to cpu%d\n",
						p->comm, p->scx->gdsq_idx, c1, c2);
	return false;
}

static void slim_stats_record(enum stat_items item, int idx, int dsq_id, int cpu)
{
	unsigned long flags;
	u64 *pval;
	u64 *pbase = (u64*)&stats_data;

	if (!slim_stats)
		return;

	switch (item) {
	case GLOBAL_STAT:
		fallthrough;
	case CPU_ALLOW_FAIL:
		fallthrough;
	case RT_CNT:
		fallthrough;
	case KEY_TASK_CNT:
		fallthrough;
	case SWITCH_IDX:
		fallthrough;
	case TIMEOUT_CNT:
		fallthrough;
	case TOTAL_DSP_CNT:
		fallthrough;
	case MOVE_RQ_CNT:
		fallthrough;
	case SELECT_CPU:
		pval = pbase + item * 2 + idx;
		break;
	case GDSQ_CNT:
		pval = &stats_data.gdsq_count[dsq_id][idx];
		break;
	case ERR_IDX:
		pval = &stats_data.err_idx[idx];
		break;
	case PCP_TIMEOUT_CNT:
		pval = &stats_data.pcp_timeout_cnt[cpu];
		break;
	case PCP_LDSQ_CNT:
		pval = &stats_data.pcp_ldsq_count[cpu][idx];
		break;
	case PCP_ENQL_CNT:
		pval = &stats_data.pcp_enql_cnt[cpu];
		break;
	default:
		return;
	}

	spin_lock_irqsave(&stats_lock, flags);
	*pval += 1;
	spin_unlock_irqrestore(&stats_lock, flags);
}

#define HANDLE_RET(ret, idx)			\
	if (ret < 0 || ret >= len - idx)	\
		return;				\
	idx += ret;

#define PRINT_INTV	(5 * HZ)
void stats_print(char *buf, int len)
{
	int idx = 0, i, j, ret;
	int item = 0;
	u64 *pval;
	u64 *pbase = (u64*)&stats_data;

	ret = snprintf(&buf[idx], len - idx, "-------------schedinfo stats :---------------\n");
	HANDLE_RET(ret, idx);
	for (item = 0; item < MAX_ITEMS; item++) {
		if (item <= DWORD_STAT_END) {
			pval = pbase + item * 2;
			ret = snprintf(&buf[idx], len - idx, "%s:%llu, %llu\n",
					stats_str[item], pval[0],  pval[1]);
			HANDLE_RET(ret, idx);
		} else if (GDSQ_CNT == item) {
			for (j = 0; j < MAX_GLOBAL_DSQS; j++) {
				pval = (u64*)&stats_data.gdsq_count[j];
				ret = snprintf(&buf[idx], len - idx, "%s[%d]:%llu, %llu\n",
						stats_str[item], j, pval[0], pval[1]);
				HANDLE_RET(ret, idx);
			}
		} else if (ERR_IDX == item) {
			pval = (u64*)&stats_data.err_idx;
			ret = snprintf(&buf[idx], len - idx, "%s:%llu, %llu, %llu, %llu,"
						"%llu\n", stats_str[item], pval[0],
						pval[1], pval[2], pval[3], pval[4]);
			HANDLE_RET(ret, idx);
		} else if (PCP_TIMEOUT_CNT == item) {
			for (j = 0; j < nr_cpu_ids; j++) {
				pval = (u64*)&stats_data.pcp_timeout_cnt[j];
				ret = snprintf(&buf[idx], len - idx, "%s[%d]:%llu\n",
							stats_str[item], j, *pval);
				HANDLE_RET(ret, idx);
			}
		} else if (PCP_LDSQ_CNT == item) {
			for (j = 0; j < nr_cpu_ids; j++) {
				pval = (u64*)&stats_data.pcp_ldsq_count[j];
				ret = snprintf(&buf[idx], len - idx, "%s[%d]:%llu,%llu\n",
						stats_str[item], j, pval[0], pval[1]);
				HANDLE_RET(ret, idx);
			}
		} else if (PCP_ENQL_CNT == item) {
			for (j = 0; j < nr_cpu_ids; j++) {
				pval = (u64*)&stats_data.pcp_enql_cnt[j];
				ret = snprintf(&buf[idx], len - idx, "%s[%d]:%llu\n",
						stats_str[item], j, *pval);
				HANDLE_RET(ret, idx);
			}
		}
		else {}
	}

	if (!md_info) {
		buf[idx] = '\0';
		return;
	}

	ret = snprintf(&buf[idx], len - idx, "\n\n------------minidump stats :---------------\n");
	HANDLE_RET(ret, idx);

	for (i = 0; i < MAX_SWITCHS; i++) {
		ret = snprintf(&buf[idx], len - idx,
				"sw_rec[%d] = %llu %llu %llu %llu\n", i,
				md_info->kern_dump.sw_rec[i].switch_at,
				md_info->kern_dump.sw_rec[i].is_success,
				md_info->kern_dump.sw_rec[i].end_state,
				md_info->kern_dump.sw_rec[i].switch_reason);
		HANDLE_RET(ret, idx);
	}
	ret = snprintf(&buf[idx], len - idx, "sw_idx = %llu\n", md_info->kern_dump.sw_idx);
	HANDLE_RET(ret, idx);

	for (i = 0; i < MAX_EXCEP_ID; i++) {
		ret = snprintf(&buf[idx], len - idx,
				"excep[%d] = %llu %llu %llu %llu %llu\n", i,
				md_info->kern_dump.excep_rec[i][0],
				md_info->kern_dump.excep_rec[i][1],
				md_info->kern_dump.excep_rec[i][2],
				md_info->kern_dump.excep_rec[i][3],
				md_info->kern_dump.excep_rec[i][4]);
		HANDLE_RET(ret, idx);

		ret = snprintf(&buf[idx], len - idx, "excep_idx[%d] = %llu\n",
					i, md_info->kern_dump.excep_idx[i]);
		HANDLE_RET(ret, idx);
	}

	buf[idx] = '\0';
}

enum cpu_type
{
	LITTLE,
	BIG,
	PARTIAL,
	EXCLUSIVE,
	EX_FREE,
	INVALID
};

enum dsq_type
{
	GLOBAL_DSQ,
	PCP_DSQ,
	OTHER,
	MAX_DSQ_TYPE,
};

static enum cpu_type cpu_cluster(int cpu)
{
	int exclusive = 0;

	trace_android_vh_scx_cpu_exclusive(cpu, &exclusive);
	if (exclusive) {
		return EXCLUSIVE;
	} else {
		if (cpumask_test_cpu(cpu, iso_masks.little))
			return LITTLE;
		else if (cpumask_test_cpu(cpu, iso_masks.big))
			return BIG;
		else if (cpumask_test_cpu(cpu, iso_masks.partial))
			return PARTIAL;
		else if (cpumask_test_cpu(cpu, iso_masks.exclusive))
			return EXCLUSIVE;
		else if (cpumask_test_cpu(cpu, iso_masks.ex_free))
			return EX_FREE;
	}
	return INVALID;
}

static enum dsq_type get_dsq_type(struct scx_dispatch_q *dsq)
{
	if (!dsq)
		return OTHER;

	if ((dsq->id & SCX_DSQ_FLAG_BUILTIN) &&
		((dsq->id & 0xff) >= GDSQS_ID_BASE) &&
		((dsq->id & 0xff) < MAX_GLOBAL_DSQS))
		return GLOBAL_DSQ;

	if ((dsq->id & SCX_DSQ_FLAG_BUILTIN) &&
		((dsq->id & 0xff) >= MAX_GLOBAL_DSQS) &&
		((dsq->id & 0xff) < max_ext_dsq_internal_id))
		return PCP_DSQ;

	return OTHER;
}

static int dsq_id_to_internal(struct scx_dispatch_q *dsq)
{
	enum dsq_type type;

	type = get_dsq_type(dsq);
	switch (type) {
	case GLOBAL_DSQ:
	case PCP_DSQ:
		return (dsq->id & 0xff) - GDSQS_ID_BASE;
	default:
		return -1;
	}
	return -1;
}

static void update_cpus_idle(bool set, struct cpumask *mask)
{
	int cpu;
	struct rq *rq;

	if (set) {
		for_each_cpu(cpu, mask) {
			rq = cpu_rq(cpu);
			if (is_idle_task(rq->curr))
				cpumask_set_cpu(cpu, idle_masks.cpu);
		}
	}
	else {
		cpumask_andnot(idle_masks.cpu, idle_masks.cpu, mask);
	}
}

static void set_partial_status(bool enable, bool little, bool big)
{
	WRITE_ONCE(partial_enable, enable);
	WRITE_ONCE(l_need_rescue, little);
	WRITE_ONCE(b_need_rescue, big);
}

static bool is_little_need_rescue(void)
{
	return READ_ONCE(l_need_rescue);
}

static bool is_big_need_rescue(void)
{
	return READ_ONCE(b_need_rescue);
}

static bool is_partial_enabled(void)
{
	return READ_ONCE(partial_enable);
}

static bool is_partial_cpu(int cpu)
{
	return cpumask_test_cpu(cpu, iso_masks.partial);
}

static void set_iso_par_free(bool enable)
{
	WRITE_ONCE(isolate_ctrl, enable);
}

static bool is_iso_par_free(void)
{
	return READ_ONCE(isolate_ctrl);
}

static bool skip_update_idle(void)
{
	int cpu = smp_processor_id();
	enum cpu_type type = cpu_cluster(cpu);

	if ((type == EXCLUSIVE && !is_iso_par_free()) ||
		/* partial enable may changed during idle, it doesn't matter. */
		(!is_partial_enabled() && type == PARTIAL))
		return true;

	return false;
}

static void init_isolate_cpus(void)
{
	WARN_ON(!alloc_cpumask_var(&iso_masks.ex_free, GFP_KERNEL));
	WARN_ON(!alloc_cpumask_var(&iso_masks.partial, GFP_KERNEL));
	WARN_ON(!alloc_cpumask_var(&iso_masks.exclusive, GFP_KERNEL));
	WARN_ON(!alloc_cpumask_var(&iso_masks.big, GFP_KERNEL));
	WARN_ON(!alloc_cpumask_var(&iso_masks.little, GFP_KERNEL));
	cpumask_set_cpu(0, iso_masks.little);
	cpumask_set_cpu(1, iso_masks.little);
	cpumask_set_cpu(2, iso_masks.big);
	cpumask_set_cpu(3, iso_masks.big);
	cpumask_set_cpu(4, iso_masks.ex_free);
	cpumask_set_cpu(5, iso_masks.partial);
	cpumask_set_cpu(6, iso_masks.partial);
	cpumask_set_cpu(7, iso_masks.ex_free);
}

extern spinlock_t css_set_lock;
static struct cgroup *cgroup_ancestor_l1(struct cgroup *cgrp)
{
	int i;
	struct cgroup *anc;

	spin_lock_irq(&css_set_lock);
	for (i = 0; i < cgrp->level; i++) {
		anc = cgrp->ancestors[i];
		if (CREATE_DSQ_LEVEL_WITHIN != anc->level)
			continue;
		cgroup_get(anc);
		spin_unlock_irq(&css_set_lock);
		return anc;
	}
	spin_unlock_irq(&css_set_lock);
	scx_err(NO_CGROUP_L1, "<fatal>:error cgroup = %s\n", cgrp->kn->name);
	return NULL;
}

static bool is_pcp_rt(struct task_struct *p)
{
	return rt_prio(p->prio) && (1 == p->nr_cpus_allowed);
}

static bool is_pcp_idx(int idx)
{
	return idx >= MAX_GLOBAL_DSQS;
}

static bool is_critical_system_task(struct task_struct *p)
{
	int sp_dl = p->scx->sched_prop & SCHED_PROP_DEADLINE_MASK;

	return (p->prio < (MAX_RT_PRIO >> 1) &&
		(sp_dl < SCHED_PROP_DEADLINE_LEVEL3));
}

#define ISOLATE_TASK_TOP_BIT	(1 << 17)
#define PIPELINE_TASK_TOP_BIT	(1 << 9)

static bool is_pipeline_task(struct task_struct *p)
{
	return (get_top_task_prop(p) & PIPELINE_TASK_TOP_BIT);
}

static bool is_isolate_task(struct task_struct *p)
{
	return (get_top_task_prop(p) & ISOLATE_TASK_TOP_BIT);
}

static bool is_critical_app_task_without_isolate(struct task_struct *p)
{
	return task_is_top_task(p) && !is_isolate_task(p);
}

static int find_idx_from_task(struct task_struct *p)
{
	int idx, cpu;
	int sp_dl;
	struct task_group *tg = p->sched_task_group;

	if (1 == p->nr_cpus_allowed || is_migration_disabled(p)) {
		cpu = cpumask_any(p->cpus_ptr);
		idx = cpu + MAX_GLOBAL_DSQS;
		return idx;
	}

	if (is_critical_system_task(p)) {
		idx = SCHED_PROP_DEADLINE_LEVEL0;
		goto done;
	}

	if (is_critical_app_task_without_isolate(p)) {
		idx = SCHED_PROP_DEADLINE_LEVEL1;
		goto done;
	}

	sp_dl = sched_get_dsq_id(p);
	if (sp_dl) {
		idx = sp_dl;
		goto done;
	}

	if (rt_prio(p->prio)) {
		idx = SCHED_PROP_DEADLINE_LEVEL3;
		goto done;
	}

	if (tg && tg->css.cgroup) {
		idx = tg->scx_deadline_idx;
	} else {
		idx = DEFAULT_CGROUP_DL_IDX;
	}

done:
	if (idx < 0 || idx >= MAX_GLOBAL_DSQS) {
		scx_deferred_err(DSQ_ID_ERR, "<error> : idx error, idx = %d-----\n", idx);
		idx = DEFAULT_CGROUP_DL_IDX;
	}
	return idx;
}

static struct scx_dispatch_q* find_dsq_from_task(struct task_struct *p)
{
        int idx;
	unsigned long flags;
	struct scx_dispatch_q *dsq;

        if (!p)
                return NULL;

        idx = find_idx_from_task(p);
	if(is_pcp_idx(idx)) {
		idx -= MAX_GLOBAL_DSQS;
                dsq = &per_cpu(pcp_ldsq, idx);
		p->scx->gdsq_idx = dsq_id_to_internal(dsq);
		slim_stats_record(PCP_LDSQ_CNT, 0, 0, idx);
	} else {
		dsq = &gdsqs[idx];
                p->scx->gdsq_idx = idx;
		slim_stats_record(GDSQ_CNT, 0, idx, 0);
	}

	raw_spin_lock_irqsave(&dsq->lock, flags);
        if (list_empty(&dsq->fifo)) {
                dsq->last_consume_at = jiffies;
        }
	raw_spin_unlock_irqrestore(&dsq->lock, flags);

        return dsq;
}


bool consume_dispatch_q(struct rq *rq, struct rq_flags *rf,
                               struct scx_dispatch_q *dsq);

static void set_partial_rescue(bool p_state, bool l_over, bool b_over)
{
	set_partial_status(p_state, l_over, b_over);
	update_cpus_idle(p_state, iso_masks.partial);
	scx_internal_systrace("C|9999|partial_enable|%d\n", is_partial_enabled());
	scx_internal_systrace("C|9999|l_need_rescue|%d\n", is_little_need_rescue());
	scx_internal_systrace("C|9999|b_need_rescue|%d\n", is_big_need_rescue());
}

static void free_isocpu(bool enable)
{
	set_iso_par_free(enable);
	update_cpus_idle(enable, iso_masks.ex_free);
	scx_internal_systrace("C|9999|free_iso|%d\n", is_iso_par_free());
}

static u64 get_cpus_max_util(struct cpumask *mask)
{
	int cpu;
	u64 max = 0;
	u64 util, ratio;

	for_each_cpu(cpu, mask) {
                trace_android_vh_get_util(cpu, NULL, &util);
                ratio = util * 100 / arch_scale_cpu_capacity(cpu);
		scx_info_systrace("C|9999|Cpu%d_util|%llu\n", cpu, util);
		scx_info_systrace("C|9999|Cpu%d_cap|%llu\n", cpu, (u64)arch_scale_cpu_capacity(cpu));
                if (ratio > max)
                        max = ratio;
        }
	return max;
}

static bool cluster_need_rescue(struct cpumask *mask, int hres)
{
	return get_cpus_max_util(mask) > hres;
}

void partial_dynamic_ctrl(void)
{
	u64 lmax = 0, bmax = 0;
	bool l_over, l_under, b_over, b_under;
	static bool last_l_over = false, last_b_over = false;
	static unsigned long last_check;

	/* Check partial every jiffies. need lock? */
	if (time_before_eq(jiffies, READ_ONCE(last_check)))
		return;

	WRITE_ONCE(last_check, jiffies);

	lmax = get_cpus_max_util(iso_masks.little);
	l_over = lmax > parctrl_high_ratio_l;
	l_under = lmax < parctrl_low_ratio_l;

	bmax = get_cpus_max_util(iso_masks.big);
	b_over = bmax > parctrl_high_ratio;
	b_under = bmax < parctrl_low_ratio;

	if (is_partial_enabled() && (l_over || b_over)) {
		if (last_l_over != l_over || last_b_over != b_over)
			set_partial_rescue(true, l_over, b_over);
	}
	else if (!is_partial_enabled() && (l_over || b_over)) {
		set_partial_rescue(true, l_over, b_over);
		scx_info_trace("<par>bmax = %llu, lmax = %llu\n", bmax, lmax);
	} else if (is_partial_enabled() && l_under && b_under) {
		set_partial_rescue(false, false, false);
	} else {}
	last_l_over = l_over;
	last_b_over = b_over;

	if (is_partial_enabled()) {
		bmax = get_cpus_max_util(iso_masks.partial);
		if (!is_iso_par_free() && bmax > isoctrl_high_ratio) {
			scx_info_trace("<par>partial max = %llu\n", bmax);
			free_isocpu(true);
		}
		else if (is_iso_par_free() && bmax < isoctrl_low_ratio)
			free_isocpu(false);
	} else if (is_iso_par_free()) {
		free_isocpu(false);
	}
}

static inline void slim_trace_show_cpu_consume_dsq_idx(unsigned int cpu, unsigned int idx)
{
	scx_info_systrace("C|9999|Cpu%d_dsq_id|%d\n", cpu, idx);
}

static int consume_target_dsq(struct rq *rq, struct rq_flags *rf, unsigned int idx)
{
	if (idx < 0 || idx >= max_ext_dsq_internal_id)
		return 0;

	if (consume_dispatch_q(rq, rf, &gdsqs[idx])) {
		slim_stats_record(GDSQ_CNT, 1, idx, 0);
		return 1;
	}
	return 0;
}

static int consume_period_dsq(struct rq *rq, struct rq_flags *rf)
{
        int i;

        for (i = 0; i < NON_PERIOD_START; i++) {
                if (consume_dispatch_q(rq, rf, &gdsqs[i])) {
			slim_stats_record(GDSQ_CNT, 1, i, 0);
                        return 1;
                }
        }
        return 0;
}

static void update_timeout_stats(struct rq *rq, struct scx_dispatch_q *dsq, u64 deadline)
{
	struct sched_ext_entity *entity;
	unsigned long flags;

	raw_spin_lock_irqsave(&dsq->lock, flags);
	if (list_empty(&dsq->fifo))
		goto clear_timeout;

	entity = list_first_entry(&dsq->fifo, struct sched_ext_entity, dsq_node.fifo);
	if (time_before_eq(jiffies, entity->runnable_at + msecs_to_jiffies(deadline)))
		goto clear_timeout;

	raw_spin_unlock_irqrestore(&dsq->lock, flags);
	scx_info_trace("<timeout>dsq[%d] still timeout task-%s, "
				"jiffies = %lu, deadline = %lu, runnable at = %lu\n",
				dsq_id_to_internal(dsq), entity->task->comm,
				jiffies, msecs_to_jiffies(deadline), entity->runnable_at);
	scx_info_systrace("C|9999|dsq_%d_timeout|%d\n", dsq_id_to_internal(dsq), 1);
	return;

clear_timeout:
	scx_info_trace("<timeout>dsq[%d] clear timeout\n",
				dsq_id_to_internal(dsq));
	scx_info_systrace("C|9999|dsq_%d_timeout|%d\n", dsq_id_to_internal(dsq), 0);
	dsq->is_timeout = false;
	slim_stats_record(PCP_TIMEOUT_CNT, 0, 0, cpu_of(rq));
	raw_spin_unlock_irqrestore(&dsq->lock, flags);
}

static void systrace_output_rtime_state(struct scx_dispatch_q *dsq, int rtime)
{
	scx_info_systrace("C|9999|dsq%d_rtime|%d\n", dsq_id_to_internal(dsq), rtime);
}

static int consume_pcp_dsq(struct rq *rq, struct rq_flags *rf, bool any)
{
        bool is_timeout;
        int cpu = cpu_of(rq);
        unsigned long flags;
        struct scx_dispatch_q *dsq = &per_cpu(pcp_ldsq, cpu);

        raw_spin_lock_irqsave(&dsq->lock, flags);
        is_timeout = dsq->is_timeout;
        raw_spin_unlock_irqrestore(&dsq->lock, flags);

	/*
	 * dsq->is_timeout may change here, let it be.
	 * it won't cause serious problems.
	 * the same for consume_dispatch_q later.
	 */
	if (!is_timeout && !any)
		return 0;

	if (consume_dispatch_q(rq, rf, dsq)) {
		if (is_timeout) {
			scx_info_trace("<timeout>dsq[%d] consume a pcp timeout task\n",
								dsq_id_to_internal(dsq));
			update_timeout_stats(rq, dsq, pcp_dsq_deadline);
			slim_stats_record(PCP_TIMEOUT_CNT, 0, 0, cpu);
		}
		slim_stats_record(PCP_LDSQ_CNT, 1, 0, cpu);
		return 1;
	}
	/*
	 * No pcp task, clear quota.
	 */
	if (any) {
		if (per_cpu(pcp_info, cpu_of(rq)).pcp_round) {
			per_cpu(pcp_info, cpu).rtime = 0;
			per_cpu(pcp_info, cpu).pcp_round = false;
			scx_info_systrace("C|9999|pcp_%d_round|%d\n", cpu, false);
			systrace_output_rtime_state(&per_cpu(pcp_ldsq, cpu),
					per_cpu(pcp_info, cpu).rtime);
		}
	}
        return 0;
}

static int consume_timeout_dsq(struct rq *rq, struct rq_flags *rf, struct cluster_ctx *ctx)
{
	int i;
	bool is_timeout;
	unsigned long flags;

	/* Third param <false> means only consume timeout pcp dsq. */
	if (consume_pcp_dsq(rq, rf, false))
		return 1;

	for(i = ctx->lower; i < ctx->upper; i++) {
		raw_spin_lock_irqsave(&gdsqs[i].lock, flags);
                is_timeout = gdsqs[i].is_timeout;
                raw_spin_unlock_irqrestore(&gdsqs[i].lock, flags);
		/* gdsqs[i].is_timeout may change here, let it be... */
		if (is_timeout) {
			/*
			 * consume_dispatch_q will acquire dsq-lock,
			 * So cannot keep lock here, annoy enough.
			 * may rewrite a consume_dispatch_q_locked, TODO.
			 */
                        if (consume_dispatch_q(rq, rf, &gdsqs[i])) {
				scx_info_trace("<timeout>dsq[%d] consume a timeout task\n", i);
                                slim_stats_record(TIMEOUT_CNT, ctx->tidx, 0, 0);
				update_timeout_stats(rq, &gdsqs[i], SCX_BPF_DSQS_DEADLINE[i]);
                                return 1;
                        }
                }
	}
	return 0;
}

static int check_pcp_dsq_round(struct rq *rq, struct rq_flags *rf)
{
	if (per_cpu(pcp_info, cpu_of(rq)).pcp_round) {
		if (consume_pcp_dsq(rq, rf, true))
			return 1;
	}
	return 0;
}

static int check_non_period_dsq_phase(struct rq *rq, struct rq_flags *rf,
						     int tmp, int cidx, int tidx)
{
	unsigned long flags;

	if (consume_dispatch_q(rq, rf, &gdsqs[tmp])) {
		if (tmp != cidx) {
			spin_lock(&sinfo.lock);
			sinfo.curr_idx[tidx] = tmp;
			spin_unlock(&sinfo.lock);
			scx_info_systrace("C|9999|cidx_%d|%d\n", tidx, sinfo.curr_idx[tidx]);
			slim_stats_record(SWITCH_IDX, 0, 0, 0);
		}
		slim_stats_record(GDSQ_CNT, 1, tmp, 0);

		raw_spin_lock_irqsave(&gdsqs[tmp].lock, flags);
		gdsqs[tmp].last_consume_at = jiffies;
		raw_spin_unlock_irqrestore(&gdsqs[tmp].lock, flags);
		return 1;
	}
	return 0;

}

static int get_cidx(struct cluster_ctx *ctx)
{
	int cidx;

	spin_lock(&sinfo.lock);
	cidx = sinfo.curr_idx[ctx->tidx];
	if (cidx < ctx->lower || cidx >= ctx->upper) {
		sinfo.curr_idx[ctx->tidx] = ctx->lower;
		scx_info_systrace("C|9999|cidx_%d|%d\n", ctx->tidx, sinfo.curr_idx[ctx->tidx]);
		slim_stats_record(ERR_IDX, ctx->tidx + 3, 0, 0);
		cidx = sinfo.curr_idx[ctx->tidx];
	}
	spin_unlock(&sinfo.lock);

	return cidx;
}


static int gen_cluster_ctx(struct cluster_ctx* ctx, enum cpu_type type)
{
	switch (type) {
	case PARTIAL:
		if (!is_partial_enabled())
			return -1;
		fallthrough;
#ifdef CLUSTER_SEPARATE
        case BIG:
                ctx->lower = NON_PERIOD_START;
                ctx->upper = CLUSTER_SEPARATE_IDX;
                ctx->tidx = 0;
                break;
        case LITTLE:
                ctx->lower = CLUSTER_SEPARATE_IDX;
                ctx->upper = NON_PERIOD_END;
                ctx->tidx = 1;
                break;
#else
	case BIG:
/*		ctx->lower = NON_PERIOD_START;
                ctx->upper = NON_PERIOD_END;
                ctx->tidx = 0;
		break;
*/
	case LITTLE:
		ctx->lower = NON_PERIOD_START;
		ctx->upper = NON_PERIOD_END;
		ctx->tidx = 0;
		break;
#endif
        default:
		scx_deferred_err(CPU_NO_MASK, "can't find cpu cluster\n");
                return -1;
        }
	return 0;
}

static int consume_non_period_dsq(struct rq *rq, struct rq_flags *rf, enum cpu_type type)
{
	struct cluster_ctx ctx;
        int cidx;
        int tmp;

	if (gen_cluster_ctx(&ctx, type))
		return 0;

	if (consume_timeout_dsq(rq, rf, &ctx))
		return 1;

	cidx = get_cidx(&ctx);
	tmp = cidx;
	do {
		if (check_pcp_dsq_round(rq, rf))
			return 1;
		if (check_non_period_dsq_phase(rq, rf, tmp, cidx, ctx.tidx))
			return 1;
		spin_lock(&sinfo.lock);
		sinfo.rtime[tmp] = 0;
		systrace_output_rtime_state(&gdsqs[tmp], sinfo.rtime[tmp]);
		tmp++;
		if (tmp >= ctx.upper) {
			atomic64_inc(&pcp_dsq_round);
			scx_info_systrace("C|9999|pcp_dsq_round|%lld\n", atomic64_read(&pcp_dsq_round));
			tmp = ctx.lower;
		}
		spin_unlock(&sinfo.lock);
	} while (tmp != cidx);

	return consume_pcp_dsq(rq, rf, true);
}


static int b_rescue_l, l_rescue_b;
static bool consume_hmbird_global_dsq(struct rq *rq, struct rq_flags *rf)
{
	enum cpu_type type = cpu_cluster(cpu_of(rq));
	int period_allowed = 1;
	int non_period_allowed = 1;

	trace_android_vh_scx_consume_dsq_allowed(rq, rf, SCHED_EXT_DSQ_TYPE_PERIOD, &period_allowed);
	trace_android_vh_scx_consume_dsq_allowed(rq, rf, SCHED_EXT_DSQ_TYPE_NON_PERIOD, &non_period_allowed);

	switch (type) {
		case EX_FREE:
			if (consume_period_dsq(rq, rf))
				return 1;
			if (consume_non_period_dsq(rq, rf, BIG))
				return 1;
			if (is_little_need_rescue())
				if (consume_non_period_dsq(rq, rf, LITTLE))
					return 1;
			break;
		case EXCLUSIVE:
			if (!is_iso_par_free()) {
				if (consume_pcp_dsq(rq, rf, true))
					return 1;
				break;
			}
			/* Only non-period task can run on isolate cpus */
			if (!READ_ONCE(iso_free_rescue)) {
				if (is_big_need_rescue())
					if (consume_non_period_dsq(rq, rf, BIG))
						return 1;
				if (is_little_need_rescue())
					if (consume_non_period_dsq(rq, rf, LITTLE))
						return 1;
			} else {
			/* Free run, can run on any task. */
				if (consume_period_dsq(rq, rf))
					return 1;
				if (consume_non_period_dsq(rq, rf, BIG))
					return 1;
				if (consume_non_period_dsq(rq, rf, LITTLE))
					return 1;
			}
			if (consume_pcp_dsq(rq, rf, true))
				return 1;
			break;
		case PARTIAL:
			if (!is_partial_enabled()) {
				if (consume_pcp_dsq(rq, rf, true))
					return 1;
				return 0;
			}
			if (is_big_need_rescue()) {
				if (period_allowed && consume_period_dsq(rq, rf))
					return 1;
				if (non_period_allowed && consume_non_period_dsq(rq, rf, BIG))
					return 1;
			}
			if (is_little_need_rescue()) {
				if (consume_target_dsq(rq, rf, SCHED_PROP_DEADLINE_LEVEL0))
					return 1;
				if (consume_target_dsq(rq, rf, SCHED_PROP_DEADLINE_LEVEL2))
					return 1;
				if (consume_target_dsq(rq, rf, SCHED_PROP_DEADLINE_LEVEL3))
					return 1;
				if (consume_target_dsq(rq, rf, SCHED_PROP_DEADLINE_LEVEL4))
					return 1;
				if (non_period_allowed && consume_non_period_dsq(rq, rf, LITTLE))
					return 1;
			}
			if (consume_pcp_dsq(rq, rf, true))
				return 1;
			break;

		case BIG:
			if (period_allowed && consume_period_dsq(rq, rf))
				return 1;
			if (non_period_allowed && consume_non_period_dsq(rq, rf, type))
				return 1;
			if (is_iso_par_free() || (is_little_need_rescue() &&
				!cluster_need_rescue(iso_masks.big, parctrl_high_ratio))) {
				if (consume_non_period_dsq(rq, rf, LITTLE)) {
					scx_internal_systrace("C|9999|b_rescue_l|%d\n", b_rescue_l++);
					return 1;
				}
			}
			break;

		case LITTLE:
			if (consume_target_dsq(rq, rf, SCHED_PROP_DEADLINE_LEVEL0))
				return 1;
			if (consume_target_dsq(rq, rf, SCHED_PROP_DEADLINE_LEVEL2))
				return 1;
			if (consume_target_dsq(rq, rf, SCHED_PROP_DEADLINE_LEVEL3))
				return 1;
			if (consume_target_dsq(rq, rf, SCHED_PROP_DEADLINE_LEVEL4))
				return 1;

			if (non_period_allowed && consume_non_period_dsq(rq, rf, type))
				return 1;

			if (is_iso_par_free() || (is_big_need_rescue() &&
				!cluster_need_rescue(iso_masks.little, parctrl_high_ratio_l))) {
				if (consume_non_period_dsq(rq, rf, BIG)) {
					scx_internal_systrace("C|9999|l_rescue_b|%d\n", l_rescue_b++);
					return 1;
				}
			}
			break;

		default:
			break;
	}
	return 0;
}

static int consume_dispatch_global(struct rq *rq, struct rq_flags *rf)
{
	return consume_hmbird_global_dsq(rq, rf);
}


static void update_runningtime(struct rq *rq, struct task_struct *p, unsigned long exec_time)
{
	int idx;

	/* which dsq belongs to while task enqueue, task will consume its running time. */
	idx = p->scx->gdsq_idx;
	/* Only non-period dsq share running time between each other. */
	if (idx < NON_PERIOD_START || idx >= max_ext_dsq_internal_id)
		return;

	if (idx >= MAX_GLOBAL_DSQS) {
		per_cpu(pcp_info, cpu_of(rq)).rtime += exec_time;
		systrace_output_rtime_state(&per_cpu(pcp_ldsq, cpu_of(rq)),
					per_cpu(pcp_info, cpu_of(rq)).rtime);
	}
	else {
		spin_lock(&sinfo.lock);
		sinfo.rtime[idx] += exec_time;
		spin_unlock(&sinfo.lock);
		systrace_output_rtime_state(&gdsqs[idx], sinfo.rtime[idx]);
	}
}

static void update_dsq_idx(struct rq *rq, struct task_struct *p, enum cpu_type type)
{
	int cidx;
	struct cluster_ctx ctx;
	int cpu = cpu_of(rq);

	if (gen_cluster_ctx(&ctx, type))
		return;

	spin_lock(&sinfo.lock);
	cidx = sinfo.curr_idx[ctx.tidx];
	if (cidx < ctx.lower || cidx >= ctx.upper) {
		sinfo.curr_idx[ctx.tidx] = ctx.lower;
		scx_info_systrace("C|9999|cidx_%d|%d\n", ctx.tidx, sinfo.curr_idx[ctx.tidx]);
		slim_stats_record(ERR_IDX, ctx.tidx, 0, 0);
		cidx = sinfo.curr_idx[ctx.tidx];
	}

	while(1) {
		if (per_cpu(pcp_info, cpu).pcp_round) {
			if (per_cpu(pcp_info, cpu).rtime >= pcp_dsq_quota) {
				scx_info_trace("<non> : cpu[%d] pcp_dsq_round is full, rtime = %d \n",
								cpu, per_cpu(pcp_info, cpu).rtime);
				per_cpu(pcp_info, cpu).rtime = 0;
				per_cpu(pcp_info, cpu).pcp_round = false;
				scx_info_systrace("C|9999|pcp_%d_round|%d\n", cpu, false);
				systrace_output_rtime_state(&per_cpu(pcp_ldsq, cpu),
						per_cpu(pcp_info, cpu_of(rq)).rtime);
			}
		}
		if (sinfo.rtime[cidx] < dsq_quota[cidx])
			break;

		/* clear current dsq rtime */
		sinfo.rtime[cidx] = 0;
		systrace_output_rtime_state(&gdsqs[cidx], sinfo.rtime[cidx]);

		sinfo.curr_idx[ctx.tidx]++;
		scx_info_systrace("C|9999|cidx_%d|%d\n", ctx.tidx, sinfo.curr_idx[ctx.tidx]);
		if (sinfo.curr_idx[ctx.tidx] >= ctx.upper) {
			atomic64_inc(&pcp_dsq_round);
			scx_info_systrace("C|9999|pcp_dsq_round|%lld\n", atomic64_read(&pcp_dsq_round));
			sinfo.curr_idx[ctx.tidx] = ctx.lower;
			scx_info_systrace("C|9999|cidx_%d|%d\n", ctx.tidx, sinfo.curr_idx[ctx.tidx]);
		}
		cidx = sinfo.curr_idx[ctx.tidx];
		slim_stats_record(SWITCH_IDX, 1, 0, 0);
	}
	spin_unlock(&sinfo.lock);
}

static void update_dispatch_dsq_info(struct rq *rq, struct task_struct *p)
{
	enum cpu_type type;
	if (!rq || !p)
		return;

	type = cpu_cluster(cpu_of(rq));
	/* rescue mode don't account running time, TODO. */
	switch(type) {
	case PARTIAL:
		return;
	case EXCLUSIVE:
		return;
	case EX_FREE:
		return;
	default:
		break;
        }
	update_dsq_idx(rq, p, type);
}


static bool scan_dsq_timeout(struct rq *rq, struct scx_dispatch_q *dsq, u64 deadline)
{
	struct sched_ext_entity *entity;
	int dsq_id;

	raw_spin_lock(&dsq->lock);
	if (list_empty(&dsq->fifo) || dsq->is_timeout) {
		raw_spin_unlock(&dsq->lock);
		return false;
	}

	entity = list_first_entry(&dsq->fifo, struct sched_ext_entity, dsq_node.fifo);
	if (!entity) {
		scx_deferred_err(SCAN_ENTITY_NULL, "<error> : entity is NULL, dsq->id = %llu\n", dsq->id);
		raw_spin_unlock(&dsq->lock);
		return false;
	}

	if (time_before_eq(jiffies, entity->runnable_at + msecs_to_jiffies(deadline))) {
		raw_spin_unlock(&dsq->lock);
		return false;
	}

	dsq->is_timeout = true;
	dsq_id = dsq_id_to_internal(dsq);
	scx_info_trace("<timeout>dsq[%d] has timeout task-%s, jiffies = %lu, runnable at = %lu\n",
						dsq_id, entity->task->comm,
						jiffies, entity->runnable_at);
	scx_info_systrace("C|9999|dsq_%d_timeout|%d\n", dsq_id, 1);
	raw_spin_unlock(&dsq->lock);

	return true;
}

void scan_timeout(struct rq *rq)
{
	int i;
	int cpu = cpu_of(rq);
	struct scx_dispatch_q *dsq;
	static u64 last_scan_at = 0;
	static DEFINE_PER_CPU(u64, pcp_last_scan_at);

	if (time_before_eq(jiffies, (unsigned long)per_cpu(pcp_last_scan_at, cpu)))
		return;
	per_cpu(pcp_last_scan_at, cpu) = jiffies;

	dsq = &per_cpu(pcp_ldsq, cpu);
	scan_dsq_timeout(rq, dsq, pcp_dsq_deadline);

	if (time_before_eq(jiffies, (unsigned long)last_scan_at))
		return;
	last_scan_at = jiffies;

	for (i = NON_PERIOD_START; i < NON_PERIOD_END; i++) {
		dsq = &gdsqs[i];
		scan_dsq_timeout(rq, dsq, SCX_BPF_DSQS_DEADLINE[i]);
	}
}

/*******************************Initialize***********************************/

void init_dsq(struct scx_dispatch_q *dsq, u64 dsq_id);
static void init_dsq_at_boot(void)
{
	int i, cpu;

	for (i = 0; i < MAX_GLOBAL_DSQS; i++) {
		init_dsq(&gdsqs[i], (u64)SCX_DSQ_FLAG_BUILTIN |
				(GDSQS_ID_BASE + i));
        }
	for_each_possible_cpu(cpu)
		init_dsq(&per_cpu(pcp_ldsq, cpu), (u64)SCX_DSQ_FLAG_BUILTIN |
				(GDSQS_ID_BASE + i + cpu));

	max_ext_dsq_internal_id = GDSQS_ID_BASE + i + cpu;
	spin_lock_init(&sinfo.lock);
}


static int cgrp_name_to_idx(struct cgroup *cgrp)
{
	int idx;

	if (!cgrp)
		return -1;

	if (!strcmp(cgrp->kn->name, "display")
			|| !strcmp(cgrp->kn->name, "multimedia"))
		idx = 5; /* 8ms */
	else if (!strcmp(cgrp->kn->name, "top-app")
			|| !strcmp(cgrp->kn->name, "ss-top"))
		idx = 6; /* 16ms */
	else if (!strcmp(cgrp->kn->name, "ssfg")
			|| !strcmp(cgrp->kn->name, "foreground"))
		idx = 7; /* 32ms */
	else if (!strcmp(cgrp->kn->name, "bg")
			|| !strcmp(cgrp->kn->name, "log")
			|| !strcmp(cgrp->kn->name, "dex2oat")
			|| !strcmp(cgrp->kn->name, "background"))
		idx = 9; /* 128ms */
	else
		idx = DEFAULT_CGROUP_DL_IDX; /* 64ms */

	return idx;
}

static void init_root_tg(struct cgroup  *cgrp, struct task_group *tg)
{
	if (!cgrp || !tg)
		return;
	tg->scx_deadline_idx = DEFAULT_CGROUP_DL_IDX;
}

static void init_level1_tg(struct cgroup *cgrp, struct task_group *tg)
{
	if (!cgrp || !tg)
		return;

	if (-1 == tg->scx_deadline_idx)
		tg->scx_deadline_idx = cgrp_name_to_idx(cgrp);
}

static void init_child_tg(struct cgroup *cgrp, struct task_group *tg)
{
	struct cgroup *l1cgrp;

	if (!cgrp || !tg)
		return;

	l1cgrp = cgroup_ancestor_l1(cgrp);
	if (NULL == l1cgrp) {
		tg->scx_deadline_idx = DEFAULT_CGROUP_DL_IDX;
		return;
	}
	tg->scx_deadline_idx = cgrp_name_to_idx(l1cgrp);
	cgroup_put(l1cgrp);
}

static void cgrp_dsq_idx_init(struct cgroup *cgrp, struct task_group *tg)
{
	switch (cgrp->level) {
	case 0:
		init_root_tg(cgrp, tg);
		break;
	case 1:
		init_level1_tg(cgrp, tg);
		break;
	default:
		init_child_tg(cgrp, tg);
		break;
	}
}

/**************************************************************************/

static u64 tick_sched_clock;
static DECLARE_COMPLETION(tick_sched_clock_completion);

void scx_scheduler_tick(void)
{
	int cpu = smp_processor_id();
	struct rq *rq = cpu_rq(cpu);

	if (!atomic_cmpxchg(&set_sched_clock_prepare, true, false))
		return;

	if(unlikely(!tick_sched_clock)) {
		/*
		 * Let the window begin 20us prior to the tick,
		 * that way we are guaranteed a rollover when the tick occurs.
		 * Use rq->clock directly instead of rq_clock() since
		 * we do not have the rq lock and
		 * rq->clock was updated in the tick callpath.
		 */
		if (cmpxchg64(&tick_sched_clock, 0, rq->clock - 20000))
			return;
		for_each_possible_cpu(cpu) {
			struct scx_sched_rq_stats *srq = &per_cpu(scx_sched_rq_stats, cpu);
			srq->window_start = tick_sched_clock;
		}
		complete(&tick_sched_clock_completion);
	}
}


struct scx_task_iter {
	struct sched_ext_entity		cursor;
	struct task_struct		*locked;
	struct rq			*rq;
	struct rq_flags			rf;
};

/**
 * scx_task_iter_init - Initialize a task iterator
 * @iter: iterator to init
 *
 * Initialize @iter. Must be called with scx_tasks_lock held. Once initialized,
 * @iter must eventually be exited with scx_task_iter_exit().
 *
 * scx_tasks_lock may be released between this and the first next() call or
 * between any two next() calls. If scx_tasks_lock is released between two
 * next() calls, the caller is responsible for ensuring that the task being
 * iterated remains accessible either through RCU read lock or obtaining a
 * reference count.
 *
 * All tasks which existed when the iteration started are guaranteed to be
 * visited as long as they still exist.
 */
static void scx_task_iter_init(struct scx_task_iter *iter)
{
	lockdep_assert_held(&scx_tasks_lock);

	iter->cursor = (struct sched_ext_entity){ .flags = SCX_TASK_CURSOR };
	list_add(&iter->cursor.tasks_node, &scx_tasks);
	iter->locked = NULL;
}

/**
 * scx_task_iter_exit - Exit a task iterator
 * @iter: iterator to exit
 *
 * Exit a previously initialized @iter. Must be called with scx_tasks_lock held.
 * If the iterator holds a task's rq lock, that rq lock is released. See
 * scx_task_iter_init() for details.
 */
static void scx_task_iter_exit(struct scx_task_iter *iter)
{
	struct list_head *cursor = &iter->cursor.tasks_node;

	lockdep_assert_held(&scx_tasks_lock);

	if (iter->locked) {
		task_rq_unlock(iter->rq, iter->locked, &iter->rf);
		iter->locked = NULL;
	}

	if (list_empty(cursor))
		return;

	list_del_init(cursor);
}

/**
 * scx_task_iter_next - Next task
 * @iter: iterator to walk
 *
 * Visit the next task. See scx_task_iter_init() for details.
 */
static struct task_struct *scx_task_iter_next(struct scx_task_iter *iter)
{
	struct list_head *cursor = &iter->cursor.tasks_node;
	struct sched_ext_entity *pos;

	lockdep_assert_held(&scx_tasks_lock);

	list_for_each_entry(pos, cursor, tasks_node) {
		if (&pos->tasks_node == &scx_tasks)
			return NULL;
		if (!(pos->flags & SCX_TASK_CURSOR)) {
			list_move(cursor, &pos->tasks_node);
			return pos->task;
		}
	}

	/* can't happen, should always terminate at scx_tasks above */
	scx_deferred_err(ITER_RET_NULL, "<error> : unreachable path in scx_task_iter_next\n");
	return NULL;
}

/**
 * scx_task_iter_next_filtered - Next non-idle task
 * @iter: iterator to walk
 *
 * Visit the next non-idle task. See scx_task_iter_init() for details.
 */
static struct task_struct *
scx_task_iter_next_filtered(struct scx_task_iter *iter)
{
	struct task_struct *p;

	while ((p = scx_task_iter_next(iter))) {
		if (!is_idle_task(p))
			return p;
	}
	return NULL;
}

/**
 * scx_task_iter_next_filtered_locked - Next non-idle task with its rq locked
 * @iter: iterator to walk
 *
 * Visit the next non-idle task with its rq lock held. See scx_task_iter_init()
 * for details.
 */
static struct task_struct *
scx_task_iter_next_filtered_locked(struct scx_task_iter *iter)
{
	struct task_struct *p;

	if (iter->locked) {
		task_rq_unlock(iter->rq, iter->locked, &iter->rf);
		iter->locked = NULL;
	}

	p = scx_task_iter_next_filtered(iter);
	if (!p)
		return NULL;

	iter->rq = task_rq_lock(p, &iter->rf);
	iter->locked = p;
	return p;
}

static enum scx_ops_enable_state scx_ops_enable_state(void)
{
	return atomic_read(&scx_ops_enable_state_var);
}

static enum scx_ops_enable_state
scx_ops_set_enable_state(enum scx_ops_enable_state to)
{
	return atomic_xchg(&scx_ops_enable_state_var, to);
}

static bool scx_ops_tryset_enable_state(enum scx_ops_enable_state to,
					enum scx_ops_enable_state from)
{
	int from_v = from;

	return atomic_try_cmpxchg(&scx_ops_enable_state_var, &from_v, to);
}

static bool scx_ops_disabling(void)
{
	return false;
}

/**
 * wait_ops_state - Busy-wait the specified ops state to end
 * @p: target task
 * @opss: state to wait the end of
 *
 * Busy-wait for @p to transition out of @opss. This can only be used when the
 * state part of @opss is %SCX_QUEUEING or %SCX_DISPATCHING. This function also
 * has load_acquire semantics to ensure that the caller can see the updates made
 * in the enqueueing and dispatching paths.
 */
static void wait_ops_state(struct task_struct *p, u64 opss)
{
	do {
		cpu_relax();
	} while (atomic64_read_acquire(&p->scx->ops_state) == opss);
}


static void update_curr_scx(struct rq *rq)
{
	struct task_struct *curr = rq->curr;
	u64 now = rq_clock_task(rq);
	u64 delta_exec;

	if (time_before_eq64(now, curr->se.exec_start))
		return;

	delta_exec = now - curr->se.exec_start;
	curr->se.exec_start = now;
	update_runningtime(rq, curr, delta_exec);
	curr->se.sum_exec_runtime += delta_exec;
	account_group_exec_runtime(curr, delta_exec);
	cgroup_account_cputime(curr, delta_exec);

	if (curr->scx->slice != SCX_SLICE_INF)
		curr->scx->slice -= min(curr->scx->slice, delta_exec);

	trace_sched_stat_runtime(curr, delta_exec, 0);
}

static bool scx_dsq_priq_less(struct rb_node *node_a,
			      const struct rb_node *node_b)
{
	const struct sched_ext_entity *a =
		container_of(node_a, struct sched_ext_entity, dsq_node.priq);
	const struct sched_ext_entity *b =
		container_of(node_b, struct sched_ext_entity, dsq_node.priq);

	return time_before64(a->dsq_vtime, b->dsq_vtime);
}

static void dispatch_enqueue(struct scx_dispatch_q *dsq, struct task_struct *p,
			     u64 enq_flags)
{
	bool is_local = dsq->id == SCX_DSQ_LOCAL;
	unsigned long flags;

	scx_cond_deferred_err(ENQ_EXIST1, p->scx->dsq || !list_empty(&p->scx->dsq_node.fifo),
					"task = %s, dsq->id = %llu\n", p->comm, dsq->id);
	scx_cond_deferred_err(ENQ_EXIST2, (p->scx->dsq_flags & SCX_TASK_DSQ_ON_PRIQ) ||
						!RB_EMPTY_NODE(&p->scx->dsq_node.priq),
						"task = %s\n", p->comm);

	if (!is_local) {
		raw_spin_lock_irqsave(&dsq->lock, flags);
		if (unlikely(dsq->id == SCX_DSQ_INVALID)) {
			WRITE_ONCE(sw_type, SCX_SWITCH_ERR_DSQ);
			scx_ops_error("<hmbird_sched>:attempting to dispatch to a destroyed dsq");
			/* fall back to the global dsq */
			raw_spin_unlock_irqrestore(&dsq->lock, flags);
			dsq = &scx_dsq_global;
			raw_spin_lock_irqsave(&dsq->lock, flags);
		}
	}

	if (enq_flags & SCX_ENQ_DSQ_PRIQ) {
		p->scx->dsq_flags |= SCX_TASK_DSQ_ON_PRIQ;
		rb_add_cached(&p->scx->dsq_node.priq, &dsq->priq,
			      scx_dsq_priq_less);
	} else {
		if (enq_flags & (SCX_ENQ_HEAD | SCX_ENQ_PREEMPT))
			list_add(&p->scx->dsq_node.fifo, &dsq->fifo);
		else
			list_add_tail(&p->scx->dsq_node.fifo, &dsq->fifo);
	}
	dsq->nr++;
	p->scx->dsq = dsq;

	/*
	 * We're transitioning out of QUEUEING or DISPATCHING. store_release to
	 * match waiters' load_acquire.
	 */
	if (enq_flags & SCX_ENQ_CLEAR_OPSS)
		atomic64_set_release(&p->scx->ops_state, SCX_OPSS_NONE);

	if (is_local) {
		struct scx_rq *scx = container_of(dsq, struct scx_rq, local_dsq);
		struct rq *rq = scx->rq;
		bool preempt = false;

		if ((enq_flags & SCX_ENQ_PREEMPT) && p != rq->curr &&
		    rq->curr->sched_class == &ext_sched_class) {
			rq->curr->scx->slice = 0;
			preempt = true;
		}

		if (preempt || sched_class_above(&ext_sched_class,
						 rq->curr->sched_class))
			resched_curr(rq);
	} else {
		raw_spin_unlock_irqrestore(&dsq->lock, flags);
	}
}

static void task_unlink_from_dsq(struct task_struct *p,
				 struct scx_dispatch_q *dsq)
{
	if (p->scx->dsq_flags & SCX_TASK_DSQ_ON_PRIQ) {
		rb_erase_cached(&p->scx->dsq_node.priq, &dsq->priq);
		RB_CLEAR_NODE(&p->scx->dsq_node.priq);
		p->scx->dsq_flags &= ~SCX_TASK_DSQ_ON_PRIQ;
	} else {
		list_del_init(&p->scx->dsq_node.fifo);
	}
}

static bool task_linked_on_dsq(struct task_struct *p)
{
	return !list_empty(&p->scx->dsq_node.fifo) ||
		!RB_EMPTY_NODE(&p->scx->dsq_node.priq);
}

static void dispatch_dequeue(struct scx_rq *scx_rq, struct task_struct *p)
{
	unsigned long flags;
	struct scx_dispatch_q *dsq = p->scx->dsq;
	bool is_local = dsq == &scx_rq->local_dsq;

	if (!dsq) {
		scx_cond_deferred_err(TASK_LINKED1, task_linked_on_dsq(p), "task = %s\n", p->comm);
		/*
		 * When dispatching directly from the BPF scheduler to a local
		 * DSQ, the task isn't associated with any DSQ but
		 * @p->scx->holding_cpu may be set under the protection of
		 * %SCX_OPSS_DISPATCHING.
		 */
		if (p->scx->holding_cpu >= 0)
			p->scx->holding_cpu = -1;
		return;
	}

	if (!is_local)
		raw_spin_lock_irqsave(&dsq->lock, flags);

	/*
	 * Now that we hold @dsq->lock, @p->holding_cpu and @p->scx->dsq_node
	 * can't change underneath us.
	*/
	if (p->scx->holding_cpu < 0) {
		/* @p must still be on @dsq, dequeue */
		scx_cond_deferred_err(TASK_UNLINKED, !task_linked_on_dsq(p), "task = %s\n", p->comm);
		task_unlink_from_dsq(p, dsq);
		dsq->nr--;
	} else {
		/*
		 * We're racing against dispatch_to_local_dsq() which already
		 * removed @p from @dsq and set @p->scx->holding_cpu. Clear the
		 * holding_cpu which tells dispatch_to_local_dsq() that it lost
		 * the race.
		 */
		scx_cond_deferred_err(TASK_LINKED2, task_linked_on_dsq(p), "task = %s\n", p->comm);
		p->scx->holding_cpu = -1;
	}
	p->scx->dsq = NULL;

	if (!is_local)
		raw_spin_unlock_irqrestore(&dsq->lock, flags);
}


static bool test_rq_online(struct rq *rq)
{
#ifdef CONFIG_SMP
	return rq->online;
#else
	return true;
#endif
}

static void refill_task_slice(struct task_struct *p)
{
	if (is_isolate_task(p))
		p->scx->slice = SCX_SLICE_ISO;
	else if (is_pipeline_task(p))
		p->scx->slice = SCX_SLICE_ISO / 2;
	else
		p->scx->slice = SCX_SLICE_DFL;
}

static void do_enqueue_task(struct rq *rq, struct task_struct *p, u64 enq_flags,
			    int sticky_cpu)
{
	struct scx_dispatch_q* d;

	scx_cond_deferred_err(TASK_UNQUED, !test_bit(ffs(SCX_TASK_QUEUED),
				(unsigned long*)&p->scx->flags),
				"task = %s\n", p->comm);

	if (is_pcp_rt(p)) {
		/* Enqueue percpu rt task to local directly. */
		/* Or cause a bug when disable dispatch. */
		if (cpumask_test_cpu(cpu_of(rq), p->cpus_ptr)) {
			enq_flags |= SCX_ENQ_LOCAL;
			scx_info_trace("<pcprt>:find a pcp rt task:%s\n", p->comm);
		}
	}

	if (test_bit(ffs(SCX_TASK_ENQ_LOCAL), (unsigned long*)&p->scx->flags)) {
		enq_flags |= SCX_ENQ_LOCAL;
		clear_bit(ffs(SCX_TASK_ENQ_LOCAL), (unsigned long*)&p->scx->flags);
	}
	/* rq migration */
	if (sticky_cpu == cpu_of(rq))
		goto local_norefill;
	/*
	 * If !rq->online, we already told the BPF scheduler that the CPU is
	 * offline. We're just trying to on/offline the CPU. Don't bother the
	 * BPF scheduler.
	 */
	if (unlikely(!test_rq_online(rq)))
		goto local;

	/* see %SCX_OPS_ENQ_LAST */
	if (enq_flags & SCX_ENQ_LAST)
		goto local;

	if (enq_flags & SCX_ENQ_LOCAL)
		goto local;
	else
		goto global;
local:
	/*
	 * For task-ordering, slice refill must be treated as implying the end
	 * of the current slice. Otherwise, the longer @p stays on the CPU, the
	 * higher priority it becomes from scx_prio_less()'s POV.
	 */
	refill_task_slice(p);
local_norefill:
	dispatch_enqueue(&rq->scx->local_dsq, p, enq_flags);
	slim_stats_record(PCP_ENQL_CNT, 0, 0, cpu_of(rq));
	return;

global:
	d = find_dsq_from_task(p);
	if (d) {
		refill_task_slice(p);
		dispatch_enqueue(d, p, enq_flags);
		return;
	}
	slim_stats_record(GLOBAL_STAT, 0, 0, 0);
	refill_task_slice(p);
	dispatch_enqueue(&scx_dsq_global, p, enq_flags);
}

static bool watchdog_task_watched(const struct task_struct *p)
{
	return !list_empty(&p->scx->watchdog_node);
}

static void watchdog_watch_task(struct rq *rq, struct task_struct *p)
{
	lockdep_assert_rq_held(rq);
	if (test_bit(ffs(SCX_TASK_WATCHDOG_RESET), (unsigned long*)&p->scx->flags))
		p->scx->runnable_at = jiffies;
	clear_bit(ffs(SCX_TASK_WATCHDOG_RESET), (unsigned long*)&p->scx->flags);
	list_add_tail(&p->scx->watchdog_node, &rq->scx->watchdog_list);
}

static void watchdog_unwatch_task(struct task_struct *p, bool reset_timeout)
{
	list_del_init(&p->scx->watchdog_node);
	if (reset_timeout)
		set_bit(ffs(SCX_TASK_WATCHDOG_RESET), (unsigned long*)&p->scx->flags);
}

static void enqueue_task_scx(struct rq *rq, struct task_struct *p, int enq_flags)
{
	int sticky_cpu = p->scx->sticky_cpu;

	enq_flags |= rq->scx->extra_enq_flags;

	if (sticky_cpu >= 0)
		p->scx->sticky_cpu = -1;

	/*
	 * Restoring a running task will be immediately followed by
	 * set_next_task_scx() which expects the task to not be on the BPF
	 * scheduler as tasks can only start running through local DSQs. Force
	 * direct-dispatch into the local DSQ by setting the sticky_cpu.
	 */
	if (unlikely(enq_flags & ENQUEUE_RESTORE) && task_current(rq, p))
		sticky_cpu = cpu_of(rq);

	if (test_bit(ffs(SCX_TASK_QUEUED), (unsigned long*)&p->scx->flags)) {
		scx_cond_deferred_err(TASK_UNWATCHED,
			!watchdog_task_watched(p), "task = %s\n", p->comm);
		return;
	}

	watchdog_watch_task(rq, p);
	set_bit(ffs(SCX_TASK_QUEUED), (unsigned long*)&p->scx->flags);
	rq->scx->nr_running++;
	add_nr_running(rq, 1);

	do_enqueue_task(rq, p, enq_flags, sticky_cpu);
}

static void ops_dequeue(struct task_struct *p, u64 deq_flags)
{
	u64 opss;

	watchdog_unwatch_task(p, false);

	/* acquire ensures that we see the preceding updates on QUEUED */
	opss = atomic64_read_acquire(&p->scx->ops_state);

	switch (opss & SCX_OPSS_STATE_MASK) {
	case SCX_OPSS_NONE:
		break;
	case SCX_OPSS_QUEUEING:
		/*
		 * QUEUEING is started and finished while holding @p's rq lock.
		 * As we're holding the rq lock now, we shouldn't see QUEUEING.
		 */
		scx_deferred_err(DEQ_DEQING, "<error> : unreachable path in ops_dequeue\n");
		break;
	case SCX_OPSS_QUEUED:
		if (atomic64_try_cmpxchg(&p->scx->ops_state, &opss,
					 SCX_OPSS_NONE))
			break;
		fallthrough;
	case SCX_OPSS_DISPATCHING:
		/*
		 * If @p is being dispatched from the BPF scheduler to a DSQ,
		 * wait for the transfer to complete so that @p doesn't get
		 * added to its DSQ after dequeueing is complete.
		 *
		 * As we're waiting on DISPATCHING with the rq locked, the
		 * dispatching side shouldn't try to lock the rq while
		 * DISPATCHING is set. See dispatch_to_local_dsq().
		 *
		 * DISPATCHING shouldn't have qseq set and control can reach
		 * here with NONE @opss from the above QUEUED case block.
		 * Explicitly wait on %SCX_OPSS_DISPATCHING instead of @opss.
		 */
		wait_ops_state(p, SCX_OPSS_DISPATCHING);
		scx_cond_deferred_err(SCX_OPN,
			atomic64_read(&p->scx->ops_state) != SCX_OPSS_NONE, "task = %s\n", p->comm);
		break;
	}
}

static void dequeue_task_scx(struct rq *rq, struct task_struct *p, int deq_flags)
{
	struct scx_rq *scx_rq = rq->scx;

	if (!test_bit(ffs(SCX_TASK_QUEUED), (unsigned long*)&p->scx->flags)) {
		scx_cond_deferred_err(TASK_WATCHED, watchdog_task_watched(p), "task = %s\n", p->comm);
		return;
	}

	ops_dequeue(p, deq_flags);

	if(task_current(rq, p))
		trace_android_vh_hmbird_update_load(p, rq, PUT_PREV_TASK, rq->clock);

	if (deq_flags & SCX_DEQ_SLEEP)
		set_bit(ffs(SCX_TASK_DEQD_FOR_SLEEP), (unsigned long*)&p->scx->flags);
	else
		clear_bit(ffs(SCX_TASK_DEQD_FOR_SLEEP), (unsigned long*)&p->scx->flags);

	clear_bit(ffs(SCX_TASK_QUEUED), (unsigned long*)&p->scx->flags);
	scx_cond_deferred_err(RQ_NO_RUNNING, !scx_rq->nr_running, "task = %s\n", p->comm);
	scx_rq->nr_running--;
	sub_nr_running(rq, 1);
	dispatch_dequeue(scx_rq, p);
}

static void yield_task_scx(struct rq *rq)
{
	struct task_struct *p = rq->curr;

	p->scx->slice = 0;
}

static bool yield_to_task_scx(struct rq *rq, struct task_struct *to)
{
	return false;
}

#ifdef CONFIG_SMP
/**
 * move_task_to_local_dsq - Move a task from a different rq to a local DSQ
 * @rq: rq to move the task into, currently locked
 * @p: task to move
 * @enq_flags: %SCX_ENQ_*
 *
 * Move @p which is currently on a different rq to @rq's local DSQ. The caller
 * must:
 *
 * 1. Start with exclusive access to @p either through its DSQ lock or
 *    %SCX_OPSS_DISPATCHING flag.
 *
 * 2. Set @p->scx->holding_cpu to raw_smp_processor_id().
 *
 * 3. Remember task_rq(@p). Release the exclusive access so that we don't
 *    deadlock with dequeue.
 *
 * 4. Lock @rq and the task_rq from #3.
 *
 * 5. Call this function.
 *
 * Returns %true if @p was successfully moved. %false after racing dequeue and
 * losing.
 */
static bool move_task_to_local_dsq(struct rq *rq, struct task_struct *p,
				   u64 enq_flags)
{
	struct rq *task_rq;

	lockdep_assert_rq_held(rq);

	/*
	 * If dequeue got to @p while we were trying to lock both rq's, it'd
	 * have cleared @p->scx->holding_cpu to -1. While other cpus may have
	 * updated it to different values afterwards, as this operation can't be
	 * preempted or recurse, @p->scx->holding_cpu can never become
	 * raw_smp_processor_id() again before we're done. Thus, we can tell
	 * whether we lost to dequeue by testing whether @p->scx->holding_cpu is
	 * still raw_smp_processor_id().
	 *
	 * See dispatch_dequeue() for the counterpart.
	 */
	if (unlikely(p->scx->holding_cpu != raw_smp_processor_id()))
		return false;

	/* @p->rq couldn't have changed if we're still the holding cpu */
	task_rq = task_rq(p);
	lockdep_assert_rq_held(task_rq);
	deactivate_task(task_rq, p, 0);
	set_task_cpu(p, cpu_of(rq));
	p->scx->sticky_cpu = cpu_of(rq);

	/*
	 * We want to pass scx-specific enq_flags but activate_task() will
	 * truncate the upper 32 bit. As we own @rq, we can pass them through
	 * @rq->scx->extra_enq_flags instead.
	 */
	scx_cond_deferred_err(EXTRA_FLAGS, rq->scx->extra_enq_flags, "task = %s\n", p->comm);
	rq->scx->extra_enq_flags = enq_flags;
	activate_task(rq, p, 0);
	rq->scx->extra_enq_flags = 0;

	return true;
}

#endif	/* CONFIG_SMP */

static int task_fits_cpu_scx(struct task_struct *p, int cpu)
{
	int fitable = 1;

	trace_android_vh_task_fits_cpu_scx(p, cpu, &fitable);

	return fitable;
}

static int check_misfit_task_on_little(struct task_struct *p, struct rq *rq, struct scx_dispatch_q *dsq)
{
	bool dsq_misfit;
	int cpu = cpu_of(rq);
	u64 task_util = 0;
	struct cluster_ctx ctx;
	int dsq_int = dsq_id_to_internal(dsq);

	if (!cpumask_test_cpu(cpu, iso_masks.little))
		return false;

	gen_cluster_ctx(&ctx, BIG);
	dsq_misfit = (dsq_int >= SCHED_PROP_DEADLINE_LEVEL1 &&
				dsq_int <= SCHED_PROP_DEADLINE_LEVEL3);
#ifdef CLUSTER_SEPARATE
	/* In rescue mode, little will consume big cluster's dsq.*/
	dsq_misfit |= (dsq_int >= ctx.lower && dsq_int < ctx.upper);
#endif
	if (!dsq_misfit)
		return false;

	trace_android_vh_get_util(-1, p, &task_util);
	if (task_util <= misfit_ds)
		return false;

	scx_info_trace("<filter>:task %s can't run on cpu%d, util = %llu\n",
							p->comm, cpu, task_util);
	return true;
}

static bool task_can_run_on_rq(struct task_struct *p, struct rq *rq, struct scx_dispatch_q *dsq)
{
	if (!task_fits_cpu_scx(p, cpu_of(rq)))
		return false;

	if (check_misfit_task_on_little(p, rq, dsq))
		return false;

	return likely(test_rq_online(rq));
}

static int skip_num[MAX_GLOBAL_DSQS];

static void set_skip_num(struct scx_dispatch_q *dsq, int *skipn, bool add)
{
	int idx = dsq_id_to_internal(dsq);
	int type = get_dsq_type(dsq);

	if (type != GLOBAL_DSQ)
		return;

	if (add)
		skipn[idx]++;
	else
		skipn[idx] = 0;
}

static bool skip_too_much(struct scx_dispatch_q *dsq)
{
	int idx = dsq_id_to_internal(dsq);
	int type = get_dsq_type(dsq);

	if (type != GLOBAL_DSQ)
		return false;

	if (skip_num[idx] > 3) {
		skip_num[idx] = 0;
		return true;
	}

	return false;
}

bool consume_dispatch_q(struct rq *rq, struct rq_flags *rf,
			       struct scx_dispatch_q *dsq)
{
	struct scx_rq *scx_rq = rq->scx;
	struct sched_ext_entity *entity;
	struct task_struct *p;
	struct rb_node *rb_node;
	struct rq *task_rq;
	unsigned long flags;
	bool moved = false;
	struct task_struct *may_fit = NULL;
	int skip = 0;

retry:
	if (list_empty(&dsq->fifo) && !rb_first_cached(&dsq->priq))
		return false;

	raw_spin_lock_irqsave(&dsq->lock, flags);

	list_for_each_entry(entity, &dsq->fifo, dsq_node.fifo) {
		p = entity->task;
		task_rq = task_rq(p);
		if (!task_can_run_on_rq(p, rq, dsq))
			continue;
		if (rq == task_rq) {
			set_skip_num(dsq, skip_num, (bool)may_fit);
			goto this_rq;
		}
		if (skip_too_much(dsq))
			goto remote_rq;
		if (!may_fit)
			may_fit = p;
		if (++skip <= 3)
			continue;
		/*
		 * If the recent 3 tasks not fit, use the first one.
		 * and clear the skip, because the first one is consumed.
		 */
		set_skip_num(dsq, skip_num, false);
		p = may_fit;
		task_rq = task_rq(p);
		goto remote_rq;
	}
	/* No more task, use the first may fit task.*/
	if (may_fit) {
		p = may_fit;
		task_rq = task_rq(p);
		goto remote_rq;
	}

	for (rb_node = rb_first_cached(&dsq->priq); rb_node;
	     rb_node = rb_next(rb_node)) {
		entity = container_of(rb_node, struct sched_ext_entity, dsq_node.priq);
		p = entity->task;
		task_rq = task_rq(p);
		if (!task_can_run_on_rq(p, rq, dsq))
			continue;
		if (rq == task_rq)
			goto this_rq;
		goto remote_rq;
	}

	raw_spin_unlock_irqrestore(&dsq->lock, flags);
	return false;

this_rq:
	/* @dsq is locked and @p is on this rq */
	scx_cond_deferred_err(HOLDING_CPU1, p->scx->holding_cpu >= 0, "task = %s\n", p->comm);
	task_unlink_from_dsq(p, dsq);
	list_add_tail(&p->scx->dsq_node.fifo, &scx_rq->local_dsq.fifo);
	dsq->nr--;
	scx_rq->local_dsq.nr++;
	p->scx->dsq = &scx_rq->local_dsq;
	raw_spin_unlock_irqrestore(&dsq->lock, flags);
	slim_stats_record(TOTAL_DSP_CNT, 0, 0, 0);
	return true;

remote_rq:
#ifdef CONFIG_SMP
	if (cpu_same_cluster_stat(p, rq, task_rq))
		slim_stats_record(MOVE_RQ_CNT, 0, 0, 0);
	else
		slim_stats_record(MOVE_RQ_CNT, 1, 0, 0);
	/*
	 * @dsq is locked and @p is on a remote rq. @p is currently protected by
	 * @dsq->lock. We want to pull @p to @rq but may deadlock if we grab
	 * @task_rq while holding @dsq and @rq locks. As dequeue can't drop the
	 * rq lock or fail, do a little dancing from our side. See
	 * move_task_to_local_dsq().
	 */
	scx_cond_deferred_err(HOLDING_CPU2, p->scx->holding_cpu >= 0, "task = %s\n", p->comm);
	task_unlink_from_dsq(p, dsq);
	dsq->nr--;
	p->scx->holding_cpu = raw_smp_processor_id();
	raw_spin_unlock_irqrestore(&dsq->lock, flags);

	rq_unpin_lock(rq, rf);
	double_lock_balance(rq, task_rq);
	rq_repin_lock(rq, rf);

	moved = move_task_to_local_dsq(rq, p, 0);

	double_unlock_balance(rq, task_rq);
#endif /* CONFIG_SMP */
	if (likely(moved)) {
		slim_stats_record(TOTAL_DSP_CNT, 0, 0, 0);
		return true;
	}
	/*
	 * MUST reset may_fit, we had released dsq->lock for a while.
	 * the fifo may changed.
	 */
	may_fit = NULL;
	goto retry;
}


static int balance_one(struct rq *rq, struct task_struct *prev,
		       struct rq_flags *rf, bool local)
{
	struct scx_rq *scx_rq = rq->scx;
	bool prev_on_scx = prev->sched_class == &ext_sched_class;

	lockdep_assert_rq_held(rq);

	if (static_branch_unlikely(&scx_ops_cpu_preempt) &&
	    unlikely(rq->scx->cpu_released)) {
		/*
		 * If the previous sched_class for the current CPU was not SCX,
		 * notify the BPF scheduler that it again has control of the
		 * core. This callback complements ->cpu_release(), which is
		 * emitted in scx_notify_pick_next_task().
		 */
		rq->scx->cpu_released = false;
	}

	if (prev_on_scx)
		update_curr_scx(rq);

	/* if there already are tasks to run, nothing to do */
	if (scx_rq->local_dsq.nr)
		return 1;

	if (consume_dispatch_q(rq, rf, &scx_dsq_global)) {
		slim_stats_record(GLOBAL_STAT, 1, 0, 0);
		return 1;
	}

	if (consume_dispatch_global(rq, rf))
		return 1;

	return 0;
}

static int balance_scx(struct rq *rq, struct task_struct *prev,
		       struct rq_flags *rf)
{
	return balance_one(rq, prev, rf, true);
}

static void set_next_task_scx(struct rq *rq, struct task_struct *p, bool first)
{
	u64 util = 0;
	if (test_bit(ffs(SCX_TASK_QUEUED), (unsigned long*)&p->scx->flags)) {
		/*
		 * Core-sched might decide to execute @p before it is
		 * dispatched. Call ops_dequeue() to notify the BPF scheduler.
		 */
		ops_dequeue(p, SCX_DEQ_CORE_SCHED_EXEC);
		dispatch_dequeue(rq->scx, p);
	}

	p->se.exec_start = rq_clock_task(rq);

	if(test_bit(ffs(SCX_TASK_QUEUED), (unsigned long*)&p->scx->flags))
		trace_android_vh_hmbird_update_load(p, rq, PICK_NEXT_TASK, rq->clock);

	watchdog_unwatch_task(p, true);
	slim_trace_show_cpu_consume_dsq_idx(smp_processor_id(), p->scx->gdsq_idx);
	if (debug_enabled()) {
		trace_android_vh_get_util(-1, p, &util);
		scx_info_systrace("C|9999|cpu_%d_ds|%llu\n", cpu_of(rq), util);
	}
	/*
	 * @p is getting newly scheduled or got kicked after someone updated its
	 * slice. Refresh whether tick can be stopped. See can_stop_tick_scx().
	 */
	if ((p->scx->slice == SCX_SLICE_INF) !=
	    (bool)(rq->scx->flags & SCX_RQ_CAN_STOP_TICK)) {
		if (p->scx->slice == SCX_SLICE_INF)
			rq->scx->flags |= SCX_RQ_CAN_STOP_TICK;
		else
			rq->scx->flags &= ~SCX_RQ_CAN_STOP_TICK;

		sched_update_tick_dependency(rq);
	}
}

static void put_prev_task_scx(struct rq *rq, struct task_struct *p)
{
	update_curr_scx(rq);

	update_dispatch_dsq_info(rq, p);

	if(test_bit(ffs(SCX_TASK_QUEUED), (unsigned long*)&p->scx->flags))
		trace_android_vh_hmbird_update_load(p, rq, PUT_PREV_TASK, rq->clock);

	slim_trace_show_cpu_consume_dsq_idx(smp_processor_id(), 0);

	if (test_bit(ffs(SCX_TASK_QUEUED), (unsigned long*)&p->scx->flags)) {
		watchdog_watch_task(rq, p);

		if (is_pipeline_task(p)) {
			do_enqueue_task(rq, p, SCX_ENQ_LOCAL, -1);
			return;
		}

		/*
		 * If we're in the pick_next_task path, balance_scx() should
		 * have already populated the local DSQ if there are any other
		 * available tasks. If empty, tell ops.enqueue() that @p is the
		 * only one available for this cpu. ops.enqueue() should put it
		 * on the local DSQ so that the subsequent pick_next_task_scx()
		 * can find the task unless it wants to trigger a separate
		 * follow-up scheduling event.
		 */
		if (list_empty(&rq->scx->local_dsq.fifo)) {
			do_enqueue_task(rq, p, SCX_ENQ_LAST | SCX_ENQ_LOCAL, -1);
		} else
			do_enqueue_task(rq, p, 0, -1);
	}
}

static struct task_struct *first_local_task(struct rq *rq)
{
	struct rb_node *rb_node;
	struct sched_ext_entity *entity;

	if (!list_empty(&rq->scx->local_dsq.fifo)) {
		entity = list_first_entry(&rq->scx->local_dsq.fifo, struct sched_ext_entity, dsq_node.fifo);
		return entity->task;
	}

	rb_node = rb_first_cached(&rq->scx->local_dsq.priq);
	if (rb_node) {
		entity = container_of(rb_node, struct sched_ext_entity, dsq_node.priq);
		return entity->task;
	}
	return NULL;
}

static struct task_struct *pick_next_task_scx(struct rq *rq)
{
	struct task_struct *p;

	p = first_local_task(rq);
	if (!p)
		return NULL;

	if (unlikely(!p->scx->slice)) {
		if (!scx_ops_disabling() && !scx_warned_zero_slice) {
			printk_deferred(KERN_WARNING "sched_ext: %s[%d] has zero slice in pick_next_task_scx()\n",
					p->comm, p->pid);
			scx_warned_zero_slice = true;
		}
		refill_task_slice(p);
	}
	set_next_task_scx(rq, p, true);

	return p;
}

void __scx_notify_pick_next_task(struct rq *rq, struct task_struct *task,
				 const struct sched_class *active)
{
	lockdep_assert_rq_held(rq);

	/*
	 * The callback is conceptually meant to convey that the CPU is no
	 * longer under the control of SCX. Therefore, don't invoke the
	 * callback if the CPU is is staying on SCX, or going idle (in which
	 * case the SCX scheduler has actively decided not to schedule any
	 * tasks on the CPU).
	 */
	if (likely(active >= &ext_sched_class))
		return;

	/*
	 * At this point we know that SCX was preempted by a higher priority
	 * sched_class, so invoke the ->cpu_release() callback if we have not
	 * done so already. We only send the callback once between SCX being
	 * preempted, and it regaining control of the CPU.
	 *
	 * ->cpu_release() complements ->cpu_acquire(), which is emitted the
	 *  next time that balance_scx() is invoked.
	 */
	if (!rq->scx->cpu_released)
		rq->scx->cpu_released = true;
}

#ifdef CONFIG_SMP

static bool test_and_clear_cpu_idle(int cpu)
{
	if (cpumask_test_and_clear_cpu(cpu, idle_masks.cpu)) {
		if (cpumask_empty(idle_masks.cpu))
			scx_has_idle_cpus = false;
		return true;
	} else {
		return false;
	}
}

static s32 scx_pick_idle_cpu(const struct cpumask *cpus_allowed)
{
	int cpu;

	do {
		cpu = cpumask_any_and_distribute(idle_masks.cpu, cpus_allowed);
		if (cpu >= nr_cpu_ids)
			return -EBUSY;
	} while (!test_and_clear_cpu_idle(cpu));

	return cpu;
}


static bool prev_cpu_misfit(int prev)
{
	if (!is_partial_enabled() && is_partial_cpu(prev))
		return true;

	return false;
}

static int heavy_rt_placement(struct task_struct *p, int prev)
{
	struct cpumask tmp = {.bits = {0}};
	int cpu;
	u64 util;

        trace_android_vh_get_util(-1, p, &util);

	if (!rt_prio(p->prio))
		return -EFAULT;

	if ((util < misfit_ds))
		return -EFAULT;

	if (is_partial_enabled())
		cpumask_or(&tmp, iso_masks.big, iso_masks.partial);
	else
		cpumask_copy(&tmp, iso_masks.big);

	cpu = scx_pick_idle_cpu(&tmp);
	if (cpu >= 0)
                return cpu;

	if (cpumask_test_cpu(prev, iso_masks.big) ||
		(is_partial_enabled() && is_partial_cpu(prev)))
		return prev;

	return cpumask_first(&tmp);
}

static int spec_task_before_pick_idle(struct task_struct *p, int prev)
{
	int cpu;

	cpu = heavy_rt_placement(p, prev);
	if (cpu >= 0)
		return cpu;
	return -EFAULT;
}


/* per cluster or per cpu? */
static int big_distribute_mask_prev;
static int little_distribute_mask_prev;

static int cpumask_distribute_next(struct cpumask *mask, int *prev)
{
	int p = *prev, n;

	n = find_next_bit_wrap(cpumask_bits(mask), nr_cpumask_bits, p + 1);
	if (n < nr_cpu_ids)
		WRITE_ONCE(*prev, n);
	return n;
}

static int repick_fallback_cpu(void)
{
	/*
	 * partial cpu follow big cluster's Scheduling policy,
	 * simply return first bit cpu.
	 */
	return cpumask_distribute_next(iso_masks.big, &big_distribute_mask_prev);
}

/*
 * Must return a valid cpu num, as this task's cpu.
 */
static int select_cpu_from_cluster(struct task_struct *p, int prev_cpu,
					struct cpumask *mask, int *prev_mask)
{
	int cpu;

	cpu = scx_pick_idle_cpu(mask);
	if (cpu >= 0)
		return cpu;
	return cpumask_distribute_next(mask, prev_mask);
}

static bool task_only_blongs_to_cluster(struct task_struct *p, enum cpu_type type)
{
	int idx;
	struct cluster_ctx ctx;

	idx = find_idx_from_task(p);
	if (idx < NON_PERIOD_START || idx >= MAX_GLOBAL_DSQS)
		return false;

	gen_cluster_ctx(&ctx, type);
	if (idx >= ctx.lower && idx < ctx.upper)
		return true;
	return false;
}

static bool is_valid_cpu(int cpu)
{
	return (cpu >= 0) && (cpu < nr_cpu_ids);
}

static s32 scx_select_cpu_dfl(struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	s32 cpu = -1;
	struct cpumask mask = {.bits = {0}};

	trace_android_vh_scx_select_cpu_dfl(p, &cpu);
	if (is_valid_cpu(cpu)) {
		set_bit(ffs(SCX_TASK_ENQ_LOCAL), (unsigned long*)&p->scx->flags);
		slim_stats_record(SELECT_CPU, 0, 0, 0);
		return cpu;
	}

	/* Backup cpus ctrl. */
	partial_dynamic_ctrl();

	/* For critical tasks, isolate task will return above.*/
	if (is_critical_app_task_without_isolate(p)) {
		cpu = select_cpu_from_cluster(p, prev_cpu, iso_masks.big, &big_distribute_mask_prev);
		slim_stats_record(SELECT_CPU, 0, 0, 0);
		if (is_valid_cpu(cpu))
			return cpu;
	}
	/* Enqueue to pcp dsq, not local. */
	if (p->nr_cpus_allowed == 1) {
		cpu = cpumask_any(p->cpus_ptr);
		slim_stats_record(SELECT_CPU, 0, 0, 0);
                return cpu;
        }

	/* For non-period global dsq, not contain pcp task. */
	if (task_only_blongs_to_cluster(p, LITTLE)) {
		cpumask_copy(&mask, iso_masks.little);
		if (unlikely(l_need_rescue))
			cpumask_or(&mask, iso_masks.partial, &mask);
		cpu = select_cpu_from_cluster(p, prev_cpu, &mask, &little_distribute_mask_prev);
		slim_stats_record(SELECT_CPU, 1, 0, 0);
		if (is_valid_cpu(cpu))
			return cpu;
	}
	if (task_only_blongs_to_cluster(p, BIG)) {
		cpumask_copy(&mask, iso_masks.big);
		if (unlikely(b_need_rescue))
			cpumask_or(&mask, iso_masks.partial, &mask);
		cpu = select_cpu_from_cluster(p, prev_cpu, &mask, &big_distribute_mask_prev);
		slim_stats_record(SELECT_CPU, 1, 0, 0);
		if (is_valid_cpu(cpu))
			return cpu;
	}

	cpu = spec_task_before_pick_idle(p, prev_cpu);
	if (is_valid_cpu(cpu)) {
		slim_stats_record(SELECT_CPU, 0, 0, 0);
		return cpu;
	}

	/* if the previous CPU is idle, dispatch directly to it */
	if (test_and_clear_cpu_idle(prev_cpu) && is_valid_cpu(prev_cpu)) {
		slim_stats_record(SELECT_CPU, 0, 0, 0);
		return prev_cpu;
	}

	cpu = scx_pick_idle_cpu(cpu_possible_mask);
	if (is_valid_cpu(cpu)) {
		slim_stats_record(SELECT_CPU, 0, 0, 0);
		return cpu;
	}

	/* Misfit, select a new task. */
	if (prev_cpu_misfit(prev_cpu)) {
		slim_stats_record(SELECT_CPU, 0, 0, 0);
		cpu = repick_fallback_cpu();
		if (is_valid_cpu(cpu))
			return cpu;
	}

	slim_stats_record(SELECT_CPU, 0, 0, 0);
	return prev_cpu;
}

static int select_task_rq_scx(struct task_struct *p, int prev_cpu, int wake_flags)
{
	return scx_select_cpu_dfl(p, prev_cpu, wake_flags);
}

static void set_cpus_allowed_scx(struct task_struct *p,
				 const struct cpumask *new_mask,
				u32 flags)
{
	set_cpus_allowed_common(p, new_mask, flags);
}

static void reset_idle_masks(void)
{
	cpumask_or(idle_masks.cpu, idle_masks.cpu, iso_masks.little);
	cpumask_or(idle_masks.cpu, idle_masks.cpu, iso_masks.big);
	if (is_partial_enabled())
		cpumask_or(idle_masks.cpu, idle_masks.cpu, iso_masks.partial);
	scx_has_idle_cpus = true;
}

void __scx_update_idle(struct rq *rq, bool idle)
{
	int cpu = cpu_of(rq);
	struct cpumask *sib_mask = topology_sibling_cpumask(cpu);

	if (skip_update_idle())
		return;

	if (idle) {
		cpumask_set_cpu(cpu, idle_masks.cpu);
		if (!scx_has_idle_cpus)
			scx_has_idle_cpus = true;

		/*
		 * idle_masks.smt handling is racy but that's fine as it's only
		 * for optimization and self-correcting.
		 */
		for_each_cpu(cpu, sib_mask) {
			if (!cpumask_test_cpu(cpu, idle_masks.cpu))
				return;
		}
		cpumask_or(idle_masks.smt, idle_masks.smt, sib_mask);
	} else {
		cpumask_clear_cpu(cpu, idle_masks.cpu);
		if (scx_has_idle_cpus && cpumask_empty(idle_masks.cpu))
			scx_has_idle_cpus = false;

		cpumask_andnot(idle_masks.smt, idle_masks.smt, sib_mask);
	}
}

#else /* !CONFIG_SMP */

static bool test_and_clear_cpu_idle(int cpu) { return false; }
static s32 scx_pick_idle_cpu(const struct cpumask *cpus_allowed) { return -EBUSY; }
static void reset_idle_masks(void) {}

#endif /* CONFIG_SMP */

static bool check_rq_for_timeouts(struct rq *rq)
{
	struct sched_ext_entity *entity;
	struct task_struct *p;
	struct rq_flags rf;

	rq_lock_irqsave(rq, &rf);
	list_for_each_entry(entity, &rq->scx->watchdog_list, watchdog_node) {
		unsigned long last_runnable;

		p = entity->task;
		last_runnable = p->scx->runnable_at;

		if (unlikely(time_after(jiffies,
					last_runnable + scx_watchdog_timeout)) || watchdog_enable) {
			u32 dur_ms = jiffies_to_msecs(jiffies - last_runnable);

			rq_unlock_irqrestore(rq, &rf);
			WRITE_ONCE(sw_type, SCX_SWITCH_ERR_WDT);
			SCX_FATAL_INFO_FN(SCX_EXIT_ERROR_STALL, "%-12s[%d] failed to run for %u.%03us,"
						"dsq=%d,"
						"mask=%*pb",
					   	p->comm, p->pid,
					   	dur_ms / 1000, dur_ms % 1000,
						dsq_id_to_internal(p->scx->dsq),
						cpumask_pr_args(&p->cpus_mask));
			return 1;
		}
	}
	rq_unlock_irqrestore(rq, &rf);

	return 0;
}

static void scx_watchdog_workfn(struct work_struct *work)
{
	int cpu;
	bool timeout;

	scx_watchdog_timestamp = jiffies;

	for_each_online_cpu(cpu) {
		timeout = check_rq_for_timeouts(cpu_rq(cpu));
		if (unlikely(timeout))
			break;

		cond_resched();
	}
	if (!timeout)
		queue_delayed_work(system_unbound_wq, to_delayed_work(work),
				scx_watchdog_timeout / 2);
}

static void set_pcp_round(struct rq *rq)
{
	int cpu = cpu_of(rq);

	if (atomic64_read(&pcp_dsq_round) != per_cpu(pcp_info, cpu).pcp_seq) {
		per_cpu(pcp_info, cpu).pcp_seq = atomic64_read(&pcp_dsq_round);
		per_cpu(pcp_info, cpu).pcp_round = true;
		scx_info_systrace("C|9999|pcp_%d_round|%d\n", cpu, true);
		per_cpu(pcp_info, cpu).rtime = 0;
		systrace_output_rtime_state(&per_cpu(pcp_ldsq, cpu),
                                        per_cpu(pcp_info, cpu).rtime);
	}
}


/*
 * Just for debug: output ext on/off state per 10s.
 */
#define OUTPUT_INTVAL	(msecs_to_jiffies(10 * 1000))
static void inform_ext_onoff_from_systrace(void)
{
	static unsigned long __read_mostly next_print;

	if (time_before(jiffies, READ_ONCE(next_print)))
		return;

	WRITE_ONCE(next_print, jiffies + OUTPUT_INTVAL);
	scx_internal_systrace("C|9999|scx_status|%d\n", curr_ss);
	scx_internal_systrace("C|9999|partial_enable|%d\n", is_partial_enabled());
	scx_internal_systrace("C|9999|l_need_rescue|%d\n", is_little_need_rescue());
	scx_internal_systrace("C|9999|b_need_rescue|%d\n", is_big_need_rescue());
	scx_internal_systrace("C|9999|free_iso|%d\n", is_iso_par_free());
	scx_internal_systrace("C|9999|iso_free_rescue|%d\n", iso_free_rescue);
}

void scx_notify_sched_tick(void)
{
	unsigned long last_check;
	int cpu = smp_processor_id();
	struct rq *rq = cpu_rq(cpu);

	scx_scheduler_tick();

	if (!scx_enabled())
		return;

	last_check = scx_watchdog_timestamp;
	if (unlikely(time_after(jiffies, last_check + scx_watchdog_timeout))) {
		u32 dur_ms = jiffies_to_msecs(jiffies - last_check);

		SCX_FATAL_INFO_FN(SCX_EXIT_ERROR_STALL,
				"watchdog failed to check in for %u.%03us",
				dur_ms / 1000, dur_ms % 1000);
	}
	scan_timeout(rq);
}

static void task_tick_scx(struct rq *rq, struct task_struct *curr, int queued)
{
	update_curr_scx(rq);

	set_pcp_round(rq);

	trace_android_vh_hmbird_update_load(curr, rq, TASK_UPDATE, rq->clock);
	/*
	 * While disabling, always resched and refresh core-sched timestamp as
	 * we can't trust the slice management or ops.core_sched_before().
	 */
	if (scx_ops_disabling())
		curr->scx->slice = 0;

	if (!curr->scx->slice)
		resched_curr(rq);

	inform_ext_onoff_from_systrace();
}

static int scx_ops_prepare_task(struct task_struct *p, struct task_group *tg)
{
	scx_cond_deferred_err(TASK_OPS_PREPPED, test_bit(ffs(SCX_TASK_OPS_PREPPED),
				(unsigned long*)&p->scx->flags), "task = %s\n", p->comm);

	p->scx->disallow = false;

	trace_android_vh_hmbird_init_task(p);

	set_bit(ffs(SCX_TASK_OPS_PREPPED), (unsigned long*)&p->scx->flags);
	set_bit(ffs(SCX_TASK_WATCHDOG_RESET), (unsigned long*)&p->scx->flags);
	return 0;
}

static void scx_ops_enable_task(struct task_struct *p)
{
	lockdep_assert_rq_held(task_rq(p));
	scx_cond_deferred_err(TASK_OPS_UNPREPPED, !test_bit(ffs(SCX_TASK_OPS_PREPPED),
				(unsigned long*)&p->scx->flags), "task = %s\n", p->comm);

	clear_bit(ffs(SCX_TASK_OPS_PREPPED), (unsigned long*)&p->scx->flags);
	set_bit(ffs(SCX_TASK_OPS_ENABLED), (unsigned long*)&p->scx->flags);
}

static void scx_ops_disable_task(struct task_struct *p)
{
	lockdep_assert_rq_held(task_rq(p));

	if (test_bit(ffs(SCX_TASK_OPS_PREPPED), (unsigned long*)&p->scx->flags)) {
		clear_bit(ffs(SCX_TASK_OPS_PREPPED), (unsigned long*)&p->scx->flags);
	} else if (test_bit(ffs(SCX_TASK_OPS_ENABLED), (unsigned long*)&p->scx->flags)) {
		clear_bit(ffs(SCX_TASK_OPS_ENABLED), (unsigned long*)&p->scx->flags);
	}
}

static void set_task_scx_weight(struct task_struct *p)
{
	u32 weight = sched_prio_to_weight[p->static_prio - MAX_RT_PRIO];

	p->scx->weight = sched_weight_to_cgroup(weight);
}

/**
 * refresh_scx_weight - Refresh a task's ext weight
 * @p: task to refresh ext weight for
 *
 * @p->scx->weight carries the task's static priority in cgroup weight scale to
 * enable easy access from the BPF scheduler. To keep it synchronized with the
 * current task priority, this function should be called when a new task is
 * created, priority is changed for a task on sched_ext, and a task is switched
 * to sched_ext from other classes.
 */
static void refresh_scx_weight(struct task_struct *p)
{
	lockdep_assert_rq_held(task_rq(p));
	set_task_scx_weight(p);
}

int scx_pre_fork(struct task_struct *p)
{
	int ret = 0;

	p->scx = kmalloc(sizeof(struct sched_ext_entity), GFP_KERNEL);
	if (!p->scx) {
		ret = -1;
		goto lock;
	}

	p->scx->dsq              = NULL;
	INIT_LIST_HEAD(&p->scx->dsq_node.fifo);
	RB_CLEAR_NODE(&p->scx->dsq_node.priq);
	INIT_LIST_HEAD(&p->scx->watchdog_node);
	p->scx->flags            = 0;
	p->scx->weight           = 0;
	p->scx->sticky_cpu       = -1;
	p->scx->holding_cpu      = -1;
	p->scx->kf_mask          = 0;
	atomic64_set(&p->scx->ops_state, 0);
	p->scx->runnable_at      = INITIAL_JIFFIES;
	p->scx->slice            = SCX_SLICE_DFL;
	p->scx->task             = p;
	sched_set_sched_prop(p, 0);

	/*
	 * BPF scheduler enable/disable paths want to be able to iterate and
	 * update all tasks which can become complex when racing forks. As
	 * enable/disable are very cold paths, let's use a percpu_rwsem to
	 * exclude forks.
	 */
lock:
	percpu_down_read(&scx_fork_rwsem);

	return ret;
}

int scx_fork(struct task_struct *p)
{
	percpu_rwsem_assert_held(&scx_fork_rwsem);

	if (scx_enabled())
		return scx_ops_prepare_task(p, task_group(p));
	else
		return 0;
}

void scx_post_fork(struct task_struct *p)
{
	if (scx_enabled()) {
		struct rq_flags rf;
		struct rq *rq;

		rq = task_rq_lock(p, &rf);
		/*
		 * Set the weight manually before calling ops.enable() so that
		 * the scheduler doesn't see a stale value if they inspect the
		 * task struct. We'll invoke ops.set_weight() afterwards, as it
		 * would be odd to receive a callback on the task before we
		 * tell the scheduler that it's been fully enabled.
		 */
		set_task_scx_weight(p);
		scx_ops_enable_task(p);
		refresh_scx_weight(p);
		task_rq_unlock(rq, p, &rf);
	}

	spin_lock_irq(&scx_tasks_lock);
	list_add_tail(&p->scx->tasks_node, &scx_tasks);
	spin_unlock_irq(&scx_tasks_lock);

	percpu_up_read(&scx_fork_rwsem);
}

void scx_cancel_fork(struct task_struct *p)
{
	if (scx_enabled())
		scx_ops_disable_task(p);

	if (p->scx) {
		kfree(p->scx);
		p->scx = NULL;
	}
	percpu_up_read(&scx_fork_rwsem);
}

void sched_ext_free(struct task_struct *p)
{
	unsigned long flags;

	spin_lock_irqsave(&scx_tasks_lock, flags);
	list_del_init(&p->scx->tasks_node);
	spin_unlock_irqrestore(&scx_tasks_lock, flags);

	/*
	 * @p is off scx_tasks and wholly ours. scx_ops_enable()'s PREPPED ->
	 * ENABLED transitions can't race us. Disable ops for @p.
	 */
	if (test_bit(ffs(SCX_TASK_OPS_PREPPED), (unsigned long*)&p->scx->flags) ||
		test_bit(ffs(SCX_TASK_OPS_ENABLED), (unsigned long*)&p->scx->flags)) {
		struct rq_flags rf;
		struct rq *rq;

		rq = task_rq_lock(p, &rf);
		scx_ops_disable_task(p);
		task_rq_unlock(rq, p, &rf);
	}
	if (p->scx) {
		kfree(p->scx);
		p->scx = NULL;
	}
}

static void prio_changed_scx(struct rq *rq, struct task_struct *p, int oldprio)
{
}


static void check_preempt_curr_scx(struct rq *rq, struct task_struct *p, int wake_flags)
{
	int check_result = -1;
	enum cpu_type type;
	int sp_dl;

	trace_android_vh_check_preempt_curr_scx(rq, p, wake_flags, &check_result);

	if (check_result > 0)
		goto preempt;

	if ((is_pipeline_task(p) && !is_pipeline_task(rq->curr)) ||
		(is_critical_system_task(p) && !is_critical_system_task(rq->curr)))
		goto preempt;

	sp_dl = find_idx_from_task(p);
	if ((sp_dl >= SCHED_PROP_DEADLINE_LEVEL1))
		return;

	type = cpu_cluster(cpu_of(rq));
	if (type == EXCLUSIVE || ((type == PARTIAL) && !is_partial_enabled()))
		return;

	if (rq->curr->prio > p->prio)
		goto preempt;

	return;
preempt:
	scx_info_trace("<preempt>task:%s(pid:%d,prio:%d) preempt task:%s(pid:%d,prio:%d)\n",
				p->comm, p->pid, p->prio, rq->curr->comm, rq->curr->pid, rq->curr->prio);
	resched_curr(rq);
}
static void switched_to_scx(struct rq *rq, struct task_struct *p) {}

int scx_check_setscheduler(struct task_struct *p, int policy)
{
	lockdep_assert_rq_held(task_rq(p));

	/* if disallow, reject transitioning into SCX */
	if (scx_enabled() && READ_ONCE(p->scx->disallow) &&
	    p->policy != policy && policy == SCHED_EXT)
		return -EACCES;

	return 0;
}

#ifdef CONFIG_NO_HZ_FULL
bool scx_can_stop_tick(struct rq *rq)
{
	struct task_struct *p = rq->curr;

	if (scx_ops_disabling())
		return false;

	if (p->sched_class != &ext_sched_class)
		return true;

	/*
	 * @rq can dispatch from different DSQs, so we can't tell whether it
	 * needs the tick or not by looking at nr_running. Allow stopping ticks
	 * iff the BPF scheduler indicated so. See set_next_task_scx().
	 */
	return rq->scx->flags & SCX_RQ_CAN_STOP_TICK;
}
#endif

int scx_tg_online(struct task_group *tg)
{
	tg->scx_deadline_idx = -1;
	return 0;
}

/*
 * Omitted operations:
 *
 * - check_preempt_curr: NOOP as it isn't useful in the wakeup path because the
 *   task isn't tied to the CPU at that point. Preemption is implemented by
 *   resetting the victim task's slice to 0 and triggering reschedule on the
 *   target CPU.
 *
 * - migrate_task_rq: Unncessary as task to cpu mapping is transient.
 *
 * - task_fork/dead: We need fork/dead notifications for all tasks regardless of
 *   their current sched_class. Call them directly from sched core instead.
 *
 * - task_woken, switched_from: Unnecessary.
 */
DEFINE_SCHED_CLASS(ext) = {
	.enqueue_task		= enqueue_task_scx,
	.dequeue_task		= dequeue_task_scx,
	.yield_task		= yield_task_scx,
	.yield_to_task		= yield_to_task_scx,

	.check_preempt_curr	= check_preempt_curr_scx,

	.pick_next_task		= pick_next_task_scx,

	.put_prev_task		= put_prev_task_scx,
	.set_next_task          = set_next_task_scx,

#ifdef CONFIG_SMP
	.balance		= balance_scx,
	.select_task_rq		= select_task_rq_scx,
	.set_cpus_allowed	= set_cpus_allowed_scx,
#endif
	.task_tick		= task_tick_scx,

	.switched_to		= switched_to_scx,
	.prio_changed		= prio_changed_scx,

	.update_curr		= update_curr_scx,

#ifdef CONFIG_UCLAMP_TASK
	.uclamp_enabled		= 0,
#endif
};

/*
 * Must with rq lock held.
 */
bool task_is_scx(struct task_struct *p)
{
	return p->sched_class == &ext_sched_class;
}
EXPORT_SYMBOL_GPL(task_is_scx);


void init_dsq(struct scx_dispatch_q *dsq, u64 dsq_id)
{
	memset(dsq, 0, sizeof(*dsq));

	raw_spin_lock_init(&dsq->lock);
	INIT_LIST_HEAD(&dsq->fifo);
	dsq->id = dsq_id;
}

static int scx_cgroup_init(void)
{
	struct cgroup_subsys_state *css;

	css_for_each_descendant_pre(css, &root_task_group.css) {
		struct task_group *tg = css_tg(css);
		cgrp_dsq_idx_init(css->cgroup, tg);
	}
	return 0;
}

/*
 * Used by sched_fork() and __setscheduler_prio() to pick the matching
 * sched_class. dl/rt are already handled.
 */
bool task_on_scx(struct task_struct *p)
{
	return scx_enabled();
}

/* Protected by scx_ops_enable_mutex. */
static void update_scx_enable(bool enable)
{
	static bool prev = false;

	if (prev == enable)
		return;

	prev = enable;
	WRITE_ONCE(tick_sched_clock, 0);
	if (enable)
		atomic_set_release(&set_sched_clock_prepare, true);
	trace_android_vh_hmbird_update_load_enable(enable);
}

static void __setscheduler_prio(struct task_struct *p, int prio)
{
	bool on_scx = task_on_scx(p);

	if (p->sched_class == &stop_sched_class) {}
	else if (dl_prio(prio))
		p->sched_class = &dl_sched_class;
	else if (on_scx && rt_prio(prio))
		p->sched_class = &ext_sched_class;
	else if (rt_prio(prio))
		p->sched_class = &rt_sched_class;
	else if (on_scx)
		p->sched_class = &ext_sched_class;
	else
		p->sched_class = &fair_sched_class;

	p->prio = prio;
}

/*
 * Heartbeat, avoid scx keep running while APP already exit.
 * Check whether APP send alive-signal periodly.
 */
#define HEARTBEAT_TIMEOUT		(msecs_to_jiffies(2500))
#define HEARTBEAT_CHECK_INTERVAL	(msecs_to_jiffies(1000))
static struct timer_list hb_timer;
static unsigned long next_hb;

void hb_timer_handler(struct timer_list *timer)
{
	if (!heartbeat_enable)
		goto refill;

	if (heartbeat) {
		heartbeat = 0;
		WRITE_ONCE(next_hb, jiffies + HEARTBEAT_TIMEOUT);
		scx_info_trace("<hearbeat>:detect feed dog.\n");
	}

	/* can't detect heartbeat, disable ext. */
	if(time_after(jiffies, READ_ONCE(next_hb))) {
		WRITE_ONCE(sw_type, SCX_SWITCH_ERR_HB);
		SCX_FATAL_INFO_FN(SCX_EXIT_ERROR_HEARTBEAT, "can't detect heartbeat, disable ext");
	}
refill:
	mod_timer(&hb_timer, jiffies + HEARTBEAT_CHECK_INTERVAL);
}

static void hb_timer_start(void)
{
	mod_timer(&hb_timer, jiffies + HEARTBEAT_CHECK_INTERVAL);
}

static void hb_timer_init(void)
{
	timer_setup(&hb_timer, hb_timer_handler, 0);
}

static void hb_timer_exit(void)
{
	del_timer(&hb_timer);
}

static bool check_and_disable_cpuhp(void)
{
	struct rq *rq;
	struct rq_flags rf;
	int cpu;

	cpu_hotplug_disable();
	cpus_read_lock();
	for_each_possible_cpu(cpu) {
		rq = cpu_rq(cpu);
		rq_lock_irqsave(rq, &rf);
		if (!rq->online) {
			rq_unlock_irqrestore(rq, &rf);
			goto err_offline;
		}
		rq_unlock_irqrestore(rq, &rf);
	}
	cpus_read_unlock();
	return true;

err_offline:
	cpus_read_unlock();
	cpu_hotplug_enable();
	return false;
}

static void reenable_cpuhp(void)
{
	cpu_hotplug_enable();
}

static void scheduler_switch_done(bool final_state)
{
	/* set scx_enable again, switch may fail. */
	scx_enable = final_state;
	/* reset heartbeat*/
	WRITE_ONCE(next_hb, jiffies + HEARTBEAT_TIMEOUT);

	if (final_state)
		hb_timer_start();
	else
		hb_timer_exit();
}

/**
 * ss : curr switch state
 * finish : success or fail
 * enable : curr operation is diabling or enabling?
 * fail_reason : string output when failed, empty string when success.
 */
static void scx_switch_log(enum switch_stat ss, bool finish, bool enable, char *fail_reason)
{
	char *s1 = finish ? "finished" : "failed";
	char *s2 = enable ? "enabled" : "disabled";

	scx_internal_systrace("C|9999|scx_status|%d\n", ss);

	if (ss == SCX_DISABLED || ss == SCX_ENABLED) {
		sw_update(md_info, jiffies, finish, ss, READ_ONCE(sw_type));
		scx_debug("<switch>: ext %s %s at jiffies = %lu, clock = %lu, reason = %s\n",
				s2, s1, jiffies, (unsigned long)sched_clock(), fail_reason);
	}
	curr_ss = ss;
}

static void scx_ops_disable_workfn(struct kthread_work *work)
{
	struct scx_task_iter sti;
	struct task_struct *p;
	int cpu;

	scx_switch_log(SCX_SWITCH_PREP, 0, 0, "");
	cancel_delayed_work_sync(&scx_watchdog_work);

	mutex_lock(&scx_ops_enable_mutex);
	switch (scx_ops_set_enable_state(SCX_OPS_DISABLING)) {
	case SCX_OPS_DISABLED:
		WARN_ON_ONCE(scx_ops_set_enable_state(SCX_OPS_DISABLED) !=
			     SCX_OPS_DISABLING);
		scx_switch_log(SCX_DISABLED, 0, 0, "already disabled");
		scheduler_switch_done(false);
		mutex_unlock(&scx_ops_enable_mutex);
		return;
	case SCX_OPS_PREPPING:
		fallthrough;
	case SCX_OPS_DISABLING:
		/* shouldn't happen but handle it like ENABLING if it does */
		WARN_ONCE(true, "sched_ext: duplicate disabling instance?");
		fallthrough;
	case SCX_OPS_ENABLING:
	case SCX_OPS_ENABLED:
		break;
	}

	/* kick all CPUs to restore ticks */
	for_each_possible_cpu(cpu)
		resched_cpu(cpu);

	/* avoid racing against fork and cgroup changes */
	cpus_read_lock();
	percpu_down_write(&scx_fork_rwsem);

	scx_switch_log(SCX_RQ_SWITCH_BEGIN, 0, 0, "");
	spin_lock_irq(&scx_tasks_lock);
	atomic_set(&__scx_ops_enabled, false);
	scx_task_iter_init(&sti);
	while ((p = scx_task_iter_next_filtered_locked(&sti))) {
		const struct sched_class *old_class = p->sched_class;
		struct rq *rq = task_rq(p);
		bool alive = READ_ONCE(p->__state) != TASK_DEAD;

		update_rq_clock(rq);

		SCHED_CHANGE_BLOCK(rq, p, DEQUEUE_SAVE | DEQUEUE_MOVE |
				   DEQUEUE_NOCLOCK) {
			p->scx->slice = min_t(u64, p->scx->slice, SCX_SLICE_DFL);

			__setscheduler_prio(p, p->prio);
		}

		if (alive)
			check_class_changed(task_rq(p), p, old_class, p->prio);

		scx_ops_disable_task(p);
	}
	scx_task_iter_exit(&sti);
	spin_unlock_irq(&scx_tasks_lock);
	scx_switch_log(SCX_RQ_SWITCH_DONE, 0, 0, "");

	atomic_set(&non_ext_task, true);
	/* no task is on scx, turn off all the switches and flush in-progress calls */
	static_branch_disable_cpuslocked(&scx_ops_cpu_preempt);
	synchronize_rcu();

	percpu_up_write(&scx_fork_rwsem);
	cpus_read_unlock();

	update_scx_enable(false);

	mutex_unlock(&scx_ops_enable_mutex);

	WARN_ON_ONCE(scx_ops_set_enable_state(SCX_OPS_DISABLED) !=
		     SCX_OPS_DISABLING);
	scx_switch_log(SCX_DISABLED, 1, 0, "");
	scheduler_switch_done(false);
	reenable_cpuhp();
}

static DEFINE_KTHREAD_WORK(scx_ops_disable_work, scx_ops_disable_workfn);

static void schedule_scx_ops_disable_work(void)
{
	struct kthread_worker *helper = READ_ONCE(scx_ops_helper);

	/*
	 * We may be called spuriously before the first bpf_sched_ext_reg(). If
	 * scx_ops_helper isn't set up yet, there's nothing to do.
	 */
	if (helper)
		kthread_queue_work(helper, &scx_ops_disable_work);
}

static void scx_ops_disable(void)
{
	schedule_scx_ops_disable_work();
}

/* ext_ctrl may sleep, must not called in atomic env. */
static void scx_err_exit_workfn(struct work_struct *work)
{
	int cpu;
	struct cpufreq_policy *policy;

	ext_ctrl(false);

	for_each_present_cpu(cpu) {
		policy = cpufreq_cpu_get(cpu);
		if (cpu != policy->cpu)
			continue;
		down_write(&policy->rwsem);
		WARN_ON(store_scaling_governor(policy, saved_gov[cpu], strlen(saved_gov[cpu])) <= 0);
		up_write(&policy->rwsem);
		scx_info_trace("<heartbeat>:restore origin gov : %s\n", saved_gov[cpu]);
		cpufreq_cpu_put(policy);
	}
	memset((char*)saved_gov, 0 , sizeof(saved_gov));
}

void scx_ops_error_type(void)
{
	queue_work(system_unbound_wq, &scx_err_exit_work);
}

static struct kthread_worker *scx_create_rt_helper(const char *name)
{
	struct kthread_worker *helper;

	helper = kthread_create_worker(KTW_FREEZABLE, name);
	if (helper)
		sched_set_fifo(helper->task);
	return helper;
}

static inline void set_audio_thread_sched_prop(struct task_struct *p)
{
	struct cgroup_subsys_state *css;

	if (likely(p->prio >= MAX_RT_PRIO))
		return;

	rcu_read_lock();
	css = task_css(p, cpuset_cgrp_id);
	if (!css) {
		rcu_read_unlock();
		return;
	}
	rcu_read_unlock();

	if (!strcmp(css->cgroup->kn->name, "audio-app"))
		sched_set_sched_prop(p, SCHED_PROP_DEADLINE_LEVEL1);

	return;
}

static int scx_ops_enable(void *unused)
{
	struct scx_task_iter sti;
	struct task_struct *p;
	int ret;
	int tcnt = 0;
	unsigned long long start = 0;

	if (!check_and_disable_cpuhp()) {
		scx_switch_log(SCX_DISABLED, 0, 1, "cpu offline");
		return -EBUSY;
	}

	scx_switch_log(SCX_SWITCH_PREP, 0, 1, "");
	mutex_lock(&scx_ops_enable_mutex);

	if (!scx_ops_helper) {
		WRITE_ONCE(scx_ops_helper,
			   scx_create_rt_helper("sched_ext_ops_helper"));
		if (!scx_ops_helper) {
			ret = -ENOMEM;
			goto err_unlock;
		}
	}

	if (scx_ops_enable_state() != SCX_OPS_DISABLED) {
		ret = -EBUSY;
		goto err_unlock;
	}

	update_scx_enable(true);

	WARN_ON_ONCE(scx_ops_set_enable_state(SCX_OPS_PREPPING) !=
		     SCX_OPS_DISABLED);

	scx_warned_zero_slice = false;

	atomic64_set(&scx_nr_rejected, 0);

	/*
	 * Keep CPUs stable during enable so that the BPF scheduler can track
	 * online CPUs by watching ->on/offline_cpu() after ->init().
	 */
	cpus_read_lock();

	scx_watchdog_timeout = SCX_WATCHDOG_MAX_TIMEOUT;

	scx_watchdog_timestamp = jiffies;
	queue_delayed_work(system_unbound_wq, &scx_watchdog_work,
			   scx_watchdog_timeout / 2);

	/*
	 * Lock out forks, cgroup on/offlining and moves before opening the
	 * floodgate so that they don't wander into the operations prematurely.
	 */
	percpu_down_write(&scx_fork_rwsem);

	reset_idle_masks();

	/*
	 * All cgroups should be initialized before letting in tasks. cgroup
	 * on/offlining and task migrations are already locked out.
	 */
	ret = scx_cgroup_init();
	if (ret)
		goto err_disable_unlock;


	wait_for_completion_interruptible(&tick_sched_clock_completion);
	atomic64_set(&scx_irq_work_lastq_ws, tick_sched_clock);

	/*
	 * Enable ops for every task. Fork is excluded by scx_fork_rwsem
	 * preventing new tasks from being added. No need to exclude tasks
	 * leaving as sched_ext_free() can handle both prepped and enabled
	 * tasks. Prep all tasks first and then enable them with preemption
	 * disabled.
	 */
	spin_lock_irq(&scx_tasks_lock);

	atomic_set(&non_ext_task, false);
	atomic_set(&__scx_ops_enabled, true);

	scx_task_iter_init(&sti);
	while ((p = scx_task_iter_next_filtered(&sti))) {
		scx_ops_prepare_task(p, task_group(p));
	}
	scx_task_iter_exit(&sti);

	/*
	 * All tasks are prepped but are still ops-disabled. Ensure that
	 * %current can't be scheduled out and switch everyone.
	 * preempt_disable() is necessary because we can't guarantee that
	 * %current won't be starved if scheduled out while switching.
	 */
	preempt_disable();

	/*
	 * From here on, the disable path must assume that tasks have ops
	 * enabled and need to be recovered.
	 */
	if (!scx_ops_tryset_enable_state(SCX_OPS_ENABLING, SCX_OPS_PREPPING)) {
		atomic_set(&non_ext_task, true);
		atomic_set(&__scx_ops_enabled, false);
		preempt_enable();
		spin_unlock_irq(&scx_tasks_lock);
		ret = -EBUSY;
		goto err_disable_unlock;
	}

	/*
	 * We're fully committed and can't fail. The PREPPED -> ENABLED
	 * transitions here are synchronized against sched_ext_free() through
	 * scx_tasks_lock.
	 */
	start = sched_clock();
	scx_switch_log(SCX_RQ_SWITCH_BEGIN, 0, 1, "");
	scx_task_iter_init(&sti);
	while ((p = scx_task_iter_next_filtered_locked(&sti))) {
		tcnt++;
		if (READ_ONCE(p->__state) != TASK_DEAD) {
			const struct sched_class *old_class = p->sched_class;
			struct rq *rq = task_rq(p);

			set_audio_thread_sched_prop(p);
			update_rq_clock(rq);

			SCHED_CHANGE_BLOCK(rq, p, DEQUEUE_SAVE | DEQUEUE_MOVE |
					   DEQUEUE_NOCLOCK) {
				scx_ops_enable_task(p);
				__setscheduler_prio(p, p->prio);
			}

			check_class_changed(task_rq(p), p, old_class, p->prio);
		} else {
			scx_ops_disable_task(p);
		}
	}
	scx_task_iter_exit(&sti);

	spin_unlock_irq(&scx_tasks_lock);
	scx_switch_log(SCX_RQ_SWITCH_DONE, 0, 1, "");
	preempt_enable();
	percpu_up_write(&scx_fork_rwsem);

	if (!scx_ops_tryset_enable_state(SCX_OPS_ENABLED, SCX_OPS_ENABLING)) {
		ret = -EBUSY;
		goto err_disable;
	}

	cpus_read_unlock();
	mutex_unlock(&scx_ops_enable_mutex);
	scx_switch_log(SCX_ENABLED, 1, 1, "");
	scheduler_switch_done(true);

	return 0;

err_unlock:
	update_scx_enable(false);
	mutex_unlock(&scx_ops_enable_mutex);
	scx_switch_log(SCX_DISABLED, 0, 1, "err_unlock");
	scheduler_switch_done(false);
	return ret;

err_disable_unlock:
	percpu_up_write(&scx_fork_rwsem);
err_disable:
	cpus_read_unlock();
	update_scx_enable(false);
	mutex_unlock(&scx_ops_enable_mutex);
	/* must be fully disabled before returning */
	scx_ops_disable();
	kthread_flush_work(&scx_ops_disable_work);
	scx_switch_log(SCX_DISABLED, 0, 1, "err_disable");
	scheduler_switch_done(false);
	return ret;
}

#ifdef CONFIG_SCHED_DEBUG
static const char *scx_ops_enable_state_str[] = {
	[SCX_OPS_PREPPING]	= "prepping",
	[SCX_OPS_ENABLING]	= "enabling",
	[SCX_OPS_ENABLED]	= "enabled",
	[SCX_OPS_DISABLING]	= "disabling",
	[SCX_OPS_DISABLED]	= "disabled",
};

static int scx_debug_show(struct seq_file *m, void *v)
{
	mutex_lock(&scx_ops_enable_mutex);
	seq_printf(m, "%-30s: %d\n", "enabled", scx_enabled());
	seq_printf(m, "%-30s: %s\n", "enable_state",
		   scx_ops_enable_state_str[scx_ops_enable_state()]);
	seq_printf(m, "%-30s: %llu\n", "nr_rejected",
		   atomic64_read(&scx_nr_rejected));
	mutex_unlock(&scx_ops_enable_mutex);
	return 0;
}

static int scx_debug_open(struct inode *inode, struct file *file)
{
	return single_open(file, scx_debug_show, NULL);
}

const struct file_operations sched_ext_fops = {
	.open		= scx_debug_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};
#endif


static int bpf_scx_reg(void *kdata)
{
	return scx_ops_enable(kdata);
}

static int bpf_scx_unreg(void *kdata)
{
	scx_ops_disable();
	kthread_flush_work(&scx_ops_disable_work);
	return 0;
}

/*
 * MUST load ext module before enable ext scheduler
 * load track & ext gover implemented in ext module
 */
int ext_ctrl(bool enable)
{
	if (!atomic_read(&ext_module_loaded)) {
		scx_switch_log(scx_enabled() ? SCX_ENABLED : SCX_DISABLED,
					0, enable, "ext module unloaded\n");
		return -EINVAL;
	}

	if (enable && (scx_ops_enable_state() == SCX_OPS_ENABLED
			|| scx_ops_enable_state() == SCX_OPS_ENABLING
			|| scx_ops_enable_state() == SCX_OPS_PREPPING)) {
		/* Executing or completed, no need to repeat. */
		scx_switch_log(scx_enabled() ? SCX_ENABLED : SCX_DISABLED,
					0, enable, "already enabled(ing)\n");
		scx_err(ALREADY_ENABLED, "ext already in enable state, exit!\n");
		return -EBUSY;
	}
	if (!enable && (scx_ops_enable_state() == SCX_OPS_DISABLING ||
			scx_ops_enable_state() == SCX_OPS_DISABLED)) {
		/* Executing or completed, no need to repeat. */
		scx_switch_log(scx_enabled() ? SCX_ENABLED : SCX_DISABLED,
					0, enable, "already disabled(ing)\n");
		scx_err(ALREADY_DISABLED, "ext already in disable state, exit!\n");
		return -EBUSY;
	}

	if (enable)
		return bpf_scx_reg(NULL);
	else
		return bpf_scx_unreg(NULL);
}

#define MD_BUF_SIZE		(4 * 1024)
#define HMBIRD_MD_VERSION	"v1.0.0"

void scx_get_md_info(unsigned long *vaddr, unsigned long *size)
{
	*vaddr = (unsigned long)md_info;
	*size = max_t(u32, sizeof(struct md_info_t), MD_BUF_SIZE);
	return;
}
EXPORT_SYMBOL_GPL(scx_get_md_info);

static void get_hmbird_snapshot(struct panic_snapshot_t *p)
{
	struct scx_dispatch_q *dsq;
	struct rq *rq;
	int cpu, i;

	for_each_possible_cpu(cpu) {
		rq = cpu_rq(cpu);
		p->rq_nr[cpu] = rq->nr_running;
		p->scxrq_nr[cpu] = rq->scx->nr_running;
	}

	for (i = 0; i < MAX_GLOBAL_DSQS; i++) {
		struct sched_ext_entity *entity;

		dsq = &gdsqs[i];
		raw_spin_lock(&dsq->lock);
		if (list_empty(&dsq->fifo)) {
			raw_spin_unlock(&dsq->lock);
			continue;
		}

		entity = list_first_entry(&dsq->fifo, struct sched_ext_entity, dsq_node.fifo);
		if (!entity) {
			raw_spin_unlock(&dsq->lock);
			continue;
		}
		p->runnable_at[i] = entity->runnable_at;
		raw_spin_unlock(&dsq->lock);

	}

	p->snap_misc.scx_enabled = scx_enabled();
	p->snap_misc.curr_ss = curr_ss;
	p->snap_misc.scx_ops_enable_state_var = (u64)scx_ops_enable_state();
	p->snap_misc.non_ext_task = atomic_read(&non_ext_task);
	p->snap_misc.parctrl_high_ratio = parctrl_high_ratio;
	p->snap_misc.parctrl_low_ratio = parctrl_low_ratio;
	p->snap_misc.parctrl_high_ratio_l = parctrl_high_ratio_l;
	p->snap_misc.parctrl_low_ratio_l = parctrl_low_ratio_l;
	p->snap_misc.isoctrl_high_ratio = isoctrl_high_ratio;
	p->snap_misc.isoctrl_low_ratio = isoctrl_low_ratio;
	p->snap_misc.misfit_ds = misfit_ds;
	p->snap_misc.partial_enable = partial_enable;
	p->snap_misc.iso_free_rescue = iso_free_rescue;
	p->snap_misc.isolate_ctrl = isolate_ctrl;
	p->snap_misc.snap_jiffies = jiffies;
	p->snap_misc.snap_time = local_clock();
}

struct notifier_block hmbird_panic_blk;
static int hmbird_panic_handler(struct notifier_block *this,
					unsigned long event, void *ptr)
{
	if (!md_info)
		return NOTIFY_DONE;

	get_hmbird_snapshot(&md_info->kern_dump.snap);

	return NOTIFY_DONE;
}

static void panic_blk_init(void)
{
	hmbird_panic_blk.notifier_call = hmbird_panic_handler;
	/* we hope to be notified last.*/
	hmbird_panic_blk.priority = -INT_MAX;
	atomic_notifier_chain_register(&panic_notifier_list, &hmbird_panic_blk);
}

static void init_desc_meta(struct meta_desc_t *m, char *str, u64 d1, u64 d2, u64 d3)
{
	strncpy(m->desc_str, str, DESC_STR_LEN);
	m->len = d1 * d2 * d3;
	m->parse[0] = d1;
	m->parse[1] = d2;
	m->parse[2] = d3;
}

static void init_desc_metas(struct md_info_t *m)
{
	init_desc_meta(&m->kern_dump.sw_rec_meta, "switch record :",
			1, MAX_SWITCHS, SWITCH_ITEMS);

	init_desc_meta(&m->kern_dump.sw_idx_meta, "switch idx :", 1, 1, 1);

	init_desc_meta(&m->kern_dump.excep_rec_meta,
			"excep record :", 1, MAX_EXCEP_ID, MAX_EXCEPS);

	init_desc_meta(&m->kern_dump.excep_idx_meta,
			"excep idx :", 1, 1, MAX_EXCEP_ID);

	init_desc_meta(&m->kern_dump.snap.runnable_at_meta,
			"each dsq runnable at :", 1, 1, MAX_GLOBAL_DSQS);

	init_desc_meta(&m->kern_dump.snap.rq_nr_meta,
			"rq runnable task nr:", 1, 1, NR_CPUS);

	init_desc_meta(&m->kern_dump.snap.scxrq_nr_meta,
			"scxrq runnable task nr :", 1, 1, NR_CPUS);

	init_desc_meta(&m->kern_dump.snap.snap_misc_meta,
			"misc snap params :", 1, 1, SNAP_ITEMS);
}

static void init_md_meta(struct md_info_t *m)
{
	strcpy((char*)&m->meta.version, HMBIRD_MD_VERSION);
	m->meta.desc_meta_len = sizeof(struct meta_desc_t) / sizeof(u64);
	m->meta.desc_str_len = DESC_STR_LEN / sizeof(u64);
	m->meta.unit_size = sizeof(u64);
	m->meta.switchs = MAX_SWITCHS;
	m->meta.exceps = MAX_EXCEPS;
	m->meta.global_dsqs = MAX_GLOBAL_DSQS;
	m->meta.parse_dimens = PARSE_DIMENS;
	m->meta.nr_cpus = NR_CPUS;
	m->meta.real_cpus = nr_cpu_ids;
	m->meta.self_len = sizeof(struct md_meta_t) / sizeof(u64);
	m->meta.nr_meta_desc = 8;
	m->meta.dump_real_size = sizeof(struct md_info_t) / sizeof(u64);

	init_desc_metas(m);
}

static void md_info_init(void)
{
	u32 dump_size = max_t(u32, sizeof(struct md_info_t), MD_BUF_SIZE);

	md_info = kzalloc(dump_size, GFP_KERNEL);
	if (!md_info) {
		WARN_ON(1);
		return;
	}
	init_md_meta(md_info);

}

static void hmbird_md_init(void)
{
	md_info_init();
	panic_blk_init();
}

void __init init_sched_ext_class(void)
{
	int cpu;
	u32 v;

	/*
	 * The following is to prevent the compiler from optimizing out the enum
	 * definitions so that BPF scheduler implementations can use them
	 * through the generated vmlinux.h.
	 */
	WRITE_ONCE(v, SCX_WAKE_EXEC | SCX_ENQ_WAKEUP | SCX_DEQ_SLEEP |
		   SCX_KICK_PREEMPT);

	init_dsq(&scx_dsq_global, SCX_DSQ_GLOBAL);
	init_dsq_at_boot();
	init_isolate_cpus();
	hb_timer_init();
#ifdef CONFIG_SMP
	WARN_ON(!alloc_cpumask_var(&idle_masks.cpu, GFP_KERNEL));
	WARN_ON(!alloc_cpumask_var(&idle_masks.smt, GFP_KERNEL));
#endif

	/*
	 * we can't static init init_task's scx struct, init here.
	 * init_task->scx would not use during boot.
	 */
	init_task.scx = kmalloc(sizeof(struct sched_ext_entity), GFP_KERNEL);
	if (init_task.scx) {
		INIT_LIST_HEAD(&init_task.scx->dsq_node.fifo);
		INIT_LIST_HEAD(&init_task.scx->watchdog_node);
		init_task.scx->sticky_cpu = -1;
		init_task.scx->holding_cpu = -1;
		atomic64_set(&init_task.scx->ops_state, 0);
		init_task.scx->runnable_at = jiffies;
		init_task.scx->slice = SCX_SLICE_DFL;
		init_task.scx->task = &init_task;
		sched_set_sched_prop(&init_task, 0);
	} else {
		scx_err(INIT_TASK_FAIL, "<fatal>:alloc init_task.scx failed!!!\n");
	}

	for_each_possible_cpu(cpu) {
		struct rq *rq = cpu_rq(cpu);

		/*
		 * exec during boot phase, no need to care about alloc faild.
		 * lifecycle same to rq, no need to free.
		 */
		rq->scx = kmalloc(sizeof(struct scx_rq), GFP_KERNEL);
		if (rq->scx)
			rq->scx->rq = rq;
		else
			scx_err(ALLOC_RQSCX_FAIL, "<fatal>:alloc rq->scx failed!!!\n");


		init_dsq(&rq->scx->local_dsq, SCX_DSQ_LOCAL);
		INIT_LIST_HEAD(&rq->scx->watchdog_list);

		WARN_ON(!zalloc_cpumask_var(&rq->scx->cpus_to_kick, GFP_KERNEL));
		WARN_ON(!zalloc_cpumask_var(&rq->scx->cpus_to_preempt, GFP_KERNEL));
		WARN_ON(!zalloc_cpumask_var(&rq->scx->cpus_to_wait, GFP_KERNEL));
	}

	INIT_DELAYED_WORK(&scx_watchdog_work, scx_watchdog_workfn);
	INIT_WORK(&scx_err_exit_work, scx_err_exit_workfn);
	hmbird_md_init();
}

