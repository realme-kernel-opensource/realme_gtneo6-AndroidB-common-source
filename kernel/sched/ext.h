/* SPDX-License-Identifier: GPL-2.0 */
/*
 * BPF extensible scheduler class: Documentation/scheduler/sched-ext.rst
 *
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2022 Tejun Heo <tj@kernel.org>
 * Copyright (c) 2022 David Vernet <dvernet@meta.com>
 */

#ifndef _EXT_H_
#define _EXT_H_

/*
 * Tag marking a kernel function as a kfunc. This is meant to minimize the
 * amount of copy-paste that kfunc authors have to include for correctness so
 * as to avoid issues such as the compiler inlining or eliding either a static
 * kfunc, or a global kfunc in an LTO build.
 */

#define DEBUG_INTERNAL		(1 << 0)
#define	DEBUG_INFO_TRACE	(1 << 1)
#define DEBUG_INFO_SYSTRACE	(1 << 2)

extern struct md_info_t *md_info;
#define SCX_EXIT_ERROR_STALL		(1)
#define SCX_EXIT_ERROR_HEARTBEAT	(2)

#define debug_enabled()	\
	(unlikely(hmbirdcore_debug & DEBUG_INFO_TRACE | DEBUG_INFO_SYSTRACE))

#define scx_debug(fmt, ...) \
	pr_info("<hmbird_sched> "fmt, ##__VA_ARGS__);

#define scx_err(id, fmt, ...) \
do {							\
	pr_err("<hmbird_sched>"fmt, ##__VA_ARGS__);	\
	exceps_update(md_info, id, jiffies);	\
} while (0)

#define scx_deferred_err(id, fmt, ...) \
do {					\
	printk_deferred(KERN_ERR "<hmbird_sched>"fmt, ##__VA_ARGS__);	\
	exceps_update(md_info, id, jiffies);	\
} while (0)

#define scx_cond_deferred_err(id, cond, fmt, ...) \
do {							\
	if (unlikely(cond)) {				\
		scx_deferred_err(id, #cond","fmt, ##__VA_ARGS__);	\
		exceps_update(md_info, id, jiffies);	\
	}							\
} while (0)

#define scx_info_trace(fmt, ...)			\
do {						\
	if (unlikely(hmbirdcore_debug & DEBUG_INFO_TRACE))		\
		trace_printk("<hmbird_sched> "fmt, ##__VA_ARGS__); \
} while (0)


#define scx_info_systrace(fmt, ...)	\
do {					\
	if (unlikely(hmbirdcore_debug & DEBUG_INFO_SYSTRACE)) {	\
		char buf[256];		\
		snprintf(buf, sizeof(buf), fmt, ##__VA_ARGS__);	\
		tracing_mark_write(buf);			\
	}				\
} while (0)


#define scx_internal_trace(fmt, ...)			\
do {						\
	if (unlikely(hmbirdcore_debug & DEBUG_INTERNAL))		\
		trace_printk("<hmbird_sched> "fmt, ##__VA_ARGS__); \
} while (0)

#define scx_internal_systrace(fmt, ...)	\
do {					\
	if (unlikely(hmbirdcore_debug & DEBUG_INTERNAL)) {	\
		char buf[256];		\
		snprintf(buf, sizeof(buf), fmt, ##__VA_ARGS__);	\
		tracing_mark_write(buf);			\
	}				\
} while (0)

enum scx_wake_flags {
	/* expose select WF_* flags as enums */
	SCX_WAKE_EXEC		= WF_EXEC,
	SCX_WAKE_FORK		= WF_FORK,
	SCX_WAKE_TTWU		= WF_TTWU,
	SCX_WAKE_SYNC		= WF_SYNC,
};

enum scx_enq_flags {
	/* expose select ENQUEUE_* flags as enums */
	SCX_ENQ_WAKEUP		= ENQUEUE_WAKEUP,
	SCX_ENQ_HEAD		= ENQUEUE_HEAD,

	/* high 32bits are SCX specific */

	/*
	 * Set the following to trigger preemption when calling
	 * scx_bpf_dispatch() with a local dsq as the target. The slice of the
	 * current task is cleared to zero and the CPU is kicked into the
	 * scheduling path. Implies %SCX_ENQ_HEAD.
	 */
	SCX_ENQ_PREEMPT		= 1LLU << 32,

	/*
	 * The task being enqueued was previously enqueued on the current CPU's
	 * %SCX_DSQ_LOCAL, but was removed from it in a call to the
	 * bpf_scx_reenqueue_local() kfunc. If bpf_scx_reenqueue_local() was
	 * invoked in a ->cpu_release() callback, and the task is again
	 * dispatched back to %SCX_LOCAL_DSQ by this current ->enqueue(), the
	 * task will not be scheduled on the CPU until at least the next invocation
	 * of the ->cpu_acquire() callback.
	 */
	SCX_ENQ_REENQ		= 1LLU << 40,

	/*
	 * The task being enqueued is the only task available for the cpu. By
	 * default, ext core keeps executing such tasks but when
	 * %SCX_OPS_ENQ_LAST is specified, they're ops.enqueue()'d with
	 * %SCX_ENQ_LAST and %SCX_ENQ_LOCAL flags set.
	 *
	 * If the BPF scheduler wants to continue executing the task,
	 * ops.enqueue() should dispatch the task to %SCX_DSQ_LOCAL immediately.
	 * If the task gets queued on a different dsq or the BPF side, the BPF
	 * scheduler is responsible for triggering a follow-up scheduling event.
	 * Otherwise, Execution may stall.
	 */
	SCX_ENQ_LAST		= 1LLU << 41,

	/*
	 * A hint indicating that it's advisable to enqueue the task on the
	 * local dsq of the currently selected CPU. Currently used by
	 * select_cpu_dfl() and together with %SCX_ENQ_LAST.
	 */
	SCX_ENQ_LOCAL		= 1LLU << 42,

	/* high 8 bits are internal */
	__SCX_ENQ_INTERNAL_MASK	= 0xffLLU << 56,

	SCX_ENQ_CLEAR_OPSS	= 1LLU << 56,
	SCX_ENQ_DSQ_PRIQ	= 1LLU << 57,
};

enum scx_deq_flags {
	/* expose select DEQUEUE_* flags as enums */
	SCX_DEQ_SLEEP		= DEQUEUE_SLEEP,

	/* high 32bits are SCX specific */

	/*
	 * The generic core-sched layer decided to execute the task even though
	 * it hasn't been dispatched yet. Dequeue from the BPF side.
	 */
	SCX_DEQ_CORE_SCHED_EXEC	= 1LLU << 32,
};

enum scx_kick_flags {
	SCX_KICK_PREEMPT	= 1LLU << 0,	/* force scheduling on the CPU */
	SCX_KICK_WAIT		= 1LLU << 1,	/* wait for the CPU to be rescheduled */
};

extern const struct sched_class ext_sched_class;
extern const struct bpf_verifier_ops bpf_sched_ext_verifier_ops;
extern const struct file_operations sched_ext_fops;
extern unsigned long scx_watchdog_timeout;
extern unsigned long scx_watchdog_timestamp;

DECLARE_STATIC_KEY_FALSE(scx_ops_cpu_preempt);

bool task_on_scx(struct task_struct *p);
int scx_pre_fork(struct task_struct *p);
int scx_fork(struct task_struct *p);
void scx_post_fork(struct task_struct *p);
void scx_cancel_fork(struct task_struct *p);
int scx_check_setscheduler(struct task_struct *p, int policy);
bool scx_can_stop_tick(struct rq *rq);
void init_sched_ext_class(void);

void __scx_notify_pick_next_task(struct rq *rq,
				 struct task_struct *p,
				 const struct sched_class *active);

static inline void scx_notify_pick_next_task(struct rq *rq,
					     struct task_struct *p,
					     const struct sched_class *active)
{
	if (!scx_enabled())
		return;
#ifdef CONFIG_SMP
	/*
	 * Pairs with the smp_load_acquire() issued by a CPU in
	 * kick_cpus_irq_workfn() who is waiting for this CPU to perform a
	 * resched.
	 */
	smp_store_release(&rq->scx->pnt_seq, rq->scx->pnt_seq + 1);
#endif
	if (!static_branch_unlikely(&scx_ops_cpu_preempt))
		return;
	__scx_notify_pick_next_task(rq, p, active);
}

extern void scx_scheduler_tick(void);
void scan_timeout(struct rq *rq);
void scx_notify_sched_tick(void);

static inline const struct sched_class *next_active_class(const struct sched_class *class)
{
	class++;
	if (scx_enabled() && class == &fair_sched_class)
		class++;
	if (!scx_enabled() && class == &ext_sched_class)
		class++;
	return class;
}

#define for_active_class_range(class, _from, _to)				\
	for (class = (_from); class != (_to); class = next_active_class(class))

#define for_each_active_class(class)						\
	for_active_class_range(class, __sched_class_highest, __sched_class_lowest)

/*
 * SCX requires a balance() call before every pick_next_task() call including
 * when waking up from idle.
 */
#define for_balance_class_range(class, prev_class, end_class)			\
	for_active_class_range(class, (prev_class) > &ext_sched_class ?		\
			       &ext_sched_class : (prev_class), (end_class))

#define MAX_GLOBAL_DSQS (10)
#define MIN_CGROUP_DL_IDX (5)      /* 8ms */
#define DEFAULT_CGROUP_DL_IDX (8)  /* 64ms */
extern u32 SCX_BPF_DSQS_DEADLINE[MAX_GLOBAL_DSQS];


void __scx_update_idle(struct rq *rq, bool idle);

static inline void scx_update_idle(struct rq *rq, bool idle)
{
	if (scx_enabled())
		__scx_update_idle(rq, idle);
}

int ext_ctrl(bool enable);

int scx_tg_online(struct task_group *tg);


static inline u16 scx_task_util(struct task_struct *p)
{
	return (p->sched_class == &ext_sched_class) ? p->scx->sts.demand_scaled : 0;
}
u16 scx_cpu_util(int cpu);

/*
 * All variables use 64bits width,
 * Avoid parsing problems caused by automatic alignment(with padding) of structures.
 */

/* NOTING : Must align to 64bits. */
#define DESC_STR_LEN	(32)
/* Supporti up to  three-dimensional arrays. */
#define PARSE_DIMENS	(3)
struct meta_desc_t {
	char desc_str[DESC_STR_LEN];
	u64 len;
	u64 parse[PARSE_DIMENS];
};

#define MAX_SWITCHS	(5)
struct hmbird_switch_t {
	u64 switch_at;
	u64 is_success;
	u64 end_state;
	u64 switch_reason;
};
#define SWITCH_ITEMS	(sizeof(struct hmbird_switch_t) / sizeof(u64))

#define MAX_EXCEPS	(5)
enum excep_id {
	NO_CGROUP_L1,
	MODULE_UNLOAD,
	ALREADY_ENABLED,
	ALREADY_DISABLED,
	INIT_TASK_FAIL,
	ALLOC_RQSCX_FAIL,
	DSQ_ID_ERR,
	CPU_NO_MASK,
	SCAN_ENTITY_NULL,
	ITER_RET_NULL,
	DEQ_DEQING,
	ENQ_EXIST1,
	ENQ_EXIST2,
	TASK_LINKED1,
	TASK_UNLINKED,
	TASK_LINKED2,
	TASK_UNQUED,
	TASK_UNWATCHED,
	SCX_OPN,
	TASK_WATCHED,
	RQ_NO_RUNNING,
	EXTRA_FLAGS,
	HOLDING_CPU1,
	HOLDING_CPU2,
	TASK_OPS_PREPPED,
	TASK_OPS_UNPREPPED,
	SCX_OPS_ERR,
	MAX_EXCEP_ID,
};

struct snap_misc_t {
	u64 scx_enabled;
	u64 curr_ss;
	u64 scx_ops_enable_state_var;
	u64 non_ext_task;
	u64 parctrl_high_ratio;
	u64 parctrl_low_ratio;
	u64 parctrl_high_ratio_l;
	u64 parctrl_low_ratio_l;
	u64 isoctrl_high_ratio;
	u64 isoctrl_low_ratio;
	u64 misfit_ds;
	u64 partial_enable;
	u64 iso_free_rescue;
	u64 isolate_ctrl;
	u64 snap_jiffies;
	u64 snap_time;
};
#define SNAP_ITEMS	(sizeof(struct snap_misc_t) / sizeof(u64))

struct panic_snapshot_t {
	/* what time dose the first task of dsq trun in runnable, check starvation */
	struct meta_desc_t runnable_at_meta;
	u64 runnable_at[MAX_GLOBAL_DSQS];

	struct meta_desc_t rq_nr_meta;
	u64 rq_nr[NR_CPUS];

	struct meta_desc_t scxrq_nr_meta;
	u64 scxrq_nr[NR_CPUS];

	struct meta_desc_t snap_misc_meta;
	struct snap_misc_t snap_misc;
};

/*
 * Do not record info in hot paths unless absolutely necessary,
 * The impact on performance should be minimized.
 */
struct kernel_info_t {
	struct meta_desc_t sw_rec_meta;
	struct hmbird_switch_t sw_rec[MAX_SWITCHS];

	struct meta_desc_t sw_idx_meta;
	u64 sw_idx;

	struct meta_desc_t excep_rec_meta;
	u64 excep_rec[MAX_EXCEP_ID][MAX_EXCEPS];

	struct meta_desc_t excep_idx_meta;
	u64 excep_idx[MAX_EXCEP_ID];

	/* snapshot while panic. */
	struct panic_snapshot_t snap;
};

struct ko_info_t {};

struct md_meta_t {
	u64 version;
	u64 self_len;
	u64 unit_size;
	u64 desc_meta_len;
	u64 desc_str_len;
	u64 switchs;
	u64 exceps;
	u64 global_dsqs;
	u64 parse_dimens;
	u64 nr_cpus;
	u64 real_cpus;
	u64 nr_meta_desc;
	u64 dump_real_size;
};

struct md_info_t {
	struct md_meta_t meta;
	struct kernel_info_t kern_dump;
	struct ko_info_t ko_dump;
};

static inline void exceps_update(struct md_info_t *rec, int id, unsigned long jiffies)
{
	u64 *idx;

	if (!rec)
		return;

	idx = &rec->kern_dump.excep_idx[id];
	rec->kern_dump.excep_rec[id][*idx] = jiffies;
	*idx = ++(*idx) % MAX_EXCEPS;
}

static inline void sw_update(struct md_info_t *rec, u64 switch_at,
				u64 is_success, u64 end_state, u64 switch_reason)
{
	u64 *idx;

	if (!rec)
		return;

	idx = &rec->kern_dump.sw_idx;
	rec->kern_dump.sw_rec[*idx].switch_at = switch_at;
	rec->kern_dump.sw_rec[*idx].is_success = is_success;
	rec->kern_dump.sw_rec[*idx].end_state = end_state;
	rec->kern_dump.sw_rec[*idx].switch_reason = switch_reason;
	*idx = ++(*idx) % MAX_SWITCHS;
}

void scx_ops_error_type(void);
#define scx_ops_error(fmt, ...)						\
do {										\
	scx_deferred_err(SCX_OPS_ERR, fmt, ##__VA_ARGS__);                      \
	scx_ops_error_type();				\
} while (0)

#endif /*_EXT_H_*/
