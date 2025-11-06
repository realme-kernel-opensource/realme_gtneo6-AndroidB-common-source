/* SPDX-License-Identifier: GPL-2.0 */
/*
 * BPF extensible scheduler class: Documentation/scheduler/sched-ext.rst
 *
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2022 Tejun Heo <tj@kernel.org>
 * Copyright (c) 2022 David Vernet <dvernet@meta.com>
 */
#ifndef _LINUX_SCHED_EXT_H
#define _LINUX_SCHED_EXT_H

#include <linux/llist.h>

extern atomic_t non_ext_task;
extern atomic_t __scx_ops_enabled;
#define scx_enabled()           atomic_read(&__scx_ops_enabled)

struct scx_iso_masks {
	cpumask_var_t ex_free;
	cpumask_var_t exclusive;
	cpumask_var_t partial;
	cpumask_var_t big;
	cpumask_var_t little;
};

enum scx_consts {
	SCX_OPS_NAME_LEN	= 128,
	SCX_EXIT_REASON_LEN	= 128,
	SCX_EXIT_BT_LEN		= 64,
	SCX_EXIT_MSG_LEN	= 1024,

	SCX_SLICE_DFL		= 1 * NSEC_PER_MSEC,
	SCX_SLICE_ISO		= 8 * SCX_SLICE_DFL,
	SCX_SLICE_INF		= U64_MAX,	/* infinite, implies nohz */
};

/*
 * DSQ (dispatch queue) IDs are 64bit of the format:
 *
 *   Bits: [63] [62 ..  0]
 *         [ B] [   ID   ]
 *
 *    B: 1 for IDs for built-in DSQs, 0 for ops-created user DSQs
 *   ID: 63 bit ID
 *
 * Built-in IDs:
 *
 *   Bits: [63] [62] [61..32] [31 ..  0]
 *         [ 1] [ L] [   R  ] [    V   ]
 *
 *    1: 1 for built-in DSQs.
 *    L: 1 for LOCAL_ON DSQ IDs, 0 for others
 *    V: For LOCAL_ON DSQ IDs, a CPU number. For others, a pre-defined value.
 */
enum scx_dsq_id_flags {
	SCX_DSQ_FLAG_BUILTIN	= 1LLU << 63,
	SCX_DSQ_FLAG_LOCAL_ON	= 1LLU << 62,

	SCX_DSQ_INVALID		= SCX_DSQ_FLAG_BUILTIN | 0,
	SCX_DSQ_GLOBAL		= SCX_DSQ_FLAG_BUILTIN | 1,
	SCX_DSQ_LOCAL		= SCX_DSQ_FLAG_BUILTIN | 2,
	SCX_DSQ_LOCAL_ON	= SCX_DSQ_FLAG_BUILTIN | SCX_DSQ_FLAG_LOCAL_ON,
	SCX_DSQ_LOCAL_CPU_MASK	= 0xffffffffLLU,
};

enum scx_switch_type {
	SCX_SWITCH_PROC,
	SCX_SWITCH_ERR_WDT,
	SCX_SWITCH_ERR_HB,
	SCX_SWITCH_ERR_DSQ,
};


/* sched_ext_ops.flags */
enum scx_ops_flags {
	/*
	 * Keep built-in idle tracking even if ops.update_idle() is implemented.
	 */
	SCX_OPS_KEEP_BUILTIN_IDLE = 1LLU << 0,

	/*
	 * By default, if there are no other task to run on the CPU, ext core
	 * keeps running the current task even after its slice expires. If this
	 * flag is specified, such tasks are passed to ops.enqueue() with
	 * %SCX_ENQ_LAST. See the comment above %SCX_ENQ_LAST for more info.
	 */
	SCX_OPS_ENQ_LAST	= 1LLU << 1,

	/*
	 * An exiting task may schedule after PF_EXITING is set. In such cases,
	 * bpf_task_from_pid() may not be able to find the task and if the BPF
	 * scheduler depends on pid lookup for dispatching, the task will be
	 * lost leading to various issues including RCU grace period stalls.
	 *
	 * To mask this problem, by default, unhashed tasks are automatically
	 * dispatched to the local DSQ on enqueue. If the BPF scheduler doesn't
	 * depend on pid lookups and wants to handle these tasks directly, the
	 * following flag can be used.
	 */
	SCX_OPS_ENQ_EXITING	= 1LLU << 2,

	/*
	 * CPU cgroup knob enable flags
	 */
	SCX_OPS_CGROUP_KNOB_WEIGHT = 1LLU << 16,	/* cpu.weight */

	SCX_OPS_ALL_FLAGS	= SCX_OPS_KEEP_BUILTIN_IDLE |
				  SCX_OPS_ENQ_LAST |
				  SCX_OPS_ENQ_EXITING |
				  SCX_OPS_CGROUP_KNOB_WEIGHT,
};

enum scx_cpu_preempt_reason {
	/* next task is being scheduled by &sched_class_rt */
	SCX_CPU_PREEMPT_RT,
	/* next task is being scheduled by &sched_class_dl */
	SCX_CPU_PREEMPT_DL,
	/* next task is being scheduled by &sched_class_stop */
	SCX_CPU_PREEMPT_STOP,
	/* unknown reason for SCX being preempted */
	SCX_CPU_PREEMPT_UNKNOWN,
};

/*
 * Dispatch queue (dsq) is a simple FIFO which is used to buffer between the
 * scheduler core and the BPF scheduler. See the documentation for more details.
 */
struct scx_dispatch_q {
	raw_spinlock_t		lock;
	struct list_head	fifo;	/* processed in dispatching order */
	struct rb_root_cached	priq;	/* processed in p->scx.dsq_vtime order */
	u32			nr;
	u64			id;
	struct llist_node	free_node;
	struct rcu_head		rcu;
	u64                     last_consume_at;
	bool                    is_timeout;
};

/* scx_entity.flags */
enum scx_ent_flags {
	SCX_TASK_QUEUED		= 1 << 0, /* on ext runqueue */
	SCX_TASK_BAL_KEEP	= 1 << 1, /* balance decided to keep current */
	SCX_TASK_ENQ_LOCAL	= 1 << 2, /* used by scx_select_cpu_dfl() to set SCX_ENQ_LOCAL */

	SCX_TASK_OPS_PREPPED	= 1 << 8, /* prepared for BPF scheduler enable */
	SCX_TASK_OPS_ENABLED	= 1 << 9, /* task has BPF scheduler enabled */

	SCX_TASK_WATCHDOG_RESET = 1 << 16, /* task watchdog counter should be reset */
	SCX_TASK_DEQD_FOR_SLEEP	= 1 << 17, /* last dequeue was for SLEEP */

	SCX_TASK_CURSOR		= 1 << 31, /* iteration cursor, not a task */
};

/* scx_entity.dsq_flags */
enum scx_ent_dsq_flags {
	SCX_TASK_DSQ_ON_PRIQ	= 1 << 0, /* task is queued on the priority queue of a dsq */
};

#define RAVG_HIST_SIZE 5
struct scx_sched_task_stats {
	u64				mark_start;
	u64				window_start;
	u32				sum;
	u32				sum_history[RAVG_HIST_SIZE];
	int 			cidx;

	u32				demand;
	u16				demand_scaled;
	void 			*sdsq;
};


/*
 * The following is embedded in task_struct and contains all fields necessary
 * for a task to be scheduled by SCX.
 */
struct sched_ext_entity {
	struct scx_dispatch_q	*dsq;
	struct {
		struct list_head	fifo;	/* dispatch order */
		struct rb_node		priq;	/* p->scx.dsq_vtime order */
	} dsq_node;
	struct list_head	watchdog_node;
	u32			flags;		/* protected by rq lock */
	u32			dsq_flags;	/* protected by dsq lock */
	u32			weight;
	s32			sticky_cpu;
	s32			holding_cpu;
	u32			kf_mask;	/* see scx_kf_mask above */
	struct task_struct	*kf_tasks[2];	/* see SCX_CALL_OP_TASK() */
	atomic64_t		ops_state;
	unsigned long		runnable_at;

	/* BPF scheduler modifiable fields */

	/*
	 * Runtime budget in nsecs. This is usually set through
	 * scx_bpf_dispatch() but can also be modified directly by the BPF
	 * scheduler. Automatically decreased by SCX as the task executes. On
	 * depletion, a scheduling event is triggered.
	 *
	 * This value is cleared to zero if the task is preempted by
	 * %SCX_KICK_PREEMPT and shouldn't be used to determine how long the
	 * task ran. Use p->se.sum_exec_runtime instead.
	 */
	u64			slice;

	/*
	 * Used to order tasks when dispatching to the vtime-ordered priority
	 * queue of a dsq. This is usually set through scx_bpf_dispatch_vtime()
	 * but can also be modified directly by the BPF scheduler. Modifying it
	 * while a task is queued on a dsq may mangle the ordering and is not
	 * recommended.
	 */
	u64			dsq_vtime;

	/*
	 * If set, reject future set scheduler calls updating the policy
	 * to %SCHED_EXT with -%EACCES.
	 *
	 * If set from ops.prep_enable() and the task's policy is already
	 * %SCHED_EXT, which can happen while the BPF scheduler is being loaded
	 * or by inhering the parent's policy during fork, the task's policy is
	 * rejected and forcefully reverted to %SCHED_NORMAL. The number of such
	 * events are reported through /sys/kernel/debug/sched_ext::nr_rejected.
	 */
	bool			disallow;	/* reject switching into SCX */

	/* cold fields */
	struct list_head	tasks_node;
	struct task_struct	*task;
	unsigned long		sched_prop;
	unsigned long		top_task_prop;
	struct scx_sched_task_stats sts;
	unsigned long           running_at;
	int                     gdsq_idx;
	int			dsq_sync_ux;
};

void sched_ext_free(struct task_struct *p);
void scx_get_md_info(unsigned long *vaddr, unsigned long *size);

enum DSQ_SYNC_UX_FLAG {
	DSQ_SYNC_UX_NONE = 0,
	DSQ_SYNC_STATIC_UX = 1,
	DSQ_SYNC_INHERIT_UX = 1 << 1,
};
#endif	/* _LINUX_SCHED_EXT_H */
