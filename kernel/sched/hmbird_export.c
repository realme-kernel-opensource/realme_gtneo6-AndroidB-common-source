/*
 * Some variables need to export, if CONFIG_HMBIRD_SCHED not configed,
 * error will be reported by compiler, These variables must be defined
 * outside of CONFIG_HMBIRD_SCHED MICRO.
 */
int slim_for_app;
EXPORT_SYMBOL_GPL(slim_for_app);

struct scx_sched_rq_stats {
	u64             window_start;
	u64             latest_clock;
	u32             prev_window_size;
	u64             task_exec_scale;
	u64             prev_runnable_sum;
	u64             curr_runnable_sum;
};

DEFINE_PER_CPU(struct scx_sched_rq_stats, scx_sched_rq_stats);
EXPORT_SYMBOL_GPL(scx_sched_rq_stats);

atomic64_t scx_irq_work_lastq_ws;
EXPORT_SYMBOL_GPL(scx_irq_work_lastq_ws);

atomic_t ext_module_loaded = ATOMIC_INIT(0);
EXPORT_SYMBOL_GPL(ext_module_loaded);

struct proc_dir_entry *hmbird_dir;
EXPORT_SYMBOL_GPL(hmbird_dir);

atomic_t non_ext_task = ATOMIC_INIT(true);
EXPORT_SYMBOL_GPL(non_ext_task);

atomic_t __scx_ops_enabled;
EXPORT_SYMBOL_GPL(__scx_ops_enabled);

struct scx_iso_masks iso_masks;
EXPORT_SYMBOL_GPL(iso_masks);

#ifndef CONFIG_HMBIRD_SCHED
bool task_is_scx(struct task_struct *p) {return false;}
EXPORT_SYMBOL_GPL(task_is_scx);
#endif

