#ifndef __SLIM_H
#define __SLIM_H

#include <linux/time.h>
#include <linux/timer.h>
#include <linux/sysfs.h>
#include <linux/notifier.h>
#include <linux/panic_notifier.h>

extern int scx_enable;

extern int cpuctrl_high_ratio;
extern int cpuctrl_low_ratio;
extern int partial_enable;
extern int slim_stats;
extern int misfit_ds;
extern int heartbeat;
extern int heartbeat_enable;
extern int watchdog_enable;
extern int isolate_ctrl;
extern int parctrl_high_ratio;
extern int parctrl_low_ratio;
extern int isoctrl_high_ratio;
extern int isoctrl_low_ratio;
extern int iso_free_rescue;

extern int slim_walt_ctrl;
extern int slim_walt_dump;
extern int slim_walt_policy;
extern int slim_gov_debug;
extern int hmbirdcore_debug;
extern int sched_ravg_window_frame_per_sec;

extern atomic_t __scx_ops_enabled;
extern atomic_t non_ext_task;
extern enum scx_switch_type sw_type;

extern noinline int tracing_mark_write(const char *buf);
int task_top_id(struct task_struct *p);
void stats_print(char *buf, int len);
extern spinlock_t scx_tasks_lock;

#define MAX_GOV_LEN     (16)
extern char saved_gov[NR_CPUS][MAX_GOV_LEN];

#endif
