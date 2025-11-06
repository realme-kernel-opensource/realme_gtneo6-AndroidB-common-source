/* SPDX-License-Identifier: GPL-2.0 */

#include "slim.h"


int scx_enable;
int cpuctrl_high_ratio = 55;
int cpuctrl_low_ratio = 40;

int parctrl_high_ratio = 55;
int parctrl_low_ratio = 40;
int parctrl_high_ratio_l = 65;
int parctrl_low_ratio_l = 50;
int isoctrl_high_ratio = 75;
int isoctrl_low_ratio = 60;
int isolate_ctrl;
int iso_free_rescue;

int partial_enable;
int slim_stats;
int hmbirdcore_debug = DEBUG_INTERNAL;
int misfit_ds = 90;
int heartbeat;
int heartbeat_enable = 1;
int watchdog_enable;
int save_gov;

char saved_gov[NR_CPUS][MAX_GOV_LEN];

int slim_gov_debug;

extern int slim_for_app;

int sched_ravg_window_frame_per_sec = 125;

#define SLIM_SCHED_CTRL		"scx_enable"
#define PAR_CTRL_NAME           "partial_ctrl"
#define CPUCTRL_HIGH_THRES      "cpuctrl_high"
#define CPUCTRL_LOW_THRES       "cpuctrl_low"
#define SLIM_STATS		"slim_stats"
#define SLIM_TRACE		"hmbirdcore_debug"
#define MISFIT_DS		"misfit_ds"
#define SAVE_GOV		"save_gov"
#define HEARTBEAT		"heartbeat"
#define HEARTBEAT_ENABLE	"heartbeat_enable"
#define WATCHDOG_ENABLE		"watchdog_enable"

#define ISOLATE_CTRL		"isolate_ctrl"
#define PARCTRL_HIGH_THRES	"parctrl_high_ratio"
#define PARCTRL_LOW_THRES	"parctrl_low_ratio"
#define PARCTRL_HIGH_THRES_L	"parctrl_high_ratio_l"
#define PARCTRL_LOW_THRES_L	"parctrl_low_ratio_l"

#define ISOCTRL_HIGH_THRES	"isoctrl_high_ratio"
#define ISOCTRL_LOW_THRES	"isoctrl_low_ratio"
#define ISO_FREE_RESCUE		"iso_free_rescue"

#define SCHED_EXT_DIR		"hmbird_sched"

#define SLIM_FOR_APP		"slim_for_app"

noinline int tracing_mark_write(const char *buf)
{
        trace_printk(buf);
        return 0;
}

static char *slim_config[] = {
	SLIM_SCHED_CTRL,
	PAR_CTRL_NAME,
	CPUCTRL_HIGH_THRES,
	CPUCTRL_LOW_THRES,
	SLIM_STATS,
	SLIM_TRACE,
	SLIM_FOR_APP,
	MISFIT_DS,
	SAVE_GOV,
	HEARTBEAT,
	HEARTBEAT_ENABLE,
	WATCHDOG_ENABLE,
	ISOLATE_CTRL,
	PARCTRL_HIGH_THRES,
	PARCTRL_LOW_THRES,
	ISOCTRL_HIGH_THRES,
	ISOCTRL_LOW_THRES,
	ISO_FREE_RESCUE,
	PARCTRL_HIGH_THRES_L,
	PARCTRL_LOW_THRES_L,
};

static int *slim_data[] = {
	&scx_enable,
	&partial_enable,
	&cpuctrl_high_ratio,
	&cpuctrl_low_ratio,
	&slim_stats,
	&hmbirdcore_debug,
	&slim_for_app,
	&misfit_ds,
	&save_gov,
	&heartbeat,
	&heartbeat_enable,
	&watchdog_enable,
	&isolate_ctrl,
	&parctrl_high_ratio,
	&parctrl_low_ratio,
	&isoctrl_high_ratio,
	&isoctrl_low_ratio,
	&iso_free_rescue,
	&parctrl_high_ratio_l,
	&parctrl_low_ratio_l,
};

static void save_gov_str(void)
{
	int cpu;
	struct cpufreq_policy *policy;

	for_each_possible_cpu(cpu) {
		policy = cpufreq_cpu_get(cpu);
		if (!policy)
			continue;
		if (cpu != policy->cpu)
			continue;
		WARN_ON(show_scaling_governor(policy, saved_gov[cpu]) <= 0);
		scx_info_systrace("<gov_restore>:save origin gov : %s\n", saved_gov[cpu]);
	}
}

static ssize_t slim_common_write(struct file *file, const char __user *buf,
                               size_t count, loff_t *ppos)
{
	int *pval = (int *)pde_data(file_inode(file));
	char kbuf[5] = {0};
	int err;

	if (count >= 5)
		return -EFAULT;

	if (copy_from_user(kbuf, buf, count)) {
		pr_err("slim_sched : Failed to copy_from_user\n");
		return -EFAULT;
	}
	err = kstrtoint(strstrip(kbuf), 0, pval);
	if (err < 0) {
		pr_err("slim_sched: Failed to exec kstrtoint\n");
		return -EFAULT;
	}

	if (pval == &scx_enable) {
		WRITE_ONCE(sw_type, SCX_SWITCH_PROC);
		if (ext_ctrl(*pval))
			return -EFAULT;
	}

	if (pval == &save_gov)
		save_gov_str();

	if (pval == &iso_free_rescue)
		scx_internal_systrace("C|9999|iso_free_rescue|%d\n", iso_free_rescue);

	return count;
}

static int slim_common_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%d\n", *(int*) m->private);
	return 0;
}

static int slim_common_open(struct inode *inode, struct file *file)
{
	return single_open(file, slim_common_show, pde_data(inode));
}

static const struct proc_ops common_proc_ops = {
	.proc_open              = slim_common_open,
	.proc_write             = slim_common_write,
	.proc_read              = seq_read,
	.proc_lseek             = seq_lseek,
	.proc_release           = single_release,
};

#define HMBIRD_STATS	"hmbird_stats"
#define MAX_STATS_BUF	(4096)
static int hmbird_stats_show(struct seq_file *m, void *v)
{
	char *buf;

	buf = kmalloc(MAX_STATS_BUF, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	stats_print(buf, MAX_STATS_BUF);

	seq_printf(m, "%s\n", buf);

	kfree(buf);
	return 0;
}

static int hmbird_stats_open(struct inode *inode, struct file *file)
{
	return single_open(file, hmbird_stats_show, inode);
}

static const struct proc_ops hmbird_stat_fops = {
	.proc_open		= hmbird_stats_open,
	.proc_read		= seq_read,
	.proc_lseek		= seq_lseek,
	.proc_release		= single_release,
};



static int __init slim_sysfs_init(void)
{
	int i;
	hmbird_dir = proc_mkdir(SCHED_EXT_DIR, NULL);
	if (hmbird_dir) {
		for (i = 0; i < ARRAY_SIZE(slim_config); i++) {
			proc_create_data(slim_config[i], S_IRUGO | S_IWUGO,
					hmbird_dir, &common_proc_ops, slim_data[i]);
		}
		proc_create(HMBIRD_STATS, S_IRUGO | S_IWUGO, hmbird_dir, &hmbird_stat_fops);
	}
	return 0;
}

__initcall(slim_sysfs_init);
