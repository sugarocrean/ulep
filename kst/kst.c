/* The idea for this came from Werner Almesberger's umlsim
 * Copyright (C) 2004, Stephen Hemminger <shemminger@osdl.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/irq.h>
#include <linux/proc_fs.h>
#include <linux/ktime.h>
#include <linux/time.h>
#include <linux/seq_file.h>
#include <asm/traps.h>


MODULE_AUTHOR("Haiyang Tan <haiyang.tan.dev@gmail.com>");
MODULE_DESCRIPTION("Process kernel mode time-consuming measurement");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.1");

static char proc_name[NAME_MAX] = "loop4";
module_param_string(proc, proc_name, NAME_MAX, S_IRUGO);
MODULE_PARM_DESC(proc, " process to be measured; this module will report the"
			" process's max kernel mode time");

static int dbg_en __read_mostly;
MODULE_PARM_DESC(dbg_en, "debug (0=disable debug, !0=enable)");
module_param(dbg_en, int, 1);


//#define dbg_log(fmt, ...) \
//    printk(KERN_NOTICE, pr_fmt(fmt), ##__VA_ARGS__)

#define dbg_log printk


static rwlock_t kst_lock;

struct kst_meter {
    int valid;
    pid_t pid;
    ktime_t u2k_time;
    ktime_t max_time;
};

#define KST_ENTRY_NUM 6

static struct kst_meter kst_meters[KST_ENTRY_NUM];

static int kst_meter_init(void)
{
    rwlock_init(&kst_lock);
    return 0;
}


static inline struct kst_meter *kst_meter_lookup(pid_t pid)
{
    int i;
    unsigned long flags;
    struct kst_meter *meter = NULL;

    read_lock_irqsave(&kst_lock, flags);
    for (i = 0; i < KST_ENTRY_NUM; i++) {
        if (kst_meters[i].valid && kst_meters[i].pid == pid) {
            meter = &kst_meters[i];
            break;
        }
    }
    read_unlock_irqrestore(&kst_lock, flags);

    return meter;
}

static inline struct kst_meter *kst_meter_create(pid_t pid)
{
    int i;
    unsigned long flags;
    struct kst_meter *meter = NULL;

    write_lock_irqsave(&kst_lock, flags);
    for (i = 0; i < KST_ENTRY_NUM; i++) {
        if (!kst_meters[i].valid) {
            memset(&kst_meters[i], 0, sizeof(kst_meters[i]));
            kst_meters[i].valid = 1;
            kst_meters[i].pid = pid;
            meter = &kst_meters[i];
            break;
        }
    }
    write_unlock_irqrestore(&kst_lock, flags);

    return meter;
}


static inline int kst_meter_remove(pid_t pid)
{
    int i;
    unsigned long flags;

    write_lock_irqsave(&kst_lock, flags);
    for (i = 0; i < KST_ENTRY_NUM; i++) {
        if (kst_meters[i].valid && kst_meters[i].pid == pid) {
            memset(&kst_meters[i], 0, sizeof(kst_meters[i]));
            break;
        }
    }
    write_unlock_irqrestore(&kst_lock, flags);

    return 0;
}

static void jp_entry_comm_handler(const char *caller, struct pt_regs *regs)
{
    if (!strcmp(current->comm, proc_name)) {
        if (user_mode(regs)) {
            struct kst_meter *kst = kst_meter_lookup(current->pid);
            if (kst == NULL) {
                kst = kst_meter_create(current->pid);
            }

            if (kst) {
                kst->u2k_time = ktime_get();
                dbg_log("%s: pid %d, from user mode, now is %lu\n", 
                        caller, current->pid, ktime_to_us(kst->u2k_time));
            }
        } else {
           printk(KERN_INFO, "===================== %s: irq occures in kernel mode\n", caller);
           //dump_stack();
        }
    }
}

static void kp_comm_handler_post(struct kprobe *p,
        struct pt_regs *regs, unsigned long flags)
{
    if (!strcmp(current->comm, proc_name)) {
        struct kst_meter *kst = kst_meter_lookup(current->pid);
        if (kst) {
            ktime_t now = ktime_get();
            ktime_t delta = ktime_sub(now, kst->u2k_time);
            if (ktime_compare(delta, kst->max_time) > 0) {
                kst->max_time = delta;
                dbg_log("%s: pid is %d, now is %lu, diff is %lu, max is updated to %lu\n",
                        __FUNCTION__,
                        current->pid,
                        ktime_to_us(now),
                        ktime_to_us(delta),
                        ktime_to_us(kst->max_time));
                dump_stack();
                dbg_log("========================================================\n\n");
            }
        }
    }
}

__visible unsigned int __irq_entry jsmp_apic_timer_interrupt(struct pt_regs *regs)
{
    jp_entry_comm_handler(__FUNCTION__, regs);

    /* Always end with a call to jprobe_return(). */
    jprobe_return();
    return 0;
}

static struct jprobe jprobe_smp_apic_timer_interrupt = {
    .entry = jsmp_apic_timer_interrupt,
    .kp = { .symbol_name = "smp_apic_timer_interrupt", },
};

static struct kprobe kp_smp_apic_timer_interrupt = {
    .post_handler = kp_comm_handler_post,
    .symbol_name = "smp_apic_timer_interrupt",
};


__visible unsigned int __irq_entry jdo_IRQ(struct pt_regs *regs)
{
    jp_entry_comm_handler(__FUNCTION__, regs);

    /* Always end with a call to jprobe_return(). */
    jprobe_return();
    return 0;
}

static struct jprobe jprobe_do_IRQ = {
    .entry = jdo_IRQ,
    .kp = { .symbol_name = "do_IRQ", },
};

static struct kprobe kp_do_IRQ = {
    .post_handler = kp_comm_handler_post,
    .symbol_name = "do_IRQ",
};

void __noreturn jdo_exit(long code)
{
    if (!strcmp(current->comm, proc_name)) {
        if (!kst_meter_remove(current->pid))
            dbg_log("%s: remove pid %d's record successfully\n", __FUNCTION__, current->pid);
        else
            dbg_log("%s: remove pid %d's record failed\n", __FUNCTION__, current->pid);
    }

    /* Always end with a call to jprobe_return(). */
    jprobe_return();
}

static struct jprobe jprobe_do_exit = {
    .entry = jdo_exit,
    .kp = { .symbol_name = "do_exit", },
};


static dotraplinkage void notrace
jdo_page_fault(struct pt_regs *regs, unsigned long error_code)
{
    jp_entry_comm_handler(__FUNCTION__, regs);
    /* Always end with a call to jprobe_return(). */
    jprobe_return();
}

static struct jprobe jprobe_do_page_fault = {
    .entry = jdo_page_fault,
    .kp = { .symbol_name = "do_page_fault", },
};

static struct jprobe *jprobe_set[] = {
    &jprobe_smp_apic_timer_interrupt,
    &jprobe_do_IRQ,
    &jprobe_do_exit,
//    &jprobe_do_page_fault,
};

static struct kprobe kp_do_page_fault = {
    .post_handler = kp_comm_handler_post,
    .symbol_name = "do_page_fault",
};

static struct kprobe *kprobe_set[] = {
//    &kp_do_page_fault,
    &kp_do_IRQ,
    &kp_smp_apic_timer_interrupt,
};

static int kst_proc_show(struct seq_file *m, void *v)
{
    int i;
    unsigned long flags;

    read_lock_irqsave(&kst_lock, flags);
    for (i = 0; i < KST_ENTRY_NUM; i++) {
        struct kst_meter *meter = &kst_meters[i];
        if (meter->valid) {
            seq_printf(m, "pid=%d,max_latency=%luus\n",
                          meter->pid, ktime_to_us(meter->max_time));
        }
    }
    read_unlock_irqrestore(&kst_lock, flags);

    return 0;
}

static int kst_proc_open(struct inode *inode, struct file *file)
{
    return single_open(file, kst_proc_show, NULL);
}

static const struct file_operations kst_proc_fops = {
    .open    = kst_proc_open,
    .read    = seq_read,
    .llseek  = seq_lseek,
    .release = single_release,
};

static int __init kst_mod_init(void)
{
    int ret;
    int i, j;

    BUILD_BUG_ON(__same_type(do_exit, jdo_exit) == 0);
    BUILD_BUG_ON(__same_type(do_IRQ, jdo_IRQ) == 0);
    BUILD_BUG_ON(__same_type(do_page_fault, jdo_page_fault) == 0);
//  BUILD_BUG_ON(__same_type(smp_apic_timer_interrupt, 
//                          jsmp_apic_timer_interrupt) == 0);

    ret = kst_meter_init();
    if (ret < 0) {
        printk(KERN_INFO "kst_meter_init() failed, returned %d\n", ret);
        return -1;
    }

    for (i = 0; i < ARRAY_SIZE(jprobe_set); i++) {
        ret = register_jprobe(jprobe_set[i]);
        if (ret < 0) {
            printk(KERN_INFO "register jprobe %s failed, rc %d\n",
                              jprobe_set[i]->kp.symbol_name, ret);
            goto undo_jp;
        } else {
            printk(KERN_INFO "register jprobe %s successfaully\n",
                              jprobe_set[i]->kp.symbol_name);
        } 
    }

    for (i = 0; i < ARRAY_SIZE(kprobe_set); i++) {
        ret = register_kprobe(kprobe_set[i]);
        if (ret < 0) {
            printk(KERN_INFO "register kprobe %s failed, rc %d\n",
                              kprobe_set[i]->symbol_name, ret);
            goto undo_kp;
        } else {
            printk(KERN_INFO "register kprobe %s successfaully\n",
                              kprobe_set[i]->symbol_name);
        } 
    }

    proc_create("kst_info", 0, NULL, &kst_proc_fops);
    pr_info("kst module is loaded\n");
    return 0;

undo_kp:
    for (j = 0; j < i; j++) {
        printk(KERN_INFO "unregister kprobe %s\n",
                          kprobe_set[j]->symbol_name);
        unregister_kprobe(kprobe_set[j]);
    }

    i = ARRAY_SIZE(jprobe_set);
undo_jp:
    for (j = 0; j < i; j++) {
        printk(KERN_INFO "unregister jprobe %s\n",
                          jprobe_set[j]->kp.symbol_name);
        unregister_jprobe(jprobe_set[j]);
    }

    return -1;
}

static void __exit kst_mod_exit(void)
{
    int i;

    remove_proc_entry("kst_info", NULL);

    for (i = 0; i < ARRAY_SIZE(kprobe_set); i++)
        unregister_kprobe(kprobe_set[i]);

    for (i = 0; i < ARRAY_SIZE(jprobe_set); i++)
        unregister_jprobe(jprobe_set[i]);

    pr_info("kst module is unloaded\n");
}

module_init(kst_mod_init)
module_exit(kst_mod_exit)
MODULE_LICENSE("GPL");

