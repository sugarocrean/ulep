
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/irq.h>
#include <linux/proc_fs.h>
#include <net/net_namespace.h>
#include <linux/ktime.h>
#include <linux/time.h>

static raw_spinlock_t kst_lock;

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
    raw_spin_lock_init(&kst_lock);

    return 0;
}


static inline struct kst_meter *kst_meter_lookup(pid_t pid)
{
    int i;
    unsigned long flags;
    struct kst_meter *meter = NULL;

    raw_spin_lock_irqsave(&kst_lock, flags);
    for (i = 0; i < KST_ENTRY_NUM; i++) {
        if (kst_meters[i].valid && kst_meters[i].pid == pid) {
            meter = &kst_meters[i];
            break;
        }
    }
    raw_spin_unlock_irqrestore(&kst_lock, flags);

    return meter;
}

static inline struct kst_meter *kst_meter_create(pid_t pid)
{
    int i;
    unsigned long flags;
    struct kst_meter *meter = NULL;

    raw_spin_lock_irqsave(&kst_lock, flags);
    for (i = 0; i < KST_ENTRY_NUM; i++) {
        if (!kst_meters[i].valid) {
            memset(&kst_meters[i], 0, sizeof(kst_meters[i]));
            kst_meters[i].valid = 1;
            kst_meters[i].pid = pid;
            meter = &kst_meters[i];
            break;
        }
    }
    raw_spin_unlock_irqrestore(&kst_lock, flags);

    return meter;
}


static inline int kst_meter_remove(pid_t pid)
{
    int i;
    unsigned long flags;
    int ret = -1;

    raw_spin_lock_irqsave(&kst_lock, flags);
    for (i = 0; i < KST_ENTRY_NUM; i++) {
        if (kst_meters[i].valid && kst_meters[i].pid == pid) {
            memset(&kst_meters[i], 0, sizeof(kst_meters[i]));
            ret = 0;
            break;
        }
    }
    raw_spin_unlock_irqrestore(&kst_lock, flags);

    return 0;
}



__visible unsigned int __irq_entry jsmp_apic_timer_interrupt(struct pt_regs *regs)
{
    if (!strcmp(current->comm, "loop4")) {
        if (user_mode(regs)) {
            struct kst_meter *kst = kst_meter_lookup(current->pid);
            if (kst == NULL) {
                kst = kst_meter_create(current->pid);
            }

            if (kst) {
                kst->u2k_time = ktime_get();
                printk(KERN_INFO "%s: from user mode, now is %lu\n", __FUNCTION__, ktime_to_us(kst->u2k_time));
            }
        } else {
            dump_stack();
        }
    }

    /* Always end with a call to jprobe_return(). */
    jprobe_return();
    return 0;
}

static void kp_smp_apic_timer_interrupt_post(struct kprobe *p, struct pt_regs *regs,
                                unsigned long flags)
{
    if (!strcmp(current->comm, "loop4")) {
        struct kst_meter *kst = kst_meter_lookup(current->pid);
        if (kst) {
            ktime_t now = ktime_get();
            ktime_t delta = ktime_sub(now, kst->u2k_time);
            if (ktime_compare(delta, kst->max_time) > 0)
                kst->max_time = delta;
            printk(KERN_INFO "%s: pid is %d, now is %lu, diff is %lu, max is %lu\n", __FUNCTION__,
                             current->pid, ktime_to_us(delta), ktime_to_us(kst->max_time), ktime_to_us(kst->max_time));
        }
    }
}

static struct jprobe jprobe_smp_apic_timer_interrupt = {
    .entry = jsmp_apic_timer_interrupt,
    .kp = {
        .symbol_name = "smp_apic_timer_interrupt",
    },
};

static struct kprobe kp_smp_apic_timer_interrupt = {
    .post_handler = kp_smp_apic_timer_interrupt_post,
    .symbol_name = "smp_apic_timer_interrupt",
};


__visible unsigned int __irq_entry jdo_IRQ(struct pt_regs *regs)
{
    if (!strcmp(current->comm, "loop4")) {
        if (user_mode(regs)) {
            struct kst_meter *kst = kst_meter_lookup(current->pid);
            if (kst == NULL)
                kst = kst_meter_create(current->pid);

            if (kst) {
                kst->u2k_time = ktime_get();
                printk(KERN_INFO "%s: from user mode, now is %lu\n", __FUNCTION__, ktime_to_us(kst->u2k_time));
            }
        } else {
            dump_stack();
        }
    }

    /* Always end with a call to jprobe_return(). */
    jprobe_return();
    return 0;
}

static struct jprobe jprobe_do_IRQ = {
    .entry = jdo_IRQ,
    .kp = { .symbol_name = "do_IRQ", },
};

static void kp_do_IRQ_post(struct kprobe *p, struct pt_regs *regs,
                                unsigned long flags)
{
    if (!strcmp(current->comm, "loop4")) {
        struct kst_meter *kst = kst_meter_lookup(current->pid);
        if (kst) {
            ktime_t now = ktime_get();
            ktime_t delta = ktime_sub(now, kst->u2k_time);
            if (ktime_compare(delta, kst->max_time) > 0)
                kst->max_time = delta;
            printk(KERN_INFO "%s: pid is %d, now is %lu, diff is %lu, max is %lu\n", __FUNCTION__,
                             current->pid, ktime_to_us(now), ktime_to_us(delta), ktime_to_us(kst->max_time));
        }
    }
}

static struct kprobe kp_do_IRQ = {
    .post_handler = kp_do_IRQ_post,
    .symbol_name = "do_IRQ",
};



void __noreturn jdo_exit(long code)
{
    if (!strcmp(current->comm, "loop4")) {
        if (!kst_meter_remove(current->pid))
            printk(KERN_INFO "%s: remove pid %d's record successfully\n", __FUNCTION__, current->pid);
        else
            printk(KERN_INFO "%s: remove pid %d's record failed\n", __FUNCTION__, current->pid);
    }

    /* Always end with a call to jprobe_return(). */
    jprobe_return();
    //return 0;
}

static struct jprobe jprobe_do_exit = {
    .entry = jdo_exit,
    .kp = { .symbol_name = "do_exit", },
};


static int kst_proc_show(struct seq_file *m, void *v)
{
    int i;
    unsigned long flags;

    raw_spin_lock_irqsave(&kst_lock, flags);
    for (i = 0; i < KST_ENTRY_NUM; i++) {
        struct kst_meter *meter = &kst_meters[i];
        if (meter->valid) {
            seq_printf(m, "pid=%d,max_latency=%luns\n",
                          meter->pid, ktime_to_us(meter->max_time));
        }
    }
    raw_spin_unlock_irqrestore(&kst_lock, flags);
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


static int __init jprobe_init(void)
{
    int ret;

    BUILD_BUG_ON(__same_type(do_exit, jdo_exit) == 0);
    BUILD_BUG_ON(__same_type(do_IRQ, jdo_IRQ) == 0);
//  BUILD_BUG_ON(__same_type(smp_apic_timer_interrupt, 
//                          jsmp_apic_timer_interrupt) == 0);

    ret = kst_meter_init();
    if (ret < 0) {
        printk(KERN_INFO "kst_meter_init() failed, returned %d\n", ret);
        return -1;
    }

    ret = register_jprobe(&jprobe_do_exit);
    if (ret < 0) {
        printk(KERN_INFO "register_jprobe failed, returned %d\n", ret);
        return -1;
    }

    ret = register_jprobe(&jprobe_smp_apic_timer_interrupt);
    if (ret < 0) {
        printk(KERN_INFO "register_jprobe failed, returned %d\n", ret);
        return -1;
    }

    ret = register_jprobe(&jprobe_do_IRQ);
    if (ret < 0) {
        printk(KERN_INFO "register_jprobe failed, returned %d\n", ret);
        goto err3;
    }

    ret = register_kprobe(&kp_smp_apic_timer_interrupt);
    if (ret < 0) {
        pr_err("register_kprobe failed, returned %d\n", ret);
        goto err2;
    }

    ret = register_kprobe(&kp_do_IRQ);
    if (ret < 0) {
        pr_err("register_kprobe failed, returned %d\n", ret);
        goto err1;
    }

    proc_create("kst_info", 0, NULL, &kst_proc_fops);

    return 0;

err1:
    unregister_kprobe(&kp_smp_apic_timer_interrupt);
err2:
    unregister_jprobe(&jprobe_do_IRQ);
err3:
    unregister_jprobe(&jprobe_smp_apic_timer_interrupt);
    return ret;
}

static void __exit jprobe_exit(void)
{
    remove_proc_entry("kst_info", NULL);
    unregister_kprobe(&kp_smp_apic_timer_interrupt);
    unregister_kprobe(&kp_do_IRQ);
    unregister_jprobe(&jprobe_smp_apic_timer_interrupt);
    unregister_jprobe(&jprobe_do_IRQ);
    unregister_jprobe(&jprobe_do_exit);
}

module_init(jprobe_init)
module_exit(jprobe_exit)
MODULE_LICENSE("GPL");

