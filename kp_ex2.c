/* 
 * Simple kernel module that intercepts the sys_mkdir() system call.
 * Also shows how to obtain user ID and process ID correctly in kernel verison 3.13
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/time.h>
#include <linux/string.h>


typedef struct sys_call_node {
    struct list_head list;
    char symbol_name[10];
    kuid_t uid;
    int pid;
    int tgid;
    struct timespec start_time;
    struct timespec end_time;
    unsigned long ax;
    char di[128];
    unsigned long num_di;
    unsigned long si;
    unsigned long dx;
    unsigned long cx;
    unsigned long r8;
    unsigned long r9;
    
    //TODO: args
} sys_call_node;

struct list_head head;

/* For each probe you need to allocate a kprobe structure */
#define symname_size ((sizeof(symname))/(sizeof(char*)))
static const char *symname[] = {
	"sys_access",	
	"sys_brk",	
	"sys_chdir",	
	"sys_chmod",	
	"sys_clone",  
	"sys_close",	
	"sys_dup",	
	"sys_dup2",
	"sys_execve",	
	"sys_exit_group",	
	"sys_fcntl",	
	"sys_fork",
	"sys_getdents",	
	"sys_getpid",	
	"sys_gettid",	
	"sys_ioctl",	
	"sys_lseek",	
	"sys_mkdir",	
	"sys_mmap",	
	"sys_munmap",	
	"sys_open",	
	"sys_pipe",	
	"sys_read",
	"sys_rmdir",	
	"sys_select",	
	"sys_stat",	
	"sys_fstat",	
	"sys_lstat",	
	"sys_wait4",	
	"sys_write"
};

static struct kprobe kp[symname_size];

int UID = -1;
int TOGGLE = 0;

static void *sysmon_log_start(struct seq_file *m, loff_t *pos){
	void* lh=seq_list_start(&head,*pos);
	if (lh == NULL){
		INIT_LIST_HEAD(&head);
	} else {
		return lh;
	}
}

static void *sysmon_log_next(struct seq_file *m, void *v, loff_t *pos){
	return seq_list_next(v,&head,pos);
}

static int sysmon_log_show(struct seq_file *m, void *v) {
    sys_call_node *node=(sys_call_node *) v;

    switch(node->ax) {

        case __NR_fork:
        case __NR_getpid:
        case __NR_gettid:
            seq_printf(m, "symbol: %s, uid = %lu, pid = %d, start_time = %llu.%.9ld, tgid = %d, ax = %lu\n",
                node->symbol_name,
                node->uid,
                node->pid,
                (long long) node->start_time.tv_sec,
                node->start_time.tv_nsec,
                node->tgid,
                node->ax);
            break;

        //di as char
        case __NR_chdir:
        case __NR_rmdir:
            seq_printf(m, "symbol: %s, uid = %lu, pid = %d, start_time = %llu.%.9ld, tgid = %d, ax = %lu, di = %lu\n",
                node->symbol_name, node->uid, node->pid, (long long) node->start_time.tv_sec, node->start_time.tv_nsec,
                node->tgid, node->ax, node->di);
            break;

        //di and si
        case __NR_access:
        case __NR_chmod:
        case __NR_mkdir:
        case __NR_stat:
        case __NR_lstat:
            seq_printf(m, "symbol: %s, uid = %lu, pid = %d, start_time = %llu.%.9ld, tgid = %d, ax = %lu, di = %lu, si = %lu\n",
                node->symbol_name, node->uid, node->pid, (long long) node->start_time.tv_sec, node->start_time.tv_nsec,
                node->tgid, node->ax, node->di, node->si);
            break;

        //di si dx
        case __NR_open:
            seq_printf(m, "symbol: %s, uid = %lu, pid = %d, start_time = %llu.%.9ld, tgid = %d, ax = %lu, di = %lu, si = %lu, dx = %lu\n",
                node->symbol_name, node->uid, node->pid, (long long) node->start_time.tv_sec, node->start_time.tv_nsec,
                node->tgid, node->ax, node->di, node->si, node->dx);
            break;

        //OUT OF ORDER IS INTENTIONAL, swapping di and si
        case __NR_read:
        case __NR_write:
            seq_printf(m, "symbol: %s, uid = %lu, pid = %d, start_time = %llu.%.9ld, tgid = %d, ax = %lu, di = %lu, si = %lu, dx = %lu\n",
                node->symbol_name, node->uid, node->pid, (long long) node->start_time.tv_sec, node->start_time.tv_nsec,
                node->tgid, node->ax, node->si, node->di, node->dx);
            break;

        //num_di
        case __NR_brk:
        case __NR_close:
        case __NR_dup:
        case __NR_exit_group: //exit_group
        case __NR_pipe:
            //prints out si into di register because I don't want to change variable names
            // di is the first argument, and my structure has di has a char, first structure var that is a number is si
            seq_printf(m, "symbol: %s, uid = %lu, pid = %d, start_time = %llu.%.9ld, tgid = %d, ax = %lu, di = %lu\n",
                node->symbol_name, node->uid, node->pid, (long long) node->start_time.tv_sec, node->start_time.tv_nsec,
                node->tgid, node->ax, node->num_di);
            break;

        //num_di and si
        case __NR_dup2:
        case __NR_munmap:
        case __NR_fstat:
            seq_printf(m, "symbol: %s, uid = %lu, pid = %d, start_time = %llu.%.9ld, tgid = %d, ax = %lu, di = %lu, si = %lu\n",
                node->symbol_name, node->uid, node->pid, (long long) node->start_time.tv_sec, node->start_time.tv_nsec,
                node->tgid, node->ax, node->num_di, node->si);
            break;

        //num_di si dx
        case __NR_fcntl:
        case __NR_getdents:
        case __NR_ioctl:
        case __NR_lseek:
            seq_printf(m, "symbol: %s, uid = %lu, pid = %d, start_time = %llu.%.9ld, tgid = %d, ax = %lu, di = %lu, si = %lu, dx = %lu, cx = %lu\n", node->symbol_name, node->uid, node->pid,
                        (long long) node->start_time.tv_sec, node->start_time.tv_nsec, node->tgid, node->ax, node->num_di, node->si, node->dx, node->cx);
            break;

        case __NR_wait4:
            seq_printf(m, "symbol: %s, uid = %lu, pid = %d, start_time = %llu.%.9ld, tgid = %d, ax = %lu, di = %lu, si = %lu, dx = %lu, cx = %lu, r8 = %lu\n", node->symbol_name, node->uid, node->pid,
                        (long long) node->start_time.tv_sec, node->start_time.tv_nsec, node->tgid, node->ax, node->num_di, node->si, node->dx, node->cx, node->r8);
            break;
        //all 5
        case 59: //__NR_sys_execve
            seq_printf(m, "symbol: %s, uid = %lu, pid = %d, start_time = %llu.%.9ld, tgid = %d, ax = %lu, di = %lu, si = %lu, dx = %lu, cx = %lu, r8 = %lu, r9 = %lu\n", node->symbol_name, node->uid, node->pid,
                        (long long) node->start_time.tv_sec, node->start_time.tv_nsec, node->tgid, node->ax, node->di, node->si, node->dx, node->cx, node->r8, node->r9);
            break;
        //all 5 w/ num_di
        case __NR_clone:
        case __NR_mmap:
        case __NR_select:
            seq_printf(m, "symbol: %s, uid = %lu, pid = %d, start_time = %llu.%.9ld, tgid = %d, ax = %lu, di = %lu, si = %lu, dx = %lu, cx = %lu, r8 = %lu, r9 = %lu\n",
                node->symbol_name,
                node->uid,
                node->pid,
                (long long) node->start_time.tv_sec,
                node->start_time.tv_nsec,
                node->tgid,
                node->ax,
                node->num_di,
                node->si,
                node->dx,
                node->cx,
                node->r8,
                node->r9);
            break;
    }


    // seq_printf(m, "symbol: %s, uid = %lu, pid = %d, start_time = %llu.%.9ld, tgid = %d, ax = %lu, di = %lu, si = %lu, dx = %lu, r10 = %d, r8 = %lu, r9 = %d\n", node->symbol_name, node->uid, node->pid,
    //    (long long) node->start_time.tv_sec, node->start_time.tv_nsec, node->tgid, node->ax, node->di, node->si, node->dx, node->r10, node->r8, node->r9);
    return 0;
}

static void sysmon_log_stop(struct seq_file *m, void *v){
	seq_printf(m,"sysmon_log_stop\n");
}

static struct seq_operations sysmon_log_seqops = {
	.start=sysmon_log_start,
	.next=sysmon_log_next,
	.show=sysmon_log_show,
	.stop=sysmon_log_stop
};

static int sysmon_log_open(struct inode *inode, struct  file *file) {
    return seq_open(file, &sysmon_log_seqops);
}

static const struct file_operations sysmon_log_fops = {
    .owner =    THIS_MODULE,
    .open = sysmon_log_open,
    .read = seq_read
};


static int sysmon_uid_write(struct file *filp, const char *buff, size_t len, loff_t *off) {
    
    char *ptr;
    char temp[256];
    long temp_uid;

    if(copy_from_user(temp, buff, len)) {
        return -EFAULT;
    }
    // needs to be null terminated in order for it to work
    temp[len] = '\0';

    if (kstrtol(temp, 10, &temp_uid)) {
        return -EFAULT;
    }

    if (!(temp_uid > 0)) {
        return -EINVAL;
    }

    UID = (int)temp_uid;
    printk(KERN_INFO "sysmon_uid_write: %d\n", UID);

    return len;
}

static int sysmon_uid_show(struct seq_file *m, void *v) {
    seq_printf(m, "%d\n", UID);
    return 0;
}

static int sysmon_uid_open(struct inode *inode, struct  file *file) {
    return single_open(file, sysmon_uid_show, NULL);
}

static const struct file_operations sysmon_uid_fops = {
    .owner =    THIS_MODULE,
    .write = sysmon_uid_write,
    .open = sysmon_uid_open,
    .read = seq_read

};

static int sysmon_toggle_write(struct file *filp, const char *buff, size_t len, loff_t *off) {
    
    char *ptr;
    char temp[256];
    long temp_toggle;

    if(copy_from_user(temp, buff, len)) {
        return -EFAULT;
    }
    // needs to be null terminated in order for it to work
    temp[len] = '\0';

    if (kstrtol(temp, 10, &temp_toggle)) {
        return -EFAULT;
    }

    if (temp_toggle != 1 && temp_toggle != 0) {
        return -EINVAL;
    }

    TOGGLE = (int)temp_toggle;
    #ifdef DEBUG
        printk(KERN_INFO "sysmon_toggle_write: %d\n", TOGGLE);
    #endif

    return len;
}

static int sysmon_toggle_show(struct seq_file *m, void *v) {
    seq_printf(m, "%d\n", TOGGLE);
    return 0;
}

static int sysmon_toggle_open(struct inode *inode, struct  file *file) {
    return single_open(file, sysmon_toggle_show, NULL);
}

static const struct file_operations sysmon_toggle_fops = {
    .owner =    THIS_MODULE,
    .write = sysmon_toggle_write,
    .open = sysmon_toggle_open,
    .read = seq_read
};

/* kprobe pre_handler: called just before the probed instruction is executed */
static int sysmon_intercept_before(struct kprobe *p, struct pt_regs *regs)
{
    int ret = 0;
    kuid_t cuid;
    sys_call_node *new_node;

    //if run out of kernel memory, use these to "remove" the first node
    struct list_head *first;

    if (TOGGLE == 0) {
        #ifdef DEBUG
            printk(KERN_INFO "sysmon_intercept_before toggle is 0\n");
        #endif
        return 0;
    }

    cuid = current_uid();

    // if it is the user that we are looking at
    #ifdef DEBUG
        printk(KERN_INFO "sysmon_intercept_before %d %d\n", cuid.val, UID);
    #endif

    if (cuid.val == UID) {

        pid_t pid = task_pid_nr(current);
        
        #ifdef DEBUG
            printk(KERN_INFO "my sysmon_intercept_before: uid = %lu, pid = %lu, regs->ax = %lu, regs->di = %lu\n", 
                cuid, pid, regs->ax, regs->di);
            printk(KERN_INFO "__NR_mkdir: %lu\n", __NR_mkdir);
        #endif

        new_node = kmalloc(sizeof(sys_call_node), GFP_KERNEL);
        if (new_node == NULL) {
            if (head.next != NULL) {
                first = head.next;
                new_node = list_entry(first, sys_call_node, list);
                list_del(&new_node->list);
                new_node->end_time.tv_sec = 0;
                new_node->end_time.tv_nsec = 0;
            }
        }

        // printk("%s %d %d %d\n", regs->di, regs->si, regs->ax, __NR_mkdir);

        strcpy(new_node->symbol_name, p->symbol_name);
        new_node->uid = cuid;
        new_node->pid = pid;
        new_node->tgid = current->tgid;
        new_node->ax = regs->ax;

        switch(regs->ax) {

            case __NR_fork:
            case __NR_getpid:
            case __NR_gettid:
                break;
            //di only
            case __NR_chdir:
            case __NR_rmdir:
                copy_from_user(new_node->di, (char *)regs->di, sizeof(regs->di));
                new_node->di[sizeof(regs->di)] = '\0';
                break;

            //di and si
            case __NR_access:
            case __NR_mkdir:
            case __NR_chmod:
            case __NR_stat:
            case __NR_lstat:
                copy_from_user(new_node->di, (char *)regs->di, sizeof(regs->di));
                new_node->di[sizeof(regs->di)] = '\0';
                new_node->si = regs->si;
                break;

            //di si dx
            case __NR_open:
                copy_from_user(new_node->di, (char *)regs->di, sizeof(regs->di));
                new_node->di[sizeof(regs->di)] = '\0';
                new_node->si = regs->si;
                new_node->dx = regs->dx;
                break;

            //int char size_t
            // these arguments are WAY OUT OF ORDER HERE
            case __NR_read:
            case __NR_write:
                copy_from_user(new_node->di, (char *)regs->si, sizeof(regs->si));
                new_node->di[sizeof(regs->si)] = '\0';
                new_node->si = regs->di;
                new_node->dx = regs->dx;
                break;

            //num_di
            case __NR_brk:
            case __NR_close:
            case __NR_dup:
            case __NR_exit_group: //exit_group
            case __NR_pipe:
                new_node->num_di = regs->di;
                break;

            //num_di and si
            case __NR_dup2:
            case __NR_munmap:
            case __NR_fstat:
                new_node->num_di = regs->di;
                new_node->si = regs->si;
                break;

            //num_di si dx
            case __NR_fcntl:
            case __NR_getdents:
            case __NR_ioctl:
            case __NR_lseek:
                new_node->num_di = regs->di;
                new_node->si = regs->si;
                new_node->dx = regs->dx;
                break;

            case __NR_wait4:
                new_node->num_di = regs->di;
                new_node->si = regs->si;
                new_node->dx = regs->dx;
                new_node->cx = regs->cx;
                new_node->r8 = regs->r8;
                break;

            // di , si, dx, cx, r8, r9
            case 59: //__NR_sys_execve
                copy_from_user(new_node->di, (char *)regs->di, sizeof(regs->di));
                new_node->di[sizeof(regs->di)] = '\0';
                new_node->si = regs->si;
                new_node->dx = regs->dx;
                new_node->cx = regs->cx;
                new_node->r8 = regs->r8;
                new_node->r9 = regs->r9;
                break;

            // di as num, si, dx, cx, r8, r9
            case __NR_clone:
            case __NR_mmap:
            case __NR_select:
                new_node->num_di = regs->di;
                new_node->si = regs->si;
                new_node->dx = regs->dx;
                new_node->cx = regs->cx;
                new_node->r8 = regs->r8;
                new_node->r9 = regs->r9;
                break;
            default:
                printk("%d\n", regs->ax);

        }


        // new_node->ax = regs->ax; 
        // copy_from_user(new_node->di, regs->di, sizeof(regs->di));
        // new_node->di[sizeof(regs->di)] = '\0';
        // new_node->si = regs->si;
        
        // new_node->dx = regs->dx;
        // new_node->r10 = regs->r10;
        // new_node->r8 = regs->r8;
        // new_node->r9 = regs->r9;
        
        getnstimeofday(&new_node->start_time);
        list_add_tail(&new_node->list, &head);
    }

    return 0;
}

/* kprobe post_handler: called after the probed instruction is executed */
static void sysmon_intercept_after(struct kprobe *p, struct pt_regs *regs,
				unsigned long flags)
{
    #ifdef DEBUG
        printk(KERN_INFO "my sysmon_intercept_after\n");
    #endif

    // sys_call_node *node, *temp_node;
    // struct list_head *list_head_node;
    // pid_t pid = task_pid_nr(current);
    // kuid_t cuid = current_uid();
    
    // need to find another way to measure latency, this method is too slow
    /*list_for_each_entry_safe(node, temp_node, &head, list) {
        if (uid_eq(node->uid, cuid) &&
            node->pid == pid &&
            node->tgid == current->tgid &&
            node->ax == regs->ax &&
            node->di == regs->di &&
            node->si == regs->si &&
            strcmp(node->symbol_name, p->symbol_name) == 0) {
            getnstimeofday(&node->end_time);
            break;
        }
    }*/
}

/*
 * fault_handler: this is called if an exception is generated for any
 * instruction within the pre- or post-handler, or when Kprobes
 * single-steps the probed instruction.
 */
static int handler_fault(struct kprobe *p, struct pt_regs *regs, int trapnr)
{
    #ifdef DEBUG
	    printk(KERN_INFO "fault_handler: p->addr = 0x%p, trap #%dn",
		    p->addr, trapnr);
	#endif
    /* Return 0 because we don't handle the fault. */
	return 0;
}

static int __init kprobe_init(void)
{
    int ret;
    int i;

    proc_create("sysmon_log", 0400, NULL, &sysmon_log_fops);
    proc_create("sysmon_uid", 0600, NULL, &sysmon_uid_fops);
    proc_create("sysmon_toggle", 0600, NULL, &sysmon_toggle_fops);

    INIT_LIST_HEAD(&head);

    
	for (i = 0; i < symname_size; i++) {
		printk("%s\n", symname[i]);
		kp[i].symbol_name = symname[i];
		kp[i].pre_handler = sysmon_intercept_before;
		kp[i].post_handler = sysmon_intercept_after;
		ret = register_kprobe(&kp[i]);
		if (ret < 0){
			printk(KERN_INFO "register_kbrobe failed, returned %d\n", ret);
			return ret;
		}
		printk(KERN_INFO "Planted kprobe at %x\n", kp[i].addr);
	}
    return 0;
}

static void __exit kprobe_exit(void)
{
    remove_proc_entry("sysmon_log",NULL);
    remove_proc_entry("sysmon_uid",NULL);
    remove_proc_entry("sysmon_toggle",NULL);

    sys_call_node *node, *temp_node;
    struct list_head *list_head_node;
    list_for_each_entry_safe(node, temp_node, &head, list) {
        list_del(&node->list);
        kfree(node);
    }

	int i;
	for (i = 0; i < symname_size; i++) {
		unregister_kprobe(&kp[i]);
		printk(KERN_INFO "kprobe at %p unregistered\n", kp[i].addr);
	}
}

module_init(kprobe_init);
module_exit(kprobe_exit);
MODULE_LICENSE("GPL");