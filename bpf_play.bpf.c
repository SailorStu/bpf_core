/*
    Minimal include files for BPF programs.
    See: https://nakryiko.com/posts/libbpf-bootstrap/#includes-vmlinux-h-libbpf-and-app-headers

*/
//#define __x86_64__
//#define __TARGET_ARCH_x86


#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>




void ReadPid(struct task_struct *task, int *pid, int *ppid) {

    if (pid != NULL){
        BPF_CORE_READ_INTO(pid, task, pid);
    }
    // Get parent task's pid.
    if (ppid != NULL){
        BPF_CORE_READ_INTO(ppid, task, parent, pid);
    }
}



/*
   arg 0 = SI = filename
*/
#define PATHLEN 256

/*
kfunc:vmlinux:do_sys_open
    int dfd
    const char * filename
    int flags
    umode_t mode
    long int retval

*/
// regs get turned into ctx, which is arch-specific.
SEC("kprobe/kprobe__do_sys_open") 
int sys_open( const struct pt_regs *ctx) {
    struct task_struct *task = (void*)bpf_get_current_task();
    struct task_struct *parent_task;
    int err;
    int res;
    int pid, ppid;
    ReadPid(task, &pid, &ppid);

    // Get parameters of sys_open

    char name[PATHLEN];
    res = bpf_probe_read_user_str(name, sizeof(name), (void*)PT_REGS_PARM1(ctx));
    if (res <= 0) {
        /* handle error */
        bpf_printk("ERROR: bpf_probe_read failed(%d)  for name parm\n", res);
        return 0;
    }
    // Print passed file name and pid
    bpf_printk("Open %s from pid %d, parent pid %d\n", name, pid, ppid);
    return 0;
}  


char _license[] SEC("license") = "GPL";