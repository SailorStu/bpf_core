/*
    Minimal include files for BPF programs.
    See: https://nakryiko.com/posts/libbpf-bootstrap/#includes-vmlinux-h-libbpf-and-app-headers

*/

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

/*


int ReadPid(struct task_struct *task) {
    int pid;
    struct task_struct *parent_task;
    int err;

    err = bpf_core_read(&parent_task, sizeof(void *), &task->parent);
    if (err) {
        bpf_printk("ERROR: bpf_core_read failed(%d)  for parent_task\n", err);
        return -1;
    }
    // pid = task->pid; the BCC way. Non portable across different kernel versions/kernels.
    // bpf_probe_read(&pid, sizeof(pid), &task->pid); the portable, non CO-RE way.
    // this is CO-RE + libpf way.
    if(!bpf_core_field_exists(task->pid)) {
        bpf_printk("ERROR: task->pid does not exist in the target kernel\n");
        return -1;
    }
    bpf_core_read(&pid, sizeof(pid), &task->pid);

    return pid;
}
*/


SEC("kprobe/sys_open") 

int kprobe__sys_open(struct pt_regs *ctx) {
    struct task_struct *task = (void*)bpf_get_current_task();
    struct task_struct *parent_task;
    int err;

    err = bpf_core_read(&parent_task, sizeof(void *), &task->parent);
    if (err) {
        bpf_printk("ERROR: bpf_core_read failed(%d)  for parent_task\n", err);
        return 0;
    }
    void *namePtr = (void*)PT_REGS_PARAM2(ctx);
    char name[255];

    err = bpf_probe_read(name, sizeof(name), namePtr);
    if (err) {
        /* handle error */
        bpf_printk("ERROR: bpf_probe_read failed(%d)  for name\n", err);
        return 0;
    }
    // Print passed file name and pid
    bpf_printk("Open %s from pid %d\n", name, task->pid);
    return 0;
}  


char _license[] SEC("license") = "GPL";