/*
    Minimal include files for BPF programs.
    See: https://nakryiko.com/posts/libbpf-bootstrap/#includes-vmlinux-h-libbpf-and-app-headers

*/

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>






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

struct task_struct *GetCurrentTask() {
    return (struct task_struct *)bpf_get_current_task();
}

//SEC("kprobe/sys_open") 
SEC("prog")
int kprobe__sys_open(struct pt_regs *ctx) {
    struct task_struct *task = GetCurrentTask();
    int pid = ReadPid(task);

    bpf_printk("pid: %d and size of task_struct is %d bytes.\n", pid, bpf_core_type_size(struct task_struct));
    return 0;
}  


char _license[] SEC("license") = "GPL";