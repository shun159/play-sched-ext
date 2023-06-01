// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

#include "../../../scx_common.bpf.h"
#include "usched.h"

#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

const volatile bool switch_partial;
const volatile s32 usersched_pid;
const volatile u32 num_possible_cpus = 64;

/* base slice duration */
const volatile __u64 slice_ns = SCX_SLICE_DFL;

/*
 * Whether the user space scheduler needs to be scheduled due to a task being
 * enqueued in user space.
 */
static bool usersched_needed;

/* Per-task scheduling context */
struct task_ctx {
    bool force_local; /* Dispatch directly to local DSQ */
};

/*
 * An instance of a task that has been enqueued by the kernel for consumption
 * by a user space global scheduler thread.
 */
struct scx_userland_enqueued_task {
    __s32 pid;
    u64 sum_exec_runtime;
    u64 weight;
};

struct {
    __uint(type, BPF_MAP_TYPE_USER_RINGBUF);
    __uint(max_entries, 8192);
} uprod_ringbuffers SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 8192);
} kprod_ringbuffers SEC(".maps");

/* Map that contains task-local storage. */
struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, struct task_ctx);
} task_ctx_stor SEC(".maps");

static bool is_usersched_task(struct task_struct *p)
{
    return p->pid == usersched_pid;
}

static bool keep_in_kernel(struct task_struct *p)
{
    return p->nr_cpus_allowed < num_possible_cpus;
}

static struct task_struct *usersched_task(void)
{
    struct task_struct *p;

    p = bpf_task_from_pid(usersched_pid);
    if (!p)
        scx_bpf_error("Failed to find usersched task %d", usersched_pid);

    return p;
}

static void dispatch_task_in_kernel(struct task_struct *p, u64 enq_flags)
{
    u64 dsq_id = SCX_DSQ_GLOBAL;
    struct task_ctx *tctx;

    tctx = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
    if (!tctx) {
        scx_bpf_error("Failed to lookup task ctx for %s", p->comm);
        return;
    }

    if (tctx->force_local)
        dsq_id = SCX_DSQ_LOCAL;

    tctx->force_local = false;
    scx_bpf_dispatch(p, dsq_id, slice_ns, enq_flags);
}

static void dispatch_task_in_userspace(struct task_struct *p, u64 enq_flags)
{
    struct scx_userland_enqueued_task *task;
    task = bpf_ringbuf_reserve(&kprod_ringbuffers, sizeof(*task), 0);
    if (!task) {
        // if there is no memory left in the ringbuf,
        // put it directly on the local DSQ.
        scx_bpf_dispatch(p, SCX_DSQ_LOCAL, slice_ns, enq_flags);
        return;
    }

    task->pid = p->pid;
    task->sum_exec_runtime = p->se.sum_exec_runtime;
    task->weight = p->scx.weight;

    bpf_ringbuf_submit(task, 0);
    usersched_needed = true;
}

static void dispatch_user_sched(void)
{
    struct task_struct *p;

    usersched_needed = false;
    p = usersched_task();
    if (p) {
        scx_bpf_dispatch(p, SCX_DSQ_GLOBAL, SCX_SLICE_DFL, 0);
        bpf_task_release(p);
    }
}

static int dispatch_cpu_drain(struct bpf_dynptr *dynptr, void *context)
{
    struct scx_userland_enqueued_task *task = NULL;
    struct task_struct *p;

    task = bpf_dynptr_data(dynptr, 0, sizeof(*task));
    if (!task)
        return 1;

    s32 pid = task->pid;
    p = bpf_task_from_pid(pid);
    if (!p) {
        scx_bpf_error("Failed to find task for pid %d", pid);
        return 1;
    }

    /* First try to find an idle CPU. */
    s32 cpu = scx_bpf_pick_idle_cpu(p->cpus_ptr);
    if (cpu >= 0) {
        scx_bpf_kick_cpu(cpu, 0);
        scx_bpf_dispatch(p, SCX_DSQ_LOCAL_ON | cpu, slice_ns, 0);
    }

    bpf_task_release(p);

    return 0;
}

s32 BPF_STRUCT_OPS(usched_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
    if (keep_in_kernel(p)) {
        s32 cpu;
        struct task_ctx *tctx;

        tctx = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
        if (!tctx) {
            scx_bpf_error("Failed to look up task-local storage for %s", p->comm);
            return -ESRCH;
        }

        if (p->nr_cpus_allowed == 1 || scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
            tctx->force_local = true;
            return prev_cpu;
        }

        cpu = scx_bpf_pick_idle_cpu(p->cpus_ptr);
        if (cpu >= 0) {
            tctx->force_local = true;
            return cpu;
        }
    }

    return prev_cpu;
}

void BPF_STRUCT_OPS(usched_enqueue, struct task_struct *p, u64 enq_flags)
{
    if (keep_in_kernel(p)) {
        dispatch_task_in_kernel(p, enq_flags);
    } else {
        dispatch_task_in_userspace(p, enq_flags);
    }
}

void BPF_STRUCT_OPS(usched_dispatch, s32 cpu, struct task_struct *prev)
{
    int ret;

    if (usersched_needed)
        dispatch_user_sched();

    ret = bpf_user_ringbuf_drain(&uprod_ringbuffers, dispatch_cpu_drain, NULL, 0);
    if (ret < 0) {
        scx_bpf_error("user_rb drain failed (%d) for cpu[%d]", ret, cpu);
    }
}

s32 BPF_STRUCT_OPS(usched_prep_enable, struct task_struct *p,
                   struct scx_enable_args *args)
{
    if (bpf_task_storage_get(&task_ctx_stor, p, 0, BPF_LOCAL_STORAGE_GET_F_CREATE))
        return 0;
    else
        return -ENOMEM;
}

s32 BPF_STRUCT_OPS(usched_init)
{
    if (!switch_partial)
        scx_bpf_switch_all();
    return 0;
}

SEC(".struct_ops")
struct sched_ext_ops usched_ops = {
    .select_cpu = (void *)usched_select_cpu,
    .enqueue = (void *)usched_enqueue,
    .dispatch = (void *)usched_dispatch,
    .prep_enable = (void *)usched_prep_enable,
    .init = (void *)usched_init,
    .name = "usched",
};
