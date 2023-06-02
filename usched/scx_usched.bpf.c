// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

#include "scx_common.bpf.h"
#include "scx_usched.h"

char _license[] SEC("license") = "GPL";

const volatile s32 usersched_pid;
const volatile u32 num_possible_cpus = 0;

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

struct {
    __uint(type, BPF_MAP_TYPE_USER_RINGBUF);
    __uint(max_entries, 8192);
} urb SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 8192);
} krb SEC(".maps");

/* Map that contains task-local storage. */
struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, struct task_ctx);
} task_ctx_stor SEC(".maps");

static bool keep_in_kernel(const struct task_struct *p)
{
    return p->nr_cpus_allowed < num_possible_cpus;
}

static bool is_usersched_task(struct task_struct *p)
{
    return p->pid == usersched_pid;
}

static struct task_struct *usersched_task(void)
{
    struct task_struct *p;

    p = bpf_task_from_pid(usersched_pid);
    if (!p)
        scx_bpf_error("Failed to find usersched task %d", usersched_pid);

    return p;
}

static void upcall_task(struct task_struct *p, u64 enq_flags)
{
    struct scx_userland_enqueued_task *task;
    task = bpf_ringbuf_reserve(&krb, sizeof(*task), 0);
    if (!task) {
        // if there is no memory left in the ringbuf,
        // put it directly on the local DSQ.
        scx_bpf_dispatch(p, SCX_DSQ_GLOBAL, slice_ns, enq_flags);
        return;
    }

    task->pid = p->pid;
    task->sum_exec_runtime = p->se.sum_exec_runtime;
    task->weight = p->scx.weight;

    bpf_ringbuf_submit(task, BPF_RB_FORCE_WAKEUP);
    usersched_needed = true;
}

static int dispatch_queued_task(struct bpf_dynptr *dynptr, void *context)
{
    struct scx_userland_enqueued_task *task = NULL;
    struct task_struct *p;

    task = bpf_dynptr_data(dynptr, 0, sizeof(*task));
    if (!task) {
        scx_bpf_error("Failed to read data from ptr");
        return 1;
    }

    s32 pid = task->pid;
    p = bpf_task_from_pid(pid);
    if (!p) {
        scx_bpf_error("Failed to find task for pid %d", pid);
        return 1;
    }

    scx_bpf_dispatch(p, SCX_DSQ_GLOBAL, slice_ns, 0);
    bpf_task_release(p);

    return 0;
}

static void dispatch_usersched(void)
{
    struct task_struct *p;

    usersched_needed = false;
    p = usersched_task();
    if (p) {
        scx_bpf_dispatch(p, SCX_DSQ_GLOBAL, SCX_SLICE_DFL, 0);
        bpf_task_release(p);
    }
}

s32 BPF_STRUCT_OPS(usched_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
    s32 cpu;
    struct task_ctx *tctx;

    if (keep_in_kernel(p)) {
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
    if (p->flags & PF_KTHREAD) {
        scx_bpf_dispatch(p, SCX_DSQ_GLOBAL, SCX_SLICE_DFL, 0);
        return;
    }

    if (keep_in_kernel(p)) {
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
        scx_bpf_dispatch(p, dsq_id, SCX_SLICE_DFL, enq_flags);
        return;
    }

    if (!is_usersched_task(p))
        upcall_task(p, enq_flags);
}

void BPF_STRUCT_OPS(usched_dispatch, s32 cpu, struct task_struct *prev)
{
    if (usersched_needed)
        dispatch_usersched();
    bpf_user_ringbuf_drain(&urb, dispatch_queued_task, NULL, 0);
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
