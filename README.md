Learning BPF extensible scheduler class (a.k.a sched-ext)
---

## Overview
The core idea behind BPF is that it allows programs to be loaded into the kernel from user space at runtime; using BPF for scheduling has the potential to enable significantly different scheduling behavior than is seen in Linux systems now. The ability to write scheduling policies in BPF will greatly lowers the difficulty of experimenting with new approaches to scheduling.

`sched-ext` allows that experimentation in a safe manner without even needing to reboot the test machine. BPF-written schedulers can also improve performance for niche workloads that may not be worth supporting in the mainline kernel and are much easier to deploy to a large fleet of systems.

[In the patch series](https://lore.kernel.org/all/20221130082313.3241517-1-tj@kernel.org/T/#u), a new policy constant `SCHED_EXT` is added and a task can select `sched_ext` by invoking `sched_setscheduler()`. In case of the BPF scheduler is not loaded, `SCHED_EXT` is the same as `SCHED_NORMAL` and the task is scheduled by CFS. When the BPF scheduler is loaded, all tasks which have the `SCHED_EXT` policy are switched to `sched_ext`.

`scx_bpf_switch_all()`, a new kfunc call added in the patch, that BPF scheduler can call from `ops.init()` to switch all `SCHED_NORMAL`, `SCHED_BATCH` and `SCHED_IDLE` tasks into `sched_ext`. This has the benefit that the scheduler swaps are "transpant" to the users and applications. CFS is not being used when `scx_bpf_switch_all()` is used.

#### Basics
Userspace can implement an arbitrary BPF scheduler by loading a set of BPF programs that implement `struct sched_ext_ops`. The only mandatory field is `ops.name` which must be a valid BPF object name. All operations are optional. The following example is showing a minimal global FIFO scheduler.

```C
/*scx_example_dummy.c*/
    s32 BPF_STRUCT_OPS(dummy_init)
    {
            if (switch_all)
                    scx_bpf_switch_all();
            return 0;
    }

    void BPF_STRUCT_OPS(dummy_enqueue, struct task_struct *p, u64 enq_flags)
    {
            if (enq_flags & SCX_ENQ_LOCAL)
                    scx_bpf_dispatch(p, SCX_DSQ_LOCAL, enq_flags);
            else
                    scx_bpf_dispatch(p, SCX_DSQ_GLOBAL, enq_flags);
    }

    void BPF_STRUCT_OPS(dummy_exit, struct scx_exit_info *ei)
    {
            exit_type = ei->type;
    }

    SEC(".struct_ops")
    struct sched_ext_ops dummy_ops = {
            .enqueue                = (void *)dummy_enqueue,
            .init                   = (void *)dummy_init,
            .exit                   = (void *)dummy_exit,
            .name                   = "dummy",
    };
```

#### Dispatch Queues
To bridge the workflow imbalance between the scheduler core and `sched_ext_ops` callbacks, `sched_ext` uses simple FIFOs called **dispatch queues(DSQ's)**. By default, there is one global dsq (`SCX_DSQ_GLOBAL`) and one local per-CPU dsq (`SCX_DSQ_LOCAL`). `SCX_DSQ_GLOBAL` is provided for convenience and need not be used by a scheduler that doesn't require it. `SCX_DSQ_LOCAL` is the per-CPU FIFO that `sched_ext` fetches a task from the corresponding scheduling queue and assigns the CPU to it. The BPF scheduler can manage an arbitrary number of dsq's using `scx_bpf_create_dsq()` and `scx_bpf_destroy_dsq()`.

A CPU always executes a task from its local DSQ.  A task is __dispatched__ to a DSQ. A non-local DSQ is __comsumed__  to transfer a task to the consuming CPU's local DSQ.

When a CPU is looking for the next task to run, if the local DSQ is not empty, the first task is picked. Otherwise, the CPU tries to consume the global DSQ. If that doesn't yield a runnable task either, `ops.dispatch()` is invoked.

A task is not tied to its `runqueue` while enqueued. This decouples CPU selection from queueing and allows sharing a scheduling queue across an arbitrary subset of CPUs.

## Getting started
To be updated

## Play with userspace scheduler!
To be updated
