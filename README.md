Learning BPF extensible scheduler class (a.k.a sched-ext)
---

## Overview
<[The extensible scheduler class](https://lwn.net/Articles/922405/)>

The core idea behind BPF is that it allows programs to be loaded into the kernel from user space at runtime; using BPF for scheduling has the potential to enable significantly different scheduling behavior than is seen in Linux systems now. The ability to write scheduling policies in BPF will greatly lowers the difficulty of experimenting with new approaches to scheduling. 

`sched-ext` allows that experimentation in a safe manner without even needing to reboot the test machine. BPF-written schedulers can also improve performance for niche workloads that may not be worth supporting  in the mainline kernel and are much easier to deploy to a large fleet of systems.

[In the patch series](https://lore.kernel.org/all/20221130082313.3241517-1-tj@kernel.org/T/#u), a new policy constant `SCHED_EXT` is added and a task can select `sched_ext` by invoking `sched_setscheduler()`. In case of the BPF scheduler is not loaded, `SCHED_EXT` is the same as `SCHED_NORMAL` and the task is scheduled by CFS. When the BPF scheduler is loaded, all tasks which have the `SCHED_EXT` policy are switched to `sched_ext`.

`scx_bpf_switch_all()`, a new kfunc call added in the patch, that BPF scheduler can call from `ops.init()` to switch all `SCHED_NORMAL`, `SCHED_BATCH` and `SCHED_IDLE` tasks into `sched_ext`. This has the benefit that the scheduler swaps are "transpant" to the users and applications. CFS is not being used when `scx_bpf_switch_all()` is used.

## Getting started
To be updated

## Play with userspace scheduler!
To be updated
