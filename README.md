Learning BPF extensible scheduler class (a.k.a sched-ext)
---

<[The extensible scheduler class](https://lwn.net/Articles/922405/)>
The core idea behind BPF is that it allows programs to be loaded into the kernel from user space at runtime; using BPF for scheduling has the potential to enable significantly different scheduling behavior than is seen in Linux systems now. The ability to write scheduling policies in BPF will greatly lowers the difficulty of experimenting with new approaches to scheduling.

`sched-ext` allows that experimentation in a safe manner without even needing to reboot the test machine. BPF-written schedulers can also improve performance for niche workloads that may not be worth supporting in the mainline kernel and are much easier to deploy to a large fleet of systems.

[In the patch series](https://lore.kernel.org/all/20221130082313.3241517-1-tj@kernel.org/T/#u), a new policy constant `SCHED_EXT` is added and a task can select `sched_ext` by invoking `sched_setscheduler()`. In case of the BPF scheduler is not loaded, `SCHED_EXT` is the same as `SCHED_NORMAL` and the task is scheduled by CFS. When the BPF scheduler is loaded, all tasks which have the `SCHED_EXT` policy are switched to `sched_ext`.

`scx_bpf_switch_all()`, a new kfunc call added in the patch, that BPF scheduler can call from `ops.init()` to switch all `SCHED_NORMAL`, `SCHED_BATCH` and `SCHED_IDLE` tasks into `sched_ext`. This has the benefit that the scheduler swaps are "transpant" to the users and applications. CFS is not being used when `scx_bpf_switch_all()` is used.

### Basics
Userspace can implement an arbitrary BPF scheduler by loading a set of BPF programs that implement `struct sched_ext_ops`. The only mandatory field is `ops.name` which must be a valid BPF object name. All operations are optional. The following example is showing a minimal global FIFO scheduler.
`
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

### Dispatch Queues
To bridge the workflow imbalance between the scheduler core and `sched_ext_ops` callbacks, `sched_ext` uses simple FIFOs called **"dispatch queues(DSQ's)"**. By default, there is one global dsq (`SCX_DSQ_GLOBAL`) and one local per-CPU dsq (`SCX_DSQ_LOCAL`). `SCX_DSQ_GLOBAL` is provided for convenience and need not be used by a scheduler that doesn't require it. `SCX_DSQ_LOCAL` is the per-CPU FIFO that `sched_ext` fetches a task from the corresponding scheduling queue and assigns the CPU to it. The BPF scheduler can manage an arbitrary number of dsq's using `scx_bpf_create_dsq()` and `scx_bpf_destroy_dsq()`.

A CPU always executes a task from its local DSQ.  A task is __"dispatched"__ to a DSQ. A non-local DSQ is __"comsumed"__  to transfer a task to the consuming CPU's local DSQ.

When a CPU is looking for the next task to run, if the local DSQ is not empty, the first task is picked. Otherwise, the CPU tries to consume the global DSQ. If that doesn't yield a runnable task either, `ops.dispatch()` is invoked.

A task is not tied to its `runqueue` while enqueued. This decouples CPU selection from queueing and allows sharing a scheduling queue across an arbitrary subset of CPUs.

### Scheduling Cycle

<[BPF_at_IETF116.pdf](https://github.com/IETF-Hackathon/ietf116-project-presentations/blob/main/BPF_at_IETF116.pdf)>
![sched_ext: Flow Chart](https://github.com/shun159/play-sched-ext/blob/main/sched-ext_BPF_Scheduling.png?raw=true)

1. When a task is waking up. `ops.select_cpu()` is the first operation invoked. this serves two purposes. First, CPU selection optimization hint. Second, waking up the selected CPU if idle.
2. Once the target CPU is selected, `ops.enqueue()` is invoked. It can make one of the following decisions:
	1. Immediately dispatch the task to either the global or local DSQ by calling `scx_bpf_dispatch()` with `SCX_DSQ_GLOBAL` or `SCX_DSQ_LOCAL`, respectively.
	2. Immediately dispatch the task to a custom DSQ by calling `scx_bpf_dispatch()` with a DSQ ID which is smaller than $2^{63}$.
	3. Queue the task on the BPF side.
3. When a CPU is ready to schedule, it first looks at its local DSQ. if empty, it then looks at the global DSQ. If there still isn't a task to run, `ops.dispatch()` is invoked.
	1. `scx_bpf_dispatch()` dispatches a task to a DSQ
	2. `scx_bpf_comsume()` transfers a task from the specified non-local DSQ to the dispatching DSQ.
4.  After `ops.dispatch()` returns, if there are tasks in the local DSQ, the CPU runs the first one.
	1. Try to consume the global DSQ. If successful, run the task
	2. If `ops.dispatch()` has dispatched any tasks, retry (3).
	3. If the previous task is an SCX task and still runnable, keep executing it
	4. idle

### Callback functions
`sched_ext` provides callbacks and helpers to common operations such as managing idle CPUs, schduling tasks on arbitrary CPUs, handling preemptions from other scheduling classes, and more.  Callback definitions for sched_ext and documents for each callbacks is located on `include/linux/sched/ext.h`.

```c
	/**
	 * select_cpu - Pick the target CPU for a task which is being woken up
	 * @p: task being woken up
	 * @prev_cpu: the cpu @p was on before sleeping
	 * @wake_flags: SCX_WAKE_*
	 *
	 * Decision made here isn't final. @p may be moved to any CPU while it
	 * is getting dispatched for execution later. However, as @p is not on
	 * the rq at this point, getting the eventual execution CPU right here
	 * saves a small bit of overhead down the line.
	 *
	 * If an idle CPU is returned, the CPU is kicked and will try to
	 * dispatch. While an explicit custom mechanism can be added,
	 * select_cpu() serves as the default way to wake up idle CPUs.
	 */
	s32 (*select_cpu)(struct task_struct *p, s32 prev_cpu, u64 wake_flags);

	/**
	 * enqueue - Enqueue a task on the BPF scheduler
	 * @p: task being enqueued
	 * @enq_flags: %SCX_ENQ_*
	 *
	 * @p is ready to run. Dispatch directly by calling scx_bpf_dispatch()
	 * or enqueue on the BPF scheduler. If not directly dispatched, the bpf
	 * scheduler owns @p and if it fails to dispatch @p, the task will
	 * stall.
	 */
	void (*enqueue)(struct task_struct *p, u64 enq_flags);

	/**
	 * dequeue - Remove a task from the BPF scheduler
	 * @p: task being dequeued
	 * @deq_flags: %SCX_DEQ_*
	 *
	 * Remove @p from the BPF scheduler. This is usually called to isolate
	 * the task while updating its scheduling properties (e.g. priority).
	 *
	 * The ext core keeps track of whether the BPF side owns a given task or
	 * not and can gracefully ignore spurious dispatches from BPF side,
	 * which makes it safe to not implement this method. However, depending
	 * on the scheduling logic, this can lead to confusing behaviors - e.g.
	 * scheduling position not being updated across a priority change.
	 */
	void (*dequeue)(struct task_struct *p, u64 deq_flags);

	/**
	 * dispatch - Dispatch tasks from the BPF scheduler and/or consume DSQs
	 * @cpu: CPU to dispatch tasks for
	 * @prev: previous task being switched out
	 *
	 * Called when a CPU's local dsq is empty. The operation should dispatch
	 * one or more tasks from the BPF scheduler into the DSQs using
	 * scx_bpf_dispatch() and/or consume user DSQs into the local DSQ using
	 * scx_bpf_consume().
	 *
	 * The maximum number of times scx_bpf_dispatch() can be called without
	 * an intervening scx_bpf_consume() is specified by
	 * ops.dispatch_max_batch. See the comments on top of the two functions
	 * for more details.
	 *
	 * When not %NULL, @prev is an SCX task with its slice depleted. If
	 * @prev is still runnable as indicated by set %SCX_TASK_QUEUED in
	 * @prev->scx.flags, it is not enqueued yet and will be enqueued after
	 * ops.dispatch() returns. To keep executing @prev, return without
	 * dispatching or consuming any tasks. Also see %SCX_OPS_ENQ_LAST.
	 */
	void (*dispatch)(s32 cpu, struct task_struct *prev);

	/**
	 * runnable - A task is becoming runnable on its associated CPU
	 * @p: task becoming runnable
	 * @enq_flags: %SCX_ENQ_*
	 *
	 * This and the following three functions can be used to track a task's
	 * execution state transitions. A task becomes ->runnable() on a CPU,
	 * and then goes through one or more ->running() and ->stopping() pairs
	 * as it runs on the CPU, and eventually becomes ->quiescent() when it's
	 * done running on the CPU.
	 *
	 * @p is becoming runnable on the CPU because it's
	 *
	 * - waking up (%SCX_ENQ_WAKEUP)
	 * - being moved from another CPU
	 * - being restored after temporarily taken off the queue for an
	 *   attribute change.
	 *
	 * This and ->enqueue() are related but not coupled. This operation
	 * notifies @p's state transition and may not be followed by ->enqueue()
	 * e.g. when @p is being dispatched to a remote CPU. Likewise, a task
	 * may be ->enqueue()'d without being preceded by this operation e.g.
	 * after exhausting its slice.
	 */
	void (*runnable)(struct task_struct *p, u64 enq_flags);

	/**
	 * running - A task is starting to run on its associated CPU
	 * @p: task starting to run
	 *
	 * See ->runnable() for explanation on the task state notifiers.
	 */
	void (*running)(struct task_struct *p);

	/**
	 * stopping - A task is stopping execution
	 * @p: task stopping to run
	 * @runnable: is task @p still runnable?
	 *
	 * See ->runnable() for explanation on the task state notifiers. If
	 * !@runnable, ->quiescent() will be invoked after this operation
	 * returns.
	 */
	void (*stopping)(struct task_struct *p, bool runnable);

	/**
	 * quiescent - A task is becoming not runnable on its associated CPU
	 * @p: task becoming not runnable
	 * @deq_flags: %SCX_DEQ_*
	 *
	 * See ->runnable() for explanation on the task state notifiers.
	 *
	 * @p is becoming quiescent on the CPU because it's
	 *
	 * - sleeping (%SCX_DEQ_SLEEP)
	 * - being moved to another CPU
	 * - being temporarily taken off the queue for an attribute change
	 *   (%SCX_DEQ_SAVE)
	 *
	 * This and ->dequeue() are related but not coupled. This operation
	 * notifies @p's state transition and may not be preceded by ->dequeue()
	 * e.g. when @p is being dispatched to a remote CPU.
	 */
	void (*quiescent)(struct task_struct *p, u64 deq_flags);

	/**
	 * yield - Yield CPU
	 * @from: yielding task
	 * @to: optional yield target task
	 *
	 * If @to is NULL, @from is yielding the CPU to other runnable tasks.
	 * The BPF scheduler should ensure that other available tasks are
	 * dispatched before the yielding task. Return value is ignored in this
	 * case.
	 *
	 * If @to is not-NULL, @from wants to yield the CPU to @to. If the bpf
	 * scheduler can implement the request, return %true; otherwise, %false.
	 */
	bool (*yield)(struct task_struct *from, struct task_struct *to);

	/**
	 * core_sched_before - Task ordering for core-sched
	 * @a: task A
	 * @b: task B
	 *
	 * Used by core-sched to determine the ordering between two tasks. See
	 * Documentation/admin-guide/hw-vuln/core-scheduling.rst for details on
	 * core-sched.
	 *
	 * Both @a and @b are runnable and may or may not currently be queued on
	 * the BPF scheduler. Should return %true if @a should run before @b.
	 * %false if there's no required ordering or @b should run before @a.
	 *
	 * If not specified, the default is ordering them according to when they
	 * became runnable.
	 */
	bool (*core_sched_before)(struct task_struct *a,struct task_struct *b);

	/**
	 * set_weight - Set task weight
	 * @p: task to set weight for
	 * @weight: new eight [1..10000]
	 *
	 * Update @p's weight to @weight.
	 */
	void (*set_weight)(struct task_struct *p, u32 weight);

	/**
	 * set_cpumask - Set CPU affinity
	 * @p: task to set CPU affinity for
	 * @cpumask: cpumask of cpus that @p can run on
	 *
	 * Update @p's CPU affinity to @cpumask.
	 */
	void (*set_cpumask)(struct task_struct *p, struct cpumask *cpumask);

	/**
	 * update_idle - Update the idle state of a CPU
	 * @cpu: CPU to udpate the idle state for
	 * @idle: whether entering or exiting the idle state
	 *
	 * This operation is called when @rq's CPU goes or leaves the idle
	 * state. By default, implementing this operation disables the built-in
	 * idle CPU tracking and the following helpers become unavailable:
	 *
	 * - scx_bpf_select_cpu_dfl()
	 * - scx_bpf_test_and_clear_cpu_idle()
	 * - scx_bpf_pick_idle_cpu()
	 * - scx_bpf_any_idle_cpu()
	 *
	 * The user also must implement ops.select_cpu() as the default
	 * implementation relies on scx_bpf_select_cpu_dfl().
	 *
	 * If you keep the built-in idle tracking, specify the
	 * %SCX_OPS_KEEP_BUILTIN_IDLE flag.
	 */
	void (*update_idle)(s32 cpu, bool idle);

	/**
	 * cpu_acquire - A CPU is becoming available to the BPF scheduler
	 * @cpu: The CPU being acquired by the BPF scheduler.
	 * @args: Acquire arguments, see the struct definition.
	 *
	 * A CPU that was previously released from the BPF scheduler is now once
	 * again under its control.
	 */
	void (*cpu_acquire)(s32 cpu, struct scx_cpu_acquire_args *args);

	/**
	 * cpu_release - A CPU is taken away from the BPF scheduler
	 * @cpu: The CPU being released by the BPF scheduler.
	 * @args: Release arguments, see the struct definition.
	 *
	 * The specified CPU is no longer under the control of the BPF
	 * scheduler. This could be because it was preempted by a higher
	 * priority sched_class, though there may be other reasons as well. The
	 * caller should consult @args->reason to determine the cause.
	 */
	void (*cpu_release)(s32 cpu, struct scx_cpu_release_args *args);

	/**
	 * cpu_online - A CPU became online
	 * @cpu: CPU which just came up
	 *
	 * @cpu just came online. @cpu doesn't call ops.enqueue() or run tasks
	 * associated with other CPUs beforehand.
	 */
	void (*cpu_online)(s32 cpu);

	/**
	 * cpu_offline - A CPU is going offline
	 * @cpu: CPU which is going offline
	 *
	 * @cpu is going offline. @cpu doesn't call ops.enqueue() or run tasks
	 * associated with other CPUs afterwards.
	 */
	void (*cpu_offline)(s32 cpu);

	/**
	 * prep_enable - Prepare to enable BPF scheduling for a task
	 * @p: task to prepare BPF scheduling for
	 * @args: enable arguments, see the struct definition
	 *
	 * Either we're loading a BPF scheduler or a new task is being forked.
	 * Prepare BPF scheduling for @p. This operation may block and can be
	 * used for allocations.
	 *
	 * Return 0 for success, -errno for failure. An error return while
	 * loading will abort loading of the BPF scheduler. During a fork, will
	 * abort the specific fork.
	 */
	s32 (*prep_enable)(struct task_struct *p, struct scx_enable_args *args);

	/**
	 * enable - Enable BPF scheduling for a task
	 * @p: task to enable BPF scheduling for
	 * @args: enable arguments, see the struct definition
	 *
	 * Enable @p for BPF scheduling. @p is now in the cgroup specified for
	 * the preceding prep_enable() and will start running soon.
	 */
	void (*enable)(struct task_struct *p, struct scx_enable_args *args);

	/**
	 * cancel_enable - Cancel prep_enable()
	 * @p: task being canceled
	 * @args: enable arguments, see the struct definition
	 *
	 * @p was prep_enable()'d but failed before reaching enable(). Undo the
	 * preparation.
	 */
	void (*cancel_enable)(struct task_struct *p,
			      struct scx_enable_args *args);

	/**
	 * disable - Disable BPF scheduling for a task
	 * @p: task to disable BPF scheduling for
	 *
	 * @p is exiting, leaving SCX or the BPF scheduler is being unloaded.
	 * Disable BPF scheduling for @p.
	 */
	void (*disable)(struct task_struct *p);
	/*
	 * All online ops must come before ops.init().
	 */

	/**
	 * init - Initialize the BPF scheduler
	 */
	s32 (*init)(void);
	/**
	 * name - BPF scheduler's name
	 *
	 * Must be a non-zero valid BPF object name including only isalnum(),
	 * '_' and '.' chars. Shows up in kernel.sched_ext_ops sysctl while the
	 * BPF scheduler is enabled.
	 */
	char name[SCX_OPS_NAME_LEN];
```

### Writing a userspace application

`sched_ext` uses BPF [struct_ops](https://lwn.net/Articles/809092/) features to define a structure which exports function callback and flags to BPF program that wish to implement scheduling policies. The struct_ops structure exported by `sched_ext` is `struct sched_ext_ops`, and is conceptually similar to `struct sched_class`.  So, need to load an application as a `struct_ops`. Let's look at the example program:

```c
int main(int argc, char **argv)
{
	struct scx_example_simple *skel;
	struct bpf_link *link;
	u32 opt;

	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

	skel = scx_example_simple__open();
	assert(skel);

	while ((opt = getopt(argc, argv, "fph")) != -1) {
		switch (opt) {
		case 'f':
			skel->rodata->fifo_sched = true;
			break;
		case 'p':
			skel->rodata->switch_partial = true;
			break;
		default:
			fprintf(stderr, help_fmt, basename(argv[0]));
			return opt != 'h';
		}
	}

	assert(!scx_example_simple__load(skel));

	link = bpf_map__attach_struct_ops(skel->maps.simple_ops);
	assert(link);

	while (!exit_req && !uei_exited(&skel->bss->uei)) {
		u64 stats[2];

		read_stats(skel, stats);
		printf("local=%lu global=%lu\n", stats[0], stats[1]);
		fflush(stdout);
		sleep(1);
	}

	bpf_link__destroy(link);
	uei_print(&skel->bss->uei);
	scx_example_simple__destroy(skel);
	return 0;
}
```
## Getting Started

#### 1. checkout the sched_ext repo from github:
```
git clone https://github.com/sched-ext/sched_ext
```

#### 2. checkout and build the latest clang:
```shellsession
$ yay -S cmake ninja
$ mkdir ~/llvm
$ git clone https://github.com/llvm/llvm-project.git llvm-project
$ mkdir -p llvm-project/build; cd llvm-project/build
$ cmake -G Ninja \
    -DLLVM_TARGETS_TO_BUILD="BPF;X86" \
    -DCMAKE_INSTALL_PREFIX="/$HOME/llvm/$(date +%Y%m%d)" \
    -DBUILD_SHARED_LIBS=OFF \
    -DLIBCLANG_BUILD_STATIC=ON \
    -DCMAKE_BUILD_TYPE=Release \
    -DLLVM_ENABLE_TERMINFO=OFF \
    -DLLVM_ENABLE_PROJECTS="clang;lld" \
    ../llvm
$ ninja install -j$(nproc)
$ ln -sf /$HOME/llvm/$(date +%Y%m%d) /$HOME/llvm/latest
```
After build the clang, make sure the `$HOME/llvm/latest` in your `$PATH`

#### 3. Download and build the latest pahole:
```shellsession
$ cd /data/users/$USER  
$ git clone https://git.kernel.org/pub/scm/devel/pahole/pahole.git
$ mkdir -p pahole/build; cd pahole/build  
$ cmake -G Ninja ../  
$ ninja
```
After build the pahole, make sure pahole in your `$PATH`

#### 4. Build sched_ext kernel
config options we need to enable `sched_ext` feature:
```
CONFIG_DEBUG_INFO_BTF=y  
CONFIG_PAHOLE_HAS_SPLIT_BTF=y  
CONFIG_PAHOLE_HAS_BTF_TAG=y  
CONFIG_SCHED_CLASS_EXT=y  
CONFIG_BPF_SYSCALL=y  
CONFIG_BPF_JIT=y  
CONFIG_9P_FS=y  
CONFIG_NET_9P=y  
CONFIG_NET_9P_FD=y  
CONFIG_NET_9P_VIRTIO=y
```

Creates config. might have to set some config options above. You may use `make menuconfig`
```shellsession
$ make CC=clang LD=ld.lld LLVM=1 olddefconfig
$ make CC=clang LD=ld.lld LLVM=1 -j$(nproc)
```

## Play with userspace scheduler!
To be updated
