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
```

### kfuncs

- `scx_bpf_switch_all()`: Switch all tasks into SCX
- `scx_bpf_create_dsq(u64 dsq_id, s32 node)`: Create a custom DSQ
	- Args:
		- dsq_id: DSQ id to create.
		- node: NUMA node allocate from.
	- Returns:
		- `s32`: return negative value if creation fails, otherwise 0.
- `scx_bpf_dispatch(struct task_struct *p, u64 dsq_id, u64 slice, u64 enqueue_flags)`: Dispatch a task into the FIFO queue of a DSQ 
	- Args:
		- p: task_struct to dispatch
		- dsq_id: DSQ to dispatch to
		- slice: duration p can run for in __nsecs__
		- enqueue_flags: `SCX_ENQ_*`
- `scx_bpf_dispatch_vtime(struct task_struct *p, u64 dsq_id, u64 slice,u64 vtime, u64 enq_flags)`:  Dispatch a task into the vtime priority queue of a DSQ
	- Args:
		- p: task_struct to dispatch
		- dsq_id: DSQ to dispatch to
		- slice: duration p can run for in __nsecs__
		- vtime: @p's ordering inside the vtime-sorted queue of the target DSQ
		- enq_flags: `SCX_ENQ_*`
- `scx_bpf_dispatch_nr_slots()`: Return the number of remaining dispatch slots
	- Returns:
		- `u32`: number of remaining dispatch slots.
- `scx_bpf_consume(u64 dsq_id)`:  Transfer a task from a DSQ to the current CPU's local DSQ
	- Args:
		- dsq_id: DSQ to consume
	- Returns:
		- `bool`: `true` the consuming is succeeded, otherwise `false`.
- `scx_bpf_reenqueue_local()`: Re-enqueue tasks on a local DSQ
	- Rerurns:
		- `u32` : number of re-enqueued tasks
- `scx_bpf_kick_cpu(s32 cpu, u64 flags)`: Trigger reschedule on a CPU
	- Args:
		- cpu: cpu to kick
		- flags: `SCX_KICK_*` flags
- `scx_bpf_dsq_nr_queued(u64 dsq_id)`:  Return the number of queued tasks
	- Args:
		- dsq_id: id of the DSQ
	- Returns:
		- `s32`: number of queued tasks
- `scx_bpf_test_and_clear_cpu_idle(s32 cpu)`: Test and clear @cpu's idle state
	- Args:
		- cpu: cpu to test and clear idle for
	- Returns:
		- `bool`:  `true` if cpu was idle and its idle state was successfully cleared. `false` otherwise.
- `scx_bpf_pick_idle_cpu(const struct cpumask *cpu_allowed)`: Pick and claim an idle cpu
	- Args:
		- cpu_allowed: Allowed cpu mask
	- Returns:
		- `s32`: the picked idle cpu number on success. `-EBUSY` if no matching cpu was found.
- `scx_bpf_get_idle_cpumask()`: Get a referenced kptr to the idle-tracking per-CPU cpumask.
	- Returns:
		- `const struct cpumask`: `NULL` if idle tracking is not enabled. 
- `scx_bpf_get_idle_smtmask()`: Get a referenced kptr to the idle-tracking, per-physical-core cpumask. Can be used to determine if an entire physical core is free.
- `scx_bpf_destroy_dsq(u64 dsq_id)`: Destroy a custom DSQ
	- Args:
		- dsq_id: DSQ to destroy
- `scx_bpf_task_running(const struct task_struct *p)`: Is task currently running?
	- Args:
		- p: task of interest
	- Returns:
		- `bool`: true if the task running.
- `scx_bpf_task_cpu(const struct task_struct *p)`: CPU a task is currently associated with
	- Args:
		- p: task of interest
	- Returns:
		- `s32`: CPU associated with the task.

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
CONFIG_DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT=y
CONFIG_DEBUG_INFO_BTF=y
CONFIG_PAHOLE_HAS_SPLIT_BTF=y
CONFIG_PAHOLE_HAS_BTF_TAG=y
CONFIG_SCHED_CLASS_EXT=y
CONFIG_SCHED_DEBUG=y
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_JIT=y
### 9P_FS is used by osandov-linux to mount the custom build directory from the hostmachine
CONFIG_9P_FS=y
CONFIG_NET_9P=y
CONFIG_NET_9P_FD=y
CONFIG_NET_9P_VIRTIO=y
```

Creates config. might have to set some config options above. You may use `make menuconfig`
```shellsession
$ make CC=clang-17 LD=ld.lld LLVM=1 menuconfig
$ make CC=clang-17 LD=ld.lld LLVM=1 olddefconfig
$ make CC=clang-17 LD=ld.lld LLVM=1 -j$(nproc)
```
#### 5. Build scx_samples
To build the userspace scheduler "Atropos," you need to use rustup nightly. Visit [link](https://rust-lang.github.io/rustup/concepts/channels.html#channels) to install the Rustup toolchain.

```shellsession
$ cd tools/sched_ext 
$ make CC=clang-17 LD=ld.lld LLVM=1 -j$(nproc)
```

#### 6. Setup a VM for the sched_ext kernel.
In this memo, I will use [osantov-linux](https://github.com/osandov/osandov-linux), the tool is very handy for running a custom build kernel. visit the repository for details.

```shellsession
$ vm.py create -c 4 -m 8192 -s 50G <vm name>
$ vm.py archinstall <vm name>
$ kconfig.py <path to osandov-linux>/configs/vmpy.fragment
$ vm.py run -k $PWD -- <vm name>
```

And then run them from the VM by executing the executable binaries on the tool/sched_ext:

```shellsession
/usr/lib/modules/<custom build kernel path>/build/tools/sched_ext/scx_example_simple
local=0 global=0
local=7 global=4
local=10 global=6
EXIT: BPF scheduler unregistered
```

## Play with userspace scheduler!
To be updated
