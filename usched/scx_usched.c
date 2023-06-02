/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023 Eishun Kondoh <dreamdiagnosis@gmail.com>
 */

#define _GNU_SOURCE
#include <argp.h>
#include <stdio.h>
#include <unistd.h>
#include <sched.h>
#include <signal.h>
#include <assert.h>
#include <bpf/bpf.h>
#include <sys/mman.h>
#include <sys/queue.h>
#include <sys/syscall.h>

#include "scx_usched.h"
#include "scx_usched.skel.h"

/* Defined in UAPI */
#define SCHED_EXT 7

/* Number of tasks to batch when dispatching to user space. */
static __u32 batch_size = 8;

static volatile int exit_req;

/* Stats collected in user space. */
static __u64 nr_vruntime_enqueues, nr_vruntime_dispatches;

/* The data structure containing tasks that are enqueued in user space. */
struct enqueued_task {
    LIST_ENTRY(enqueued_task) entries;
    __s32 pid;
    __u64 sum_exec_runtime;
    __u64 weight;
    double vruntime;
};

/*
 * Use a vruntime-sorted list to store tasks. This could easily be extended to
 * a more optimal data structure, such as an rbtree as is done in CFS. We
 * currently elect to use a sorted list to simplify the example for
 * illustrative purposes.
 */
LIST_HEAD(listhead, enqueued_task);

/*
 * A vruntime-sorted list of tasks. The head of the list contains the task with
 * the lowest vruntime. That is, the task that has the "highest" claim to be
 * scheduled.
 */
static struct listhead vruntime_head = LIST_HEAD_INITIALIZER(vruntime_head);

/*
 * The statically allocated array of tasks. We use a statically allocated list
 * here to avoid having to allocate on the enqueue path, which could cause a
 * deadlock. A more substantive user space scheduler could e.g. provide a hook
 * for newly enabled tasks that are passed to the scheduler from the
 * .prep_enable() callback to allows the scheduler to allocate on safe paths.
 */
struct enqueued_task tasks[USERLAND_MAX_TASKS];

static double min_vruntime;

const char help_fmt[] = "A minimal userspace sched_ext scheduler.\n"
                        "  --help            Display this help and exit\n";

static const struct argp_option opts[] = {
    { "verbose", 'v', NULL, 0, "Verbose debug output" },
    { "slice_us", 's', "SLICE_US", 0, "Scheduling slice duration in microseconds" },
    {},
};

static struct env {
    // Enable verbose output include libbpf details.
    bool verbose;
    // Scheduling slice duration in microseconds
    long slice_us;
} env;

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    switch (key) {
    case 'v':
        env.verbose = true;
        break;
    case 's':
        errno = 0;
        env.slice_us = strtol(arg, NULL, 10);
        if (errno || env.slice_us <= 0) {
            fprintf(stderr, "Invalid slice: %s\n", arg);
            argp_usage(state);
        }
        break;
    case ARGP_KEY_ARG:
        argp_usage(state);
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static const struct argp argp = {
    .options = opts,
    .parser = parse_arg,
    .doc = help_fmt,
};

static void sigint_handler(int simple)
{
    exit_req = 1;
}

static int switch_to_scx(pid_t pid)
{
    int err;

    struct sched_param param = { 0 };
    param.sched_priority = sched_get_priority_max(SCHED_EXT);
    /*
	 * Enforce that the user scheduler task is managed by sched_ext. The
	 * task eagerly drains the list of enqueued tasks in its main work
	 * loop, and then yields the CPU. The BPF scheduler only schedules the
	 * user space scheduler task when at least one other task in the system
	 * needs to be scheduled.
	 */
    err = syscall(__NR_sched_setscheduler, pid, SCHED_EXT, &param);
    if (err) {
        fprintf(stderr, "Failed to set scheduler to SCHED_EXT: %s\n", strerror(err));
        return err;
    }

    return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
                           va_list args)
{
    if (level == LIBBPF_DEBUG && !env.verbose)
        return 0;
    return vfprintf(stderr, format, args);
}

static struct enqueued_task *get_enqueued_task(__s32 pid)
{
    if (pid >= USERLAND_MAX_TASKS)
        return NULL;

    return &tasks[pid];
}

static double calc_vruntime_delta(__u64 weight, __u64 delta)
{
    double weight_f = (double)weight / 100.0;
    double delta_f = (double)delta;

    return delta_f / weight_f;
}

static void update_enqueued(struct enqueued_task *enqueued,
                            const struct scx_userland_enqueued_task *bpf_task)
{
    __u64 delta;

    delta = bpf_task->sum_exec_runtime - enqueued->sum_exec_runtime;

    enqueued->vruntime += calc_vruntime_delta(bpf_task->weight, delta);
    if (min_vruntime > enqueued->vruntime)
        enqueued->vruntime = min_vruntime;

    enqueued->pid = bpf_task->pid;
    enqueued->sum_exec_runtime = bpf_task->sum_exec_runtime;
    enqueued->weight = bpf_task->weight;
}

static int vruntime_enqueue(const struct scx_userland_enqueued_task *bpf_task)
{
    struct enqueued_task *curr, *enqueued, *prev;

    curr = get_enqueued_task(bpf_task->pid);
    if (!curr)
        return ENOENT;

    update_enqueued(curr, bpf_task);
    nr_vruntime_enqueues++;

    /*
	 * Enqueue the task in a vruntime-sorted list. A more optimal data
	 * structure such as an rbtree could easily be used as well. We elect
	 * to use a list here simply because it's less code, and thus the
	 * example is less convoluted and better serves to illustrate what a
	 * user space scheduler could look like.
	 */

    if (LIST_EMPTY(&vruntime_head)) {
        LIST_INSERT_HEAD(&vruntime_head, curr, entries);
        return 0;
    }

    LIST_FOREACH(enqueued, &vruntime_head, entries)
    {
        if (curr->vruntime <= enqueued->vruntime) {
            LIST_INSERT_BEFORE(enqueued, curr, entries);
            return 0;
        }
        prev = enqueued;
    }

    LIST_INSERT_AFTER(prev, curr, entries);

    return 0;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    struct scx_userland_enqueued_task *task;
    int err;

    task = (struct scx_userland_enqueued_task *)data;
    err = vruntime_enqueue(task);
    if (err) {
        fprintf(stderr, "Failed to enqueue task %d: %s", task->pid, strerror(err));
        exit_req = 1;
        return 1;
    }

    return 0;
}

static int dispatch_task(struct enqueued_task *task, struct user_ring_buffer *urb)
{
    struct scx_userland_enqueued_task *bpf_task;

    bpf_task = user_ring_buffer__reserve(urb, sizeof(*bpf_task));
    if (!bpf_task) {
        fprintf(stderr, "Failed to dispatch task %d\n", task->pid);
        exit_req = 1;
    }

    bpf_task->pid = task->pid;
    bpf_task->sum_exec_runtime = task->sum_exec_runtime;
    bpf_task->weight = task->weight;
    user_ring_buffer__submit(urb, bpf_task);
    nr_vruntime_dispatches++;

    return 0;
}

static void dispatch_batch(struct user_ring_buffer *urb)
{
    __u32 i;

    for (i = 0; i < batch_size; i++) {
        struct enqueued_task *task;
        int err;

        task = LIST_FIRST(&vruntime_head);
        if (!task)
            return;

        min_vruntime = task->vruntime;
        LIST_REMOVE(task, entries);
        err = dispatch_task(task, urb);
        if (err) {
            fprintf(stderr, "Failed to dispatch task %d in %u\n", task->pid, i);
            return;
        }
    }
}

static void enter_loop(struct ring_buffer *rb, struct user_ring_buffer *urb)
{
    int err;

    while (!exit_req) {
        err = ring_buffer__poll(rb, 100 /* timeout, ms */);
        /* Ctrl-C will cause -EINTR */
        if (err == -EINTR) {
            printf("Error polling perf buffer: %d\n", err);
            err = 0;
            break;
        }
        if (err < 0) {
            printf("Error polling perf buffer: %d\n", err);
            break;
        }
        dispatch_batch(urb);
        sched_yield();
    }
}

int main(int argc, char **argv)
{
    struct scx_usched *skel;
    struct bpf_link *link;

    struct ring_buffer *krb = NULL;
    struct user_ring_buffer *urb = NULL;
    int err;

    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err)
        return err;

    /* Set up libbpf errors and debug info callback */
    libbpf_set_print(libbpf_print_fn);

    signal(SIGINT, sigint_handler);
    signal(SIGTERM, sigint_handler);

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    skel = scx_usched__open();
    assert(skel);

    skel->rodata->num_possible_cpus = libbpf_num_possible_cpus();
    assert(skel->rodata->num_possible_cpus > 0);
    skel->rodata->usersched_pid = getpid();
    assert(skel->rodata->usersched_pid > 0);
    skel->rodata->slice_ns = env.slice_us * 1000;
    assert(skel->rodata->slice_ns > 0);

    assert(!scx_usched__load(skel));

    /*
	 * It's not always safe to allocate in a user space scheduler, as an
	 * enqueued task could hold a lock that we require in order to be able
	 * to allocate.
	 */
    err = mlockall(MCL_CURRENT | MCL_FUTURE);
    if (err) {
        fprintf(stderr, "Failed to prefault and lock address space: %s\n", strerror(err));
        return err;
    }

    err = switch_to_scx(getpid()); //(int32_t)getpid());
    if (err) {
        fprintf(stderr, "Failed to set scheduler to SCHED_EXT: %s\n", strerror(err));
    }

    link = bpf_map__attach_struct_ops(skel->maps.usched_ops);
    assert(link);

    /* Set up ring buffer polling */
    urb = user_ring_buffer__new(bpf_map__fd(skel->maps.urb), NULL);
    if (!urb) {
        err = -1;
        fprintf(stderr, "Failed to create user ring buffer\n");
        goto cleanup;
    }

    /* Set up ring buffer polling */
    krb = ring_buffer__new(bpf_map__fd(skel->maps.krb), handle_event, urb, NULL);
    if (!krb) {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    enter_loop(krb, urb);

cleanup:
    exit_req = 1;
    bpf_link__destroy(link);
    scx_usched__destroy(skel);

    return 0;
}
