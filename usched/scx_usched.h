// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.
//
#ifndef __USCHED_H
#define __USCHED_H

#define USERLAND_MAX_TASKS 16384

/*
 * An instance of a task that has been enqueued by the kernel for consumption
 * by a user space global scheduler thread.
 */
struct scx_userland_enqueued_task {
    __s32 pid;
    u64 sum_exec_runtime;
    u64 weight;
};

#include <stdbool.h>
#ifndef __kptr
#ifdef __KERNEL__
#error "__kptr_ref not defined in the kernel"
#endif
#define __kptr
#endif

#endif
