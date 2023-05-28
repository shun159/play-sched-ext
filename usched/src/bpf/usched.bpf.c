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

const volatile bool switch_all;

s32 BPF_STRUCT_OPS(usched_init)
{
        if (switch_all)
                scx_bpf_switch_all();
        return 0;
}

void BPF_STRUCT_OPS(usched_enqueue, struct task_struct *p, u64 enq_flags)
{
        if (enq_flags & SCX_ENQ_LOCAL)
                scx_bpf_dispatch(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, enq_flags);
        else
                scx_bpf_dispatch(p, SCX_DSQ_GLOBAL, SCX_SLICE_DFL, enq_flags);
}

SEC(".struct_ops")
struct sched_ext_ops usched_ops = {
        .enqueue                = (void *)usched_enqueue,
        .init                   = (void *)usched_init,
        .name                   = "usched",
};
