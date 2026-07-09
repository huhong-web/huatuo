#ifndef __BPF_TCP_REORDER_H__
#define __BPF_TCP_REORDER_H__

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

struct reorder_metrics {
	u32 reord_seen;
	u32 dsack_dups;
};

static __always_inline void read_reorder_metrics(struct sock *sk,
						  struct reorder_metrics *m)
{
	if (!sk || !m)
		return;

	struct tcp_sock *tp = (struct tcp_sock *)sk;

	if (bpf_core_field_exists(((struct tcp_sock *)0)->reord_seen))
		m->reord_seen = BPF_CORE_READ(tp, reord_seen);

	if (bpf_core_field_exists(((struct tcp_sock *)0)->dsack_dups))
		m->dsack_dups = BPF_CORE_READ(tp, dsack_dups);
}

#endif
