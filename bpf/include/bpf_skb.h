#ifndef __BPF_SKB_H__
#define __BPF_SKB_H__

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>

#include "vmlinux_net.h"

/* Read the TCP header at skb->transport_header into caller-owned storage. */
static __always_inline bool
skb_tcp_header(struct sk_buff *skb, struct tcphdr *tcp_hdr)
{
	if (!skb || !tcp_hdr)
		return false;

	return bpf_probe_read(tcp_hdr, sizeof(*tcp_hdr),
			      skb_transport_header(skb)) == 0;
}

#endif /* __BPF_SKB_H__ */
