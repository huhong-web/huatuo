// go:build ignore

#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "bpf_common.h"
#include "bpf_cgroup.h"
#include "bpf_net_namespace.h"
#include "bpf_pcap_stub.h"
#include "bpf_tcp_reorder.h"
#include "vmlinux_net.h"

#define RETRANS_EVENT_SKB    1
#define RETRANS_EVENT_SYNACK 2

#define TCP_NEW_SYN_RECV 12

#ifndef bpf_core_field_offset
#define compat_bpf_core_field_offset(field) \
	__builtin_preserve_field_info(field, BPF_FIELD_BYTE_OFFSET)
#else
#define compat_bpf_core_field_offset(field) bpf_core_field_offset(field)
#endif

struct retrans_event {
	u64 ktime_ns;
	u64 tgid_pid;
	u64 memcg_css_addr;
	u64 skb_addr;
	u64 net_cookie;
	u32 net_inum;
	u32 state;
	u16 sport;
	u16 dport;
	u16 family;
	u8  saddr[4];
	u8  daddr[4];
	u8  saddr_v6[16];
	u8  daddr_v6[16];
	u8  ca_state;
	u8  icsk_retransmits;
	u8  event_type;
	u8  _pad;
	u8 _go_pad[2];
	u8  icsk_pending;
	u8  _pad3[3];
	u32 reord_seen;
	u32 dsack_dups;
	u32 tcp_seq;
	u32 tcp_ack;
	u8  comm[COMPAT_TASK_COMM_LEN];
	u32 tcp_end_seq;
	u8  tcp_flags;
	u8  _tail_pad[3];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(u32));
} perf_events SEC(".maps");

char __license[] SEC("license") = "Dual MIT/GPL";

static __always_inline u8 read_ca_state(struct sock *sk)
{
	struct inet_connection_sock *icsk = (struct inet_connection_sock *)sk;

	if (!sk)
		return 0;

	if (!bpf_core_field_exists(icsk->icsk_ca_state))
		return 0;

	/* icsk_ca_state is a bitfield whose width changed across kernels
	 * (6 bits before 4.20, 5 bits after); let CO-RE relocate the shift
	 * and mask instead of hardcoding them. */
	u8 ca = BPF_CORE_READ_BITFIELD_PROBED(icsk, icsk_ca_state);

	if (ca > 4)
		return 0;
	return ca;
}

static __always_inline void fill_addrs_v4_from_sk(struct retrans_event *ev,
						   struct sock *sk)
{
	if (!sk)
		return;
	if (!bpf_core_field_exists(((struct sock *)0)->__sk_common.skc_rcv_saddr))
		return;
	__be32 src = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
	__be32 dst = BPF_CORE_READ(sk, __sk_common.skc_daddr);
	__builtin_memcpy(ev->saddr, &src, sizeof(src));
	__builtin_memcpy(ev->daddr, &dst, sizeof(dst));
}

static __always_inline void fill_addrs_v6_from_sk(struct retrans_event *ev,
						   struct sock *sk)
{
	if (!sk)
		return;
	if (!bpf_core_field_exists(((struct sock *)0)->__sk_common.skc_v6_rcv_saddr))
		return;
	struct in6_addr src = {};
	struct in6_addr dst = {};
	BPF_CORE_READ_INTO(&src, sk, __sk_common.skc_v6_rcv_saddr);
	BPF_CORE_READ_INTO(&dst, sk, __sk_common.skc_v6_daddr);
	__builtin_memcpy(ev->saddr_v6, &src, sizeof(src));
	__builtin_memcpy(ev->daddr_v6, &dst, sizeof(dst));
}

static __always_inline void fill_addrs_v4_from_req(struct retrans_event *ev,
						    struct request_sock *req)
{
	if (!req)
		return;
	if (!bpf_core_field_exists(((struct request_sock *)0)->__req_common.skc_rcv_saddr))
		return;
	__be32 src = BPF_CORE_READ(req, __req_common.skc_rcv_saddr);
	__be32 dst = BPF_CORE_READ(req, __req_common.skc_daddr);
	__builtin_memcpy(ev->saddr, &src, sizeof(src));
	__builtin_memcpy(ev->daddr, &dst, sizeof(dst));
}

static __always_inline void fill_addrs_v6_from_req(struct retrans_event *ev,
						    struct request_sock *req)
{
	if (!req)
		return;
	if (!bpf_core_field_exists(((struct request_sock *)0)->__req_common.skc_v6_rcv_saddr))
		return;
	struct in6_addr src = {};
	struct in6_addr dst = {};
	BPF_CORE_READ_INTO(&src, req, __req_common.skc_v6_rcv_saddr);
	BPF_CORE_READ_INTO(&dst, req, __req_common.skc_v6_daddr);
	__builtin_memcpy(ev->saddr_v6, &src, sizeof(src));
	__builtin_memcpy(ev->daddr_v6, &dst, sizeof(dst));
}

static __always_inline void fill_addrs_from_req(struct retrans_event *ev,
						 struct request_sock *req)
{
	if (!req)
		return;

	if (ev->family == AF_INET)
		fill_addrs_v4_from_req(ev, req);
	else if (ev->family == AF_INET6)
		fill_addrs_v6_from_req(ev, req);
}

static __always_inline void read_icsk_pending(struct sock *sk, struct retrans_event *ev)
{
	if (!sk)
		return;

	struct inet_connection_sock *icsk = (struct inet_connection_sock *)sk;

	if (bpf_core_field_exists(icsk->icsk_pending))
		ev->icsk_pending = BPF_CORE_READ(icsk, icsk_pending);
}

static __always_inline void fill_retrans_event_from_sk(struct retrans_event *ev,
							struct sock *sk)
{
	if (!sk)
		return;

	ev->state = BPF_CORE_READ(sk, __sk_common.skc_state);
	ev->family = BPF_CORE_READ(sk, __sk_common.skc_family);
	ev->sport = BPF_CORE_READ(sk, __sk_common.skc_num);
	ev->dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
	ev->ca_state = read_ca_state(sk);
	if (bpf_core_field_exists(((struct inet_connection_sock *)0)->icsk_retransmits))
		ev->icsk_retransmits = BPF_CORE_READ((struct inet_connection_sock *)sk,
						      icsk_retransmits);

	ev->memcg_css_addr = sk_memcg_css_addr(sk);
	ev->net_cookie = sk_netns_cookie(sk);
	ev->net_inum = sk_netns_inum(sk);

	read_icsk_pending(sk, ev);

	struct reorder_metrics rm = {};
	read_reorder_metrics(sk, &rm);
	ev->reord_seen = rm.reord_seen;
	ev->dsack_dups = rm.dsack_dups;

	if (ev->family == AF_INET)
		fill_addrs_v4_from_sk(ev, sk);
	else if (ev->family == AF_INET6)
		fill_addrs_v6_from_sk(ev, sk);
}

static __always_inline void read_retransmit_skb_tcp_info(struct retrans_event *ev,
							  struct sock *sk,
							  struct sk_buff *skb)
{
	if (skb) {
		struct tcp_skb_cb *tcb =
			(struct tcp_skb_cb *)((void *)skb +
				compat_bpf_core_field_offset(((struct sk_buff *)0)->cb));

		if (bpf_core_field_exists(((struct tcp_skb_cb *)0)->seq))
			ev->tcp_seq = BPF_CORE_READ(tcb, seq);
		if (bpf_core_field_exists(((struct tcp_skb_cb *)0)->end_seq))
			ev->tcp_end_seq = BPF_CORE_READ(tcb, end_seq);
		if (bpf_core_field_exists(((struct tcp_skb_cb *)0)->tcp_flags))
			ev->tcp_flags = BPF_CORE_READ(tcb, tcp_flags);
	}

	if (sk && bpf_core_field_exists(((struct tcp_sock *)0)->rcv_nxt))
		ev->tcp_ack = BPF_CORE_READ((struct tcp_sock *)sk, rcv_nxt);
}

struct tcp_retransmit_skb_ctx {
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;

	const void *skbaddr;
	const void *skaddr;
};

SEC("tracepoint/tcp/tcp_retransmit_skb")
int tcp_retransmit_skb_prog(struct tcp_retransmit_skb_ctx *ctx)
{
	struct sk_buff *skb = (struct sk_buff *)ctx->skbaddr;

	if (skb && !PCAP_STUB_PASS_SKB(skb))
		return 0;

	struct retrans_event ev = {};

	ev.event_type = RETRANS_EVENT_SKB;
	ev.ktime_ns = bpf_ktime_get_ns();
	ev.tgid_pid = bpf_get_current_pid_tgid();
	bpf_get_current_comm(&ev.comm, sizeof(ev.comm));

	struct sock *sk = (struct sock *)ctx->skaddr;

	ev.skb_addr = (u64)(unsigned long)skb;
	fill_retrans_event_from_sk(&ev, sk);

	read_retransmit_skb_tcp_info(&ev, sk, skb);

	bpf_perf_event_output(ctx, &perf_events, COMPAT_BPF_F_CURRENT_CPU, &ev, sizeof(ev));
	return 0;
}

SEC("tracepoint/tcp/tcp_retransmit_synack")
int tcp_retransmit_synack_prog(struct trace_event_raw_tcp_retransmit_synack *ctx)
{
	struct retrans_event ev = {};

	ev.event_type = RETRANS_EVENT_SYNACK;
	ev.ktime_ns = bpf_ktime_get_ns();
	ev.tgid_pid = bpf_get_current_pid_tgid();
	bpf_get_current_comm(&ev.comm, sizeof(ev.comm));

	struct sock *sk = (struct sock *)ctx->skaddr;
	struct request_sock *req = (struct request_sock *)ctx->req;

	if (sk) {
		ev.family = BPF_CORE_READ(sk, __sk_common.skc_family);
		ev.sport = BPF_CORE_READ(sk, __sk_common.skc_num);
		ev.memcg_css_addr = sk_memcg_css_addr(sk);
		ev.net_cookie = sk_netns_cookie(sk);
		ev.net_inum = sk_netns_inum(sk);
	}

	if (req) {
		if (!ev.family)
			ev.family = BPF_CORE_READ(req, __req_common.skc_family);
		ev.dport = bpf_ntohs(BPF_CORE_READ(req, __req_common.skc_dport));
		if (bpf_core_field_exists(((struct request_sock *)0)->num_retrans))
			ev.icsk_retransmits = BPF_CORE_READ(req, num_retrans);
	}

	ev.state = TCP_NEW_SYN_RECV;
	ev.skb_addr = 0;
	ev.ca_state = 0;

	fill_addrs_from_req(&ev, req);

	bpf_perf_event_output(ctx, &perf_events, COMPAT_BPF_F_CURRENT_CPU, &ev, sizeof(ev));
	return 0;
}
