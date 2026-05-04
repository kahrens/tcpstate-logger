#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define AF_INET     2
#define AF_INET6    10
#define IPPROTO_TCP 6

#define EVENT_TCP_STATE 0
#define EVENT_UDP_SEND  1
#define EVENT_UDP_RECV  2

char __license[] SEC("license") = "Dual MIT/GPL";

struct trace_event_inet_sock_set_state {
	__u64       pad;
	const void *skaddr;
	int         oldstate;
	int         newstate;
	__u16       sport;
	__u16       dport;
	__u16       family;
	__u16       protocol;
	__u8        saddr[4];
	__u8        daddr[4];
	__u8        saddr_v6[16];
	__u8        daddr_v6[16];
};

struct event {
	__u64 timestamp_ns;
	__u32 pid;
	__u16 sport;
	__u16 dport;
	__u16 family;
	__u8  event_type;
	__u8  oldstate;
	__u8  newstate;
	__u8  pad[3];
	__u32 datalen;
	__u8  saddr[16];
	__u8  daddr[16];
	char  comm[16];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
	__type(value, struct event);
} events SEC(".maps");

struct udp_recv_args {
	__u64 sk;  /* struct sock * */
	__u64 msg; /* struct msghdr * */
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);
	__type(value, struct udp_recv_args);
} udp_recv_scratch SEC(".maps");

SEC("tracepoint/sock/inet_sock_set_state")
int handle_inet_sock_set_state(struct trace_event_inet_sock_set_state *ctx)
{
	if (ctx->protocol != IPPROTO_TCP)
		return 0;

	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	e->timestamp_ns = bpf_ktime_get_ns();
	e->pid          = (__u32)(bpf_get_current_pid_tgid() >> 32);
	e->sport        = ctx->sport;
	e->dport        = ctx->dport;
	e->family       = ctx->family;
	e->event_type   = EVENT_TCP_STATE;
	e->oldstate     = (__u8)ctx->oldstate;
	e->newstate     = (__u8)ctx->newstate;
	e->pad[0]       = e->pad[1] = e->pad[2] = 0;
	e->datalen      = 0;

	if (ctx->family == AF_INET6) {
		__builtin_memcpy(e->saddr, ctx->saddr_v6, 16);
		__builtin_memcpy(e->daddr, ctx->daddr_v6, 16);
	} else {
		__builtin_memcpy(e->saddr, ctx->saddr, 4);
		__builtin_memset(e->saddr + 4, 0, 12);
		__builtin_memcpy(e->daddr, ctx->daddr, 4);
		__builtin_memset(e->daddr + 4, 0, 12);
	}

	bpf_get_current_comm(e->comm, sizeof(e->comm));
	bpf_ringbuf_submit(e, 0);
	return 0;
}

static __always_inline int fill_udp_send(struct sock *sk, struct msghdr *msg, __u32 len)
{
	__u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
	if (family != AF_INET)
		return 0;

	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	e->timestamp_ns = bpf_ktime_get_ns();
	e->pid          = (__u32)(bpf_get_current_pid_tgid() >> 32);
	e->event_type   = EVENT_UDP_SEND;
	e->family       = family;
	e->datalen      = len;
	e->oldstate     = 0;
	e->newstate     = 0;
	e->pad[0]       = e->pad[1] = e->pad[2] = 0;

	__be32 saddr_be = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
	__builtin_memcpy(e->saddr, &saddr_be, 4);
	__builtin_memset(e->saddr + 4, 0, 12);
	e->sport = BPF_CORE_READ(sk, __sk_common.skc_num); /* host byte order */

	/* msg_name is kernel stack memory (copied from user by move_addr_to_kernel) */
	void *msg_name = BPF_CORE_READ(msg, msg_name);
	if (msg_name) {
		/* sockaddr_in layout: family(2) + port(2) + addr(4) */
		__be16 sin_port;
		__be32 sin_addr;
		bpf_probe_read_kernel(&sin_port, sizeof(sin_port), (__u8 *)msg_name + 2);
		bpf_probe_read_kernel(&sin_addr, sizeof(sin_addr), (__u8 *)msg_name + 4);
		__builtin_memcpy(e->daddr, &sin_addr, 4);
		__builtin_memset(e->daddr + 4, 0, 12);
		e->dport = __builtin_bswap16(sin_port);
	} else {
		/* connected UDP socket — peer address stored in sock */
		__be32 daddr_be = BPF_CORE_READ(sk, __sk_common.skc_daddr);
		__builtin_memcpy(e->daddr, &daddr_be, 4);
		__builtin_memset(e->daddr + 4, 0, 12);
		__be16 dport_be = BPF_CORE_READ(sk, __sk_common.skc_dport);
		e->dport = __builtin_bswap16(dport_be);
	}

	bpf_get_current_comm(e->comm, sizeof(e->comm));
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(handle_udp_sendmsg, struct sock *sk, struct msghdr *msg, size_t len)
{
	return fill_udp_send(sk, msg, (u32)len);
}

SEC("kprobe/udp_recvmsg")
int BPF_KPROBE(handle_udp_recvmsg, struct sock *sk, struct msghdr *msg,
               size_t len, int flags, int *addr_len)
{
	__u64 tid = bpf_get_current_pid_tgid();
	struct udp_recv_args args = { .sk = (__u64)sk, .msg = (__u64)msg };
	bpf_map_update_elem(&udp_recv_scratch, &tid, &args, BPF_ANY);
	return 0;
}

SEC("kretprobe/udp_recvmsg")
int BPF_KRETPROBE(handle_udp_recvmsg_ret, int ret)
{
	__u64 tid = bpf_get_current_pid_tgid();
	struct udp_recv_args *args = bpf_map_lookup_elem(&udp_recv_scratch, &tid);

	if (!args || ret <= 0)
		goto cleanup;

	{
		struct sock   *sk  = (struct sock *)(long)args->sk;
		struct msghdr *msg = (struct msghdr *)(long)args->msg;

		__u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
		if (family != AF_INET)
			goto cleanup;

		struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
		if (!e)
			goto cleanup;

		e->timestamp_ns = bpf_ktime_get_ns();
		e->pid          = (__u32)(tid >> 32);
		e->event_type   = EVENT_UDP_RECV;
		e->family       = family;
		e->datalen      = (__u32)ret;
		e->oldstate     = 0;
		e->newstate     = 0;
		e->pad[0]       = e->pad[1] = e->pad[2] = 0;

		/* daddr/dport = our local endpoint */
		__be32 laddr_be = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
		__builtin_memcpy(e->daddr, &laddr_be, 4);
		__builtin_memset(e->daddr + 4, 0, 12);
		e->dport = BPF_CORE_READ(sk, __sk_common.skc_num);

		/* saddr/sport = remote sender, written to msg_name by udp_recvmsg */
		void *msg_name = BPF_CORE_READ(msg, msg_name);
		if (msg_name) {
			/* msg_name is user-space buffer populated by the kernel */
			__be16 sin_port;
			__be32 sin_addr;
			bpf_probe_read_user(&sin_port, sizeof(sin_port), (__u8 *)msg_name + 2);
			bpf_probe_read_user(&sin_addr, sizeof(sin_addr), (__u8 *)msg_name + 4);
			__builtin_memcpy(e->saddr, &sin_addr, 4);
			__builtin_memset(e->saddr + 4, 0, 12);
			e->sport = __builtin_bswap16(sin_port);
		} else {
			/* connected UDP — sender is the stored peer */
			__be32 paddr_be = BPF_CORE_READ(sk, __sk_common.skc_daddr);
			__builtin_memcpy(e->saddr, &paddr_be, 4);
			__builtin_memset(e->saddr + 4, 0, 12);
			__be16 pport_be = BPF_CORE_READ(sk, __sk_common.skc_dport);
			e->sport = __builtin_bswap16(pport_be);
		}

		bpf_get_current_comm(e->comm, sizeof(e->comm));
		bpf_ringbuf_submit(e, 0);
	}

cleanup:
	bpf_map_delete_elem(&udp_recv_scratch, &tid);
	return 0;
}
