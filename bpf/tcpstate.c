#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define AF_INET6    10
#define IPPROTO_TCP 6

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
	__u8  oldstate;
	__u8  newstate;
	__u32 pad;
	__u8  saddr[16];
	__u8  daddr[16];
	char  comm[16];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
	__type(value, struct event);
} events SEC(".maps");

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
	e->oldstate     = (__u8)ctx->oldstate;
	e->newstate     = (__u8)ctx->newstate;
	e->pad          = 0;

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
