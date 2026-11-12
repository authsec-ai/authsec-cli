// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
//
// authsec-cli sensor. Tracepoints only (no kprobes), so one CO-RE object runs
// on amd64 and arm64 kernels with BTF (5.8+ for the ring buffer).
//
// What reaches user space:
//   exec     every process start (user space decides whether it is an agent)
//   exit     only processes in the tracked set
//   fork     only children of tracked processes (they join the set here)
//   connect  every outgoing TCP connection (LLM traffic marks unknown agents)
//   open     only files opened by tracked processes
// The tracked set is the agents and everything they start, so file events
// for the rest of the machine never leave the kernel.

#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define TASK_COMM_LEN 16
#define PATH_LEN 256

enum event_type {
	EV_EXEC = 1,
	EV_EXIT = 2,
	EV_FORK = 3,
	EV_CONNECT = 4,
	EV_OPEN = 5,
};

struct event {
	__u32 type;
	__u32 pid;   // tgid
	__u32 ppid;  // parent tgid (exec, fork: the child is pid)
	__u32 uid;
	__u64 ts_ns; // boot time
	__u16 family;
	__u16 dport;
	__s32 flags; // open flags
	__u8 daddr[16];
	char comm[TASK_COMM_LEN];
	char path[PATH_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 22); // 4 MiB
} events SEC(".maps");

// tracked: tgid -> 1. Seeded by user space, grown on fork, shrunk on exit.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, __u32);
	__type(value, __u8);
} tracked SEC(".maps");

// dropped counts events lost to a full ring buffer.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} dropped SEC(".maps");

// Minimal kernel types; CO-RE relocates the field offsets.
struct task_struct {
	int tgid;
	struct task_struct *real_parent;
} __attribute__((preserve_access_index));

struct trace_entry {
	short unsigned int type;
} __attribute__((preserve_access_index));

struct trace_event_raw_sched_process_exec {
	struct trace_entry ent;
	__u32 __data_loc_filename;
	int pid;
	int old_pid;
} __attribute__((preserve_access_index));

struct trace_event_raw_sched_process_fork {
	struct trace_entry ent;
	int parent_pid;
	int child_pid;
} __attribute__((preserve_access_index));

struct trace_event_raw_inet_sock_set_state {
	struct trace_entry ent;
	const void *skaddr;
	int oldstate;
	int newstate;
	__u16 sport;
	__u16 dport;
	__u16 family;
	__u16 protocol;
	__u8 saddr[4];
	__u8 daddr[4];
	__u8 saddr_v6[16];
	__u8 daddr_v6[16];
} __attribute__((preserve_access_index));

struct trace_event_raw_sys_enter {
	struct trace_entry ent;
	long int id;
	long unsigned int args[6];
} __attribute__((preserve_access_index));

#define TCP_SYN_SENT 2
#define AF_INET 2
#define AF_INET6 10
#define IPPROTO_TCP 6

static __always_inline void count_drop(void)
{
	__u32 k = 0;
	__u64 *v = bpf_map_lookup_elem(&dropped, &k);
	if (v)
		__sync_fetch_and_add(v, 1);
}

static __always_inline struct event *reserve(__u32 type, __u32 pid)
{
	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		count_drop();
		return 0;
	}
	e->type = type;
	e->pid = pid;
	e->ppid = 0;
	e->uid = (__u32)bpf_get_current_uid_gid();
	e->ts_ns = bpf_ktime_get_boot_ns();
	e->family = 0;
	e->dport = 0;
	e->flags = 0;
	__builtin_memset(e->daddr, 0, sizeof(e->daddr));
	e->path[0] = 0;
	bpf_get_current_comm(e->comm, sizeof(e->comm));
	return e;
}

static __always_inline __u32 current_tgid(void)
{
	return bpf_get_current_pid_tgid() >> 32;
}

SEC("tracepoint/sched/sched_process_exec")
int on_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	__u32 pid = current_tgid();
	struct event *e = reserve(EV_EXEC, pid);
	if (!e)
		return 0;
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	unsigned int off = BPF_CORE_READ(ctx, __data_loc_filename) & 0xFFFF;
	bpf_probe_read_kernel_str(e->path, sizeof(e->path), (void *)ctx + off);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/sched/sched_process_fork")
int on_fork(struct trace_event_raw_sched_process_fork *ctx)
{
	__u32 parent = current_tgid();
	if (!bpf_map_lookup_elem(&tracked, &parent))
		return 0;
	__u32 child = BPF_CORE_READ(ctx, child_pid);
	// Threads share the tgid: only a new process (a new tgid) is added.
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	if (child == parent || child == (__u32)BPF_CORE_READ(task, tgid))
		return 0;
	__u8 one = 1;
	bpf_map_update_elem(&tracked, &child, &one, BPF_ANY);
	struct event *e = reserve(EV_FORK, child);
	if (!e)
		return 0;
	e->ppid = parent;
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int on_exit(void *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	__u32 tgid = id >> 32;
	if ((__u32)id != tgid) // a thread, not the process
		return 0;
	if (!bpf_map_lookup_elem(&tracked, &tgid))
		return 0;
	bpf_map_delete_elem(&tracked, &tgid);
	struct event *e = reserve(EV_EXIT, tgid);
	if (e)
		bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/sock/inet_sock_set_state")
int on_sock_state(struct trace_event_raw_inet_sock_set_state *ctx)
{
	if (BPF_CORE_READ(ctx, protocol) != IPPROTO_TCP || BPF_CORE_READ(ctx, newstate) != TCP_SYN_SENT)
		return 0;
	// SYN_SENT is set inside connect(): the current task is the caller.
	struct event *e = reserve(EV_CONNECT, current_tgid());
	if (!e)
		return 0;
	e->family = BPF_CORE_READ(ctx, family);
	e->dport = BPF_CORE_READ(ctx, dport);
	if (e->family == AF_INET)
		bpf_core_read(e->daddr, 4, &ctx->daddr);
	else
		bpf_core_read(e->daddr, 16, &ctx->daddr_v6);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int on_openat(struct trace_event_raw_sys_enter *ctx)
{
	__u32 pid = current_tgid();
	if (!bpf_map_lookup_elem(&tracked, &pid))
		return 0;
	struct event *e = reserve(EV_OPEN, pid);
	if (!e)
		return 0;
	const char *name = (const char *)BPF_CORE_READ(ctx, args[1]);
	e->flags = (__s32)BPF_CORE_READ(ctx, args[2]);
	bpf_probe_read_user_str(e->path, sizeof(e->path), name);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

// dns_answers is a socket filter on a packet socket (SOCK_DGRAM, so data
// starts at the IP header). It keeps UDP packets from port 53 and drops the
// rest in the kernel; user space parses the answers.
SEC("socket")
int dns_answers(struct __sk_buff *skb)
{
	__u8 vihl;
	if (bpf_skb_load_bytes(skb, 0, &vihl, 1) < 0)
		return 0;
	__u8 version = vihl >> 4;
	__u32 udp_off;
	__u8 proto;
	if (version == 4) {
		if (bpf_skb_load_bytes(skb, 9, &proto, 1) < 0)
			return 0;
		udp_off = (vihl & 0x0F) * 4;
	} else if (version == 6) {
		if (bpf_skb_load_bytes(skb, 6, &proto, 1) < 0)
			return 0;
		udp_off = 40; // extension headers are not followed
	} else {
		return 0;
	}
	if (proto != 17) // UDP
		return 0;
	__u16 sport;
	if (bpf_skb_load_bytes(skb, udp_off, &sport, 2) < 0)
		return 0;
	if (sport != __builtin_bswap16(53))
		return 0;
	return skb->len;
}
