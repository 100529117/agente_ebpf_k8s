// Se disparara cuando un pod supervisado por el agente realiza lo siguiente:
//  1) connect (2) a una direccion IPv4 no privada (code=1, arg=puerto destino, ipv4=IP destino)
//  2) duplicar (dup2/dup3) un socket conectado a stdin/stdout/stderr (code=2, argumento=newfd)
//  3) execve de shells/herramientas sospechosas (code=3), coincidente con comm (nombre del exe ejecutandose)

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>   // BPF_CORE_READ
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#ifndef AF_INET
#define AF_INET 2
#endif

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define CODE_CONNECT_EXTERNAL 1
#define CODE_DUP_STDFD        2
#define CODE_EXEC_SUSPECT     3

struct rs_event {
    __u64 ts;
    __u32 pid;
    __u32 tgid;
    __u32 uid;
    __u32 mntns;
    __u32 code;
    __u32 arg;     // puerto (connect) o newfd (dup*)
    __u32 ipv4;    // host IPv4 (conexion)
    char  comm[16];
    char  exe[64]; // raiz (execve)
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} rs_events SEC(".maps");

// Watchlist por objeto: mntns -> 1
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, __u8);
} watchlist SEC(".maps");

struct sock_key { __u32 tgid; __s32 fd; };
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, struct sock_key);
    __type(value, __u8);
} rs_connected_fds SEC(".maps");

struct conn_tmp { __s32 fd; __u32 ipv4; __u16 dport; __u16 family; };
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u64);   // pidtgid
    __type(value, struct conn_tmp);
} rs_pending SEC(".maps");

static __always_inline __u32 get_mntns_id(void) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct nsproxy *ns = BPF_CORE_READ(task, nsproxy);
    if (!ns)
        return 0;
    struct mnt_namespace *mntns = BPF_CORE_READ(ns, mnt_ns);
    if (!mntns)
        return 0;
   
    return BPF_CORE_READ(mntns, ns.inum);
}

static __always_inline bool is_private_ipv4(__u32 host) {
    __u8 a = host >> 24, b = (host >> 16) & 0xff;
    if (a == 10) return true;                      // 10/8
    if (a == 172 && b >= 16 && b <= 31) return true; // 172.16/12
    if (a == 192 && b == 168) return true;         // 192.168/16
    if (a == 127) return true;                     // loopback
    if (a == 169 && b == 254) return true;         // link-local
    if (a == 100 && b >= 64 && b <= 127) return true; // CGNAT 100.64/10
    return false;
}

static __always_inline int gate_and_fill(struct rs_event *e, __u32 code) {
    __u32 m = get_mntns_id();
    __u8 *ok = bpf_map_lookup_elem(&watchlist, &m);
    if (!ok) return 1;

    __u64 pidtgid = bpf_get_current_pid_tgid();
    __u64 uidgid = bpf_get_current_uid_gid();
    e->ts   = bpf_ktime_get_ns();
    e->pid  = (__u32)pidtgid;
    e->tgid = (__u32)(pidtgid >> 32);
    e->uid  = (__u32)uidgid;
    e->mntns= m;
    e->code = code;
    e->arg  = 0;
    e->ipv4 = 0;
    __builtin_memset(e->exe, 0, sizeof(e->exe));
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    return 0;
}

// Rastramos connect(2)

SEC("tracepoint/syscalls/sys_enter_connect")
int rs_enter_connect(struct trace_event_raw_sys_enter *ctx) {
    int sockfd = (int)ctx->args[0];
    const struct sockaddr *addr = (const struct sockaddr *)(ctx->args[1]);
    __u16 family = 0;
    bpf_probe_read_user(&family, sizeof(family), &addr->sa_family);
    if (family != AF_INET) return 0;

    struct sockaddr_in sin = {};
    bpf_probe_read_user(&sin, sizeof(sin), addr);

    struct conn_tmp tmp = {};
    tmp.fd     = sockfd;
    tmp.family = family;
    tmp.ipv4   = bpf_ntohl(sin.sin_addr.s_addr);
    tmp.dport  = bpf_ntohs(sin.sin_port);

    __u64 pidtgid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&rs_pending, &pidtgid, &tmp, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_connect")
int rs_exit_connect(struct trace_event_raw_sys_exit *ctx) {
    __s64 ret = ctx->ret;
    __u64 pidtgid = bpf_get_current_pid_tgid();
    struct conn_tmp *t = bpf_map_lookup_elem(&rs_pending, &pidtgid);
    if (!t) return 0;

    if (ret == 0 && t->family == AF_INET) {
        struct sock_key key = { .tgid = (__u32)(pidtgid >> 32), .fd = t->fd };
        __u8 one = 1;
        bpf_map_update_elem(&rs_connected_fds, &key, &one, BPF_ANY);
        if (!is_private_ipv4(t->ipv4)) {
            struct rs_event *e = bpf_ringbuf_reserve(&rs_events, sizeof(*e), 0);
            if (e && !gate_and_fill(e, CODE_CONNECT_EXTERNAL)) {
                e->ipv4 = t->ipv4;
                e->arg  = t->dport;
                bpf_ringbuf_submit(e, 0);
            } else if (e) {
                bpf_ringbuf_discard(e, 0);
            }
        }
    }
    bpf_map_delete_elem(&rs_pending, &pidtgid);
    return 0;
}

// dup2/dup3

static __always_inline int handle_dup_common(int oldfd, int newfd) {
    if (newfd > 2) return 0;
    __u64 pidtgid = bpf_get_current_pid_tgid();
    struct sock_key key = { .tgid = (__u32)(pidtgid >> 32), .fd = oldfd };
    __u8 *v = bpf_map_lookup_elem(&rs_connected_fds, &key);
    if (!v) return 0;

    struct rs_event *e = bpf_ringbuf_reserve(&rs_events, sizeof(*e), 0);
    if (!e) return 0;
    if (gate_and_fill(e, CODE_DUP_STDFD)) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }
    e->arg = (__u32)newfd;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_dup2")
int rs_dup2(struct trace_event_raw_sys_enter *ctx) {
    return handle_dup_common((int)ctx->args[0], (int)ctx->args[1]);
}
SEC("tracepoint/syscalls/sys_enter_dup3")
int rs_dup3(struct trace_event_raw_sys_enter *ctx) {
    return handle_dup_common((int)ctx->args[0], (int)ctx->args[1]);
}

// Rastriemos la ejecucion de shells/herramientas sospechosas 
// (coincidencias por comando para evitar problemas con el verificador).

static __always_inline bool comm_eq(const char c[16], const char *lit, int n) {
#pragma unroll
    for (int i = 0; i < 16; i++) {
        if (i >= n) {

            return c[i] == '\0';
        }
        if (c[i] != lit[i]) return false;
    }
    return false;
}

static __always_inline bool comm_in_suspect_list(void) {
    char c[16] = {};
    bpf_get_current_comm(c, sizeof(c));

    if (comm_eq(c, "sh", 2))      return true;
    if (comm_eq(c, "bash", 4))    return true;
    if (comm_eq(c, "zsh", 3))     return true;
    if (comm_eq(c, "ksh", 3))     return true;
    if (comm_eq(c, "ash", 3))     return true;  // busybox shell
    if (comm_eq(c, "dash", 4))    return true;

    if (comm_eq(c, "busybox", 7)) return true;
    if (comm_eq(c, "nc", 2))      return true;
    if (comm_eq(c, "ncat", 4))    return true;
    if (comm_eq(c, "socat", 5))   return true;

    // interpretadores comunes para ataques
    if (comm_eq(c, "python", 6))  return true;
    if (comm_eq(c, "python3", 7)) return true;
    if (comm_eq(c, "python2", 7)) return true;
    if (comm_eq(c, "perl", 4))    return true;
    if (comm_eq(c, "php", 3))     return true;
    if (comm_eq(c, "ruby", 4))    return true;
    if (comm_eq(c, "lua", 3))     return true;

    return false;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int rs_execve(struct trace_event_raw_sys_enter *ctx) {
    if (!comm_in_suspect_list())
        return 0;

    struct rs_event *e = bpf_ringbuf_reserve(&rs_events, sizeof(*e), 0);
    if (!e) return 0;
    if (gate_and_fill(e, CODE_EXEC_SUSPECT)) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    const char *filename = (const char *)ctx->args[0];
    bpf_probe_read_user_str(e->exe, sizeof(e->exe), filename);

    bpf_ringbuf_submit(e, 0);
    return 0;
}
