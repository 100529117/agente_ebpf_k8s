#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// Constantes de llamadas al sistema (syscalls) necesarios para identificarlos
// Obtenidos de:
// https://github.com/torvalds/linux/blob/90d970cade8e67e20b09bbfdc2f0b52064322921/include/uapi/linux/sched.h
// https://github.com/torvalds/linux/blob/90d970cade8e67e20b09bbfdc2f0b52064322921/tools/perf/trace/beauty/include/uapi/linux/prctl.h
// https://github.com/torvalds/linux/blob/90d970cade8e67e20b09bbfdc2f0b52064322921/include/uapi/linux/securebits.h

#ifndef CLONE_NEWUSER
#define CLONE_NEWUSER 0x10000000
#endif
#ifndef CLONE_NEWNS
#define CLONE_NEWNS   0x00020000
#endif

#ifndef PR_CAPBSET_DROP
#define PR_CAPBSET_DROP 24
#endif
#ifndef PR_SET_SECUREBITS
#define PR_SET_SECUREBITS 28
#endif
#ifndef SECBIT_KEEP_CAPS
#define SECBIT_KEEP_CAPS 0x1
#endif

struct alert_t {
    __u64 ts;
    __u32 pid;
    __u32 tgid;
    __u32 uid;
    __u32 mntns;
    __u32 code;   // codigo del enum
    __u64 arg;    //  arg
    char  comm[16];
};

enum alert_code {
    A_UNSHARE_USER = 1,
    A_SETNS_USER   = 2,
    A_CLONE_USER   = 3,
    A_CLONE3_USER  = 4,
    A_CAPSET       = 5,
    A_PTRACE       = 6,
    A_MOUNT        = 7,
    A_PIVOT_ROOT   = 8,
    A_BPF          = 9,
    A_SETUID0      = 10,
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);  // mntns ns.inum
    __type(value, __u8);
} watchlist_priv SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 21); // 2 MiB
} alerts SEC(".maps");

static __always_inline __u32 get_mntns_id(void) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct nsproxy *nsp = BPF_CORE_READ(task, nsproxy);
    if (!nsp) return 0;
    struct mnt_namespace *mntns = BPF_CORE_READ(nsp, mnt_ns);
    if (!mntns) return 0;
    return BPF_CORE_READ(mntns, ns.inum);
}

// Funcion para emitir el evento al ring buffer.
static __always_inline int emit(__u32 code, __u64 arg) {
    __u32 mntns = get_mntns_id();
    if (!bpf_map_lookup_elem(&watchlist_priv, &mntns))
        return 0;
    struct alert_t *e = bpf_ringbuf_reserve(&alerts, sizeof(*e), 0);
    if (!e) return 0;
    e->ts = bpf_ktime_get_ns();
    __u64 pidtgid = bpf_get_current_pid_tgid();
    e->pid  = (__u32)pidtgid;
    e->tgid = (__u32)(pidtgid >> 32);
    __u64 uidgid = bpf_get_current_uid_gid();
    e->uid  = (__u32)uidgid;
    e->mntns = mntns;
    e->code = code;
    e->arg  = arg;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_unshare")
int pe_unshare(struct trace_event_raw_sys_enter *ctx) {
    __u64 flags = ctx->args[0];
    if (flags & CLONE_NEWUSER)
        return emit(A_UNSHARE_USER, flags);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_setns")
int pe_setns(struct trace_event_raw_sys_enter *ctx) {
    return emit(A_SETNS_USER, 0);
}

SEC("tracepoint/syscalls/sys_enter_clone")
int pe_clone(struct trace_event_raw_sys_enter *ctx) {
    __u64 flags = ctx->args[0];
    if (flags & CLONE_NEWUSER)
        return emit(A_CLONE_USER, flags);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_clone3")
int pe_clone3(struct trace_event_raw_sys_enter *ctx) {
    // No se puede leer de forma segura el parametro clone_args del usuario; 
    // solo se puede enviar una senal de intento de clone3.
    //return emit(A_CLONE3_USER, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_capset")
int pe_capset(struct trace_event_raw_sys_enter *ctx) { return emit(A_CAPSET, 0); }

SEC("tracepoint/syscalls/sys_enter_ptrace")
int pe_ptrace(struct trace_event_raw_sys_enter *ctx) { return emit(A_PTRACE, ctx->args[0]); }

SEC("tracepoint/syscalls/sys_enter_mount")
int pe_mount(struct trace_event_raw_sys_enter *ctx) { return emit(A_MOUNT, ctx->args[3]); /* flags */ }

SEC("tracepoint/syscalls/sys_enter_pivot_root")
int pe_pivot(struct trace_event_raw_sys_enter *ctx) { return emit(A_PIVOT_ROOT, 0); }

SEC("tracepoint/syscalls/sys_enter_bpf")
int pe_bpf(struct trace_event_raw_sys_enter *ctx) { return emit(A_BPF, ctx->args[0]); /* cmd */ }

SEC("tracepoint/syscalls/sys_enter_setresuid")
int pe_setresuid(struct trace_event_raw_sys_enter *ctx) {
    __u32 cur = (__u32)bpf_get_current_uid_gid();
    if (cur != 0 && (ctx->args[0] == 0 || ctx->args[1] == 0 || ctx->args[2] == 0))
        return emit(A_SETUID0, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_setuid")
int pe_setuid(struct trace_event_raw_sys_enter *ctx) {
    __u32 cur = (__u32)bpf_get_current_uid_gid();
    if (cur != 0 && ctx->args[0] == 0)
        return emit(A_SETUID0, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_prctl")
int pe_prctl(struct trace_event_raw_sys_enter *ctx) {
    __u64 opt  = ctx->args[0];
    __u64 arg2 = ctx->args[1];
    // Es importante destacar la posibilidad de eliminar/ajustar el conjunto de 
    // limites de capacidad o habilitar KEEP_CAPS para controlar un comportamiento 
    // en especifico relacionado con la seguridad, que afecta a como se gestionan las 
    // capacidades cuando un proceso cambia su ID de usuario.
    if (opt == PR_CAPBSET_DROP)
        //return emit(A_CAPSET, arg2);
        return 0;  
    if (opt == PR_SET_SECUREBITS && (arg2 & SECBIT_KEEP_CAPS))
        return emit(A_CAPSET, arg2);
    return 0;
}