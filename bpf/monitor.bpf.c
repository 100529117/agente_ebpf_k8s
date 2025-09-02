// Este eBPF es usado por motivos de depuracion.
// Y para temas de entendimiento del comportamiento del proyecto.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct event_t {
    __u64 ts;
    __u32 pid;
    __u32 tgid;
    __u32 uid;
    __u32 mntns;
    char  comm[16];
    char  filename[256];
};

// Lista de seguimiento por pod por mount namespace id.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);   // mntns ns.inum
    __type(value, __u8);  
} watchlist SEC(".maps");

// Eventos via ring buffer (mantener en bajo tamano para evitar problemas de bloqueo de memoria)
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 21); // 2 MiB
} events SEC(".maps");

static __always_inline __u32 get_mntns_id(void) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct nsproxy *nsp = BPF_CORE_READ(task, nsproxy);
    if (!nsp)
        return 0;
    struct mnt_namespace *mntns = BPF_CORE_READ(nsp, mnt_ns);
    if (!mntns)
        return 0;
    return BPF_CORE_READ(mntns, ns.inum);
}

// La estructura de tracepoint arg de tipo struct esta definido en vmlinux.h.
SEC("tracepoint/syscalls/sys_enter_execve")
int on_execve(struct trace_event_raw_sys_enter *ctx) {
    __u32 mntns = get_mntns_id();
    if (!bpf_map_lookup_elem(&watchlist, &mntns))
        return 0; 

    struct event_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->ts = bpf_ktime_get_ns();
    __u64 pidtgid = bpf_get_current_pid_tgid();
    e->pid  = (__u32)pidtgid;
    e->tgid = (__u32)(pidtgid >> 32);
    __u64 uidgid = bpf_get_current_uid_gid();
    e->uid  = (__u32)uidgid;
    e->mntns = mntns;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    const char *filename = (const char *)ctx->args[0];
    if (filename)
        bpf_probe_read_user_str(e->filename, sizeof(e->filename), filename);

    bpf_ringbuf_submit(e, 0);
    return 0;
}