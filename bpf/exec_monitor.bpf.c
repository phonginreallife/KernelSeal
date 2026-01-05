// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// X00 Exec Monitor: Detect process execution for secret injection

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "x00_common.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// Ring buffer for exec events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256KB
} exec_events SEC(".maps");

// Map to track processes we've seen (for deduplication)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, __u32);    // PID
    __type(value, __u64);  // Timestamp when first seen
} seen_pids SEC(".maps");

// Target cgroup IDs to monitor (0 = monitor all)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u64);    // cgroup ID
    __type(value, __u8);   // 1 = monitor this cgroup
} target_cgroups SEC(".maps");

// Configuration: set to 1 to enable cgroup filtering
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u8);
} cgroup_filter_enabled SEC(".maps");

// Target binary names to monitor (kernel-side filtering)
// Key is the binary name (e.g., "cat", "psql", "node")
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, char[16]);   // binary name (comm)
    __type(value, __u8);     // 1 = monitor this binary
} target_binaries SEC(".maps");

// Configuration: set to 1 to enable binary filtering
// When enabled, only processes matching target_binaries will be monitored
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u8);
} binary_filter_enabled SEC(".maps");

// Helper to check if we should monitor this cgroup
static __always_inline int should_monitor_cgroup(__u64 cgid) {
    __u32 key = 0;
    __u8 *enabled = bpf_map_lookup_elem(&cgroup_filter_enabled, &key);
    
    // If filtering not enabled, monitor all
    if (!enabled || *enabled == 0)
        return 1;
    
    // Check if this cgroup is in our target list
    __u8 *target = bpf_map_lookup_elem(&target_cgroups, &cgid);
    return target && *target == 1;
}

// Helper to check if we should monitor this binary
// Returns 1 if binary should be monitored, 0 otherwise
static __always_inline int should_monitor_binary(const char *comm) {
    __u32 key = 0;
    __u8 *enabled = bpf_map_lookup_elem(&binary_filter_enabled, &key);
    
    // If filtering not enabled, monitor all binaries
    if (!enabled || *enabled == 0)
        return 1;
    
    // Check if this binary is in our target list
    __u8 *target = bpf_map_lookup_elem(&target_binaries, (void *)comm);
    return target && *target == 1;
}

// Tracepoint: sys_enter_execve - Called when execve() is invoked
SEC("tracepoint/syscalls/sys_enter_execve")
int handle_sys_enter_execve(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tgid = pid_tgid & 0xFFFFFFFF;
    
    // Get cgroup ID for container identification
    __u64 cgid = bpf_get_current_cgroup_id();
    
    // Check cgroup filter first (if enabled)
    if (!should_monitor_cgroup(cgid))
        return 0;
    
    // Get the binary name from filename argument for filtering
    // We need to extract the basename for comparison
    const char *filename = (const char *)ctx->args[0];
    char binary_name[16] = {};
    
    if (filename) {
        // Read the full path
        char full_path[256];
        int ret = bpf_probe_read_user_str(full_path, sizeof(full_path), filename);
        if (ret > 0) {
            // Find the last '/' to get basename
            int last_slash = -1;
            #pragma unroll
            for (int i = 0; i < 255 && i < ret; i++) {
                if (full_path[i] == '/')
                    last_slash = i;
                if (full_path[i] == '\0')
                    break;
            }
            
            // Copy basename to binary_name
            int start = last_slash + 1;
            #pragma unroll
            for (int i = 0; i < 15; i++) {
                int idx = start + i;
                if (idx < 256 && full_path[idx] != '\0') {
                    binary_name[i] = full_path[idx];
                } else {
                    binary_name[i] = '\0';
                    break;
                }
            }
            binary_name[15] = '\0';
        }
    }
    
    // Check binary filter (if enabled) - filter in kernel space!
    if (!should_monitor_binary(binary_name))
        return 0;
    
    // Check for duplicate (same PID already being tracked)
    __u64 *existing = bpf_map_lookup_elem(&seen_pids, &pid);
    __u64 now = bpf_ktime_get_ns();
    
    if (existing) {
        // Skip if we've seen this PID in the last 100ms (dedup)
        if (now - *existing < 100000000)
            return 0;
    }
    
    // Update seen timestamp
    bpf_map_update_elem(&seen_pids, &pid, &now, BPF_ANY);
    
    // Reserve space in ring buffer
    struct x00_exec_event *event;
    event = bpf_ringbuf_reserve(&exec_events, sizeof(*event), 0);
    if (!event)
        return 0;
    
    // Fill event data
    event->timestamp = now;
    event->pid = pid;
    event->tgid = tgid;
    event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event->gid = bpf_get_current_uid_gid() >> 32;
    event->cgroup_id = cgid;
    event->event_type = X00_EVENT_EXEC;
    
    // Get parent PID
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent;
    bpf_core_read(&parent, sizeof(parent), &task->real_parent);
    if (parent) {
        bpf_core_read(&event->ppid, sizeof(event->ppid), &parent->pid);
    } else {
        event->ppid = 0;
    }
    
    // Get command name
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    
    // Copy filename
    if (filename) {
        bpf_probe_read_user_str(event->filename, sizeof(event->filename), filename);
    } else {
        event->filename[0] = '\0';
    }
    
    bpf_ringbuf_submit(event, 0);
    
    return 0;
}

// Tracepoint: sched_process_exit - Called when a process exits
SEC("tracepoint/sched/sched_process_exit")
int handle_sched_process_exit(void *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tgid = pid_tgid & 0xFFFFFFFF;
    
    // Only report if this was a tracked PID
    __u64 *existing = bpf_map_lookup_elem(&seen_pids, &pid);
    if (!existing)
        return 0;
    
    // Remove from seen map
    bpf_map_delete_elem(&seen_pids, &pid);
    
    // Get cgroup ID
    __u64 cgid = bpf_get_current_cgroup_id();
    
    // Check if we should monitor this cgroup
    if (!should_monitor_cgroup(cgid))
        return 0;
    
    // Send exit event
    struct x00_exec_event *event;
    event = bpf_ringbuf_reserve(&exec_events, sizeof(*event), 0);
    if (!event)
        return 0;
    
    event->timestamp = bpf_ktime_get_ns();
    event->pid = pid;
    event->tgid = tgid;
    event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event->gid = bpf_get_current_uid_gid() >> 32;
    event->cgroup_id = cgid;
    event->event_type = X00_EVENT_EXIT;
    event->ppid = 0;
    
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    event->filename[0] = '\0';
    
    bpf_ringbuf_submit(event, 0);
    
    return 0;
}
