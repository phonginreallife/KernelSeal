// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// KernelSeal BPF-LSM: Protect /proc/$pid/environ and /proc/$pid/mem from unauthorized reads

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define MAX_PATH_LEN 256
#define EPERM 1

// Ring buffer for audit events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256KB ring buffer
} events SEC(".maps");

// Map to store PIDs of KernelSeal sidecar processes (allowed to access protected files)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, __u32);   // PID
    __type(value, __u8);  // 1 = allowed
} ks_allowed_pids SEC(".maps");

// Map to store protected PIDs (processes that have received secrets)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);   // PID
    __type(value, __u8);  // 1 = protected
} protected_pids SEC(".maps");

// Policy configuration map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct ks_policy);
} policy_config SEC(".maps");

// Audit event structure sent to user space
struct ks_audit_event {
    __u64 timestamp;
    __u32 pid;
    __u32 tgid;
    __u32 uid;
    __u32 target_pid;      // PID being accessed in /proc
    __u8  event_type;      // 0=blocked, 1=allowed, 2=audit_only
    __u8  access_type;     // 0=environ, 1=mem, 2=other
    char  comm[16];        // Process name
    char  path[MAX_PATH_LEN];
};

// Policy structure
struct ks_policy {
    __u8 enforce_mode;         // 0=disabled, 1=audit, 2=enforce
    __u8 block_environ_read;   // Block /proc/*/environ
    __u8 block_mem_read;       // Block /proc/*/mem
    __u8 block_ptrace;         // Block ptrace to protected processes
    __u8 allow_self_read;      // Allow process to read its own environ/mem
    __u8 reserved[3];
};

// Helper: Check if path matches /proc/[0-9]+/environ or /proc/[0-9]+/mem
// Returns: 0=no match, 1=environ, 2=mem
static __always_inline int check_proc_path(const char *path, __u32 *target_pid) {
    char buf[MAX_PATH_LEN];
    int ret;
    
    ret = bpf_probe_read_kernel_str(buf, sizeof(buf), path);
    if (ret < 0)
        return 0;
    
    // Check for /proc/ prefix
    if (buf[0] != '/' || buf[1] != 'p' || buf[2] != 'r' || 
        buf[3] != 'o' || buf[4] != 'c' || buf[5] != '/')
        return 0;
    
    // Parse PID from /proc/<pid>/...
    __u32 pid = 0;
    int i = 6;
    
    #pragma unroll
    for (int j = 0; j < 10; j++) {  // Max 10 digit PID
        if (i >= MAX_PATH_LEN)
            return 0;
        char c = buf[i];
        if (c >= '0' && c <= '9') {
            pid = pid * 10 + (c - '0');
            i++;
        } else if (c == '/') {
            break;
        } else {
            return 0;  // Not a PID path
        }
    }
    
    if (pid == 0)
        return 0;
    
    *target_pid = pid;
    
    // Check for /environ or /mem suffix
    // After /proc/<pid>/, check what follows
    if (buf[i] != '/')
        return 0;
    i++;
    
    // Check "environ"
    if (buf[i] == 'e' && buf[i+1] == 'n' && buf[i+2] == 'v' && 
        buf[i+3] == 'i' && buf[i+4] == 'r' && buf[i+5] == 'o' && 
        buf[i+6] == 'n' && (buf[i+7] == '\0' || buf[i+7] == '/'))
        return 1;
    
    // Check "mem"
    if (buf[i] == 'm' && buf[i+1] == 'e' && buf[i+2] == 'm' && 
        (buf[i+3] == '\0' || buf[i+3] == '/'))
        return 2;
    
    return 0;
}

// Helper: Send audit event to user space
static __always_inline void send_audit_event(
    __u32 pid, __u32 tgid, __u32 uid, __u32 target_pid,
    __u8 event_type, __u8 access_type, const char *path) 
{
    struct ks_audit_event *event;
    
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return;
    
    event->timestamp = bpf_ktime_get_ns();
    event->pid = pid;
    event->tgid = tgid;
    event->uid = uid;
    event->target_pid = target_pid;
    event->event_type = event_type;
    event->access_type = access_type;
    
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    bpf_probe_read_kernel_str(event->path, sizeof(event->path), path);
    
    bpf_ringbuf_submit(event, 0);
}

// LSM hook: file_open - Called when a file is opened
SEC("lsm/file_open")
int BPF_PROG(ks_file_open, struct file *file) {
    // Get current process info
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tgid = pid_tgid & 0xFFFFFFFF;
    __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    
    // Get policy configuration
    __u32 key = 0;
    struct ks_policy *policy = bpf_map_lookup_elem(&policy_config, &key);
    if (!policy || policy->enforce_mode == 0)
        return 0;  // Policy disabled
    
    // Check if this is an KernelSeal allowed process
    __u8 *allowed = bpf_map_lookup_elem(&ks_allowed_pids, &pid);
    if (allowed && *allowed == 1)
        return 0;  // KernelSeal sidecar is always allowed
    
    // Get the path from the dentry
    struct path f_path;
    bpf_core_read(&f_path, sizeof(f_path), &file->f_path);
    
    struct dentry *dentry;
    bpf_core_read(&dentry, sizeof(dentry), &f_path.dentry);
    
    if (!dentry)
        return 0;
    
    // Get filename from dentry
    struct qstr d_name;
    bpf_core_read(&d_name, sizeof(d_name), &dentry->d_name);
    
    const unsigned char *name;
    bpf_core_read(&name, sizeof(name), &d_name.name);
    
    if (!name)
        return 0;
    
    char filename[32];
    bpf_probe_read_kernel_str(filename, sizeof(filename), name);
    
    __u32 target_pid = 0;
    __u8 access_type = 0;
    int should_block = 0;
    
    // Check for "environ" file
    if (filename[0] == 'e' && filename[1] == 'n' && filename[2] == 'v' &&
        filename[3] == 'i' && filename[4] == 'r' && filename[5] == 'o' &&
        filename[6] == 'n' && filename[7] == '\0') {
        
        if (policy->block_environ_read) {
            access_type = 0;
            
            // Get parent dentry to extract PID
            struct dentry *parent;
            bpf_core_read(&parent, sizeof(parent), &dentry->d_parent);
            
            if (parent) {
                struct qstr parent_name;
                bpf_core_read(&parent_name, sizeof(parent_name), &parent->d_name);
                const unsigned char *pname;
                bpf_core_read(&pname, sizeof(pname), &parent_name.name);
                
                if (pname) {
                    char pid_str[16];
                    bpf_probe_read_kernel_str(pid_str, sizeof(pid_str), pname);
                    
                    // Parse PID from directory name
                    target_pid = 0;
                    #pragma unroll
                    for (int i = 0; i < 10; i++) {
                        char c = pid_str[i];
                        if (c >= '0' && c <= '9') {
                            target_pid = target_pid * 10 + (c - '0');
                        } else {
                            break;
                        }
                    }
                }
            }
            
            // Check if target is a protected process
            if (target_pid > 0) {
                __u8 *is_protected = bpf_map_lookup_elem(&protected_pids, &target_pid);
                if (is_protected && *is_protected == 1) {
                    // Allow self-read if configured
                    if (policy->allow_self_read && pid == target_pid)
                        should_block = 0;
                    else
                        should_block = 1;
                }
            }
        }
    }
    // Check for "mem" file
    else if (filename[0] == 'm' && filename[1] == 'e' && filename[2] == 'm' && 
             filename[3] == '\0') {
        
        if (policy->block_mem_read) {
            access_type = 1;
            
            // Similar parent extraction for PID
            struct dentry *parent;
            bpf_core_read(&parent, sizeof(parent), &dentry->d_parent);
            
            if (parent) {
                struct qstr parent_name;
                bpf_core_read(&parent_name, sizeof(parent_name), &parent->d_name);
                const unsigned char *pname;
                bpf_core_read(&pname, sizeof(pname), &parent_name.name);
                
                if (pname) {
                    char pid_str[16];
                    bpf_probe_read_kernel_str(pid_str, sizeof(pid_str), pname);
                    
                    target_pid = 0;
                    #pragma unroll
                    for (int i = 0; i < 10; i++) {
                        char c = pid_str[i];
                        if (c >= '0' && c <= '9') {
                            target_pid = target_pid * 10 + (c - '0');
                        } else {
                            break;
                        }
                    }
                }
            }
            
            if (target_pid > 0) {
                __u8 *is_protected = bpf_map_lookup_elem(&protected_pids, &target_pid);
                if (is_protected && *is_protected == 1) {
                    if (policy->allow_self_read && pid == target_pid)
                        should_block = 0;
                    else
                        should_block = 1;
                }
            }
        }
    }
    
    if (should_block || (access_type <= 1 && target_pid > 0)) {
        __u8 event_type = should_block ? 0 : 1;  // 0=blocked, 1=allowed
        
        // In audit mode, don't actually block
        if (policy->enforce_mode == 1)
            should_block = 0;
        
        send_audit_event(pid, tgid, uid, target_pid, event_type, access_type, filename);
    }
    
    return should_block ? -EPERM : 0;
}

// LSM hook: ptrace_access_check - Block ptrace to protected processes
SEC("lsm/ptrace_access_check")
int BPF_PROG(ks_ptrace_access_check, struct task_struct *child, unsigned int mode) {
    // Get current process info
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    
    // Get policy configuration
    __u32 key = 0;
    struct ks_policy *policy = bpf_map_lookup_elem(&policy_config, &key);
    if (!policy || policy->enforce_mode == 0 || !policy->block_ptrace)
        return 0;
    
    // Check if this is an KernelSeal allowed process
    __u8 *allowed = bpf_map_lookup_elem(&ks_allowed_pids, &pid);
    if (allowed && *allowed == 1)
        return 0;
    
    // Get target PID
    __u32 child_pid;
    bpf_core_read(&child_pid, sizeof(child_pid), &child->pid);
    
    // Check if target is protected
    __u8 *is_protected = bpf_map_lookup_elem(&protected_pids, &child_pid);
    if (is_protected && *is_protected == 1) {
        send_audit_event(pid, pid, uid, child_pid, 0, 3, "ptrace");
        
        if (policy->enforce_mode == 2)  // Enforce mode
            return -EPERM;
    }
    
    return 0;
}
