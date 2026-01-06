// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// KernelSeal Common types shared between BPF programs and Go user space

#ifndef __KS_COMMON_H__
#define __KS_COMMON_H__

#define MAX_PATH_LEN 256
#define MAX_COMM_LEN 16
#define MAX_FILENAME_LEN 256

// Event types sent from BPF to user space
enum ks_event_type {
    KS_EVENT_EXEC      = 1,  // Process executed
    KS_EVENT_EXIT      = 2,  // Process exited
    KS_EVENT_BLOCKED   = 3,  // Access blocked by LSM
    KS_EVENT_AUDIT     = 4,  // Audit log (not blocked)
};

// Access types for LSM events
enum ks_access_type {
    KS_ACCESS_ENVIRON  = 0,
    KS_ACCESS_MEM      = 1,
    KS_ACCESS_MAPS     = 2,
    KS_ACCESS_PTRACE   = 3,
};

// Policy enforcement modes
enum ks_enforce_mode {
    KS_MODE_DISABLED   = 0,
    KS_MODE_AUDIT      = 1,  // Log only, don't block
    KS_MODE_ENFORCE    = 2,  // Log and block
};

// Exec event sent to user space for secret injection decisions
struct ks_exec_event {
    __u64 timestamp;
    __u32 pid;
    __u32 tgid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    __u64 cgroup_id;         // For container identification
    __u8  event_type;        // ks_event_type
    __u8  reserved[3];
    char  comm[MAX_COMM_LEN];
    char  filename[MAX_FILENAME_LEN];
};

// LSM audit/block event
struct ks_lsm_event {
    __u64 timestamp;
    __u32 pid;
    __u32 tgid;
    __u32 uid;
    __u32 target_pid;        // PID being accessed
    __u8  event_type;        // blocked or audit
    __u8  access_type;       // environ, mem, ptrace, etc.
    __u8  reserved[2];
    char  comm[MAX_COMM_LEN];
    char  path[MAX_PATH_LEN];
};

// Policy configuration structure
struct ks_policy_config {
    __u8 enforce_mode;       // ks_enforce_mode
    __u8 block_environ;      // Block /proc/*/environ reads
    __u8 block_mem;          // Block /proc/*/mem reads
    __u8 block_maps;         // Block /proc/*/maps reads  
    __u8 block_ptrace;       // Block ptrace to protected processes
    __u8 allow_self_read;    // Allow process to read its own /proc files
    __u8 audit_all;          // Audit even allowed accesses
    __u8 reserved;
};

#endif /* __KS_COMMON_H__ */
