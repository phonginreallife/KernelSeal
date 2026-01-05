# X00

**Kernel-level Secret Protection for Kubernetes using eBPF and BPF-LSM**

X00 is a security sidecar that protects application secrets at the kernel level. Unlike traditional secret management that mounts secrets into container filesystems, X00 injects secrets directly into process memory at runtime and uses BPF-LSM to prevent unauthorized access—even from root users inside the container.

## 🎯 Key Features

- **Zero-Mount Secrets**: Secrets are never mounted into the container filesystem
- **Runtime Injection**: Secrets are injected on-demand when target processes start
- **Kernel-Level Protection**: BPF-LSM blocks reads from `/proc/<pid>/environ` and `/proc/<pid>/mem`
- **Ptrace Prevention**: Blocks debuggers from attaching to protected processes
- **Container-Aware**: Integrates with Kubernetes namespaces and cgroups
- **No Code Changes**: Applications read secrets from environment variables as usual

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                          Kubernetes Node                            │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │                          Pod                                    │ │
│  │  ┌─────────────────────┐    ┌────────────────────────────────┐ │ │
│  │  │   Application        │    │         X00 Sidecar            │ │ │
│  │  │   Container          │    │  ┌─────────────────────────┐  │ │ │
│  │  │                      │    │  │    BPF Manager          │  │ │ │
│  │  │  ┌────────────────┐  │    │  │  • Exec Monitor         │  │ │ │
│  │  │  │  Your App      │  │    │  │  • LSM Hooks            │  │ │ │
│  │  │  │                │◄─┼────┼──┤  • Event Processing     │  │ │ │
│  │  │  │  Reads secrets │  │    │  └─────────────────────────┘  │ │ │
│  │  │  │  from ENV      │  │    │  ┌─────────────────────────┐  │ │ │
│  │  │  └────────────────┘  │    │  │    Secret Injector      │  │ │ │
│  │  │                      │    │  │  • Memory injection     │  │ │ │
│  │  │  NO secrets mounted  │    │  │  • Secret resolution    │  │ │ │
│  │  │  in filesystem!      │    │  └─────────────────────────┘  │ │ │
│  │  └─────────────────────┘    │  ┌─────────────────────────┐  │ │ │
│  │                              │  │    Policy Manager       │  │ │ │
│  │                              │  │  • Config loading       │  │ │ │
│  │                              │  │  • Secret bindings      │  │ │ │
│  │                              │  └─────────────────────────┘  │ │ │
│  │                              └────────────────────────────────┘ │ │
│  └────────────────────────────────────────────────────────────────┘ │
│                                                                     │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │                        Linux Kernel                            │ │
│  │  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────┐ │ │
│  │  │ exec_monitor.bpf │  │ lsm_file_protect │  │  Ring Buffer │ │ │
│  │  │ • Tracepoint:    │  │ • LSM: file_open │  │  • Events    │ │ │
│  │  │   sys_enter_     │  │ • LSM: ptrace_   │  │    to user   │ │ │
│  │  │   execve         │  │   access_check   │  │    space     │ │ │
│  │  └──────────────────┘  └──────────────────┘  └──────────────┘ │ │
│  └────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────┘
```

## 🔒 How It Works

### 1. Process Detection
When a new process starts in the container, the eBPF tracepoint attached to `sys_enter_execve` captures the event and sends it to user space via ring buffer.

### 2. Secret Injection
X00 checks if the process matches any configured secret bindings. If so, it injects the secrets into the process memory, making them available as environment variables.

### 3. Kernel Protection
BPF-LSM hooks prevent any process (including root) from:
- Reading `/proc/<pid>/environ` of protected processes
- Reading `/proc/<pid>/mem` of protected processes
- Attaching ptrace to protected processes

### 4. Policy Enforcement
X00 supports three enforcement modes:
- **Disabled**: No protection, useful for debugging
- **Audit**: Log access attempts but don't block
- **Enforce**: Block and log unauthorized access

## 📋 Requirements

- **Kernel**: Linux ≥ 5.7 with BPF-LSM enabled
- **Kernel Config**:
  ```
  CONFIG_BPF=y
  CONFIG_BPF_SYSCALL=y
  CONFIG_BPF_LSM=y
  CONFIG_DEBUG_INFO_BTF=y
  ```
- **Kubernetes**: 1.20+ (tested on 1.28)
- **Container Runtime**: containerd, CRI-O

### Checking BPF-LSM Support

```bash
# Check if BPF LSM is enabled
cat /sys/kernel/security/lsm
# Should include "bpf" in the output

# Check BTF availability
ls /sys/kernel/btf/vmlinux
```

## 🚀 Quick Start

### 1. Build X00

```bash
# Clone the repository
git clone https://github.com/yourorg/x00.git
cd x00

# Build using Docker (recommended)
make docker-dev

# Or build locally (requires clang, llvm, bpftool)
make all
```

### 2. Deploy to Kubernetes

```bash
# Create namespace and RBAC
kubectl apply -f deploy/manifests/namespace.yaml

# Deploy configuration
kubectl apply -f deploy/manifests/configmap.yaml

# Deploy as DaemonSet (node-wide) or use sidecar pattern
kubectl apply -f deploy/manifests/daemonset.yaml
```

### 3. Deploy Your Application with X00 Sidecar

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: myapp
spec:
  shareProcessNamespace: true  # Required!
  containers:
  - name: myapp
    image: myapp:latest
    # No secret mounts needed!
  - name: x00
    image: your-registry/x00:latest
    securityContext:
      privileged: true
      capabilities:
        add: [SYS_ADMIN, BPF, SYS_PTRACE, PERFMON]
    volumeMounts:
    - name: x00-config
      mountPath: /etc/x00
```

## ⚙️ Configuration

X00 is configured via YAML file (`/etc/x00/config.yaml`):

```yaml
version: v1

policy:
  mode: enforce          # disabled, audit, enforce
  blockEnviron: true     # Block /proc/*/environ
  blockMem: true         # Block /proc/*/mem
  blockPtrace: true      # Block ptrace
  allowSelfRead: true    # Allow process to read own /proc

secrets:
  - name: database-creds
    selector:
      binary: "postgres"   # Match by binary name
    secretRefs:
      - name: PGPASSWORD
        source:
          secretKeyRef:
            name: db-credentials
            key: password

monitoring:
  enabled: true
  metricsPort: 9090
  logLevel: info
```

### Secret Sources

X00 supports multiple secret sources:

```yaml
secretRefs:
  # From Kubernetes Secret
  - name: DB_PASSWORD
    source:
      secretKeyRef:
        name: my-secret
        key: password
  
  # From file (e.g., Vault Agent sidecar)
  - name: API_KEY
    source:
      fileRef: "/vault/secrets/api-key"
  
  # From environment variable
  - name: TOKEN
    source:
      envRef: "SOURCE_TOKEN"
```

## 🔍 Observability

### Metrics (Prometheus)

X00 exposes metrics on `:9090/metrics`:

- `x00_exec_events_total` - Total exec events processed
- `x00_secrets_injected_total` - Total secrets injected
- `x00_access_blocked_total` - Total blocked access attempts
- `x00_access_audit_total` - Total audited access attempts

### Logs

```bash
# View X00 logs
kubectl logs -n x00-system -l app.kubernetes.io/name=x00 -f

# Example output:
# 🚀 Starting X00 Sidecar - Secret Protection System
# ✅ Exec monitor BPF programs loaded and attached
# ✅ LSM BPF programs loaded and attached
# 📍 EXEC: PID=1234 Comm=postgres File=/usr/bin/postgres
# 💉 Secrets injected into PID 1234: [PGPASSWORD]
# 🛡️ LSM BLOCKED: PID=5678 attempted environ access to PID=1234 (cat)
```

## 🧪 Testing

### Verify Protection

```bash
# Deploy a test pod with X00
kubectl apply -f deploy/x00-sidecar.yaml

# Try to read environ from another process (should be blocked)
kubectl exec -it x00-demo -c myapp -- sh
$ cat /proc/1/environ
cat: /proc/1/environ: Operation not permitted
```

### Run Unit Tests

```bash
make test
```

## 🔧 Development

### Project Structure

```
x00/
├── bpf/                    # eBPF programs
│   ├── exec_monitor.bpf.c  # Process execution monitor
│   ├── lsm_file_protect.bpf.c  # LSM hooks for file protection
│   ├── vmlinux.h           # Kernel type definitions
│   └── x00_common.h        # Shared types
├── cmd/
│   └── main.go             # Entry point
├── internal/
│   ├── bpf/                # BPF loader and management
│   ├── secrets/            # Secret injection
│   ├── types/              # Shared Go types
│   └── policy.go           # Policy management
├── deploy/                 # Kubernetes manifests
├── examples/               # Example configurations
├── Dockerfile
├── Makefile
└── README.md
```

### Building Locally

```bash
# Install dependencies
make install-deps

# Generate vmlinux.h from kernel BTF
make vmlinux

# Compile BPF programs
make bpf

# Build Go binary
make build

# Run locally (requires root)
sudo ./build/x00 -config examples/config.yaml
```

## ⚠️ Security Considerations

1. **Privileged Container**: X00 requires privileged access to load BPF programs
2. **Shared Process Namespace**: Pods must set `shareProcessNamespace: true`
3. **Kernel Requirements**: BPF-LSM must be enabled in the kernel
4. **Trust Model**: X00 sidecar is trusted; ensure image integrity

## 📜 License

Apache License 2.0

## 🤝 Contributing

Contributions welcome! Please read CONTRIBUTING.md for guidelines.

## 📚 References

- [BPF LSM Documentation](https://docs.kernel.org/bpf/prog_lsm.html)
- [Cilium eBPF Library](https://github.com/cilium/ebpf)
- [Linux Security Modules](https://www.kernel.org/doc/html/latest/admin-guide/LSM/index.html)
