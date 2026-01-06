# KernelSeal

**Kernel-level Secret Protection for Kubernetes using eBPF and BPF-LSM**

KernelSeal is a security sidecar that protects application secrets at the kernel level. Unlike traditional secret management that mounts secrets into container filesystems, KernelSeal injects secrets directly into process memory at runtime and uses BPF-LSM to prevent unauthorized access, even from root users inside the container.

## Key Features

- **Zero-Mount Secrets**: Secrets are never mounted into the container filesystem
- **Runtime Injection**: Secrets are injected on-demand when target processes start
- **Kernel-Level Protection**: BPF-LSM blocks reads from `/proc/<pid>/environ` and `/proc/<pid>/mem`
- **Ptrace Prevention**: Blocks debuggers from attaching to protected processes
- **Container-Aware**: Integrates with Kubernetes namespaces and cgroups
- **No Code Changes**: Applications read secrets from environment variables as usual
- **Kernel-Side Filtering**: Optional binary filtering in kernel space reduces CPU overhead


## How It Works

### 1. Process Detection
When a new process starts, the eBPF tracepoint attached to `sys_enter_execve` (or `sched_process_exec` when kernel filtering is enabled) captures the event and sends it to user space via ring buffer.

### 2. Secret Injection
KernelSeal checks if the process matches any configured secret bindings (by binary name). If so, it injects the secrets into the process, making them available via file-based secret delivery.

### 3. Kernel Protection
BPF-LSM hooks prevent any process (including root) from:
- Reading `/proc/<pid>/environ` of protected processes
- Reading `/proc/<pid>/mem` of protected processes
- Attaching ptrace to protected processes

### 4. Policy Enforcement
KernelSeal supports three enforcement modes:
- **Disabled**: No protection, useful for debugging
- **Audit**: Log access attempts but don't block
- **Enforce**: Block and log unauthorized access

## Requirements

- **Kernel**: Linux >= 5.7 with BPF-LSM enabled
- **Kernel Config**:
  ```
  CONFIG_BPF=y
  CONFIG_BPF_SYSCALL=y
  CONFIG_BPF_LSM=y
  CONFIG_DEBUG_INFO_BTF=y
  ```
- **Boot Parameters**: `lsm=lockdown,capability,yama,bpf` (ensure `bpf` is in the list)
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

## Quick Start

### Option 1: Run with Docker (for testing)

```bash
# Pull the image
docker pull ghcr.io/phonginreallife/kernelseal:latest

# Create a config file
cat > /tmp/kernelseal-config.yaml << 'EOF'
version: v1
policy:
  mode: enforce
  blockEnviron: true
  blockMem: true
  blockPtrace: true
  allowSelfRead: true
  kernelBinaryFilter: false

secrets:
  - name: test-secrets
    selector:
      binary: "sleep"
    secretRefs:
      - name: MY_SECRET
        source:
          envRef: "KernelSeal_MY_SECRET"
EOF

# Run KernelSeal
docker run -d --name kernelseal \
  --privileged \
  --pid=host \
  -v /sys/kernel/security:/sys/kernel/security:ro \
  -v /tmp/kernelseal-config.yaml:/etc/kernelseal/config.yaml:ro \
  -e KernelSeal_MY_SECRET="secret-value-here" \
  ghcr.io/phonginreallife/kernelseal:latest

# View logs
docker logs -f kernelseal
```

### Option 2: Build from Source

```bash
# Clone the repository
git clone https://github.com/phonginreallife/kernelseal.git
cd kernelseal

# Build using Docker (recommended)
make docker-build

# Or build locally (requires clang, llvm, bpftool)
make all

# Run locally (requires root)
sudo ./build/kernelseal -config examples/config.yaml
```

### Option 3: Deploy to Kubernetes

```bash
# Create namespace and RBAC
kubectl apply -f deploy/manifests/namespace.yaml

# Deploy configuration
kubectl apply -f deploy/manifests/configmap.yaml

# Deploy as DaemonSet (node-wide) or use sidecar pattern
kubectl apply -f deploy/manifests/daemonset.yaml
```

### Deploy Your Application with KernelSeal Sidecar

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
  - name: kernelseal
    image: ghcr.io/phonginreallife/kernelseal:latest
    securityContext:
      privileged: true
      capabilities:
        add: [SYS_ADMIN, BPF, SYS_PTRACE, PERFMON]
    volumeMounts:
    - name: kernelseal-config
      mountPath: /etc/kernelseal
    - name: kernel-security
      mountPath: /sys/kernel/security
      readOnly: true
  volumes:
  - name: kernelseal-config
    configMap:
      name: kernelseal-config
  - name: kernel-security
    hostPath:
      path: /sys/kernel/security
```

## Configuration

KernelSeal is configured via YAML file (`/etc/kernelseal/config.yaml`):

```yaml
version: v1

policy:
  mode: enforce              # disabled, audit, enforce
  blockEnviron: true         # Block /proc/*/environ
  blockMem: true             # Block /proc/*/mem
  blockMaps: false           # Block /proc/*/maps
  blockPtrace: true          # Block ptrace
  allowSelfRead: true        # Allow process to read own /proc
  auditAll: false            # Log all accesses (even allowed)
  kernelBinaryFilter: true   # Enable kernel-side binary filtering

secrets:
  - name: database-creds
    selector:
      binary: "postgres"     # Match by binary name
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

### Kernel-Side Binary Filtering

When `kernelBinaryFilter: true`, KernelSeal only processes exec events for binaries listed in your `secrets` configuration. This significantly reduces CPU overhead on busy systems.

| Setting | Behavior | Use Case |
|---------|----------|----------|
| `false` | Monitor ALL processes | Development, debugging |
| `true` | Monitor only configured binaries | Production (recommended) |

### Secret Sources

KernelSeal supports multiple secret sources:

```yaml
secretRefs:
  # From Kubernetes Secret (mounted as file)
  - name: DB_PASSWORD
    source:
      secretKeyRef:
        name: my-secret
        key: password
  
  # From file (e.g., Vault Agent sidecar)
  - name: API_KEY
    source:
      fileRef: "/vault/secrets/api-key"
  
  # From environment variable (KernelSeal's own environment)
  - name: TOKEN
    source:
      envRef: "SOURCE_TOKEN"
```

## Observability

### Logs

```bash
# View KernelSeal logs
kubectl logs -n kernelseal-system -l app.kubernetes.io/name=kernelseal -f

# Or with Docker
docker logs -f kernelseal
```

Example output:
```
[START] Starting KernelSeal Sidecar - Secret Protection System
   Version: 0.1.0
   Config: /etc/kernelseal/config.yaml
[CONFIG] Loaded KernelSeal configuration from /etc/kernelseal/config.yaml
[CONFIG] Policy applied: mode=enforce
[REGISTER] Registered 2 secrets for binary: sleep
[OK] Exec monitor BPF programs loaded and attached
[FILTER] Kernel-side binary filtering DISABLED by config - monitoring all processes
[OK] LSM BPF programs loaded and attached
[ALLOW] PID 1234 added to allowed list
[CONFIG] Policy configured: mode=enforce, environ=true, mem=true, ptrace=true
[OK] KernelSeal Sidecar running - monitoring for process execution

[EXEC] PID=5678 PPID=1234 Comm=sleep File=/usr/bin/sleep Binary=sleep CgroupID=7194
[FILE] Secrets written to /run/kernelseal/secrets/5678 for PID 5678
[PROTECT] PID 5678 marked as protected
[INJECT] Secrets injected into PID 5678: [MY_SECRET]

[LSM BLOCKED] PID=9999 attempted environ access to PID=5678 (cat)
```

### Metrics (Prometheus)

KernelSeal exposes metrics on `:9090/metrics`:

- `kernelseal_exec_events_total` - Total exec events processed
- `kernelseal_secrets_injected_total` - Total secrets injected
- `kernelseal_access_blocked_total` - Total blocked access attempts
- `kernelseal_access_audit_total` - Total audited access attempts

## Testing

### Verify Protection Works

```bash
# Start a protected process
sleep 300 &
SLEEP_PID=$!
echo "Sleep PID: $SLEEP_PID"

# Wait for injection
sleep 3

# Try to read environ (should be BLOCKED)
cat /proc/$SLEEP_PID/environ
# Expected: cat: /proc/XXXX/environ: Operation not permitted
```

### Run Unit Tests

```bash
make test
```

## Development

### Project Structure

```
kernelseal/
├── .github/                # CI/CD workflows
│   ├── workflows/
│   │   ├── ci.yaml         # Build and test
│   │   └── release.yaml    # Docker image publishing
│   └── dependabot.yml      # Dependency updates
├── bpf/                    # eBPF programs
│   ├── exec_monitor.bpf.c  # Process execution monitor
│   ├── lsm_file_protect.bpf.c  # LSM hooks for file protection
│   ├── vmlinux.h           # Kernel type definitions
│   └── kernelseal_common.h        # Shared types
├── cmd/
│   └── main.go             # Entry point
├── internal/
│   ├── bpf/                # BPF loader and management
│   │   └── loader.go
│   ├── secrets/            # Secret injection
│   │   └── injector.go
│   ├── types/              # Shared Go types
│   │   └── events.go
│   └── policy.go           # Policy management
├── deploy/                 # Kubernetes manifests
│   ├── manifests/
│   └── kernelseal-sidecar.yaml
├── demo/                   # Demo scripts
├── examples/               # Example configurations
│   └── config.yaml
├── scripts/                # Build and utility scripts
├── test/                   # Integration tests
│   └── integration/
├── Dockerfile              # Multi-stage Docker build
├── Makefile                # Build automation
├── SECURITY.md             # Security policy
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
sudo ./build/kernelseal -config examples/config.yaml
```

### Building Docker Image

```bash
# Build image
make docker-build

# Tag and push (CI does this automatically on release)
docker tag kernelseal:latest ghcr.io/yourorg/kernelseal:v1.0.0
docker push ghcr.io/yourorg/kernelseal:v1.0.0
```

## Security Considerations

1. **Privileged Container**: KernelSeal requires privileged access to load BPF programs
2. **Shared Process Namespace**: Pods must set `shareProcessNamespace: true`
3. **Kernel Requirements**: BPF-LSM must be enabled in the kernel
4. **Trust Model**: KernelSeal sidecar is trusted; ensure image integrity
5. **Secret Storage**: KernelSeal reads secrets from its own environment or mounted files; protect these sources

### Security Scanning

The CI pipeline includes:
- **gosec**: Go security linting
- **govulncheck**: Go vulnerability scanning
- **Trivy**: Container image scanning
- **Hadolint**: Dockerfile linting
- **Gitleaks**: Secret detection in code


## License

Apache License 2.0

## Contributing

Contributions welcome! Please read CONTRIBUTING.md for guidelines.

## References

- [BPF LSM Documentation](https://docs.kernel.org/bpf/prog_lsm.html)
- [Cilium eBPF Library](https://github.com/cilium/ebpf)
- [Linux Security Modules](https://www.kernel.org/doc/html/latest/admin-guide/LSM/index.html)
