# Security Policy

## Table of Contents

- [Supported Versions](#supported-versions)
- [Reporting a Vulnerability](#reporting-a-vulnerability)
- [Threat Model](#threat-model)
- [Security Architecture](#security-architecture)
- [Security Controls](#security-controls)
- [Deployment Security](#deployment-security)
- [Supply Chain Security](#supply-chain-security)
- [Incident Response](#incident-response)
- [Hardening Checklist](#hardening-checklist)
- [License](#license)

## Supported Versions

| Version | Supported | Notes |
|---------|-----------|-------|
| 1.x.x   | Yes | Current stable release |
| 0.x.x   | Limited | Security fixes only |

We recommend always running the latest stable version.

## Reporting a Vulnerability

We take security seriously. If you discover a security vulnerability in KernelSeal, please report it responsibly.

### How to Report

1. **DO NOT** create a public GitHub issue for security vulnerabilities
2. Use GitHub's private vulnerability reporting: [Report a vulnerability](../../security/advisories/new)
3. Or email: phonginreallife@gmail.com

### Required Information

Please include:

| Field | Description |
|-------|-------------|
| **Summary** | Brief description of the vulnerability |
| **Severity** | Your assessment (Critical/High/Medium/Low) |
| **Affected Components** | Which parts of KernelSeal are affected |
| **Steps to Reproduce** | Detailed reproduction steps |
| **Impact** | What an attacker could achieve |
| **Proof of Concept** | Code, logs, or screenshots if available |
| **Suggested Fix** | Optional remediation suggestions |

### Response Timeline

| Phase | Timeline |
|-------|----------|
| Acknowledgment | Within 48 hours |
| Initial Assessment | Within 7 days |
| Status Update | Every 7 days until resolved |

**Resolution by Severity:**

| Severity | CVSS Score | Resolution Target |
|----------|------------|-------------------|
| Critical | 9.0 - 10.0 | 7 days |
| High | 7.0 - 8.9 | 14 days |
| Medium | 4.0 - 6.9 | 30 days |
| Low | 0.1 - 3.9 | 60 days |

### Scope

**In Scope:**

- KernelSeal sidecar binary and dependencies
- BPF programs (`exec_monitor.bpf.c`, `lsm_file_protect.bpf.c`)
- Secret injection mechanisms
- Policy enforcement bypass
- Container/VM escape via KernelSeal
- Privilege escalation
- Information disclosure
- Authentication/authorization bypass

**Out of Scope:**

- Vulnerabilities requiring physical access
- Social engineering attacks
- Denial of service without security impact
- Issues in unsupported versions
- Third-party dependencies without working exploit

## Threat Model

### Assets Protected

1. **Application Secrets** - API keys, database credentials, tokens
2. **Process Memory** - Runtime secret storage
3. **Kernel Integrity** - BPF program execution environment

### Threat Actors

| Actor | Capability | Motivation |
|-------|------------|------------|
| Compromised Container | Root access within container | Steal secrets from other processes |
| Malicious Insider | Cluster access | Exfiltrate sensitive data |
| Supply Chain Attacker | Inject malicious code | Backdoor deployments |
| Adjacent Pod | Network access | Lateral movement |

### Attack Vectors

```
┌─────────────────────────────────────────────────────────────────┐
│                     Attack Surface                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐       │
│  │ /proc/*/     │    │ ptrace()     │    │ Environment  │       │
│  │ environ,mem  │    │ syscall      │    │ Variables    │       │
│  └──────┬───────┘    └──────┬───────┘    └──────┬───────┘       │
│         │                   │                   │               │
│         └─────────┬─────────┴─────────┬─────────┘               │
│                   │                   │                         │
│                   ▼                   ▼                         │
│         ┌─────────────────────────────────────┐                 │
│         │         BPF-LSM Protection          │                 │
│         │   (Kernel-level Access Control)     │                 │
│         └─────────────────────────────────────┘                 │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Mitigations by Attack Vector

| Attack Vector | Protection | Implementation |
|---------------|------------|----------------|
| `/proc/*/environ` read | BPF-LSM `file_open` hook | Blocks unauthorized readers |
| `/proc/*/mem` read | BPF-LSM `file_open` hook | Blocks memory inspection |
| `ptrace` attach | BPF-LSM `ptrace_access_check` | Prevents debugger attach |
| Environment inheritance | Process-specific injection | Secrets not in parent env |
| Container escape | Kernel verification | BPF verifier guarantees |

## Security Architecture

### Defense in Depth

```
┌─────────────────────────────────────────────────────────────────┐
│ Layer 1: Kubernetes Security                                    │
│ - RBAC, Network Policies, Pod Security Standards                │
├─────────────────────────────────────────────────────────────────┤
│ Layer 2: Container Security                                     │
│ - Read-only filesystem, Dropped capabilities, Seccomp           │
├─────────────────────────────────────────────────────────────────┤
│ Layer 3: KernelSeal Application                                 │
│ - Policy enforcement, Binary filtering, Audit logging           │
├─────────────────────────────────────────────────────────────────┤
│ Layer 4: BPF-LSM Kernel Protection                              │
│ - Mandatory access control, Syscall interception                │
└─────────────────────────────────────────────────────────────────┘
```

### BPF Program Security

KernelSeal's BPF programs run in kernel space with strict safety guarantees:

| Control | Description |
|---------|-------------|
| **Verifier Protection** | All programs pass Linux kernel BPF verifier |
| **Bounded Execution** | No unbounded loops, guaranteed termination |
| **Memory Safety** | All memory accesses bounds-checked |
| **Type Safety** | BTF (BPF Type Format) ensures type correctness |
| **Minimal Hooks** | Only essential syscalls are intercepted |

Secret States:
1. At Rest    → Encrypted in source (Vault/K8s Secret)
2. In Transit → Memory-only transfer via memfd
3. In Use     → Protected by BPF-LSM hooks
4. Disposal   → Process termination clears memory
```

### RBAC Configuration

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: kernelseal-role
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get"]                          # Read-only secret access
    resourceNames: ["app-secrets"]          # Specific secrets only
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: kernelseal-binding
subjects:
  - kind: ServiceAccount
    name: kernelseal-sa
roleRef:
  kind: Role
  name: kernelseal-role
  apiGroup: rbac.authorization.k8s.io
```

### Network Policy

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: kernelseal-network
spec:
  podSelector:
    matchLabels:
      app: kernelseal
  policyTypes:
    - Ingress
    - Egress
  ingress: []                               # No inbound traffic
  egress:
    - to:
        - namespaceSelector:
            matchLabels:
              name: vault                   # Only Vault namespace
      ports:
        - port: 8200
          protocol: TCP
```

### Production Policy Configuration

```yaml
version: v1
policy:
  mode: enforce                             # Always enforce in production
  blockEnviron: true                        # Block /proc/*/environ
  blockMem: true                            # Block /proc/*/mem
  blockMaps: true                           # Block /proc/*/maps
  blockPtrace: true                         # Block ptrace attach
  allowSelfRead: true                       # Allow process self-inspection
  auditAll: true                            # Log all access attempts
  kernelBinaryFilter: true                  # Efficient kernel-side filtering

secrets:
  - binary: "myapp"
    envVars:
      - name: DB_PASSWORD
        source: vault
        path: secret/data/myapp/db
        key: password
```

## Supply Chain Security

### Build Verification

| Check | Tool | CI Integration |
|-------|------|----------------|
| Dependency vulnerabilities | govulncheck | Every PR |
| Container vulnerabilities | Trivy | Every build |
| Code security issues | gosec, CodeQL | Every PR |
| Secret detection | Gitleaks, TruffleHog | Every commit |
| Dockerfile best practices | Hadolint | Every PR |

### Image Signing (Recommended)

```bash
# Sign images with cosign
cosign sign --key cosign.key ghcr.io/your-org/kernelseal:v1.0.0

# Verify before deployment
cosign verify --key cosign.pub ghcr.io/your-org/kernelseal:v1.0.0
```

### SBOM Generation

```bash
# Generate Software Bill of Materials
syft ghcr.io/your-org/kernelseal:v1.0.0 -o spdx-json > sbom.json

# Scan SBOM for vulnerabilities
grype sbom:sbom.json
```

### Dependency Policy

- All dependencies pinned to specific versions
- Dependabot enabled for automated updates
- Security updates applied within 7 days
- Major version updates reviewed manually

## Incident Response

### Detection

KernelSeal provides audit logs for security monitoring:

```bash
# Monitor for blocked access attempts
kubectl logs -l app=kernelseal | grep "LSM BLOCK"

# Monitor for policy violations
kubectl logs -l app=kernelseal | grep "AUDIT"
```

### Response Playbook

**1. Suspected Secret Compromise**

```bash
# Immediate: Rotate affected secrets
vault write -force secret/data/myapp/db password=$(openssl rand -base64 32)

# Investigate: Check audit logs
kubectl logs -l app=kernelseal --since=1h | grep -E "(BLOCK|AUDIT)"

# Verify: Confirm new secrets are injected
kubectl exec -it <pod> -- env | grep -v PASSWORD  # Should not show secrets
```

**2. Unauthorized Access Attempt**

```bash
# Identify source
kubectl logs -l app=kernelseal | grep "PID=<suspicious_pid>"

# Check process details
kubectl exec -it <pod> -- cat /proc/<pid>/comm
kubectl exec -it <pod> -- cat /proc/<pid>/cmdline

# Escalate if needed
# - Container may be compromised
# - Consider pod termination and forensics
```

### Alerting Integration

```yaml
# Example: Prometheus alert for blocked access
groups:
  - name: kernelseal
    rules:
      - alert: SecretAccessBlocked
        expr: increase(kernelseal_lsm_blocks_total[5m]) > 10
        for: 1m
        labels:
          severity: warning
        annotations:
          summary: "Multiple secret access attempts blocked"
          description: "{{ $value }} access attempts blocked in last 5 minutes"
```

## Hardening Checklist

### Pre-Deployment

- [ ] Review and customize policy configuration
- [ ] Configure binary allowlist for your applications
- [ ] Set up secret source (Vault, K8s Secrets, etc.)
- [ ] Configure RBAC with least privilege
- [ ] Set up network policies
- [ ] Enable audit logging
- [ ] Configure alerting for security events

### Runtime

- [ ] KernelSeal running in `enforce` mode
- [ ] Read-only root filesystem enabled
- [ ] Unnecessary capabilities dropped
- [ ] Resource limits configured
- [ ] Liveness/readiness probes configured
- [ ] Secrets rotated on schedule

### Monitoring

- [ ] Audit logs forwarded to SIEM
- [ ] Alerts configured for blocked access
- [ ] Regular review of access patterns
- [ ] Vulnerability scanning in CI/CD
- [ ] Dependency updates monitored

### Periodic Review

- [ ] Quarterly: Review and update policies
- [ ] Monthly: Review audit logs for anomalies
- [ ] Weekly: Apply security updates
- [ ] On change: Re-validate security controls

## Security Scanning

This repository includes automated security scanning:

| Tool | Purpose | Frequency |
|------|---------|-----------|
| **gosec** | Go security static analysis | Every PR |
| **govulncheck** | Go vulnerability detection | Every PR |
| **Trivy** | Container vulnerability scanning | Every build |
| **CodeQL** | Semantic code analysis | Every PR |
| **Gitleaks** | Secret detection | Every commit |
| **Hadolint** | Dockerfile linting | Every PR |
| **Dependabot** | Dependency vulnerability alerts | Daily |

## License

KernelSeal BPF programs are dual-licensed under **GPL-2.0 OR BSD-3-Clause** as required for BPF programs.

Userspace components are licensed under **Apache-2.0**.

---

*Last updated: January 2026*
