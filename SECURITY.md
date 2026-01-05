# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

We take security seriously. If you discover a security vulnerability in X00, please report it responsibly.

### How to Report

1. **DO NOT** create a public GitHub issue for security vulnerabilities
2. Email security concerns to: [security@example.com](mailto:security@example.com)
3. Include the following information:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### What to Expect

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 7 days
- **Resolution Timeline**: Depends on severity
  - Critical: 7-14 days
  - High: 30 days
  - Medium: 60 days
  - Low: 90 days

### Scope

The following are in scope for security reports:

- X00 sidecar binary and its dependencies
- BPF programs (exec_monitor, lsm_file_protect)
- Secret injection mechanisms
- Policy enforcement bypass
- Container escape via X00
- Privilege escalation

### Out of Scope

- Vulnerabilities in dependencies without a working exploit
- Theoretical attacks without proof of concept
- Social engineering attacks
- Denial of service attacks
- Issues in unsupported versions

## Security Considerations

### BPF Program Security

X00's BPF programs run in kernel space. Security measures include:

1. **Verifier Protection**: All BPF programs pass the kernel verifier
2. **Bounded Loops**: All loops are bounded to prevent infinite execution
3. **Memory Safety**: All memory accesses are verified by the BPF verifier
4. **Minimal Attack Surface**: Programs only hook necessary syscalls

### Secret Management

1. **No Persistent Storage**: Secrets are never written to disk in plain text
2. **Memory-Only Injection**: Secrets use `memfd_create` for in-memory files
3. **Process Isolation**: Injected secrets are only accessible to target processes
4. **Kernel Protection**: BPF-LSM blocks unauthorized access to `/proc/*/environ` and `/proc/*/mem`

### Container Security

1. **Privileged Mode**: X00 requires privileged mode for BPF operations
2. **Capability Restrictions**: Only necessary capabilities should be granted:
   - `CAP_BPF` - Load BPF programs
   - `CAP_SYS_ADMIN` - Access cgroups and system resources
   - `CAP_SYS_PTRACE` - Process inspection
3. **Read-Only Root FS**: Recommended for production deployments

### Network Security

1. **No Network Listeners**: X00 does not open any network ports by default
2. **Vault Integration**: Use TLS for Vault communication
3. **mTLS**: Recommended for any external secret sources

## Security Best Practices for Deployment

### Kubernetes

```yaml
securityContext:
  privileged: true  # Required for BPF
  readOnlyRootFilesystem: true
  allowPrivilegeEscalation: false
  capabilities:
    add:
      - BPF
      - SYS_ADMIN
      - SYS_PTRACE
    drop:
      - ALL
```

### Policy Configuration

```yaml
# Always use enforce mode in production
policy:
  mode: enforce  # Not "audit"
  block_environ_read: true
  block_mem_read: true
  block_ptrace: true
```

## Security Scanning

This repository includes automated security scanning:

- **gosec**: Static analysis for Go security issues
- **trivy**: Container vulnerability scanning
- **CodeQL**: GitHub's semantic code analysis
- **Dependabot**: Dependency vulnerability alerts

## Hardening Checklist

- [ ] Run X00 with minimal required capabilities
- [ ] Use read-only root filesystem
- [ ] Enable enforce mode (not audit)
- [ ] Configure proper RBAC in Kubernetes
- [ ] Use network policies to restrict X00's network access
- [ ] Regularly update to latest version
- [ ] Monitor X00 audit logs
- [ ] Use separate service account for X00
- [ ] Rotate secrets regularly
- [ ] Enable seccomp profiles where possible

## License

X00 BPF programs are dual-licensed under GPL-2.0 OR BSD-3-Clause as required for BPF programs. The userspace components are licensed under Apache-2.0.
