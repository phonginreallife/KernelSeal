# KernelSeal All-in-One Demo Image
# Uses pre-built BPF objects from host

FROM golang:1.25-bookworm AS builder

# Install minimal BPF dependencies for compilation
RUN apt-get update && apt-get install -y \
    clang \
    llvm \
    libbpf-dev \
    make \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy source code
COPY . .

# Try to build BPF (may use pre-built objects if compilation fails)
RUN make bpf 2>/dev/null || echo "Using pre-built BPF objects"

# Build Go binary
RUN CGO_ENABLED=0 go build -o kernelseal ./cmd/main.go

# Runtime image
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    libbpf1 \
    procps \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy binary and BPF objects
COPY --from=builder /app/kernelseal /app/kernelseal
COPY --from=builder /app/bpf/*.bpf.o /app/bpf/

# Copy entrypoint
COPY demo/docker-entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Create config directory
RUN mkdir -p /etc/kernelseal

ENTRYPOINT ["/entrypoint.sh"]
