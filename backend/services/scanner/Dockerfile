# Build stage
FROM rust:1.75 as builder

WORKDIR /app

# Copy manifests
COPY Cargo.toml ./
COPY Cargo.loc[k] ./

# Copy source
COPY src ./src

# Build release binary
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1000 scanner

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/target/release/cobra-scanner /app/

# Change ownership
RUN chown -R scanner:scanner /app

# Switch to non-root user (Note: SYN scanning requires root)
USER scanner

# Expose port
EXPOSE 8002

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8002/health || exit 1

# Run the service
CMD ["./cobra-scanner"] 