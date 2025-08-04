# Multi-stage build for PegaSpy Phase 4 Go Backend
FROM golang:1.21-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o pegaspy-server cmd/pegaspy-server/main.go

# Final stage - minimal runtime image
FROM alpine:latest

# Install runtime dependencies
RUN apk --no-cache add ca-certificates tzdata

# Create non-root user
RUN addgroup -g 1001 -S pegaspy && \
    adduser -u 1001 -S pegaspy -G pegaspy

# Set working directory
WORKDIR /app

# Copy binary from builder stage
COPY --from=builder /app/pegaspy-server .

# Copy configuration files if any
COPY --from=builder /app/configs ./configs

# Change ownership to non-root user
RUN chown -R pegaspy:pegaspy /app

# Switch to non-root user
USER pegaspy

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1

# Run the application
CMD ["./pegaspy-server"]

# Metadata
LABEL maintainer="PegaSpy Team" \
      version="4.0.0" \
      description="PegaSpy Phase 4 - Advanced Security Detection Backend" \
      org.opencontainers.image.source="https://github.com/pegaspy/pegaspy" \
      org.opencontainers.image.documentation="https://docs.pegaspy.com" \
      org.opencontainers.image.licenses="MIT"