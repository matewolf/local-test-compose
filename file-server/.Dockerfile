FROM golang:1.24.4 AS builder

WORKDIR /app

# Install dependencies first for better build caching
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the source and build the binary
COPY . .
RUN go build -o file-server .

# Runtime image
FROM debian:bookworm-slim

WORKDIR /app

# Copy the compiled binary from the builder stage
COPY --from=builder /app/file-server /app/file-server

# The server listens on these ports, matching docker-compose.loads.yaml
EXPOSE 9000 9100 9200

# Run with the same flags used in docker-compose.loads.yaml
CMD ["/app/file-server", "-http-port", "9000", "-http2-port", "9100", "-tcp-port", "9200", "-tls"]
