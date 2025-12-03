FROM golang:1.25.4-alpine AS builder

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o auth-server cmd/server/main.go

# Final stage
FROM gcr.io/distroless/static-debian12

WORKDIR /app

# Copy binary and templates from builder
COPY --from=builder /app/auth-server .
COPY --from=builder /app/templates ./templates

# Run the application
CMD ["./auth-server"]
