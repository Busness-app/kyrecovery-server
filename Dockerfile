# Multi-stage build for kyrecovery-server
FROM golang:1.24-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o kyrecovery cmd/kyrecovery/main.go

FROM alpine:3.21
RUN apk --no-cache add ca-certificates tzdata

WORKDIR /app
COPY --from=builder /app/kyrecovery /app/kyrecovery

EXPOSE 8095
VOLUME ["/app/data"]

ENTRYPOINT ["/app/kyrecovery", "serve", "--port", "8095", "--data-dir", "/app/data"]
