# Multi-stage build for kyrecovery-server
FROM golang:1.26.6-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o kyrecovery cmd/kyrecovery/main.go

FROM alpine:3.24
RUN apk --no-cache add ca-certificates tzdata

# KyRecovery needs no privilege beyond its own data directory, so it does not get
# any. The uid is fixed so a bind-mounted ./data can be chowned to match.
RUN addgroup -g 10001 -S kyrecovery && \
    adduser -u 10001 -S -G kyrecovery -h /app kyrecovery

WORKDIR /app
COPY --from=builder /app/kyrecovery /app/kyrecovery
RUN mkdir -p /app/data && chown -R kyrecovery:kyrecovery /app

USER kyrecovery

EXPOSE 8095
VOLUME ["/app/data"]

# serve is the default, not the only command: `docker run <image> audit` and
# `docker run <image> help` have to reach the CLI, so the subcommand is CMD.
ENTRYPOINT ["/app/kyrecovery"]
CMD ["serve", "--port", "8095", "--data-dir", "/app/data"]
