# Multi-stage build for kyrecovery-server
FROM golang:1.27.1-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o kyrecovery cmd/kyrecovery/main.go

FROM alpine:3.24
RUN apk --no-cache add ca-certificates tzdata su-exec

# KyRecovery needs no privilege beyond its own data directory, so it does not get
# any at runtime. The uid is fixed so a bind-mounted ./data can be chowned to
# match; docker-entrypoint.sh does that chown (needs root) then drops to this
# user before the app itself ever runs. The entrypoint and binary stay
# root-owned so the app user cannot rewrite what root executes next boot.
RUN addgroup -g 10001 -S kyrecovery && \
    adduser -u 10001 -S -G kyrecovery -h /app kyrecovery

WORKDIR /app
COPY --from=builder /app/kyrecovery /app/kyrecovery
COPY docker-entrypoint.sh /app/docker-entrypoint.sh
RUN chmod 0755 /app/docker-entrypoint.sh /app/kyrecovery && \
    mkdir -p /app/data && chown kyrecovery:kyrecovery /app/data

EXPOSE 8095
VOLUME ["/app/data"]

# serve is the default, not the only command: `docker run <image> audit` and
# `docker run <image> help` have to reach the CLI, so the subcommand is CMD.
ENTRYPOINT ["/app/docker-entrypoint.sh"]
CMD ["serve", "--port", "8095", "--data-dir", "/app/data"]
