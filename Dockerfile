# syntax=docker/dockerfile:1

FROM golang:1.24-alpine AS builder

RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Pure-Go build: no CGO, no C toolchain needed — this is the whole
# point of the modernc.org/sqlite (via glebarez/sqlite) driver swap.
RUN CGO_ENABLED=0 GOOS=linux go build -o breachharbor ./cmd/breachharbor

FROM alpine:latest

RUN apk --no-cache add ca-certificates tzdata

RUN adduser -D -s /bin/sh breach
ENV HOME=/home/breach
WORKDIR /home/breach

COPY --from=builder /app/breachharbor .
COPY --from=builder /app/templates ./templates
COPY --from=builder /app/static ./static
COPY --from=builder /app/.env.example ./.env.example

# Matches internal/cli's default agent data directory for a non-root
# user (see internal/cli/doctor_cmd.go's defaultDataDir), so `doctor`
# reports a clean environment out of the box.
RUN mkdir -p .local/state/breachharbor data && chown -R breach:breach /home/breach

USER breach

EXPOSE 8080

# doctor is a real, root-free, network-declaring command — reusing it
# here means the healthcheck exercises the same code path an operator
# would run by hand, instead of a bespoke /health endpoint.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["./breachharbor", "doctor", "--json"]

# `server run` lands in M2; until then this container builds and its
# healthcheck passes, but starting it will report "not implemented yet".
CMD ["./breachharbor", "server", "run"]
