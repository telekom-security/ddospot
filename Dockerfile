# syntax=docker/dockerfile:1
#
# The builder runs on the build platform and cross-compiles, Go under QEMU
# emulation crashes
FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS builder
ARG TARGETOS
ARG TARGETARCH
RUN apk --no-cache add ca-certificates
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go test ./... && \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /ddospot ./cmd/ddospot && \
    mkdir -p /logdir
#
FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /ddospot /ddospot
# The log folder belongs to the user, so a volume mounted there starts
# writable for it
COPY --from=builder --chown=2000:2000 /logdir /var/log/ddospot
#
# Start ddospot
STOPSIGNAL SIGTERM
USER 2000:2000
ENTRYPOINT ["/ddospot"]
