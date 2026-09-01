FROM golang:1.27.0-alpine AS builder

ARG VERSION

WORKDIR /build
COPY . .
RUN apk add --no-cache git upx && \
    CGO_ENABLED=0 go build -ldflags="-s -w -X 'github.com/prometheus/common/version.Version=$VERSION'" \
        -trimpath -o dnscollector dnscollector.go && \
    upx --best --lzma dnscollector

# Prepare runtime directories and passwd/group for non-root user
RUN mkdir -p /rootfs/etc/dnscollector /rootfs/var/dnscollector && \
    echo "dnscollector:x:1000:1000::/:" > /rootfs/etc/passwd && \
    echo "dnscollector:x:1000:" > /rootfs/etc/group && \
    chown -R 1000:1000 /rootfs/etc/dnscollector /rootfs/var/dnscollector

FROM gcr.io/distroless/static-debian13:nonroot

# Runtime directories
COPY --from=builder --chown=1000:1000 /rootfs/etc/dnscollector /etc/dnscollector
COPY --from=builder --chown=1000:1000 /rootfs/var/dnscollector /var/dnscollector

# Binary and default config
COPY --from=builder /build/dnscollector /bin/dnscollector
COPY --from=builder /build/docker-config.yml /etc/dnscollector/config.yml

USER 1000

EXPOSE 6000/tcp 8080/tcp 9165/tcp

ENTRYPOINT ["/bin/dnscollector"]

CMD ["-config", "/etc/dnscollector/config.yml"]
