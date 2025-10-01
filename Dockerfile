FROM golang:1.25.1-alpine as builder

ARG VERSION

WORKDIR /build
COPY . .
RUN apk add git && \ 
    CGO_ENABLED=0 go build -ldflags="-s -w -X 'github.com/prometheus/common/version.Version=$VERSION'"

FROM alpine:3.22.1

RUN apk add --no-cache tzdata \
    && mkdir -p /etc/dnscollector/ /var/dnscollector/ \
    && addgroup -g 1000 dnscollector && adduser -D -H -G dnscollector -u 1000 -S dnscollector \
    && chown dnscollector:dnscollector /var/dnscollector /etc/dnscollector

USER dnscollector

COPY --from=builder /build/go-dnscollector /bin/dnscollector
COPY --from=builder /build/docker-config.yml ./etc/dnscollector/config.yml

EXPOSE 6000/tcp 8080/tcp 9165/tcp

ENTRYPOINT ["/bin/dnscollector"]

CMD ["-config", "/etc/dnscollector/config.yml"]
