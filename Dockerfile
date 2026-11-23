# syntax=docker/dockerfile:1.7

FROM --platform=$BUILDPLATFORM golang:1.27.4-alpine AS build
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" \
    -o /out/ozgo-cf-ddns ./cmd/ozgo-cf-ddns

# Alpine instead of scratch: CUSTOM_LOOKUP_CMD needs /bin/sh (busybox wget is
# available for lookups too).
FROM alpine:3.24
ARG VERSION=dev
LABEL org.opencontainers.image.title="ozgo-cf-ddns" \
      org.opencontainers.image.description="Cloudflare DDNS agent: many records, one container, status page" \
      org.opencontainers.image.source="https://github.com/notolac/ozgo-cf-ddns" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}"
# hadolint ignore=DL3018
RUN apk add --no-cache ca-certificates \
 && adduser -D -H -u 10001 -s /sbin/nologin ddns
COPY --from=build /out/ozgo-cf-ddns /usr/local/bin/ozgo-cf-ddns
USER 10001:10001
EXPOSE 8080
HEALTHCHECK --interval=60s --timeout=10s --start-period=120s --retries=3 \
  CMD ["/usr/local/bin/ozgo-cf-ddns", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/ozgo-cf-ddns"]
