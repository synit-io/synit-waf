# Synit WAF runtime image.
#   docker build --build-arg VERSION=v1.0.0 -t synit-waf:local .
# The build context needs go.mod, go.sum, cmd/, internal/, assets/rules/,
# third_party/, LICENSE, and NOTICE; .dockerignore excludes the rest.

# Stage 1: build a static binary (no cgo, so no C toolchain is needed).
FROM golang:1.27.3-alpine@sha256:b8c9b82affbbb82a020bbcf998dad2ba9516944ac7e883524642a481a9505e9c AS builder

WORKDIR /src

# Download modules first so source changes do not invalidate the module cache.
COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal

ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath \
      -ldflags "-s -w -X github.com/synit-io/synit-waf/internal/waf.Version=${VERSION}" \
      -o /out/synit-waf ./cmd/synit-waf

# Runtime directories, owned by the distroless "nonroot" user (UID 65532):
# rule profiles, ACME storage, and the GeoIP database mount point.
COPY assets/rules /staging/etc/waf/rules
RUN mkdir -p /staging/etc/waf/certs/acme /staging/etc/waf/geoip && \
    chown -R 65532:65532 /staging/etc/waf

# Stage 2: distroless runtime.
FROM gcr.io/distroless/static-debian13@sha256:034df5c1737e8241f6ed6423a12e720ee0f6d6f088609ee172f98f6f2166ef5d

ARG VERSION=dev
LABEL org.opencontainers.image.title="Synit WAF" \
      org.opencontainers.image.description="Multi-tenant reverse-proxy web application firewall built on Coraza" \
      org.opencontainers.image.source="https://github.com/synit-io/synit-waf" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}"

COPY --from=builder /out/synit-waf /usr/local/bin/synit-waf
COPY --from=builder --chown=65532:65532 /staging/etc/waf /etc/waf

# Project licence and third-party notices.
COPY LICENSE NOTICE /usr/share/doc/synit-waf/
COPY third_party /usr/share/doc/synit-waf/third-party

WORKDIR /
USER 65532:65532

# 80/443: public listener (443 only with ACME); 9090: admin listener.
EXPOSE 80 443 9090

ENTRYPOINT ["/usr/local/bin/synit-waf"]
CMD ["-config", "/etc/waf/config.yml"]
