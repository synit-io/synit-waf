# Synit WAF runtime image.
#   docker build --build-arg VERSION=v1.0.0 -t synit-waf:local .
# The build context needs go.mod, go.sum, cmd/, internal/, assets/rules/,
# third_party/, LICENSE, and NOTICE; .dockerignore excludes the rest.

# Stage 1: build a static binary (no cgo, so no C toolchain is needed).
FROM golang:1.27.1-alpine@sha256:8a5910f31396cd4d89662f56c68b3ae31d374308270a1c3bd96672ee5ed43414 AS builder

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
FROM gcr.io/distroless/static-debian12@sha256:d75cdd72874d4790092fcb1b058493ecf6bb5bf2b2b897045b00ff01d91843f2

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
