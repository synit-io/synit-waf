FROM golang:1.27.3-alpine@sha256:b8c9b82affbbb82a020bbcf998dad2ba9516944ac7e883524642a481a9505e9c AS builder
WORKDIR /app
COPY go.mod ./
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-w -s" -o ai-logs-receiver .
RUN mkdir -p /staging/data/ai-logs && chown -R 65532:65532 /staging/data

FROM gcr.io/distroless/static-debian13@sha256:15f8637509792e05b97d83451b0b6ccfa4abd548f997e406ac1e72c87fe1fa78
WORKDIR /app
COPY --from=builder /app/ai-logs-receiver /usr/local/bin/ai-logs-receiver
COPY --from=builder --chown=65532:65532 /staging/data /data
COPY third_party /usr/share/doc/synit-waf/third-party
ENV LOGS_DIR=/data/ai-logs
USER 65532:65532
EXPOSE 8082
CMD ["ai-logs-receiver"]
