FROM golang:1.27.3-alpine@sha256:fa3d596898d9f126af7c01d14ee7597bab3f39cccf392ef36b69fe77cd681f18 AS builder
WORKDIR /app
COPY go.mod ./
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-w -s" -o ai-logs-receiver .
RUN mkdir -p /staging/data/ai-logs && chown -R 65532:65532 /staging/data

FROM gcr.io/distroless/static-debian13@sha256:448810357cc8e67b7208988abdba0f5ec3d3aebee0a5b13eb624979792cffc0f
WORKDIR /app
COPY --from=builder /app/ai-logs-receiver /usr/local/bin/ai-logs-receiver
COPY --from=builder --chown=65532:65532 /staging/data /data
COPY third_party /usr/share/doc/synit-waf/third-party
ENV LOGS_DIR=/data/ai-logs
USER 65532:65532
EXPOSE 8082
CMD ["ai-logs-receiver"]
