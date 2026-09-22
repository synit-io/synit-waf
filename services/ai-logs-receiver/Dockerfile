FROM golang:1.27.1-alpine@sha256:8a5910f31396cd4d89662f56c68b3ae31d374308270a1c3bd96672ee5ed43414 AS builder
WORKDIR /app
COPY go.mod ./
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-w -s" -o ai-logs-receiver .
RUN mkdir -p /staging/data/ai-logs && chown -R 65532:65532 /staging/data

FROM gcr.io/distroless/static-debian12@sha256:d75cdd72874d4790092fcb1b058493ecf6bb5bf2b2b897045b00ff01d91843f2
WORKDIR /app
COPY --from=builder /app/ai-logs-receiver /usr/local/bin/ai-logs-receiver
COPY --from=builder --chown=65532:65532 /staging/data /data
COPY third_party /usr/share/doc/synit-waf/third-party
ENV LOGS_DIR=/data/ai-logs
USER 65532:65532
EXPOSE 8082
CMD ["ai-logs-receiver"]
