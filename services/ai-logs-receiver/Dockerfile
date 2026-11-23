FROM golang:1.27.4-alpine@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS builder
WORKDIR /app
COPY go.mod ./
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-w -s" -o ai-logs-receiver .
RUN mkdir -p /staging/data/ai-logs && chown -R 65532:65532 /staging/data

FROM gcr.io/distroless/static-debian13@sha256:1a64f46364620465ef9e9a8f5413757dfdf22695e050bbfd7303eeaf17a59383
WORKDIR /app
COPY --from=builder /app/ai-logs-receiver /usr/local/bin/ai-logs-receiver
COPY --from=builder --chown=65532:65532 /staging/data /data
COPY third_party /usr/share/doc/synit-waf/third-party
ENV LOGS_DIR=/data/ai-logs
USER 65532:65532
EXPOSE 8082
CMD ["ai-logs-receiver"]
