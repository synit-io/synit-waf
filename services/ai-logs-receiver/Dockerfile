FROM golang:1.27.2-alpine@sha256:f92b6ef800e499660581efdabdf25d9d817a9d124eaf900924f0504e7e27e12d AS builder
WORKDIR /app
COPY go.mod ./
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-w -s" -o ai-logs-receiver .
RUN mkdir -p /staging/data/ai-logs && chown -R 65532:65532 /staging/data

FROM gcr.io/distroless/static-debian13@sha256:58133991db06659feaabe0f4e97a35cebf15ef4ea08f8a4c6d2ee5f75e4aa6a0
WORKDIR /app
COPY --from=builder /app/ai-logs-receiver /usr/local/bin/ai-logs-receiver
COPY --from=builder --chown=65532:65532 /staging/data /data
COPY third_party /usr/share/doc/synit-waf/third-party
ENV LOGS_DIR=/data/ai-logs
USER 65532:65532
EXPOSE 8082
CMD ["ai-logs-receiver"]
