FROM golang:1.27.3-alpine@sha256:b8c9b82affbbb82a020bbcf998dad2ba9516944ac7e883524642a481a9505e9c AS builder
WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-w -s" -o synit-llm-guard .

FROM gcr.io/distroless/static-debian13@sha256:15f8637509792e05b97d83451b0b6ccfa4abd548f997e406ac1e72c87fe1fa78

WORKDIR /app
COPY --from=builder /app/synit-llm-guard /usr/local/bin/synit-llm-guard
COPY third_party /usr/share/doc/synit-waf/third-party

USER 65532:65532

EXPOSE 5001
CMD ["synit-llm-guard"]
