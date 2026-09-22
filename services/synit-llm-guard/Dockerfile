FROM golang:1.27.0-alpine@sha256:4c9fe60190a2a3350ddc51de80d0224b8a6698d12bdfc999fee45ea9d6c46dbc AS builder
WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-w -s" -o synit-llm-guard .

FROM gcr.io/distroless/static-debian12@sha256:d75cdd72874d4790092fcb1b058493ecf6bb5bf2b2b897045b00ff01d91843f2

WORKDIR /app
COPY --from=builder /app/synit-llm-guard /usr/local/bin/synit-llm-guard
COPY third_party /usr/share/doc/synit-waf/third-party

USER 65532:65532

EXPOSE 5001
CMD ["synit-llm-guard"]
