FROM golang:1.27.4-alpine@sha256:0a5f7fe796599ff487605987432e7619ae45beeb2fba4c2ce0b907879932aebf AS builder
WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-w -s" -o synit-llm-guard .

FROM gcr.io/distroless/static-debian13@sha256:4c2cd1dee442c9a99924a378c7c126fac8fef14771579ef567c3f2bdd7a5122a

WORKDIR /app
COPY --from=builder /app/synit-llm-guard /usr/local/bin/synit-llm-guard
COPY third_party /usr/share/doc/synit-waf/third-party

USER 65532:65532

EXPOSE 5001
CMD ["synit-llm-guard"]
