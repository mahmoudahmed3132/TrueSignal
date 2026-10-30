# STAGE 1: Build
FROM golang:1.26@sha256:670bb5aa5349ae03b8516764718486f4f16399134bdc9acd0c46a23f043ab05c AS builder

WORKDIR /src
COPY SDKs/go-truesignal ./SDKs/go-truesignal
COPY Sensors/official/TokenReceiver ./Sensors/official/TokenReceiver

WORKDIR /src/Sensors/official/TokenReceiver
RUN go mod download

# Pure Go, fully static binary
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o token-receiver .

# STAGE 2: Distroless
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

COPY --from=builder /src/Sensors/official/TokenReceiver/token-receiver /app/token-receiver

USER 65532
CMD ["/app/token-receiver"]
