# STAGE 1: Build
FROM golang:1.26 AS builder

WORKDIR /src
COPY SDKs/go-truesignal ./SDKs/go-truesignal
COPY Sensors/official/TokenReceiver ./Sensors/official/TokenReceiver

WORKDIR /src/Sensors/official/TokenReceiver
RUN go mod download

# Pure Go, fully static binary
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o token-receiver .

# STAGE 2: Distroless
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /src/Sensors/official/TokenReceiver/token-receiver /app/token-receiver

USER 65532
CMD ["/app/token-receiver"]
