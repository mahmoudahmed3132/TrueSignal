# STAGE 1: Build
FROM golang:1.26@sha256:670bb5aa5349ae03b8516764718486f4f16399134bdc9acd0c46a23f043ab05c AS builder

WORKDIR /src
COPY SDKs/go-truesignal ./SDKs/go-truesignal
COPY Sensors/official/IcmpCanary ./Sensors/official/IcmpCanary

WORKDIR /src/Sensors/official/IcmpCanary
RUN go mod download

# Pure Go, fully static binary
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o icmp-canary .

# STAGE 2: Distroless
# We use the standard image instead of :nonroot because raw sockets require UID 0
FROM gcr.io/distroless/static-debian12:latest@sha256:d75cdd72874d4790092fcb1b058493ecf6bb5bf2b2b897045b00ff01d91843f2

COPY --from=builder /src/Sensors/official/IcmpCanary/icmp-canary /app/icmp-canary

CMD ["/app/icmp-canary"]