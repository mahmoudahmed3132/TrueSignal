# STAGE 1: Build
FROM golang:1.26 AS builder

WORKDIR /src
COPY SDKs/go-truesignal ./SDKs/go-truesignal
COPY Sensors/official/IcmpCanary ./Sensors/official/IcmpCanary

WORKDIR /src/Sensors/official/IcmpCanary
RUN go mod download

# Pure Go, fully static binary
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o icmp-canary .

# STAGE 2: Distroless
# We use the standard image instead of :nonroot because raw sockets require UID 0
FROM gcr.io/distroless/static-debian12:latest

COPY --from=builder /src/Sensors/official/IcmpCanary/icmp-canary /app/icmp-canary

CMD ["/app/icmp-canary"]