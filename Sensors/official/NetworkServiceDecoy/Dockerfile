# STAGE 1: Build
FROM golang:1.26 AS builder

WORKDIR /src
COPY SDKs/go-truesignal ./SDKs/go-truesignal
COPY Sensors/official/NetworkServiceDecoy ./Sensors/official/NetworkServiceDecoy

WORKDIR /src/Sensors/official/NetworkServiceDecoy
RUN go mod download

# Pure Go, fully static binary
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o network-service-decoy .

# STAGE 2: Distroless
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /src/Sensors/official/NetworkServiceDecoy/network-service-decoy /app/network-service-decoy

USER 65532
CMD ["/app/network-service-decoy"]
