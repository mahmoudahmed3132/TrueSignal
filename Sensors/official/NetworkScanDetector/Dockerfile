# STAGE 1: Build
FROM golang:1.26@sha256:670bb5aa5349ae03b8516764718486f4f16399134bdc9acd0c46a23f043ab05c AS builder

WORKDIR /src
COPY SDKs/go-truesignal ./SDKs/go-truesignal
COPY Sensors/official/NetworkScanDetector ./Sensors/official/NetworkScanDetector

WORKDIR /src/Sensors/official/NetworkScanDetector
RUN go mod download

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o scan-detector .

# STAGE 2: Distroless
FROM gcr.io/distroless/static-debian12:latest@sha256:d75cdd72874d4790092fcb1b058493ecf6bb5bf2b2b897045b00ff01d91843f2

COPY --from=builder /src/Sensors/official/NetworkScanDetector/scan-detector /app/scan-detector

CMD ["/app/scan-detector"]