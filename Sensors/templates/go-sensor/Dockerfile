# STAGE 1: Build
FROM golang:1.26@sha256:670bb5aa5349ae03b8516764718486f4f16399134bdc9acd0c46a23f043ab05c AS builder

WORKDIR /src

# 1. Copy the shared SDK into the builder
COPY SDKs/go-truesignal ./SDKs/go-truesignal

# 2. Copy the specific sensor code
COPY Sensors/templates/go-sensor ./Sensors/templates/go-sensor

# 3. Move into the sensor folder to build
WORKDIR /src/Sensors/templates/go-sensor

# Download dependencies (this will successfully find the local SDK)
RUN go mod download

# Compile the pure Go, fully static binary
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o custom-sensor ./main.go

# STAGE 2: Distroless
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

COPY --chown=65532:65532 --from=builder /src/Sensors/templates/go-sensor/custom-sensor /app/custom-sensor

USER 65532
CMD ["/app/custom-sensor"]