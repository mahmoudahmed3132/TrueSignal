# STAGE 1: Build
FROM golang:1.26 AS builder

WORKDIR /src
COPY SDKs/go-truesignal ./SDKs/go-truesignal
COPY Sensors/official/IdentityDecoy ./Sensors/official/IdentityDecoy

WORKDIR /src/Sensors/official/IdentityDecoy
RUN go mod download

# Pure Go, fully static binary
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o identity-decoy .

# STAGE 2: Distroless
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /src/Sensors/official/IdentityDecoy/identity-decoy /app/identity-decoy

USER 65532
CMD ["/app/identity-decoy"]
