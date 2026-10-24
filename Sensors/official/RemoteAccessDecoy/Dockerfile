# STAGE 1: Build
FROM golang:1.26 AS builder

WORKDIR /src
COPY SDKs/go-truesignal ./SDKs/go-truesignal
COPY Sensors/official/RemoteAccessDecoy ./Sensors/official/RemoteAccessDecoy

WORKDIR /src/Sensors/official/RemoteAccessDecoy
RUN go mod download

# Pure Go, fully static binary
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o remote-access-decoy .

# STAGE 2: Distroless
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /src/Sensors/official/RemoteAccessDecoy/remote-access-decoy /app/remote-access-decoy

USER 65532
CMD ["/app/remote-access-decoy"]
