# STAGE 1: Frontend Builder
FROM node:22-alpine@sha256:fe4f6d74e20370acb04ad889077d14d0f64a9c8ea6a42bc60cddf1e844699914 AS frontend-builder
WORKDIR /app/ui

# Install dependencies
COPY ui/package*.json ./
RUN npm ci

# Copy source and build the Vue SPA
COPY ui/ ./
RUN npm run build

# STAGE 2: Go Builder
FROM golang:1.26@sha256:670bb5aa5349ae03b8516764718486f4f16399134bdc9acd0c46a23f043ab05c AS go-builder
WORKDIR /build

# Cache Go modules
COPY go.mod go.sum ./
RUN go mod download

# Copy the Go source code
COPY . .

# CRITICAL: Copy the compiled Vue app from Stage 1 into the Go build context
# so the `//go:embed all:dist` directive can find it.
COPY --from=frontend-builder /app/ui/dist ./ui/dist

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o truesignal-hub ./cmd/hub

# STAGE 3: Distroless Production Image
# The "static" image contains literally nothing except SSL certificates and a non-root user.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
WORKDIR /app

COPY --from=go-builder /build/truesignal-hub /app/

EXPOSE 8080
CMD ["/app/truesignal-hub"]