# Build
FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY *.go ./
COPY templates ./templates
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /panel .

# Run
FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=build /panel /usr/local/bin/panel
# Deployzy bind-mounts a persistent (root-owned) volume at /app/data, so store
# the panel's public-page config there — otherwise it resets on every redeploy.
# Run as root so the mounted data dir is writable.
ENV PORT=8080 DATA_DIR=/app/data
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/panel"]
