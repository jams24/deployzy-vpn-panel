# Build
FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY *.go ./
COPY templates ./templates
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /panel .

# Run
FROM alpine:3.20
RUN apk add --no-cache ca-certificates && adduser -D -u 10001 panel
COPY --from=build /panel /usr/local/bin/panel
USER panel
ENV PORT=8080 DATA_DIR=/data
EXPOSE 8080
VOLUME ["/data"]
ENTRYPOINT ["/usr/local/bin/panel"]
