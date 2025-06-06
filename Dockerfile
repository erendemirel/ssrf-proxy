FROM golang:1.21-alpine AS builder

RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY main.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o ssrf-proxy main.go

FROM alpine:latest

RUN apk --no-cache add ca-certificates

RUN addgroup -g 1001 -S ssrf && \
    adduser -S -D -H -u 1001 -h /home/ssrf -s /sbin/nologin -G ssrf -g ssrf ssrf

WORKDIR /home/ssrf

COPY --from=builder /app/ssrf-proxy .
RUN chown ssrf:ssrf ssrf-proxy

USER ssrf

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1

CMD ["./ssrf-proxy", "-port", "8080"] 