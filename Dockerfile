FROM golang:1.26-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY testdata/ testdata/
RUN CGO_ENABLED=0 go build -o /netpol-analyzer ./cmd/analyzer/
RUN CGO_ENABLED=0 go build -o /netpol-diff ./cmd/diff/

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=builder /netpol-analyzer /usr/local/bin/netpol-analyzer
COPY --from=builder /netpol-diff /usr/local/bin/netpol-diff
COPY --from=builder /app/testdata /app/testdata
# analyzer 在 :9090 上同时服务 web/，镜像里没有这个目录的话
# topology.html 和 vendor/cytoscape.min.js 都会 404。
COPY --from=builder /app/web /app/web
WORKDIR /app
EXPOSE 9090
ENTRYPOINT ["netpol-analyzer"]
