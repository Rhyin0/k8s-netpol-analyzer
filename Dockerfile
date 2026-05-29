FROM golang:1.26-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
COPY testdata/ testdata/
RUN CGO_ENABLED=0 go build -o /netpol-analyzer .

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=builder /netpol-analyzer /usr/local/bin/netpol-analyzer
COPY --from=builder /app/testdata /app/testdata
WORKDIR /app
EXPOSE 9090
ENTRYPOINT ["netpol-analyzer"]
