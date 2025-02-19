FROM golang:1.24-alpine AS builder

RUN apk update && apk add --no-cache git

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=linux GOARCH=$TARGETARCH go build -ldflags="-s -w" -o netbox-go-discovery ./cmd/netbox-go-discovery

FROM alpine:latest

RUN apk update && apk add --no-cache nmap ca-certificates

COPY --from=builder /app/netbox-go-discovery /bin/netbox-go-discovery

EXPOSE 8080

CMD ["/bin/netbox-go-discovery"]
