FROM golang:1.24.3-alpine AS builder
RUN apk --update upgrade \
    && apk --no-cache --no-progress add git ca-certificates libcap \
    && update-ca-certificates
WORKDIR /src
ADD . .
RUN go mod download
# RUN go mod verify
RUN mkdir -p /app
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-w -s" -o /app/mail-gateway ./cmd

FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /etc/group /etc/passwd /etc/
COPY --from=builder /app /

ENTRYPOINT ["/mail-gateway"]

# cap_net_bind_service çalışması için app klasör içinde olmalı, klasör kopyalanmalı.
# https://medium.com/elbstack/docker-go-and-privileged-ports-d6354db472c3


# docker build -t netyazilim/mail-gateway:1.0.0 .

