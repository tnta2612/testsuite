#!/bin/bash

if [ -z "$1" ]; then
  echo "Error: No port provided. Please provide a port number."
  exit 1
fi

PORT=$1

echo "Starting quic-go server on port $PORT"
go mod tidy
dd if=/dev/urandom of=root/largefile.bin bs=1M count=1
go run example/main.go -cert ssl_cert.pem -key ssl_key.pem -www root -bind 0.0.0.0:$PORT