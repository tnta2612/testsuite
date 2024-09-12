#!/bin/bash

echo "Starting quic-go server on port 6005"
go mod tidy
dd if=/dev/urandom of=root/largefile.bin bs=1M count=8
go run example/main.go -cert ssl_cert.pem -key ssl_key.pem -www root -bind 0.0.0.0:6005