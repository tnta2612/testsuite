#!/bin/bash

if [ -z "$1" ]; then
  echo "Error: No port provided. Please provide a port number."
  exit 1
fi

PORT=$1

echo "Starting lsquic server on port $PORT"
dd if=/dev/urandom of=root/largefile.bin bs=1M count=1

./http_server -c www.example.com,ssl_cert.pem,ssl_key.pem -s 0.0.0.0:$PORT -r root	