#!/bin/bash

if [ -z "$1" ]; then
  echo "Error: No port provided. Please provide a port number."
  exit 1
fi

PORT=$1

echo "Starting quinn server on port $PORT"

dd if=/dev/urandom of=apps/src/bin/root/largefile.bin bs=1M count=2

cargo run --example server -- ./root --listen 0.0.0.0:$PORT --key ./ssl_key.pem --cert ./ssl_cert.pem