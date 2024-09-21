#!/bin/bash

if [ -z "$1" ]; then
  echo "Error: No port provided. Please provide a port number."
  exit 1
fi

PORT=$1

echo "Starting picoquic server on port $PORT"
dd if=/dev/urandom of=root/largefile.bin bs=1M count=1

./picoquicdemo -p $PORT -w root -k ssl_key.pem -c ssl_cert.pem