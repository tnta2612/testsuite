#!/bin/bash

if [ -z "$1" ]; then
  echo "Error: No port provided. Please provide a port number."
  exit 1
fi

PORT=$1

echo "Starting mvfst server on port $PORT"
dd if=/dev/urandom of=root/largefile.bin bs=1M count=2

/proxygen/_build/proxygen/bin/hq --mode=server --static_root=root --host=0.0.0.0 --port=$PORT