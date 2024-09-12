#!/bin/bash
echo "Starting lsquic server on port 6002"
dd if=/dev/urandom of=root/largefile.bin bs=1M count=16

./http_server -c www.example.com,ssl_cert.pem,ssl_key.pem -s 0.0.0.0:6002 -r root	