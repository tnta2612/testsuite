#!/bin/bash

echo "Starting picoquic server on port 6004"
dd if=/dev/urandom of=root/largefile.bin bs=1M count=8

./picoquicdemo -p 6004 -w root -k ssl_key.pem -c ssl_cert.pem