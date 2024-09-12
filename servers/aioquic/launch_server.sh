#!/bin/bash
echo "Starting aioquic server on port 6001"
dd if=/dev/urandom of=examples/htdocs/largefile.bin bs=1M count=16

python3 examples/http3_server.py --certificate tests/ssl_cert.pem --private-key tests/ssl_key.pem --host 0.0.0.0 --port 6001
	