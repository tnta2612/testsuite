#!/bin/bash

echo "Starting mvfst server on port 6003"
dd if=/dev/urandom of=root/largefile.bin bs=1M count=1

/proxygen/_build/proxygen/bin/hq --mode=server --static_root=root --host=0.0.0.0 --port=6003