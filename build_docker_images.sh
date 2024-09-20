# Record start time
SECONDS=0

cd servers/aioquic
sudo docker build -t aioquic .
cd ../lsquic
sudo docker build -t lsquic .
cd ../mvfst
sudo docker build -t mvfst .
cd ../picoquic
sudo docker build -t picoquic .
cd ../quic-go
sudo docker build -t quic-go .
cd ../quiche
sudo docker build -t quiche .
cd ../msquic
sudo docker build -t msquic .

echo "Script runtime: $SECONDS seconds"

