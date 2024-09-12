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

