# Record start time
SECONDS=0

echo "------------------------- Building Docker image for aioquic..."
cd servers/aioquic
sudo docker build -t aioquic .
echo "------------------------- Building Docker image for lsquic..."
cd ../lsquic
sudo docker build -t lsquic .
echo "------------------------- Building Docker image for mvfst..."
cd ../mvfst
sudo docker build -t mvfst .
echo "------------------------- Building Docker image for picoquic..."
cd ../picoquic
sudo docker build -t picoquic .
echo "------------------------- Building Docker image for quic-go..."
cd ../quic-go
sudo docker build -t quic-go .
echo "------------------------- Building Docker image for quiche..."
cd ../quiche
sudo docker build -t quiche .
echo "------------------------- Building Docker image for msquic..."
cd ../msquic
sudo docker build -t msquic .
echo "------------------------- Building Docker image for quinn..."
cd ../quinn
sudo docker build -t quinn .
echo "------------------------- Building Docker image for neqo..."
cd ../neqo
sudo docker build -t neqo .
echo "------------------------- Building Docker image for ngtcp2..."
cd ../ngtcp2
sudo docker build -t ngtcp2 .
echo "------------------------- Building Docker image for chromium..."
cd ../chromium
sudo docker build -t chromium .


echo "Script runtime: $SECONDS seconds"

