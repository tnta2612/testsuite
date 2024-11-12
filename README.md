# QUIC Security Consideration Testsuite

This repository provides a test suite for validating the security mechanisms of QUIC servers for the security considerations outlined in [RFC 9000](https://datatracker.ietf.org/doc/html/rfc9000).

The test suite supports various QUIC server implementations and is containerized using Docker, with Dockerfiles provided for each server. Note that running the suite requires `sudo` privileges for network traffic analysis and `iptables` configurations.

## Prerequisites

Ensure the following dependencies are installed on your system:

1. **Install required packages**:
   ```bash
   sudo apt update
   sudo apt install build-essential libnetfilter-queue-dev
   ```
2. **Python 3.x**
3. **Docker** (with `sudo` privileges)
4. **tshark**

### Additional Setup

To switch to root:
```bash
sudo -i
```

## Project Structure

- **`build_docker_images.sh`**: Builds Docker images for the QUIC servers.
- **`setup.py`**: Runs the QUIC servers, sets up AIOQUIC client and the Python virtual environment.
- **`testsuite.py`**: Runs the test cases for security considerations.
- **`cleanup.py`**: Stops running Docker containers and cleans up generated (log) files.

## Usage Guide

### 1. Build Docker Images

```bash
./build_docker_images.sh
```
> *Note*: Initial builds may take time if images aren’t cached.

### 2. Start QUIC Servers and Set Up the AIOQUIC Client

To start the QUIC servers in Docker containers, specify the server names and ports:

```bash
python3 setup.py chromium:6001,aioquic:6002,lsquic:6003,msquic:6004,mvfst:6005,neqo:6006,ngtcp2:6007,picoquic:6008,quic-go:6009,quiche:6010,quinn:6011
```
> This command launches Docker containers with each specified server listening on the given ports.

To run a single QUIC server:
```bash
python3 setup.py chromium:6001
```

### 3. Activate the Virtual Environment

Activate the virtual environment for `aioquic`:

```bash
source ./aioquic/venv/bin/activate
```

### 4. Install Python Dependencies

Install required Python packages:

```bash
sudo pip install -r requirements.txt
```

### 5. Run Test Cases

To run tests on multiple specified servers, use:

```bash
python3 testsuite.py chromium:6001,aioquic:6002,lsquic:6003,msquic:6004,mvfst:6005,neqo:6006,ngtcp2:6007,picoquic:6008,quic-go:6009,quiche:6010,quinn:6011
```

For testing a single server, use:

```bash
python3 testsuite.py chromium:6001
```

### Sample Output

The test suite will output analysis results for each server. Review the results to determine the susceptibility of each server to specific attacks. Following is a sample output:

```bash
---------------------------------------- AMPLIFICATION ATTACK ----------------------------------------

chromium:6001	- Server supports NEW_TOKEN frames.
chromium:6001	- Length of first datagram sent: 1208
chromium:6001	- Cumulative length of datagrams received between first and second datagram sent: 8777
chromium:6001	- Amplification factor: 7.2657284768211925
chromium:6001	- Server sends more data than the Anti-Amplification limit (when sending 0-RTT with AVT). => susceptible
chromium:6001	- Length of first datagram sent: 1208
chromium:6001	- Cumulative length of datagrams received between first and second datagram sent: 7572
chromium:6001	- Amplification factor: 6.268211920529802
chromium:6001	- Server accepts valid Address Validation Tokens multiple times. => SUSCEPTIBLE


aioquic:6002	- Server doesn't support NEW_TOKEN frames.


lsquic:6003	- Server supports NEW_TOKEN frames.
lsquic:6003	- Length of first datagram sent: 1208
lsquic:6003	- Cumulative length of datagrams received between first and second datagram sent: 1331
lsquic:6003	- Amplification factor: 1.1018211920529801
lsquic:6003	- Server doesn't send more data than Anti-Amplification limit (when sending 0-RTT with AVT).


msquic:6004	- Server doesn't support NEW_TOKEN frames.


mvfst:6005	- Server doesn't support NEW_TOKEN frames.


neqo:6006	- Server supports NEW_TOKEN frames.
neqo:6006	- Length of first datagram sent: 1208
neqo:6006	- Cumulative length of datagrams received between first and second datagram sent: 3632
neqo:6006	- Amplification factor: 3.006622516556291
neqo:6006	- Server doesn't send more data than Anti-Amplification limit (when sending 0-RTT with AVT).


ngtcp2:6007	- Server supports NEW_TOKEN frames.
ngtcp2:6007	- Length of first datagram sent: 1208
ngtcp2:6007	- Cumulative length of datagrams received between first and second datagram sent: 9604
ngtcp2:6007	- Amplification factor: 7.950331125827814
ngtcp2:6007	- Server sends more data than the Anti-Amplification limit (when sending 0-RTT with AVT). => susceptible
ngtcp2:6007	- Length of first datagram sent: 1208
ngtcp2:6007	- Cumulative length of datagrams received between first and second datagram sent: 9604
ngtcp2:6007	- Amplification factor: 7.950331125827814
ngtcp2:6007	- Server accepts valid Address Validation Tokens multiple times. => SUSCEPTIBLE


picoquic:6008	- Server supports NEW_TOKEN frames.
picoquic:6008	- Length of first datagram sent: 1208
picoquic:6008	- Cumulative length of datagrams received between first and second datagram sent: 12103
picoquic:6008	- Amplification factor: 10.019039735099337
picoquic:6008	- Server sends more data than the Anti-Amplification limit (when sending 0-RTT with AVT). => susceptible
picoquic:6008	- Length of first datagram sent: 1208
picoquic:6008	- Cumulative length of datagrams received between first and second datagram sent: 2520
picoquic:6008	- Amplification factor: 2.0860927152317883
picoquic:6008	- Server doesn't accept valid Address Validation Tokens multiple times.


quic-go:6009	- Server supports NEW_TOKEN frames.
quic-go:6009	- Length of first datagram sent: 1208
quic-go:6009	- Cumulative length of datagrams received between first and second datagram sent: 1330
quic-go:6009	- Amplification factor: 1.1009933774834437
quic-go:6009	- Server doesn't send more data than Anti-Amplification limit (when sending 0-RTT with AVT).


quiche:6010	- Server doesn't support NEW_TOKEN frames.


quinn:6011	- Server doesn't support NEW_TOKEN frames.



---------------------------------------- OPTIMISTIC ACK ATTACK ----------------------------------------

chromium:6001	- Received 2657 packets in total.
chromium:6001	- 0 packets were skipped (or missed).
chromium:6001	- Complete file received: True
chromium:6001	- Server didn't skip any packet number. => susceptible


aioquic:6002	- Received 2677 packets in total.
aioquic:6002	- 0 packets were skipped (or missed).
aioquic:6002	- Complete file received: True
aioquic:6002	- Server didn't skip any packet number. => susceptible


lsquic:6003	- Received 226 packets in total.
lsquic:6003	- 1 packets were skipped (or missed).
lsquic:6003	- Complete file received: False
lsquic:6003	- Server terminated the connection upon receiving optimistic ACKs.
lsquic:6003	- Error code: 1
lsquic:6003	- Reason phrase: connection error


msquic:6004	- Received 2167 packets in total.
msquic:6004	- 1 packets were skipped (or missed).
msquic:6004	- Complete file received: True
msquic:6004	- Packet numbers were skipped (or missed), but server didn't terminate the connection upon receiving optimistic ACKs. => susceptible


mvfst:6005	- Received 2583 packets in total.
mvfst:6005	- 0 packets were skipped (or missed).
mvfst:6005	- Complete file received: True
mvfst:6005	- Server didn't skip any packet number. => susceptible


neqo:6006	- Received 36 packets in total.
neqo:6006	- 3 packets were skipped (or missed).
neqo:6006	- Complete file received: False
neqo:6006	- Server terminated the connection, but didn't send CONNECTION_CLOSE frame upon receiving optimistic ACKs.


ngtcp2:6007	- Received 2208 packets in total.
ngtcp2:6007	- 0 packets were skipped (or missed).
ngtcp2:6007	- Complete file received: True
ngtcp2:6007	- Server didn't skip any packet number. => susceptible


picoquic:6008	- Received 491 packets in total.
picoquic:6008	- 2 packets were skipped (or missed).
picoquic:6008	- Complete file received: False
picoquic:6008	- Server terminated the connection upon receiving optimistic ACKs.
picoquic:6008	- Error code: 10
picoquic:6008	- Reason phrase: Reason phrase: 


quic-go:6009	- Received 129 packets in total.
quic-go:6009	- 1 packets were skipped (or missed).
quic-go:6009	- Complete file received: False
quic-go:6009	- Server terminated the connection upon receiving optimistic ACKs.
quic-go:6009	- Error code: 10
quic-go:6009	- Reason phrase: received an ACK for skipped packet number: 51 (1-RTT)


quiche:6010	- Received 2361 packets in total.
quiche:6010	- 0 packets were skipped (or missed).
quiche:6010	- Complete file received: True
quiche:6010	- Server didn't skip any packet number. => susceptible


quinn:6011	- Received 48 packets in total.
quinn:6011	- 1 packets were skipped (or missed).
quinn:6011	- Complete file received: False
quinn:6011	- Server terminated the connection, but didn't send CONNECTION_CLOSE frame upon receiving optimistic ACKs.



---------------------------------------- REQUEST FORGERY ATTACKS ----------------------------------------

chromium:6001	- Server sent 64 packets to the new IP address.
chromium:6001	- Server sent STREAM frames containing data to the unvalidated IP address => susceptible.
chromium:6001	- Response received for spoofed port nunber 7 (Echo Protocol) => QUIC server doesn't block common UDP ports!
chromium:6001	- QUIC server sent Version Negotiation packet containng 5 supported versions.
chromium:6001	- QUIC server sent Version Negotiation packet (aka. DNS query) for 'tum.de' to spoofed IP address (8.8.8.8) => susceptible
chromium:6001	- There's no valid DNS response for 'tum.de'


aioquic:6002	- Server sent 1 packets to the new IP address.
aioquic:6002	- Server sent STREAM frames containing data to the unvalidated IP address => susceptible.
aioquic:6002	- Response received for spoofed port nunber 7 (Echo Protocol) => QUIC server doesn't block common UDP ports!
aioquic:6002	- QUIC server sent Version Negotiation packet containng 2 supported versions.
aioquic:6002	- QUIC server didn't send any Version Negotiation packet (DNS query) for 'tum.de' to spoofed IP address (8.8.8.8)
aioquic:6002	- There's no valid DNS response for 'tum.de'


lsquic:6003	- Server sent 0 packets to the new IP address.
lsquic:6003	- Server didn't send any STREAM frames to the unvalidated IP address.
lsquic:6003	- Response received for spoofed port nunber 7 (Echo Protocol) => QUIC server doesn't block common UDP ports!
lsquic:6003	- QUIC server sent Version Negotiation packet containng 6 supported versions.
lsquic:6003	- QUIC server didn't send any Version Negotiation packet (DNS query) for 'tum.de' to spoofed IP address (8.8.8.8)
lsquic:6003	- There's no valid DNS response for 'tum.de'


msquic:6004	- Server sent 2 packets to the new IP address.
msquic:6004	- Server didn't send any STREAM frames to the unvalidated IP address.
msquic:6004	- Response received for spoofed port nunber 7 (Echo Protocol) => QUIC server doesn't block common UDP ports!
msquic:6004	- QUIC server sent Version Negotiation packet containng 5 supported versions.
msquic:6004	- QUIC server sent Version Negotiation packet (aka. DNS query) for 'tum.de' to spoofed IP address (8.8.8.8) => susceptible
msquic:6004	- QUIC server received DNS response for 'tum.de' => QUIC server had sent a DNS request as a result of Request Forgery Attack via Version Negotiation => susceptible


mvfst:6005	- Server sent 1 packets to the new IP address.
mvfst:6005	- Server didn't send any STREAM frames to the unvalidated IP address.
mvfst:6005	- Response received for spoofed port nunber 7 (Echo Protocol) => QUIC server doesn't block common UDP ports!
mvfst:6005	- QUIC server sent Version Negotiation packet containng 6 supported versions.
mvfst:6005	- QUIC server didn't send any Version Negotiation packet (DNS query) for 'tum.de' to spoofed IP address (8.8.8.8)
mvfst:6005	- There's no valid DNS response for 'tum.de'


neqo:6006	- Server sent 45 packets to the new IP address.
neqo:6006	- Server sent STREAM frames containing data to the unvalidated IP address => susceptible.
neqo:6006	- Response received for spoofed port nunber 7 (Echo Protocol) => QUIC server doesn't block common UDP ports!
neqo:6006	- QUIC server sent Version Negotiation packet containng 2 supported versions.
neqo:6006	- QUIC server sent Version Negotiation packet (aka. DNS query) for 'tum.de' to spoofed IP address (8.8.8.8) => susceptible
neqo:6006	- QUIC server received DNS response for 'tum.de' => QUIC server had sent a DNS request as a result of Request Forgery Attack via Version Negotiation => susceptible


ngtcp2:6007	- Server sent 3 packets to the new IP address.
ngtcp2:6007	- Server sent STREAM frames containing data to the unvalidated IP address => susceptible.
ngtcp2:6007	- Response received for spoofed port nunber 7 (Echo Protocol) => QUIC server doesn't block common UDP ports!
ngtcp2:6007	- QUIC server sent Version Negotiation packet containng 2 supported versions.
ngtcp2:6007	- QUIC server sent Version Negotiation packet (aka. DNS query) for 'tum.de' to spoofed IP address (8.8.8.8) => susceptible
ngtcp2:6007	- QUIC server received DNS response for 'tum.de' => QUIC server had sent a DNS request as a result of Request Forgery Attack via Version Negotiation => susceptible


picoquic:6008	- Server sent 3 packets to the new IP address.
picoquic:6008	- Server didn't send any STREAM frames to the unvalidated IP address.
picoquic:6008	- Response received for spoofed port nunber 7 (Echo Protocol) => QUIC server doesn't block common UDP ports!
picoquic:6008	- QUIC server sent Version Negotiation packet containng 14 supported versions.
picoquic:6008	- QUIC server sent Version Negotiation packet (aka. DNS query) for 'tum.de' to spoofed IP address (8.8.8.8) => susceptible
picoquic:6008	- QUIC server received DNS response for 'tum.de' => QUIC server had sent a DNS request as a result of Request Forgery Attack via Version Negotiation => susceptible


quic-go:6009	- Server sent 0 packets to the new IP address.
quic-go:6009	- Server didn't send any STREAM frames to the unvalidated IP address.
quic-go:6009	- Response received for spoofed port nunber 7 (Echo Protocol) => QUIC server doesn't block common UDP ports!
quic-go:6009	- QUIC server sent Version Negotiation packet containng 3 supported versions.
quic-go:6009	- QUIC server didn't send any Version Negotiation packet (DNS query) for 'tum.de' to spoofed IP address (8.8.8.8)
quic-go:6009	- There's no valid DNS response for 'tum.de'


quiche:6010	- Server sent 2 packets to the new IP address.
quiche:6010	- Server sent STREAM frames containing data to the unvalidated IP address => susceptible.
quiche:6010	- Response received for spoofed port nunber 7 (Echo Protocol) => QUIC server doesn't block common UDP ports!
quiche:6010	- QUIC server sent Version Negotiation packet containng 1 supported versions.
quiche:6010	- QUIC server sent Version Negotiation packet (aka. DNS query) for 'tum.de' to spoofed IP address (8.8.8.8) => susceptible
quiche:6010	- QUIC server received DNS response for 'tum.de' => QUIC server had sent a DNS request as a result of Request Forgery Attack via Version Negotiation => susceptible


quinn:6011	- Server sent 1 packets to the new IP address.
quinn:6011	- Server sent STREAM frames containing data to the unvalidated IP address => susceptible.
quinn:6011	- Response received for spoofed port nunber 7 (Echo Protocol) => QUIC server doesn't block common UDP ports!
quinn:6011	- QUIC server sent Version Negotiation packet containng 8 supported versions.
quinn:6011	- QUIC server didn't send any Version Negotiation packet (DNS query) for 'tum.de' to spoofed IP address (8.8.8.8)
quinn:6011	- There's no valid DNS response for 'tum.de'



2024-11-12 15:09:45,703 - INFO - Test suite runtime: 605.3320059776306 seconds
```

### 6. Stop QUIC Servers

After testing, stop the running Docker containers:

```bash
python3 cleanup.py chromium:6001,aioquic:6002,lsquic:6003,msquic:6004,mvfst:6005,neqo:6006,ngtcp2:6007,picoquic:6008,quic-go:6009,quiche:6010,quinn:6011
```

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more information.

## Contributions

Contributions are welcome! Feel free to submit a pull request or open an issue to discuss improvements or new features.
