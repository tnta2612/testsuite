# QUIC Server Testing Framework

This repository contains scripts to start QUIC servers in Docker containers, run amplification attack test cases, analyze `.qlog` files for vulnerabilities, and clean up by stopping the servers.

## Prerequisites

Before you start, ensure you have the following installed on your system:

- Python 3.x
- Docker (add `sudo` privileges)
- tshark

add user to wireshark group to make it able to capture traffic using tshark

$ sudo dpkg-reconfigure wireshark-common 
$ sudo usermod -a -G wireshark $USER
$ gnome-session-quit --logout --no-prompt


**git diff > patch_file.patch**

**git apply patch_file.patch** 
`git apply -R <patch>`


## Project Structure

- `setup.py`: Script to start Docker containers running QUIC servers.
- `testsuite.py`: Script to run test cases (e.g., amplification attack) and analyze `.qlog` files.
- `cleanup.py`: Script to stop the running Docker containers.

## Usage

### 1. Start the QUIC Servers

Use `setup.py` to start the QUIC servers in Docker containers.

```bash
python3 setup.py 'aioquic:6001,lsquic:6002'
```

- Replace `'aioquic:6001,lsquic:6002'` with your desired server and port combinations.
- This will start the Docker containers with the specified servers listening on the provided ports.

### 2. Acitivate the virtual environment

source aioquic/venv/bin/activate

### 2. Run Test Cases

After the servers are up, use `testsuite.py` to run the amplification attack test cases and analyze the logs.

```bash
python3 testsuite.py 'aioquic:6001,lsquic:6002'
```

- This script will connect to each server, run the test cases, and analyze the `.qlog` files for vulnerabilities.

### 3. Stop the QUIC Servers

Once testing is complete, use `cleanup.py` to stop the running Docker containers.

```bash
python3 cleanup.py 'aioquic:6001,lsquic:6002'
```

- This will stop the Docker containers for the specified servers.

## Customization

### Adding More Test Cases

- To add additional test cases, modify the `testsuite.py` script by defining new functions and calling them within the `main()` function.
- Ensure that you perform any necessary setup or cleanup within these functions.

### Log Analysis

- The current log analysis in `testsuite.py` is a placeholder. Modify the `analyze_qlog()` function to include your specific analysis logic based on the `.qlog` file contents.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more details.

## Contributions

Contributions are welcome! Please submit a pull request or open an issue to discuss any changes or enhancements.