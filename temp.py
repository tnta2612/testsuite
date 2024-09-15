import subprocess

def run_aioquic_client():
    command = [
        "python3", "aioquic/examples/http3_client.py",
        "--ca-certs", "aioquic/tests/pycacert.pem",
        "--secrets-log", "aioquic/secrets.log",
        "--session-ticket", "aioquic/session",
        "--insecure",
        "--output-dir", "aioquic/output",
        "--quic-log", "aioquic/log",
        "--verbose",
        "--server-name", "www.example.com",
        "--local-port", "5555",
        "https://localhost:6001/largefile.bin"
    ]

    try:
        result = subprocess.run(command, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)

#        result = subprocess.run(command, check=True, capture_output=True, text=True)
        print("Command output:\n", result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"Command failed with error code {e.returncode}:\n{e.stderr}")

if __name__ == "__main__":
    run_aioquic_client()
