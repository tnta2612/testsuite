import subprocess
import sys
import os
import logging
import json
import shutil
import time
import pyshark
from cleanup import remove_log_files  # Import the function from cleanup.py


# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Global variable to store results as a string
results_string = ""
address_validation_token = ""
tshark_sniff_command = [
    'tshark', '-i', 'lo', '-f', 'udp port 5555', '-w', './capture.pcap'
]

def append_to_results(result):
    global results_string
    results_string += result + "\n"


def backup_files(source_files, backup_files):
    """
    Copies files from source_files to backup_files.

    Parameters:
    - source_files (list): A list of source file paths.
    - backup_files (list): A list of corresponding backup file paths.
    """
    for src, dst in zip(source_files, backup_files):
        if os.path.exists(src):
            # Copy the source file to the destination
            shutil.copy2(src, dst)


def load_qlog_file(directory='./aioquic/log/'):
    qlog_files = [f for f in os.listdir(directory) if f.endswith('.qlog')]
    
    if not qlog_files:
        logging.error("No .qlog file found in the directory.")
        return None
    
    qlog_file = qlog_files[0]
    file_path = os.path.join(directory, qlog_file)
    
    logging.info(f"Loading data from file: {qlog_file}")
    
    try:
        with open(file_path, 'r') as file:
            data = json.load(file)
        return data
    except json.JSONDecodeError as e:
        logging.error(f"Failed to decode JSON from {file_path}: {e}")
        return None


def find_key(data, key_to_find):
    """
    Recursively search for a key in the JSON structure, and return the value of the key.
    """
    if isinstance(data, dict):
        for key, value in data.items():
            if key == key_to_find:
                return value
            result = find_key(value, key_to_find)
            if result is not None:
                return result
    elif isinstance(data, list):
        for item in data:
            result = find_key(item, key_to_find)
            if result is not None:
                return result
    return None


def find_value(data, value_to_find):
    """
    Recursively search for a value in the JSON structure, and return the key of the value.
    """
    if isinstance(data, dict):
        for key, value in data.items():
            if value == value_to_find:
                return key
            result = find_value(value, value_to_find)
            if result is not None:
                return result
    elif isinstance(data, list):
        for item in data:
            result = find_value(item, value_to_find)
            if result is not None:
                return result
    return None


def search_for_new_token_frame(logs_path='./aioquic/log'):
    global address_validation_token

    if not os.path.exists(logs_path):
        logging.error(f"Logs directory {logs_path} does not exist.")
        return False

    data = load_qlog_file()
    # Search for 'new_token' frame anywhere in the JSON structure
    if find_value(data, 'new_token') is not None:
        token_data = find_key(data, 'token')
        address_validation_token = token_data#.encode('utf-8')  # Convert to bytes
        logging.info(f"New token found: {address_validation_token}")
        return True

    return False


def check_anti_amplification_limit(server, port, client_command):
    """
    Return True if the server doesn't send more than Anti-Amplification limit (with tolerance), and False otherwise.
    """
    # Start tshark in the background
    tshark_process = subprocess.Popen(tshark_sniff_command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2)  # Give tshark some time to start up

    try:
        subprocess.run(client_command, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        time.sleep(2)  
        # Stop the tshark process after the command completes
        tshark_process.terminate()
        # Wait for tshark to finish writing the capture file
        tshark_process.wait()

        # Read the capture
        capture = pyshark.FileCapture('./capture.pcap')

        first_datagram_sent_length = None
        cumulative_datagram_received_length = 0
        first_datagram_sent_found = False

        # Process each packet
        for packet in capture:
            if 'udp' in packet:
                if packet.udp.srcport == "5555":
                    if not first_datagram_sent_found:
                        first_datagram_sent_length = int(packet.udp.length)
                        first_datagram_sent_found = True  # Set flag for first datagram
                    else:
                        # Stop processing once the second datagram sent is found
                        break        
                elif packet.udp.dstport == "5555" and first_datagram_sent_found:
                    cumulative_datagram_received_length += int(packet.udp.length)
        
        capture.close()
        logging.info(f"Length of first datagram sent: {first_datagram_sent_length}")
        logging.info(f"Cumulative length of datagrams received between first and second datagram sent: {cumulative_datagram_received_length}")
        
        result = f"{server}:{port}\t- Length of first datagram sent: {first_datagram_sent_length}"
        append_to_results(result)
        result = f"{server}:{port}\t- Cumulative length of datagrams received between first and second datagram sent: {cumulative_datagram_received_length}"
        append_to_results(result)
        result = f"{server}:{port}\t- Amplification factor: {cumulative_datagram_received_length/first_datagram_sent_length}"
        append_to_results(result)

        # Check anti-amplification limit with tolerance
        if 4* first_datagram_sent_length > cumulative_datagram_received_length:
            return True
        else:
            return False
        
    except subprocess.CalledProcessError as e:
        result = f"{server}:{port}\t- Error: {e}"
        logging.error(f"Failed to run client script against {server} on port {port}: {e}")
        append_to_results(result)
        sys.exit(1)


def run_test_case_new_token_support(server, port):
    logging.info(f"Running test case new_token_support against {server} on port {port}.")
    client_command = [
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
        f"https://localhost:{str(port)}/test.html"
    ]
    
    remove_log_files()

    try:
        subprocess.run(client_command, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        found = search_for_new_token_frame()

        if found:
            result = f"{server}:{port}\t- Server supports NEW_TOKEN frames."
            logging.info("The term 'new_token' was found in the log files. Server supports NEW_TOKEN frames.")
            append_to_results(result)
            return True
        else:
            result = f"{server}:{port}\t- Server doesn't support NEW_TOKEN frames."
            logging.info("The term 'new_token' was not found in the log files. Server doesn't support NEW_TOKEN frames.")
            append_to_results(result)
            return False
        
    except subprocess.CalledProcessError as e:
        result = f"{server}:{port}\t- Error: {e}"
        logging.error(f"Failed to run client script against {server} on port {port}: {e}")
        append_to_results(result)
        sys.exit(1)


def run_test_case_anti_amplification_limit(server, port):
    """
    Return True if the server doesn't send more than Anti-Amplification limit (with tolerance), and False otherwise.
    """
    global address_validation_token
    logging.info(f"Running test case anti_amplification_limit against {server} on port {port}.")
    client_command = [
        "python", "aioquic/examples/http3_client.py",
        "--ca-certs", "aioquic/tests/pycacert.pem",
        "--secrets-log", "aioquic/secrets.log",
        "--session-ticket", "aioquic/session",
        "--zero-rtt",
        "--insecure",
        "--output-dir", "aioquic/output",
        "--quic-log", "aioquic/log",
        "--verbose",
        "--server-name", "www.example.com",
        "--local-port", "5555",
        "--token", address_validation_token,
        f"https://localhost:{str(port)}/test.html"
    ]

    ret = check_anti_amplification_limit(server, port, client_command)

    if ret:
        result = f"{server}:{port}\t- Server doesn't send more data than Anti-Amplification limit (when sending 0-RTT with AVT)."
        append_to_results(result)
        return True
    else:
        result = f"{server}:{port}\t- Server sends more data than the Anti-Amplification limit (when sending 0-RTT with AVT). => susceptible"
        append_to_results(result)
        return False


def run_test_case_sending_AVT_multiple_times(server, port):
    logging.info(f"Running test case sending_AVT_multiple_times against {server} on port {port}.")
    client_command = [
        "python", "aioquic/examples/http3_client.py",
        "--ca-certs", "aioquic/tests/pycacert.pem",
        "--secrets-log", "aioquic/secrets.log",
        "--session-ticket", "aioquic/session_old",
        "--zero-rtt",
        "--insecure",
        "--output-dir", "aioquic/output",
        "--quic-log", "aioquic/log",
        "--verbose",
        "--server-name", "www.example.com",
        "--local-port", "5555",
        "--token", address_validation_token,
        f"https://localhost:{str(port)}/test.html"
    ]
    
    if check_anti_amplification_limit(server, port, client_command):
        result = f"{server}:{port}\t- Server doesn't accept valid Address Validation Tokens multiple times."
    else:
        result = f"{server}:{port}\t- Server accepts valid Address Validation Tokens multiple times. => SUSCEPTIBLE"
        
    append_to_results(result)


def security_consideration_amplification_attack(server, port):
    """
    Run test cases for security consideration Amplification Attack.
    """
    logging.info(f"Running test cases for security consideration 'Amplification attack' against {server} on port {port}.")
    
    if run_test_case_new_token_support(server, port):
        
        # Back up session for run_test_case_sending_AVT_multiple_times() latter
        backup_files(['./aioquic/session'], ['./aioquic/session_old'])
        
        if not run_test_case_anti_amplification_limit(server, port):
            # If server sends more than the Anti-Amplification limit
            run_test_case_sending_AVT_multiple_times(server, port)


def security_consideration_optimistic_ACK_attack(server, port):
    """
    Run test cases for security consideration Optimistic ACK Attack.
    """
    logging.info(f"Running test cases for security consideration 'Optimistic ACK attack' against {server} on port {port}.")
    client_command = [
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
        f"https://localhost:{str(port)}/largefile.bin"
    ]
    # Start tshark in the background
    tshark_process = subprocess.Popen(tshark_sniff_command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2)  # Give tshark some time to start up

    try:
        subprocess.run(client_command, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
    except subprocess.CalledProcessError as e:
        result = f"{server}:{port}\t- Error: {e}"
        logging.error(f"Failed to run client script against {server} on port {port}: {e}")
        append_to_results(result)
        sys.exit(1)
    except subprocess.TimeoutExpired:
        logging.error(f"The command timed out after 5 seconds")

    time.sleep(2)  
    # Stop the tshark process after the command completes
    tshark_process.terminate()
    # Wait for tshark to finish writing the capture file
    tshark_process.wait()

    # Read the capture
    capture = pyshark.FileCapture('./capture.pcap', display_filter='udp.dstport == 5555')
    
    logging.info(f"Analyzing captured QUIC packets and searching for CONNECTION_CLOSE frame...")

    connection_close_frame_found = False

    for packet in capture:
        quic_layer = packet.quic
     
        # Check if the QUIC layer contains a CONNECTION_CLOSE frame
        if hasattr(quic_layer, 'cc_error_code') and True:
            logging.info(f"Found CONNECTION_CLOSE frame in packet {packet.number}")
            connection_close_frame_found = True
            # Print error code, and reason phrase
            error_code = quic_layer.cc_error_code  # Error code
            reason_phrase = quic_layer.cc_reason_phrase  # Reason phrase
            
            logging.info(f"Error Code: {error_code}")
            logging.info(f"Reason Phrase: {reason_phrase}")

            result = f"{server}:{port}\t- Server terminated the connection upon receiving optimistic ACKs.'"
            append_to_results(result)
            result = f"{server}:{port}\t- Error code: {error_code}"
            append_to_results(result)
            result = f"{server}:{port}\t- Reason phrase: {reason_phrase}"
            append_to_results(result)
            break  # Exit the loop once the frame is found

    capture.close()

    if not connection_close_frame_found:
        result = f"{server}:{port}\t- Server didn't terminate the connection upon receiving optimistic ACKs."
        append_to_results(result)
        
    

def main(server_ports):
    global results_string
    results_string = ""

    append_to_results(f"\n---------------------------------------- AMPLIFICATION ATTACK ----------------------------------------\n")
    for sp in server_ports:
        server, port = sp.split(':')
        port = int(port)
        security_consideration_amplification_attack(server, port)
        append_to_results(f"\n")
    
    print(results_string)

    
    logging.info("Patching aioquic code to perform optimistic ACK...")
    # patch aioquic code to perform optimistic ACK
    try:
        os.chdir("./aioquic")
        subprocess.run(f"git apply ../optimisticACK.patch", shell=True, check=True)
        os.chdir("..")
    except subprocess.CalledProcessError as e:
        logging.info(f"Patch for Optimistic ACKs was already applied")
        os.chdir("..")


    append_to_results(f"\n---------------------------------------- OPTIMISTIC ACK ATTACK ----------------------------------------\n")
    for sp in server_ports:
        server, port = sp.split(':')
        port = int(port)
        security_consideration_optimistic_ACK_attack(server, port)
        append_to_results(f"\n")

    logging.info("Reversing the patch for Optimistic ACK attack...")
    # reverse the patch
    try:
        os.chdir("./aioquic")
        subprocess.run(f"git apply -R ../optimisticACK.patch", shell=True, check=True)
        os.chdir("..")
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to reverse the patch for Optimistic ACK Attack: {e}")
        sys.exit(1)
    
    logging.info("Results Summary:")
    print(results_string)

    

   
        




if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Example Usage: python3 testsuite.py aioquic:6001,lsquic:6002")
        sys.exit(1)
    server_ports = sys.argv[1].split(',')
    main(server_ports)
