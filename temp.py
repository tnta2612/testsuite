import subprocess
import logging
import time
import sys
import pyshark
tshark_sniff_command = [
    'tshark', '-i', 'lo', '-f', 'udp port 5555', '-w', './capture.pcap'
]
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

results_string = ""

def append_to_results(result):
    global results_string
    results_string += result + "\n"

if __name__ == "__main__":
    server = "MVFST"
    port = 6003
    """
    Run test cases for security consideration Optimistic ACK Attack.
    """
    logging.info(f"Running test cases for security consideration 'Optimistic ACK attack' against mvfst on port 6003.")
    client_command = [
        "python3", "aioquic/examples/http3_client.py",
        "--ca-certs", "aioquic/tests/pycacert.pem",
        "--secrets-log", "aioquic/secrets.log",
        "--insecure",
        "--output-dir", "aioquic/output",
        "--quic-log", "aioquic/log",
        "--verbose",
        "--server-name", "www.example.com",
        "--local-port", "5555",
        f"https://localhost:6003/largefile.bin"
    ]


    # Start tshark in the background
    tshark_process = subprocess.Popen(tshark_sniff_command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2)  # Give tshark some time to start up

    try:
        logging.info(f"Executing client command: {' '.join(client_command)}")
        subprocess.run(client_command, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)#, timeout=5)
    except subprocess.CalledProcessError as e:
        result = f"{server}:{port}\t- Error: {e}"
        logging.error(f"Failed to run client script against {server} on port {port}: {e}")
        append_to_results(result)
        sys.exit(1)
    except subprocess.TimeoutExpired:
        logging.warning(f"The command timed out after 5 seconds")

    time.sleep(2)  
    # Stop the tshark process after the command completes
    tshark_process.terminate()
    # Wait for tshark to finish writing the capture file
    tshark_process.wait()

    # Read the capture
    capture = pyshark.FileCapture('./capture.pcap', display_filter='udp.dstport == 5555')
    
    logging.info(f"Analyzing captured QUIC packets and searching for CONNECTION_CLOSE frame...")

    connection_close_frame_found = False
    expected_packet_number = None
    missing_packet_number = 0
    packet_count = None

    for packet in capture:
        if connection_close_frame_found:
            break

        for layer in packet.layers:
            if layer.layer_name == "quic":
                current_packet_number = int(layer.packet_number)
                if (expected_packet_number is None) or (current_packet_number < expected_packet_number):
                    logging.info(f"Packet number reset.")
                    missing_packet_number = 0
                    packet_count = 0
                elif (current_packet_number > expected_packet_number):
                    missing_packet_number += current_packet_number - expected_packet_number
                    while (current_packet_number > expected_packet_number):
                        logging.info(f"{expected_packet_number} is missing!!!")
                        expected_packet_number += 1

                expected_packet_number = current_packet_number + 1
                packet_count += 1


#                if (missing_packet_number < 10):
#                    logging.info(f"Expect {expected_packet_number}, received {current_packet_number}") 

                # Check if the QUIC layer contains a CONNECTION_CLOSE frame
                if hasattr(layer, 'cc_error_code'):
                    logging.info(f"Found CONNECTION_CLOSE frame in packet {packet.number}")
                    connection_close_frame_found = True
                    # Print error code, and reason phrase
                    error_code = layer.cc_error_code  # Error code
                    reason_phrase = layer.cc_reason_phrase  # Reason phrase
            
                    logging.info(f"Error Code: {error_code}")
                    logging.info(f"Reason Phrase: {reason_phrase}")

                    result = f"{server}:{port}\t- Server terminated the connection upon receiving optimistic ACKs."
                    append_to_results(result)
                    result = f"{server}:{port}\t- Error code: {error_code}"
                    append_to_results(result)
                    result = f"{server}:{port}\t- Reason phrase: {reason_phrase}"
                    append_to_results(result)
                    break  # Exit the loop once the frame is found

    capture.close()

    if not connection_close_frame_found:
        logging.info(f"Received {packet_count} packets in total. {missing_packet_number} are missing. ")
        result = f"{server}:{port}\t- Server didn't skip any packet number or didn't terminate the connection upon receiving optimistic ACKs. => susceptible"
        append_to_results(result)

    print(result)
        
