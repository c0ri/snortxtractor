# -- snortxtractor.py
# -- Description: This will extract base64 encoded files from a PCAP file as collected by snort (or wireshark).

import base64
from scapy.all import *

def extract_base64_files(pcap_file, output_folder):
    packets = rdpcap(pcap_file)

    for packet in packets:
        if 'Raw' in packet and 'base64' in str(packet[Raw].load):
            try:
                base64_data = str(packet[Raw].load).split('base64')[1].strip()
                file_data = base64.b64decode(base64_data)

                # Extracted file name can be derived from packet information (e.g., packet time)
                # Replace this with your logic to generate unique file names.
                file_name = f"extracted_file_{len(os.listdir(output_folder))}.bin"

                file_path = os.path.join(output_folder, file_name)

                with open(file_path, 'wb') as file:
                    file.write(file_data)

                print(f"File extracted: {file_path}")

            except Exception as e:
                print(f"Error extracting base64 data: {e}")

if __name__ == "__main__":
    pcap_file_path = "path/to/your/file.pcap"
    output_folder_path = "path/to/output/folder"

    if not os.path.exists(output_folder_path):
        os.makedirs(output_folder_path)

    extract_base64_files(pcap_file_path, output_folder_path)
