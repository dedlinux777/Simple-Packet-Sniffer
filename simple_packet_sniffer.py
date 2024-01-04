from scapy.all import *
from scapy.layers.inet import IP
from scapy.layers.http import HTTPRequest, HTTPResponse, TCP
from colorama import init, Fore
from scapy.all import sniff
import argparse

# Function to retrieve the interface from command-line arguments
def get_interface():
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--interface', dest='interface', help='add the interface you want to sniff')
    arguments = parser.parse_args()
    return arguments

# Initialize colors using Colorama
init()
red = Fore.RED
green = Fore.GREEN
blue = Fore.BLUE
reset = Fore.RESET
yellow = Fore.YELLOW
cyan = Fore.CYAN

# Function to sniff packets on the specified interface
def sniff_packets(iface1):
    sniff(iface=iface1.interface, store=0, prn=process_packets)

# Function to process packets captured by the sniffer
def process_packets(packet):
    if packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport

        # Print TCP connection information
        print(f"{blue} [+] {src_ip} is using port {src_port} to connect to {dst_ip} at port {dst_port}")

    if packet.haslayer(HTTPRequest):
        # Extract HTTP request details
        url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
        method = packet[HTTPRequest].Method.decode()
        print(f"{green} [+] {src_ip} is making a request to {url} with method {method}")
        print(f"[+]HTTP DATA:")
        print(f"{yellow} {packet[HTTPRequest].show()}")

        if packet.haslayer(Raw):
            # Extract and print useful raw data from the packet
            print(f"{red} [+] Useful raw data: {packet.getlayer(Raw).load.decode()} {reset}")

# Retrieve the interface from command-line arguments
iface1 = get_interface()
# Start sniffing packets on the specified interface
sniff_packets(iface1)
