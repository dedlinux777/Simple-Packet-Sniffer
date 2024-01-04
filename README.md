Simple Packet Sniffer
Description
The Simple Packet Sniffer is a Python-based tool built using Scapy, allowing users to intercept and analyze network traffic on a specified interface. This tool provides basic packet sniffing capabilities, capturing TCP packets and HTTP requests to monitor network activity.

Features
Sniff packets on a specified network interface.
Capture TCP packets and display source/destination IP addresses along with corresponding ports.
Identify HTTP requests, displaying relevant details such as requested URLs and methods.
Prerequisites
Before using this tool, ensure you have the necessary dependencies installed by running:

bash
Copy code
pip install -r requirements.txt
Usage
To execute the Simple Packet Sniffer, run the Python script and specify the network interface you want to sniff:

bash
Copy code
python Simple-Packet-Sniffer.py -i <INTERFACE>
Replace <INTERFACE> with the network interface you want to monitor.

License
This project is licensed under the [LICENSE_NAME] - see the [LICENSE_FILE] file for details.

Acknowledgments
Special thanks to the creators and contributors of Scapy and other related libraries used in this project.
