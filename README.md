# Network Analyzer

Network analyzer written in C using the pcap library that can recognize the following protocols : 
- ARP
- BOOTP/DHCP
- DNS
- Ethernet
- FTP
- HTTP/1.0 and HTTP/2.0
- IMAP
- IPv4 and IPv6
- POP
- SMTP
- TCP
- Telnet
- TFTP
- TLS
- UDP


## Usage

Compile by typing ***make***

Execute by typing : 
- ***./analyseur -i eth0 -v 1*** will analyze all packets received on the **eth0** interface with a verbosity level of 1
- ***./analyseur -o file.pcap -v 3 -f "tcp port 21"*** will analyze all the FTP control packets listed in **file.pcap** with a verbosity level of 3

There are 4 options available : 
- ***-i interface_name*** : MANDATORY if the ***-o*** option is not specified, you can specify the interface on which the analyzer will analyze packets (eg. ***-i eth0***)
- ***-o pcap_file*** : MANDATORY if the ***-i*** option is not specified, you can specify a input pcap file for the analyzer (eg. ***-o file.pcap***)
- ***-f bpf_filter*** : you can specify a BPF filter to exclude certain packets (eg. ***-f "tcp port 21"***)
- ***-v {1, 2, 3}*** : MANDATORY, you can specify a verbosity level that changes the amount of information the analyzer will provide for each packet received (eg. ***-v 3***)
