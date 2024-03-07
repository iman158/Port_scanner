#!/usr/bin/env python

from scapy.all import ICMP, IP, sr1, RandShort

def port_scanner(host, port):
    ip = IP(dst=host)
    packet = ip/ICMP()
    response = sr1(packet, timeout=1, verbose=0)
    if response is not None:
        if response.haslayer(IP):
            if response.getlayer(IP).src == host:
                if port in range(1, 65535):
                    ip_protocol = IP(dst=host)
                    tcp_packet = ip_protocol/TCP(sport=RandShort(), dport=port)
                    response = sr1(tcp_packet, timeout=1, verbose=0)
                    if response is not None:
                        if response.haslayer(TCP):
                            if response.getlayer(TCP).sport == port:
                                print(f"Port {port} is open")
                                return
                print(f"Port {port} is closed")
                return
    print(f"Host {host} is unreachable")
    return

if __name__ == "__main__":
    host = input("Enter the host to scan: ")
    start_port = int(input("Enter the starting port: "))
    end_port = int(input("Enter the ending port: "))
    for port in range(start_port, end_port+1):
        port_scanner(host, port)