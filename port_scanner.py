#!/usr/bin/env python

from scapy.all import ICMP, IP, TCP, sr1, RandShort
import socket

def get_local_ip():
    try:
        # Create a socket connection to a remote host (in this case, Google's public DNS)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except socket.error:
        return "127.0.0.1"

def create_icmp_packet(host):
    return IP(dst=host)/ICMP()

def create_tcp_packet(host, port):
    return IP(dst=host)/TCP(sport=RandShort(), dport=port)

def port_scanner(host, port):
    try:
        icmp_packet = create_icmp_packet(host)
        response = sr1(icmp_packet, timeout=1, verbose=0)

        if response is not None and response.haslayer(IP) and response.getlayer(IP).src == host:
            if port in range(1, 65535):
                tcp_packet = create_tcp_packet(host, port)
                response = sr1(tcp_packet, timeout=1, verbose=0)

                if response is not None and response.haslayer(TCP) and response.getlayer(TCP).sport == port:
                    print(f"Port {port} is open")
                    return

            print(f"Port {port} is closed")
            return

        print(f"Host {host} is unreachable")

    except KeyboardInterrupt:
        print("\nScan interrupted by user.")
        exit()

if __name__ == "__main__":
    try:
        host = input("Enter the host to scan (default is localhost): ") or get_local_ip()
        print(f"Scanning ports for host: {host}")

        start_port = int(input("Enter the starting port: "))
        end_port = int(input("Enter the ending port: "))

        for port in range(start_port, end_port + 1):
            port_scanner(host, port)

        local_port = input("\nDo you want to auto-detect the local host's open port? (y/n): ")
        if local_port.lower() == 'y':
            local_host = "127.0.0.1"
            for port in range(1, 1025):  # Check common ports
                port_scanner(local_host, port)

    except ValueError:
        print("Invalid input. Please enter a valid numerical value.")
    except Exception as e:
        print(f"An error occurred: {e}")
