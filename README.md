Simple Port Scanner with Scapy
Overview

This Python script provides a simple yet effective port scanner using the Scapy library. It is designed to check the accessibility of ports on a specified host within a given port range. The scanner supports both ICMP and TCP-based scans.
Features

    ICMP Reachability Check: Initial check to verify the reachability of the target host.
    TCP Port Scanning: Dynamic TCP port scanning to identify open ports.
    Modular Structure: Organized code with modular functions for ICMP and TCP packet creation.
    Auto-detection of Local Host Port: Optionally auto-detects open ports on the local host after scanning the specified range.
    User-Friendly Interface: Simple console-based interface for easy interaction.

Requirements

    Python 3.x
    Scapy library (pip install scapy)
