# Basic-Network-Sniffer

A Python network packet sniffer built with [scapy](https://scapy.net/),
extended with [ROS 2](https://docs.ros.org/en/humble/) drone-control packages.

## Packages

| Package | Type | Description |
|---|---|---|
| `network_sniffer` | ament_python | Captures IP/TCP/UDP packets and publishes them as ROS 2 messages |
| `drone_interfaces` | ament_cmake | Custom ROS 2 messages and services for drone development |
| `drone_controller` | ament_python | Drone controller and telemetry nodes |

## Quick start (core sniffer)

```python
from scapy.all import sniff, IP, TCP, UDP

def packet_callback(packet):
    if IP in packet:
        ip_layer = packet[IP]

        print("\n--- New Packet Captured ---")
        print(f"Source IP: {ip_layer.src}")
        print(f"Destination IP: {ip_layer.dst}")
        print(f"Protocol: {ip_layer.proto}")

        if TCP in packet:
            tcp_layer = packet[TCP]
            print("Protocol Type: TCP")
            print(f"Source Port: {tcp_layer.sport}")
            print(f"Destination Port: {tcp_layer.dport}")

        elif UDP in packet:
            udp_layer = packet[UDP]
            print("Protocol Type: UDP")
            print(f"Source Port: {udp_layer.sport}")
            print(f"Destination Port: {udp_layer.dport}")

print("Starting network sniffer... Press CTRL + C to stop.")
sniff(prn=packet_callback, store=False)
```

## Developer setup

New to the project?  The docs folder has two guides:

| Guide | What it covers |
|---|---|
| [docs/development-setup.md](docs/development-setup.md) | Installing VSCode, ROS 2 Humble, Python dependencies, and building the workspace |
| [docs/usage-guide.md](docs/usage-guide.md) | **Start-to-end** walkthrough — VSCode orientation, ROS 2 concepts, running the drone simulation and network sniffer |
