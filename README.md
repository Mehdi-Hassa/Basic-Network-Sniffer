################### Basic-Network-Sniffer #################


from scapy.all import sniff, IP, TCP, UDP

# ----------------------------------------------------
# Function to process each captured packet
# ----------------------------------------------------
def packet_callback(packet):
    # Check if packet contains an IP layer
    if IP in packet:
        ip_layer = packet[IP]

        print("\n--- New Packet Captured ---")
        print(f"Source IP: {ip_layer.src}")     # IP of sender
        print(f"Destination IP: {ip_layer.dst}")  # IP of receiver
        print(f"Protocol: {ip_layer.proto}")      # Protocol number

        # Check for TCP packets
        if TCP in packet:
            tcp_layer = packet[TCP]
            print("Protocol Type: TCP")
            print(f"Source Port: {tcp_layer.sport}")
            print(f"Destination Port: {tcp_layer.dport}")

        # Check for UDP packets
        elif UDP in packet:
            udp_layer = packet[UDP]
            print("Protocol Type: UDP")
            print(f"Source Port: {udp_layer.sport}")
            print(f"Destination Port: {udp_layer.dport}")

# ----------------------------------------------------
# Start sniffing network traffic
# ----------------------------------------------------
print("Starting network sniffer... Press CTRL + C to stop.")
sniff(prn=packet_callback, store=False)
