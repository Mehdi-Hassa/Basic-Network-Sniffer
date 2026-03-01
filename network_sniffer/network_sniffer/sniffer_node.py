import threading

import rclpy
from rclpy.node import Node
from std_msgs.msg import String

try:
    from scapy.all import sniff, IP, TCP, UDP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class SnifferNode(Node):
    """ROS2 node that captures network packets and publishes their details."""

    def __init__(self):
        super().__init__('sniffer_node')
        self.publisher_ = self.create_publisher(String, 'packet_info', 10)
        self.get_logger().info('Network sniffer node started.')

        if not SCAPY_AVAILABLE:
            self.get_logger().error(
                'scapy is not installed. Install it with: pip install scapy'
            )
            raise RuntimeError('scapy is required but not installed.')

        self.get_logger().info(
            'Starting packet capture... Press CTRL+C to stop.'
        )
        self._sniffer_thread = threading.Thread(
            target=lambda: sniff(prn=self._packet_callback, store=False),
            daemon=True,
        )
        self._sniffer_thread.start()

    def _packet_callback(self, packet):
        """Process a captured packet and publish its details."""
        if IP not in packet:
            return

        ip_layer = packet[IP]
        lines = [
            '--- New Packet Captured ---',
            f'Source IP: {ip_layer.src}',
            f'Destination IP: {ip_layer.dst}',
            f'Protocol: {ip_layer.proto}',
        ]

        if TCP in packet:
            tcp_layer = packet[TCP]
            lines.append('Protocol Type: TCP')
            lines.append(f'Source Port: {tcp_layer.sport}')
            lines.append(f'Destination Port: {tcp_layer.dport}')
        elif UDP in packet:
            udp_layer = packet[UDP]
            lines.append('Protocol Type: UDP')
            lines.append(f'Source Port: {udp_layer.sport}')
            lines.append(f'Destination Port: {udp_layer.dport}')

        msg = String()
        msg.data = '\n'.join(lines)
        self.publisher_.publish(msg)
        self.get_logger().info(msg.data)


def main(args=None):
    rclpy.init(args=args)
    node = SnifferNode()
    try:
        rclpy.spin(node)
    finally:
        node.destroy_node()
        rclpy.shutdown()


if __name__ == '__main__':
    main()
