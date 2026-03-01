import unittest
from unittest.mock import MagicMock, patch

from network_sniffer.sniffer_node import SCAPY_AVAILABLE


class TestSnifferNodeImports(unittest.TestCase):

    def test_scapy_import_flag(self):
        """SCAPY_AVAILABLE should be a boolean."""
        self.assertIsInstance(SCAPY_AVAILABLE, bool)

    def test_main_is_callable(self):
        """main() should be a callable."""
        from network_sniffer.sniffer_node import main
        self.assertTrue(callable(main))

    def test_sniffer_node_class_exists(self):
        """SnifferNode should be importable."""
        from network_sniffer.sniffer_node import SnifferNode
        self.assertTrue(issubclass(SnifferNode, object))


class TestPacketCallback(unittest.TestCase):
    """Tests for _packet_callback using mocked ROS2 and scapy objects."""

    def _make_node(self):
        """Return a SnifferNode with ROS2 and scapy mocked out."""
        with patch('network_sniffer.sniffer_node.SCAPY_AVAILABLE', True), \
             patch('network_sniffer.sniffer_node.sniff'), \
             patch('network_sniffer.sniffer_node.threading.Thread') as mock_thread, \
             patch('rclpy.node.Node.__init__', return_value=None):
            mock_thread.return_value.start = MagicMock()
            from network_sniffer.sniffer_node import SnifferNode
            node = SnifferNode.__new__(SnifferNode)
            node.publisher_ = MagicMock()
            node.get_logger = MagicMock(return_value=MagicMock())
            return node

    def _make_ip_tcp_packet(self):
        """Build a minimal mock packet with IP and TCP layers."""
        from network_sniffer.sniffer_node import IP, TCP
        packet = MagicMock()
        packet.__contains__ = lambda self, item: item in (IP, TCP)

        ip = MagicMock()
        ip.src = '192.168.1.1'
        ip.dst = '10.0.0.1'
        ip.proto = 6

        tcp = MagicMock()
        tcp.sport = 12345
        tcp.dport = 80

        def getitem(key):
            if key is IP:
                return ip
            if key is TCP:
                return tcp
            raise KeyError(key)

        packet.__getitem__ = lambda self, key: getitem(key)
        return packet

    def _make_ip_udp_packet(self):
        """Build a minimal mock packet with IP and UDP layers."""
        from network_sniffer.sniffer_node import IP, TCP, UDP
        packet = MagicMock()
        packet.__contains__ = lambda self, item: item in (IP, UDP)

        ip = MagicMock()
        ip.src = '10.0.0.2'
        ip.dst = '8.8.8.8'
        ip.proto = 17

        udp = MagicMock()
        udp.sport = 54321
        udp.dport = 53

        def getitem(key):
            if key is IP:
                return ip
            if key is UDP:
                return udp
            raise KeyError(key)

        packet.__getitem__ = lambda self, key: getitem(key)
        return packet

    @unittest.skipUnless(SCAPY_AVAILABLE, 'scapy not installed')
    def test_tcp_packet_published(self):
        """A TCP packet should be published with correct fields."""
        node = self._make_node()
        packet = self._make_ip_tcp_packet()
        node._packet_callback(packet)
        node.publisher_.publish.assert_called_once()
        published = node.publisher_.publish.call_args[0][0]
        self.assertIn('192.168.1.1', published.data)
        self.assertIn('TCP', published.data)
        self.assertIn('80', published.data)

    @unittest.skipUnless(SCAPY_AVAILABLE, 'scapy not installed')
    def test_udp_packet_published(self):
        """A UDP packet should be published with correct fields."""
        node = self._make_node()
        packet = self._make_ip_udp_packet()
        node._packet_callback(packet)
        node.publisher_.publish.assert_called_once()
        published = node.publisher_.publish.call_args[0][0]
        self.assertIn('UDP', published.data)
        self.assertIn('53', published.data)

    @unittest.skipUnless(SCAPY_AVAILABLE, 'scapy not installed')
    def test_non_ip_packet_ignored(self):
        """A packet without an IP layer should not be published."""
        from network_sniffer.sniffer_node import IP
        node = self._make_node()
        packet = MagicMock()
        packet.__contains__ = lambda self, item: False
        node._packet_callback(packet)
        node.publisher_.publish.assert_not_called()


if __name__ == '__main__':
    unittest.main()
