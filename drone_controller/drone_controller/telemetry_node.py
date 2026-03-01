"""
Drone Telemetry Node
=====================
Subscribes to the ``drone_state`` topic published by the controller node and
logs a human-readable telemetry summary.  It also re-publishes a condensed
``std_msgs/String`` summary on ``drone_telemetry`` for easy monitoring with
``ros2 topic echo``.
"""

import rclpy
from rclpy.node import Node
from std_msgs.msg import String

try:
    from drone_interfaces.msg import DroneState
    INTERFACES_AVAILABLE = True
except ImportError:
    INTERFACES_AVAILABLE = False


class TelemetryNode(Node):
    """ROS2 drone telemetry monitoring node."""

    def __init__(self):
        super().__init__('telemetry_node')

        if not INTERFACES_AVAILABLE:
            self.get_logger().error(
                'drone_interfaces is not available. '
                'Build and source that package first.'
            )
            raise RuntimeError('drone_interfaces package is required.')

        self._summary_pub = self.create_publisher(
            String, 'drone_telemetry', 10
        )
        self.create_subscription(
            DroneState, 'drone_state', self._state_callback, 10
        )

        self.get_logger().info('Drone telemetry node started.')

    def _state_callback(self, msg):
        """Format and re-publish a human-readable telemetry summary."""
        summary_lines = [
            '--- Drone Telemetry ---',
            f'Mode     : {msg.mode}',
            f'Armed    : {msg.armed}',
            f'Altitude : {msg.altitude:.2f} m',
            f'Position : x={msg.position.x:.2f}  y={msg.position.y:.2f}  z={msg.position.z:.2f}',
            f'Velocity : vx={msg.velocity.x:.2f}  vy={msg.velocity.y:.2f}  vz={msg.velocity.z:.2f}',
            f'Battery  : {msg.battery_percentage:.1f}%',
        ]
        summary = '\n'.join(summary_lines)

        out = String()
        out.data = summary
        self._summary_pub.publish(out)
        self.get_logger().info(summary)


def main(args=None):
    rclpy.init(args=args)
    node = TelemetryNode()
    try:
        rclpy.spin(node)
    finally:
        node.destroy_node()
        rclpy.shutdown()


if __name__ == '__main__':
    main()
