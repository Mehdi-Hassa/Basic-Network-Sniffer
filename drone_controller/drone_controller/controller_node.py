"""
Drone Controller Node
=====================
Manages drone state and exposes ROS2 services for arm/disarm, takeoff, and
landing.  Accepts velocity commands on the ``cmd_vel`` topic and publishes a
periodic ``DroneState`` snapshot on ``drone_state``.

This node simulates drone behaviour when no real flight-controller bridge is
present, making it suitable for software-in-the-loop testing.
"""

import rclpy
from rclpy.node import Node

from geometry_msgs.msg import Twist
from std_msgs.msg import Header

try:
    from drone_interfaces.msg import DroneState
    from drone_interfaces.srv import Arm, Land, Takeoff
    INTERFACES_AVAILABLE = True
except ImportError:
    INTERFACES_AVAILABLE = False

# Default state-publish frequency (Hz)
_STATE_PUBLISH_HZ = 10
# Simulated battery drain per second while armed (percent)
_BATTERY_DRAIN_RATE = 0.005
# Simulated climb/descent rate (m/s)
_CLIMB_RATE = 1.0


class ControllerNode(Node):
    """ROS2 drone controller node."""

    def __init__(self):
        super().__init__('controller_node')

        if not INTERFACES_AVAILABLE:
            self.get_logger().error(
                'drone_interfaces is not available. '
                'Build and source that package first.'
            )
            raise RuntimeError('drone_interfaces package is required.')

        # --- internal state ---------------------------------------------------
        self._armed = False
        self._mode = 'IDLE'
        self._altitude = 0.0
        self._target_altitude = 0.0
        self._battery = 100.0
        self._velocity_x = 0.0
        self._velocity_y = 0.0
        self._velocity_z = 0.0
        self._pos_x = 0.0
        self._pos_y = 0.0

        # --- publishers -------------------------------------------------------
        self._state_pub = self.create_publisher(DroneState, 'drone_state', 10)

        # --- subscribers ------------------------------------------------------
        self.create_subscription(
            Twist, 'cmd_vel', self._cmd_vel_callback, 10
        )

        # --- services ---------------------------------------------------------
        self.create_service(Arm, 'arm', self._arm_callback)
        self.create_service(Takeoff, 'takeoff', self._takeoff_callback)
        self.create_service(Land, 'land', self._land_callback)

        # --- timer ------------------------------------------------------------
        period = 1.0 / _STATE_PUBLISH_HZ
        self.create_timer(period, self._publish_state)

        self.get_logger().info('Drone controller node started.')

    # ------------------------------------------------------------------
    # Service callbacks
    # ------------------------------------------------------------------

    def _arm_callback(self, request, response):
        if request.arm:
            if self._armed:
                response.success = False
                response.message = 'Drone is already armed.'
            else:
                self._armed = True
                self._mode = 'HOVER'
                response.success = True
                response.message = 'Drone armed successfully.'
                self.get_logger().info('Drone ARMED.')
        else:
            if not self._armed:
                response.success = False
                response.message = 'Drone is already disarmed.'
            elif self._altitude > 0.1:
                response.success = False
                response.message = 'Cannot disarm while airborne. Land first.'
            else:
                self._armed = False
                self._mode = 'IDLE'
                response.success = True
                response.message = 'Drone disarmed successfully.'
                self.get_logger().info('Drone DISARMED.')
        return response

    def _takeoff_callback(self, request, response):
        if not self._armed:
            response.success = False
            response.message = 'Drone must be armed before takeoff.'
        elif request.altitude <= 0.0:
            response.success = False
            response.message = 'Target altitude must be greater than 0.'
        else:
            self._target_altitude = request.altitude
            self._mode = 'TAKEOFF'
            response.success = True
            response.message = (
                f'Taking off to {request.altitude:.1f} m.'
            )
            self.get_logger().info(
                f'TAKEOFF commanded to {request.altitude:.1f} m.'
            )
        return response

    def _land_callback(self, request, response):
        if not self._armed:
            response.success = False
            response.message = 'Drone is not armed.'
        else:
            self._target_altitude = 0.0
            self._mode = 'LANDING'
            response.success = True
            response.message = 'Landing initiated.'
            self.get_logger().info('LAND commanded.')
        return response

    # ------------------------------------------------------------------
    # Subscription callbacks
    # ------------------------------------------------------------------

    def _cmd_vel_callback(self, msg):
        """Accept velocity commands only when airborne."""
        if self._armed and self._altitude > 0.0:
            self._velocity_x = msg.linear.x
            self._velocity_y = msg.linear.y
            self._velocity_z = msg.linear.z

    # ------------------------------------------------------------------
    # Timer callback — simulate physics and publish state
    # ------------------------------------------------------------------

    def _publish_state(self):
        dt = 1.0 / _STATE_PUBLISH_HZ

        # Simulate altitude changes
        if self._mode == 'TAKEOFF':
            self._altitude = min(
                self._altitude + _CLIMB_RATE * dt,
                self._target_altitude,
            )
            if abs(self._altitude - self._target_altitude) < 0.05:
                self._mode = 'HOVER'
                self.get_logger().info(
                    f'Reached target altitude {self._altitude:.2f} m. HOVER.'
                )
        elif self._mode == 'LANDING':
            self._altitude = max(self._altitude - _CLIMB_RATE * dt, 0.0)
            if self._altitude <= 0.0:
                self._armed = False
                self._mode = 'IDLE'
                self.get_logger().info('Landed. Drone DISARMED.')
        elif self._mode == 'HOVER' and self._armed:
            # Update position from cmd_vel
            self._pos_x += self._velocity_x * dt
            self._pos_y += self._velocity_y * dt
            self._altitude = max(
                self._altitude + self._velocity_z * dt, 0.0
            )

        # Drain battery while armed
        if self._armed:
            self._battery = max(self._battery - _BATTERY_DRAIN_RATE * dt, 0.0)
            if self._battery == 0.0:
                self.get_logger().warning('Battery depleted! Initiating emergency land.')
                self._target_altitude = 0.0
                self._mode = 'LANDING'

        # Build and publish message
        msg = DroneState()
        msg.header = Header()
        msg.header.stamp = self.get_clock().now().to_msg()
        msg.header.frame_id = 'base_link'
        msg.position.x = self._pos_x
        msg.position.y = self._pos_y
        msg.position.z = self._altitude
        msg.velocity.x = self._velocity_x
        msg.velocity.y = self._velocity_y
        msg.velocity.z = self._velocity_z
        msg.battery_percentage = self._battery
        msg.armed = self._armed
        msg.mode = self._mode
        msg.altitude = self._altitude

        self._state_pub.publish(msg)


def main(args=None):
    rclpy.init(args=args)
    node = ControllerNode()
    try:
        rclpy.spin(node)
    finally:
        node.destroy_node()
        rclpy.shutdown()


if __name__ == '__main__':
    main()
