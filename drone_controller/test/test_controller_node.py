import sys
import types
import unittest
from unittest.mock import MagicMock


# ---------------------------------------------------------------------------
# Inject lightweight stubs for rclpy and drone_interfaces before any import
# ---------------------------------------------------------------------------

def _inject_stubs():
    """Add minimal stub modules so controller_node can be imported without ROS2."""
    # rclpy stubs
    rclpy_mod = types.ModuleType('rclpy')
    rclpy_mod.init = MagicMock()
    rclpy_mod.spin = MagicMock()
    rclpy_mod.shutdown = MagicMock()
    sys.modules.setdefault('rclpy', rclpy_mod)

    node_mod = types.ModuleType('rclpy.node')

    class _FakeNode:
        def __init__(self, name):
            pass

    node_mod.Node = _FakeNode
    sys.modules.setdefault('rclpy.node', node_mod)

    # geometry_msgs stubs
    for mod_name in ('geometry_msgs', 'geometry_msgs.msg'):
        sys.modules.setdefault(mod_name, types.ModuleType(mod_name))
    geo_msg = sys.modules['geometry_msgs.msg']
    for cls in ('Twist', 'Point', 'Vector3'):
        if not hasattr(geo_msg, cls):
            setattr(geo_msg, cls, MagicMock)

    # std_msgs stubs
    for mod_name in ('std_msgs', 'std_msgs.msg'):
        sys.modules.setdefault(mod_name, types.ModuleType(mod_name))
    std_msg = sys.modules['std_msgs.msg']
    for cls in ('String', 'Header'):
        if not hasattr(std_msg, cls):
            setattr(std_msg, cls, MagicMock)

    # drone_interfaces stubs
    for mod_name in ('drone_interfaces', 'drone_interfaces.msg', 'drone_interfaces.srv'):
        sys.modules.setdefault(mod_name, types.ModuleType(mod_name))
    di_msg = sys.modules['drone_interfaces.msg']
    for cls in ('DroneState', 'Waypoint'):
        if not hasattr(di_msg, cls):
            setattr(di_msg, cls, MagicMock)
    di_srv = sys.modules['drone_interfaces.srv']
    for cls in ('Arm', 'Takeoff', 'Land'):
        if not hasattr(di_srv, cls):
            setattr(di_srv, cls, MagicMock)


_inject_stubs()

from drone_controller.controller_node import ControllerNode  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_controller():
    """Return a ControllerNode with internal state initialised directly."""
    node = ControllerNode.__new__(ControllerNode)
    node._armed = False
    node._mode = 'IDLE'
    node._altitude = 0.0
    node._target_altitude = 0.0
    node._battery = 100.0
    node._velocity_x = 0.0
    node._velocity_y = 0.0
    node._velocity_z = 0.0
    node._pos_x = 0.0
    node._pos_y = 0.0
    node._state_pub = MagicMock()
    node.get_logger = MagicMock(return_value=MagicMock())
    node.get_clock = MagicMock(return_value=MagicMock(
        now=MagicMock(return_value=MagicMock(
            to_msg=MagicMock(return_value=MagicMock())
        ))
    ))
    return node


def _make_response():
    resp = MagicMock()
    resp.success = False
    resp.message = ''
    return resp


# ---------------------------------------------------------------------------
# Arm / disarm tests
# ---------------------------------------------------------------------------

class TestArmService(unittest.TestCase):

    def test_arm_success(self):
        node = _make_controller()
        req = MagicMock(arm=True)
        resp = node._arm_callback(req, _make_response())
        self.assertTrue(resp.success)
        self.assertTrue(node._armed)
        self.assertEqual(node._mode, 'HOVER')

    def test_arm_already_armed(self):
        node = _make_controller()
        node._armed = True
        req = MagicMock(arm=True)
        resp = node._arm_callback(req, _make_response())
        self.assertFalse(resp.success)

    def test_disarm_success(self):
        node = _make_controller()
        node._armed = True
        node._altitude = 0.0
        req = MagicMock(arm=False)
        resp = node._arm_callback(req, _make_response())
        self.assertTrue(resp.success)
        self.assertFalse(node._armed)
        self.assertEqual(node._mode, 'IDLE')

    def test_disarm_while_airborne_fails(self):
        node = _make_controller()
        node._armed = True
        node._altitude = 10.0
        req = MagicMock(arm=False)
        resp = node._arm_callback(req, _make_response())
        self.assertFalse(resp.success)
        self.assertTrue(node._armed)


# ---------------------------------------------------------------------------
# Takeoff tests
# ---------------------------------------------------------------------------

class TestTakeoffService(unittest.TestCase):

    def test_takeoff_success(self):
        node = _make_controller()
        node._armed = True
        req = MagicMock(altitude=10.0)
        resp = node._takeoff_callback(req, _make_response())
        self.assertTrue(resp.success)
        self.assertEqual(node._mode, 'TAKEOFF')
        self.assertAlmostEqual(node._target_altitude, 10.0)

    def test_takeoff_not_armed(self):
        node = _make_controller()
        req = MagicMock(altitude=10.0)
        resp = node._takeoff_callback(req, _make_response())
        self.assertFalse(resp.success)

    def test_takeoff_zero_altitude_fails(self):
        node = _make_controller()
        node._armed = True
        req = MagicMock(altitude=0.0)
        resp = node._takeoff_callback(req, _make_response())
        self.assertFalse(resp.success)


# ---------------------------------------------------------------------------
# Land tests
# ---------------------------------------------------------------------------

class TestLandService(unittest.TestCase):

    def test_land_success(self):
        node = _make_controller()
        node._armed = True
        node._altitude = 5.0
        resp = node._land_callback(None, _make_response())
        self.assertTrue(resp.success)
        self.assertEqual(node._mode, 'LANDING')
        self.assertAlmostEqual(node._target_altitude, 0.0)

    def test_land_not_armed(self):
        node = _make_controller()
        resp = node._land_callback(None, _make_response())
        self.assertFalse(resp.success)


# ---------------------------------------------------------------------------
# cmd_vel tests
# ---------------------------------------------------------------------------

class TestCmdVel(unittest.TestCase):

    def test_cmd_vel_applied_when_airborne(self):
        node = _make_controller()
        node._armed = True
        node._altitude = 5.0
        twist = MagicMock()
        twist.linear.x = 1.0
        twist.linear.y = 2.0
        twist.linear.z = 0.5
        node._cmd_vel_callback(twist)
        self.assertAlmostEqual(node._velocity_x, 1.0)
        self.assertAlmostEqual(node._velocity_y, 2.0)

    def test_cmd_vel_ignored_when_not_armed(self):
        node = _make_controller()
        node._armed = False
        twist = MagicMock()
        twist.linear.x = 3.0
        twist.linear.y = 3.0
        twist.linear.z = 0.0
        node._cmd_vel_callback(twist)
        self.assertAlmostEqual(node._velocity_x, 0.0)


# ---------------------------------------------------------------------------
# Simulated physics tests
# ---------------------------------------------------------------------------

class TestSimulatedPhysics(unittest.TestCase):

    def test_takeoff_mode_increases_altitude(self):
        node = _make_controller()
        node._armed = True
        node._mode = 'TAKEOFF'
        node._target_altitude = 5.0
        node._publish_state()
        self.assertGreater(node._altitude, 0.0)

    def test_landing_mode_decreases_altitude(self):
        node = _make_controller()
        node._armed = True
        node._mode = 'LANDING'
        node._altitude = 3.0
        node._target_altitude = 0.0
        node._publish_state()
        self.assertLess(node._altitude, 3.0)

    def test_hover_updates_position(self):
        node = _make_controller()
        node._armed = True
        node._mode = 'HOVER'
        node._altitude = 5.0
        node._velocity_x = 1.0
        node._velocity_y = 1.0
        node._publish_state()
        self.assertGreater(node._pos_x, 0.0)
        self.assertGreater(node._pos_y, 0.0)

    def test_battery_drains_while_armed(self):
        node = _make_controller()
        node._armed = True
        node._mode = 'HOVER'
        node._altitude = 5.0
        node._publish_state()
        self.assertLess(node._battery, 100.0)

    def test_battery_stable_when_disarmed(self):
        node = _make_controller()
        node._armed = False
        node._publish_state()
        self.assertAlmostEqual(node._battery, 100.0)

    def test_state_published(self):
        node = _make_controller()
        node._publish_state()
        node._state_pub.publish.assert_called_once()


if __name__ == '__main__':
    unittest.main()
