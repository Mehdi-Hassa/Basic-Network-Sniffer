# Current drone state snapshot

std_msgs/Header header

# Position in local NED frame (metres)
geometry_msgs/Point position

# Linear velocity (m/s)
geometry_msgs/Vector3 velocity

# Battery state of charge (0.0 – 100.0)
float32 battery_percentage

# Whether the drone motors are armed
bool armed

# Flight mode string (e.g. "IDLE", "HOVER", "MISSION", "LANDING")
string mode

# Altitude above home point (metres)
float32 altitude
