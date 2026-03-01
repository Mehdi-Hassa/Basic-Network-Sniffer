# Using ROS 2 Humble and VSCode — Start to End

> **Prerequisites**: ROS 2 Humble and VSCode are already installed on your
> Ubuntu 22.04 machine.  If not, follow
> [development-setup.md](development-setup.md) first.

This guide takes you from a fresh terminal to a running drone simulation with
live telemetry and network packet capture, entirely inside VSCode.

---

## Table of Contents

1. [VSCode orientation](#1-vscode-orientation)
2. [Understanding ROS 2 concepts](#2-understanding-ros-2-concepts)
3. [Step 1 — Clone and prepare the workspace](#step-1--clone-and-prepare-the-workspace)
4. [Step 2 — Install extensions](#step-2--install-extensions)
5. [Step 3 — Build the workspace](#step-3--build-the-workspace)
6. [Step 4 — Run the drone controller](#step-4--run-the-drone-controller)
7. [Step 5 — Run the telemetry monitor](#step-5--run-the-telemetry-monitor)
8. [Step 6 — Fly the simulated drone](#step-6--fly-the-simulated-drone)
9. [Step 7 — Run the network sniffer](#step-7--run-the-network-sniffer)
10. [ROS 2 quick-reference cheat sheet](#ros-2-quick-reference-cheat-sheet)
11. [Troubleshooting](#troubleshooting)

---

## 1. VSCode Orientation

When you open VSCode you will see five areas:

```
┌──────────────────────────────────────────────────────┐
│  Activity Bar │  Side Bar   │   Editor               │
│  (left strip) │  (Explorer, │   (your files open     │
│               │   Search,   │    here as tabs)        │
│               │   Source    │                        │
│               │   Control,  ├────────────────────────┤
│               │   ROS…)     │   Terminal (bottom)    │
└──────────────────────────────────────────────────────┘
```

| Shortcut | Action |
|---|---|
| `Ctrl+Shift+E` | Open **Explorer** (file tree) |
| `Ctrl+Shift+X` | Open **Extensions** marketplace |
| `` Ctrl+` `` | Open / toggle the integrated **Terminal** |
| `Ctrl+Shift+P` | Open the **Command Palette** (run any VSCode command) |
| `Ctrl+Shift+B` | Run the default **build task** |
| `` Ctrl+` `` (twice) | Split the terminal |
| `F5` | Start **debugging** the current file |

You can open multiple terminal panels side-by-side — this is important for
running several ROS 2 nodes at the same time.

---

## 2. Understanding ROS 2 Concepts

Before running any code it helps to know the three building blocks ROS 2 uses.

### Nodes

A **node** is a single executable program that does one job.  This project has
three nodes:

| Node | Package | What it does |
|---|---|---|
| `controller_node` | `drone_controller` | Simulates a drone, publishes state at 10 Hz, exposes arm/takeoff/land services |
| `telemetry_node` | `drone_controller` | Subscribes to drone state and re-publishes a human-readable summary |
| `sniffer_node` | `network_sniffer` | Captures raw network packets and publishes their details |

### Topics

A **topic** is a named data channel.  Nodes *publish* data onto topics and
*subscribe* to receive data from them.

| Topic | Type | Direction |
|---|---|---|
| `/drone_state` | `drone_interfaces/msg/DroneState` | `controller_node` → everyone |
| `/drone_telemetry` | `std_msgs/msg/String` | `telemetry_node` → everyone |
| `/cmd_vel` | `geometry_msgs/msg/Twist` | you → `controller_node` |
| `/packet_info` | `std_msgs/msg/String` | `sniffer_node` → everyone |

### Services

A **service** is a request/response call (like an API call).  The drone
exposes three services:

| Service | Type | What it does |
|---|---|---|
| `/arm` | `drone_interfaces/srv/Arm` | Arm or disarm the motors |
| `/takeoff` | `drone_interfaces/srv/Takeoff` | Take off to a target altitude |
| `/land` | `drone_interfaces/srv/Land` | Initiate landing |

---

## Step 1 — Clone and prepare the workspace

Open a terminal **outside** VSCode first (press `Ctrl+Alt+T`).

```bash
# Create a colcon workspace
mkdir -p ~/ros2_ws/src
cd ~/ros2_ws/src

# Clone this repository
git clone https://github.com/Mehdi-Hassa/Basic-Network-Sniffer.git

# Install Python dependencies
pip3 install scapy
```

Now open the workspace in VSCode:

```bash
cd ~/ros2_ws
code .
```

VSCode opens with the whole workspace as its root.

---

## Step 2 — Install Extensions

Press `Ctrl+Shift+X` to open the Extensions panel, then install:

| Extension | Publisher | Why |
|---|---|---|
| **Python** | Microsoft | IntelliSense, linting, debugging for `.py` files |
| **ROS** | Microsoft | ROS 2 workspace detection, topic/node explorer |
| **C/C++** | Microsoft | IntelliSense for the `drone_interfaces` CMake package |
| **CMake Tools** | Microsoft | Build CMake projects from VSCode |

Or install them all at once from the integrated terminal (`` Ctrl+` ``):

```bash
code --install-extension ms-python.python
code --install-extension ms-iot.vscode-ros
code --install-extension ms-vscode.cpptools
code --install-extension ms-vscode.cmake-tools
```

After installing the **ROS** extension, press `Ctrl+Shift+P` and run
**"ROS: Start"** — VSCode will source your ROS 2 environment automatically for
every new terminal it opens.

---

## Step 3 — Build the workspace

### Using the integrated terminal (recommended)

Open a terminal in VSCode with `` Ctrl+` `` and run:

```bash
# Source ROS 2 (only needed if you skipped adding it to ~/.bashrc)
source /opt/ros/humble/setup.bash

cd ~/ros2_ws
colcon build --symlink-install
```

A successful build ends with output like:

```
Summary: 3 packages finished [...]
```

Then source the install overlay so the new packages are on your `PATH`:

```bash
source ~/ros2_ws/install/setup.bash
```

> **Tip**: Add `source ~/ros2_ws/install/setup.bash` to `~/.bashrc` so you
> never need to re-run it:
> ```bash
> echo "source ~/ros2_ws/install/setup.bash" >> ~/.bashrc
> ```

### Using the VSCode build task

Press `Ctrl+Shift+B`.  If you have the **CMake Tools** extension installed and
a `tasks.json` configured, it will run the build automatically.

---

## Step 4 — Run the drone controller

Open a **new terminal tab** in VSCode (click **+** in the terminal panel or
press `` Ctrl+Shift+` ``).

```bash
source ~/ros2_ws/install/setup.bash
ros2 run drone_controller controller_node
```

You should see:

```
[INFO] [controller_node]: Drone controller node started.
```

The node is now publishing `DroneState` messages on `/drone_state` at 10 Hz
and waiting for service calls on `/arm`, `/takeoff`, and `/land`.

**Verify it is running** — open a third terminal and list all active nodes:

```bash
ros2 node list
```

Expected output:

```
/controller_node
```

---

## Step 5 — Run the telemetry monitor

Open another terminal tab (split the panel with `` Ctrl+` `` twice) and run:

```bash
source ~/ros2_ws/install/setup.bash
ros2 run drone_controller telemetry_node
```

You will see telemetry lines streaming at 10 Hz:

```
[INFO] [telemetry_node]: --- Drone Telemetry ---
Mode     : IDLE
Armed    : False
Altitude : 0.00 m
Position : x=0.00  y=0.00  z=0.00
Velocity : vx=0.00  vy=0.00  vz=0.00
Battery  : 100.0%
```

You can also watch the raw topic directly:

```bash
ros2 topic echo /drone_telemetry
```

---

## Step 6 — Fly the simulated drone

Use `ros2 service call` commands from any terminal.

### Arm the motors

```bash
ros2 service call /arm drone_interfaces/srv/Arm "{arm: true}"
```

Expected response:

```
response: drone_interfaces.srv.Arm_Response(success=True, message='Drone armed successfully.')
```

### Take off to 10 m

```bash
ros2 service call /takeoff drone_interfaces/srv/Takeoff "{altitude: 10.0}"
```

Watch the telemetry terminal — `Altitude` will climb from 0 to 10 m over the
next few seconds.

### Send velocity commands (fly forward)

```bash
ros2 topic pub --once /cmd_vel geometry_msgs/msg/Twist \
    "{linear: {x: 1.0, y: 0.0, z: 0.0}, angular: {x: 0.0, y: 0.0, z: 0.0}}"
```

Run the command repeatedly to keep moving.  Watch `Position` change in the
telemetry stream.

### Land

```bash
ros2 service call /land drone_interfaces/srv/Land "{}"
```

The drone descends at 1 m/s and auto-disarms when it reaches the ground.

### Disarm (once landed)

```bash
ros2 service call /arm drone_interfaces/srv/Arm "{arm: false}"
```

---

## Step 7 — Run the network sniffer

The sniffer captures real network traffic on the machine and publishes each
packet as a ROS 2 message.  It needs elevated privileges to open a raw socket.

Open another terminal tab and run:

```bash
source ~/ros2_ws/install/setup.bash
sudo ros2 run network_sniffer sniffer_node
```

> **Why sudo?**  Raw packet capture requires the `CAP_NET_RAW` capability
> which normal users do not have.

You will see live packet output:

```
[INFO] [sniffer_node]: --- New Packet Captured ---
Source IP: 192.168.1.5
Destination IP: 8.8.8.8
Protocol: 17
Protocol Type: UDP
Source Port: 54321
Destination Port: 53
```

To read the same data as a ROS 2 topic in a separate terminal:

```bash
ros2 topic echo /packet_info
```

Press `Ctrl+C` in the sniffer terminal to stop capture.

---

## ROS 2 Quick-Reference Cheat Sheet

```bash
# --- Nodes ---
ros2 node list                        # List running nodes
ros2 node info /controller_node       # Show topics/services of a node

# --- Topics ---
ros2 topic list                       # List all active topics
ros2 topic echo /drone_state          # Print messages on a topic
ros2 topic hz /drone_state            # Show publish rate
ros2 topic info /drone_state          # Show message type and publishers

# --- Services ---
ros2 service list                     # List all active services
ros2 service type /arm                # Show service type
ros2 service call /arm \
    drone_interfaces/srv/Arm \
    "{arm: true}"                     # Call a service

# --- Messages ---
ros2 interface show drone_interfaces/msg/DroneState   # Print message fields
ros2 interface show drone_interfaces/srv/Arm          # Print service request/response

# --- Publishing a topic manually ---
ros2 topic pub --once /cmd_vel \
    geometry_msgs/msg/Twist \
    "{linear: {x: 1.0, y: 0.0, z: 0.0}}"

# --- Build ---
colcon build --symlink-install        # Build all packages
colcon build --packages-select \
    drone_controller                  # Build one package
source install/setup.bash             # Activate the build

# --- Logs ---
ros2 run --prefix 'gdb --args' \
    drone_controller controller_node  # Debug with gdb
```

---

## Troubleshooting

| Problem | Likely cause | Fix |
|---|---|---|
| `Package 'drone_interfaces' not found` | Workspace not sourced | Run `source ~/ros2_ws/install/setup.bash` |
| `drone_interfaces is not available` at runtime | Build was not re-run after changes | Run `colcon build --symlink-install` again |
| Service call returns no response | Node not running | Check `ros2 node list` and restart the node |
| Telemetry not updating | `telemetry_node` not running | Start it in a second terminal |
| `scapy` import error in sniffer | scapy not installed | `pip3 install scapy` |
| Sniffer crashes immediately | Missing raw-socket permission | Use `sudo` in front of the `ros2 run` command |
| `colcon: command not found` | `colcon` not installed | `sudo apt install -y python3-colcon-common-extensions` |
| VSCode doesn't show ROS topics in explorer | ROS extension not started | Press `Ctrl+Shift+P` → **"ROS: Start"** |
