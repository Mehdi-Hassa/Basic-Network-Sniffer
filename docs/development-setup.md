# Development Environment Setup — Ubuntu 22.04

This guide walks you through setting up a complete development environment for
this project on **Ubuntu 22.04 LTS (Jammy Jellyfish)**.  It covers:

1. [Installing Visual Studio Code](#1-installing-visual-studio-code)
2. [Recommended VSCode Extensions](#2-recommended-vscode-extensions)
3. [Installing ROS 2 Humble](#3-installing-ros-2-humble)
4. [Setting up the Python environment](#4-setting-up-the-python-environment)
5. [Building and opening the workspace in VSCode](#5-building-and-opening-the-workspace-in-vscode)

---

## 1. Installing Visual Studio Code

There are three supported ways to install VSCode on Ubuntu 22.04.
**Method A (snap)** is the quickest; **Method B (apt)** gives you automatic
updates via the system package manager; **Method C (.deb)** is best for
air-gapped machines.

### Method A — Snap (quickest)

```bash
sudo snap install --classic code
```

After the snap is installed, launch it from the terminal with `code` or from
the **Applications** menu.

---

### Method B — Microsoft APT repository (recommended for automatic updates)

1. Install prerequisites and import Microsoft's GPG key:

   ```bash
   sudo apt update
   sudo apt install -y wget gpg apt-transport-https
   wget -qO- https://packages.microsoft.com/keys/microsoft.asc \
       | gpg --dearmor \
       | sudo tee /usr/share/keyrings/packages.microsoft.gpg > /dev/null
   ```

2. Add the VSCode repository:

   ```bash
   echo "deb [arch=amd64 signed-by=/usr/share/keyrings/packages.microsoft.gpg] \
       https://packages.microsoft.com/repos/code stable main" \
       | sudo tee /etc/apt/sources.list.d/vscode.list
   ```

3. Install VSCode:

   ```bash
   sudo apt update
   sudo apt install -y code
   ```

4. Verify the installation:

   ```bash
   code --version
   ```

Future updates are applied automatically with `sudo apt upgrade`.

---

### Method C — Direct .deb download

1. Download the latest `.deb` package from the official site:

   ```bash
   wget -O /tmp/code.deb \
       "https://code.visualstudio.com/sha/download?build=stable&os=linux-deb-x64"
   ```

2. Install it:

   ```bash
   sudo apt install -y /tmp/code.deb
   ```

3. Clean up:

   ```bash
   rm /tmp/code.deb
   ```

---

### Opening VSCode on Ubuntu 22.04

Once VSCode is installed, there are four ways to launch it:

#### 1. From a terminal (most common for developers)

Open a terminal (`Ctrl+Alt+T`) and run one of these commands:

```bash
code          # Open VSCode with no file or folder
code .        # Open VSCode with the current directory as the workspace (recommended)
code myfile.py  # Open a specific file directly in VSCode
```

> **Tip**: Running `code .` inside your ROS 2 workspace (`~/ros2_ws`) is the
> standard way to open the project — VSCode will show the full workspace tree
> in the Explorer panel.

#### 2. From the GNOME Applications menu

1. Press the **Super** key (Windows key) to open the Activities Overview, or
   click **Show Applications** (the nine-dot grid) in the Dock.
2. Type **"code"** or **"Visual Studio Code"** in the search bar.
3. Click the VSCode icon to launch it.

You can also right-click the icon and choose **Pin to Dash** or
**Add to Favourites** to keep it in the Dock for quick access.

#### 3. From the Files application (Nautilus)

1. Open the **Files** app and navigate to your project folder
   (e.g. `~/ros2_ws`).
2. Right-click an empty area inside the folder.
3. Choose **"Open with Other Application"** → search for **"Code"** → click
   **Open**.

> **Note**: The "Open Folder with Code" context-menu entry is added
> automatically by the Microsoft APT and snap packages.  If it is missing,
> install the VSCode `code` package via Method A or B above.

#### 4. If `code` is not found in the terminal after a snap install

Log out and log back in, or add the snap binary directory to your path for the
current session:

```bash
export PATH="$PATH:/snap/bin"
code .
```

To make this permanent, add the line to `~/.bashrc`:

```bash
echo 'export PATH="$PATH:/snap/bin"' >> ~/.bashrc
source ~/.bashrc
```

---

## 2. Recommended VSCode Extensions

Install the following extensions for the best experience with this project.
You can install them from the **Extensions** panel (`Ctrl+Shift+X`) or via the
terminal:

```bash
code --install-extension ms-python.python          # Python language support
code --install-extension ms-python.pylint          # Python linting
code --install-extension ms-iot.vscode-ros         # ROS 2 integration
code --install-extension ms-vscode.cpptools        # C/C++ (for ROS2 CMake packages)
code --install-extension twxs.cmake                # CMake syntax highlighting
code --install-extension ms-vscode.cmake-tools     # CMake Tools
```

### Useful workspace settings

Create `.vscode/settings.json` in the repository root to configure the Python
interpreter and ROS 2 environment automatically:

```json
{
    "python.defaultInterpreterPath": "/usr/bin/python3",
    "ros.distro": "humble",
    "editor.formatOnSave": true,
    "[python]": {
        "editor.defaultFormatter": "ms-python.python"
    }
}
```

---

## 3. Installing ROS 2 Humble

The drone packages in this repository target **ROS 2 Humble Hawksbill**, the
LTS release compatible with Ubuntu 22.04.

```bash
# 1. Set up the ROS 2 apt repository
sudo apt install -y software-properties-common curl
sudo curl -sSL https://raw.githubusercontent.com/ros/rosdistro/master/ros.key \
    -o /usr/share/keyrings/ros-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/ros-archive-keyring.gpg] \
    http://packages.ros.org/ros2/ubuntu $(. /etc/os-release && echo $UBUNTU_CODENAME) main" \
    | sudo tee /etc/apt/sources.list.d/ros2.list > /dev/null

# 2. Install ROS 2 Humble Desktop (includes rviz2, rqt, demos)
sudo apt update
sudo apt upgrade -y
sudo apt install -y ros-humble-desktop

# 3. Install development tools
sudo apt install -y python3-colcon-common-extensions python3-rosdep ros-dev-tools

# 4. Initialise rosdep
sudo rosdep init
rosdep update

# 5. Source the ROS 2 setup script (add to ~/.bashrc for persistence)
source /opt/ros/humble/setup.bash
echo "source /opt/ros/humble/setup.bash" >> ~/.bashrc
```

---

## 4. Setting up the Python environment

### Install project Python dependencies

```bash
# scapy — used by the network sniffer
sudo apt install -y python3-pip
pip3 install scapy
```

### Install ROS 2 Python dependencies declared by the packages

```bash
cd ~/ros2_ws   # or wherever you cloned this repo as a colcon workspace
rosdep install --from-paths src --ignore-src -r -y
```

---

## 5. Building and opening the workspace in VSCode

### Create a colcon workspace (first time only)

```bash
mkdir -p ~/ros2_ws/src
cd ~/ros2_ws/src
# Clone or symlink this repository into src/
git clone https://github.com/Mehdi-Hassa/Basic-Network-Sniffer.git
```

### Build all packages

```bash
cd ~/ros2_ws
source /opt/ros/humble/setup.bash
colcon build --symlink-install
source install/setup.bash
```

### Open in VSCode

```bash
cd ~/ros2_ws
code .
```

VSCode will detect the ROS 2 workspace automatically when the **ROS** extension
is installed.  Use `Ctrl+Shift+B` → **colcon build** to trigger builds from
inside the editor.

### Run the nodes

```bash
# Terminal 1 — controller
source ~/ros2_ws/install/setup.bash
ros2 run drone_controller controller_node

# Terminal 2 — telemetry monitor
source ~/ros2_ws/install/setup.bash
ros2 run drone_controller telemetry_node

# Terminal 3 — network sniffer (requires root/cap_net_raw)
source ~/ros2_ws/install/setup.bash
sudo ros2 run network_sniffer sniffer_node
```

---

## Next steps

Once the build succeeds and the nodes run, continue with the
**[Usage Guide](usage-guide.md)** for a complete walkthrough of running the
drone simulation and network sniffer from start to end inside VSCode.

---

## Troubleshooting

| Problem | Fix |
|---|---|
| `code: command not found` after snap install | Log out and back in, or run `export PATH="$PATH:/snap/bin"` |
| `rosdep init` fails with "file exists" | Run `sudo rm /etc/ros/rosdep/sources.list.d/20-default.list` then retry |
| `colcon build` fails on `drone_interfaces` | Ensure `ros-humble-rosidl-default-generators` is installed: `sudo apt install -y ros-humble-rosidl-default-generators` |
| `scapy` permission error when sniffing | Sniffing raw packets requires elevated privileges: run with `sudo` or grant `CAP_NET_RAW` to Python |
