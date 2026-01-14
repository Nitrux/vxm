# V×M

![License](https://img.shields.io/badge/License-BSD--3--Clause-blue)

# Introduction

V×M (Virtual × Metal) is a specialized hypervisor orchestrator for **Nitrux**. It transforms a multi-GPU workstation into a "Twin Engine" system, allowing you to run Linux (Host) and Windows (Guest) simultaneously on separate GPUs with near-native performance.

Unlike traditional virtual machines that emulate graphics or use translation layers, V×M uses **VFIO Passthrough** to give the Guest OS complete, exclusive control over your secondary GPU.

## Features

* **Zero graphics virtualization**: The Guest OS speaks directly to the PCIe hardware.
* **Instantly toggle your keyboard** and mouse between Host and Guest without hardware switches.
* **Dynamically unbinds your dGPU** from the host kernel and attaches it to the VM on demand.

## System Requirements

V×M is a **specialized workstation tool**. It requires specific hardware architectures to function.

* **GPU Architecture:**
    * **Required:** Two separate GPUs (e.g., Integrated AMD/Intel + Discrete Radeon/Nvidia).

> [!WARNING]
> We do not support Single-GPU setups.*

* **Motherboard:**
    * IOMMU (VT-d / AMD-Vi) enabled in BIOS.
    * UEFI Boot enabled.
* **Display:**
    * A monitor with two inputs (e.g., DP for Linux, HDMI for Windows) OR two separate monitors.

## Installation and Build

V×M is a native C++ application built with modern standards.

### Dependencies

```
cmake >= 3.17
g++ (C++20 support)
qemu-system-x86_64
swtpm (for TPM 2.0 emulation)
```

### Building from Source

```bash
git clone https://github.com/Nitrux/vxm.git
cd vxm
mkdir build && cd build
cmake ..
make
sudo make install
```

## Usage

V×M provides a simple command-line interface for managing your virtualization environment.

### Initial Setup

1. **Initialize the VxM environment** (creates directories and disk images):
   ```bash
   sudo vxm init
   ```

2. **List available GPUs** to identify your passthrough device:
   ```bash
   vxm list-gpus
   ```

3. **Configure the GPU** you want to pass through:
   ```bash
   sudo vxm config --set-gpu <PCI_ID>
   ```
   Example: `sudo vxm config --set-gpu 03:00.0`

4. **Place your installation media** in `~/VxM/iso/`:
   - `win_install.iso` - Windows installation ISO
   - `virtio_drivers.iso` - VirtIO drivers for Windows

### Running the VM

```bash
sudo vxm start
```

The VM will be accessible via VNC on `localhost:5900` (port 5900). You can connect using any VNC client:
```bash
vncviewer localhost:5900
```

### Input Control

- **Toggle Mode**: Press `Left Ctrl + Right Ctrl` simultaneously to switch keyboard/mouse control between Host and Guest.
- If input passthrough fails, V×M falls back to USB tablet emulation (pointer control via VNC).

### Configuration Files

V×M stores its configuration in:
- **Profile**: `~/.config/vxm/vxm.conf` (GPU selection, MAC address)
- **VM Data**: `~/VxM/` (disk images, ISOs, UEFI variables)

# Licensing

The license for this repository and its contents is **BSD-3-Clause**.

# Issues

If you find problems with the contents of this repository, please create an issue and use the **🐞 Bug report** template.

## Submitting a bug report

Before submitting a bug, you should look at the [existing bug reports]([url](https://github.com/Nitrux/vxm/issues)) to verify that no one has reported the bug already.

©2026 Nitrux Latinoamericana S.C.
