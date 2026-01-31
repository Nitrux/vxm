# VxM — Nitrux Hypervisor Orchestrator | ![License](https://img.shields.io/badge/License-BSD--3--Clause-blue)

# Introduction

VxM is a hypervisor orchestration utility for Nitrux, engineered to enable concurrent, hardware-accelerated guest execution on multi-GPU workstations. Leveraging VFIO PCI passthrough, it enforces IOMMU isolation to dedicate discrete graphics resources to guest domains.

This architecture circumvents virtualization overhead and emulation layers, granting the guest OS direct hardware control for bare-metal performance characteristics within Nitrux's immutable infrastructure.

## Features

- **Evdev Input Arbitration**: Implements zero-latency input-linux passthrough with grab_all=on and ctrl-ctrl interrupt handling.

- **Dynamic VFIO Binding**: Runtime driver override to vfio-pci with automatic host rebinding, BDF normalization, and IOMMU group validation.

- **DDC/CI Automation**: Writes VCP commands to the monitor bus to trigger input source switching on VM state changes.

- **Latency Optimization**: Auto-provisions hugepages and initializes IVSHMEM for low-latency frame relay.

- **Firmware/TPM Lifecycle**: Heuristic detection for matching OVMF CODE/VARS pairs and managed swtpm socket execution for guest OS compatibility.

- **Rootless Model**: Unprivileged QEMU execution with privileged pre-flight hardware preparation.

## System Requirements

> [!IMPORTANT]
> VxM is a specialized workstation tool. It requires specific hardware architectures to function.

* **GPU Architecture:**
    * **Required:** Two separate GPUs (e.g., Integrated AMD/Intel + Discrete Radeon/Nvidia).

> [!WARNING]
> VxM doesn't support single-GPU setups.

* **Motherboard:**
    * IOMMU (VT-d / AMD-Vi) enabled in BIOS.
    * UEFI Boot enabled.

* **Display:**
    * A monitor with two inputs (e.g., DP for host OS, HDMI for guest OS) OR two separate monitors.

## Usage

```
Usage:
  vxm [COMMAND] <options>

Commands:
  init                     Initialize storage, directory structure, and download required drivers.
  start                    Boot the virtual machine. (requires root)
  status                   Show current VM status and hardware binding state.
  list-gpus                Scan system for available GPUs and display PCI addresses.
  fingerprint              Display the system fingerprint (DMI UUID). (requires root)
  config                   Update configuration and hardware profiles.
  reset                    Remove all VxM files and configuration.

Config options:
  vxm config --set-gpu <PCI_ADDRESS|NAME>   Set specific GPU for passthrough
  vxm config --enable-binding               Enable Static Binding (requires root + reboot)
  vxm config --disable-binding              Disable Static Binding (requires root + reboot)

Other options:
  vxm list-gpus [--json]
  vxm fingerprint [--json]
  vxm status [--json]

Notes:
  - Commands requiring root: start, fingerprint, config --enable/disable-binding
  - Use 'sudo -E vxm <command>' to preserve the user environment.
  - Static Binding is REQUIRED for VxM. Enable it before first use.
```

# Licensing

The license for this repository and its contents is **BSD-3-Clause**.

# Issues

If you find problems with the contents of this repository, please create an issue and use the **🐞 Bug report** template.

## Submitting a bug report

Before submitting a bug, you should look at the [existing bug reports](https://github.com/Nitrux/vxm/issues) to verify that no one has reported the bug already.

©2026 Nitrux Latinoamericana S.C.
