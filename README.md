# VxM — Nitrux Hypervisor Orchestrator

![License](https://img.shields.io/badge/License-BSD--3--Clause-blue)

# Introduction

VxM is a hypervisor orchestration utility for Nitrux, engineered to enable concurrent, hardware-accelerated guest execution on multi-GPU workstations. Leveraging VFIO PCI passthrough, it enforces IOMMU isolation to dedicate discrete graphics resources to guest domains.

This architecture circumvents virtualization overhead and emulation layers, granting the guest OS direct hardware control for bare-metal performance characteristics within Nitrux’s immutable infrastructure.

## Features

- **Evdev Input Arbitration**: Implements zero-latency input-linux passthrough with grab_all=on and ctrl-ctrl interrupt handling.

- **Dynamic VFIO Binding**: Runtime driver override to vfio-pci with automatic host rebinding, BDF normalization, and IOMMU group validation.

- **DDC/CI Automation**: Writes VCP 0x60 commands to the monitor bus to trigger input source switching on VM state changes.

- **Latency Optimization**: Auto-provisions hugepages and initializes IVSHMEM (/dev/shm/looking-glass) for low-latency frame relay.

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

# Licensing

The license for this repository and its contents is **BSD-3-Clause**.

# Issues

If you find problems with the contents of this repository, please create an issue and use the **🐞 Bug report** template.

## Submitting a bug report

Before submitting a bug, you should look at the [existing bug reports](https://github.com/Nitrux/vxm/issues) to verify that no one has reported the bug already.

©2026 Nitrux Latinoamericana S.C.