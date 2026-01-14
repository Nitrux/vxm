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

> [!IMPORTANT]
> V×M is a specialized workstation tool. It requires specific hardware architectures to function.

* **GPU Architecture:**
    * **Required:** Two separate GPUs (e.g., Integrated AMD/Intel + Discrete Radeon/Nvidia).

> [!WARNING]
> We do not support Single-GPU setups.

* **Motherboard:**
    * IOMMU (VT-d / AMD-Vi) enabled in BIOS.
    * UEFI Boot enabled.

* **Display:**
    * A monitor with two inputs (e.g., DP for Linux, HDMI for Windows) OR two separate monitors.

# Licensing

The license for this repository and its contents is **BSD-3-Clause**.

# Issues

If you find problems with the contents of this repository, please create an issue and use the **🐞 Bug report** template.

## Submitting a bug report

Before submitting a bug, you should look at the [existing bug reports](https://github.com/Nitrux/vxm/issues) to verify that no one has reported the bug already.

©2026 Nitrux Latinoamericana S.C.
