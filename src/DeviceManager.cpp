/*
 * Copyright (C) 2026 Nitrux Latinoamericana S.C.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "DeviceManager.h"
#include <fstream>
#include <iostream>
#include <thread>
#include <chrono>

namespace VxM
{

DeviceManager::DeviceManager(const std::string &pciAddress)
    : m_pciAddress(pciAddress)
{
    // Ensure format is 0000:XX:XX.X for sysfs path construction
    std::string fullAddress = pciAddress;
    if (fullAddress.find(':') != std::string::npos && fullAddress.length() < 10) {
        fullAddress = "0000:" + fullAddress;
    }
    m_sysPath = std::filesystem::path("/sys/bus/pci/devices") / fullAddress;
}

std::string DeviceManager::getDeviceId() const
{
    // /sys/bus/pci/devices/.../vendor and .../device
    // Returns format "vvvv dddd" for vfio-pci new_id interface
    std::string vendor = readSysfs(m_sysPath / "vendor");
    std::string device = readSysfs(m_sysPath / "device");

    // Remove "0x" prefix if present and newlines
    auto clean = [](std::string &s) {
        if (s.rfind("0x", 0) == 0) s.erase(0, 2);
        if (!s.empty() && s.back() == '\n') s.pop_back();
    };
    clean(vendor);
    clean(device);

    // The vfio-pci new_id interface expects format: "vendor_id device_id" (space-separated)
    return vendor + " " + device;
}

bool DeviceManager::isBoundToVfio() const
{
    return getCurrentDriver() == "vfio-pci";
}

std::string DeviceManager::getCurrentDriver() const
{
    std::filesystem::path driverPath = m_sysPath / "driver";
    if (std::filesystem::exists(driverPath)) {
        return std::filesystem::read_symlink(driverPath).filename().string();
    }
    return "";
}

bool DeviceManager::bindToVfio()
{
    if (isBoundToVfio()) {
        return true;
    }

    std::cout << "[VxM] Seizing control of " << m_pciAddress << "..." << std::endl;

    // 1. Unbind from current driver (e.g., amdgpu)
    std::string currentDriver = getCurrentDriver();
    if (!currentDriver.empty()) {
        std::filesystem::path unbindPath = m_sysPath / "driver" / "unbind";
        if (!writeSysfs(unbindPath, m_pciAddress)) {
            std::cerr << "[Error] Failed to unbind " << m_pciAddress << " from " << currentDriver << std::endl;
            std::cerr << "        GPU is bound to " << currentDriver << " instead of vfio-pci." << std::endl;
            std::cerr << std::endl;
            std::cerr << "        Causes:" << std::endl;
            std::cerr << "        - VFIO not configured in initramfs" << std::endl;
            std::cerr << "        - This is the primary/boot GPU\n" << std::endl;
            return false;
        }
    }

    // 2. Ensure vfio-pci module is loaded
    // Check if module is already loaded before calling modprobe
    if (!std::filesystem::exists("/sys/bus/pci/drivers/vfio-pci")) {
        std::cout << "[VxM] Loading vfio-pci kernel module..." << std::endl;
        int ret = std::system("modprobe vfio-pci 2>/dev/null");
        if (ret != 0) {
            std::cerr << "[Warning] Failed to load vfio-pci module. It may already be built-in." << std::endl;
        }
    }

    // 3. Bind to vfio-pci
    // We explicitly write the Vendor Device ID to /sys/bus/pci/drivers/vfio-pci/new_id
    std::string devId = getDeviceId();
    std::filesystem::path newIdPath = "/sys/bus/pci/drivers/vfio-pci/new_id";

    // writing new_id usually binds it, but sometimes we need to manually bind
    writeSysfs(newIdPath, devId);

    // Poll for driver binding instead of using sleep
    for (int i = 0; i < 10; i++) {
        if (isBoundToVfio()) {
            std::cout << "[VxM] Device " << m_pciAddress << " is now under VxM control." << std::endl;
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    // Try manual bind if new_id didn't trigger it
    std::filesystem::path bindPath = "/sys/bus/pci/drivers/vfio-pci/bind";
    writeSysfs(bindPath, m_pciAddress);

    // Poll again after manual bind
    for (int i = 0; i < 10; i++) {
        if (isBoundToVfio()) {
            std::cout << "[VxM] Device " << m_pciAddress << " is now under VxM control." << std::endl;
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    // Binding failed - provide detailed diagnostics
    std::string finalDriver = getCurrentDriver();
    std::cerr << "[Error] Failed to bind " << m_pciAddress << " to vfio-pci." << std::endl;
    std::cerr << std::endl;

    if (!finalDriver.empty()) {
        std::cerr << "        Device is still bound to: " << finalDriver << std::endl;
        std::cerr << std::endl;

        if (finalDriver == "nvidia" || finalDriver == "nouveau") {
            std::cerr << "        NVIDIA Optimus Laptop Detected" << std::endl;
            std::cerr << "        The NVIDIA driver is refusing to release the GPU." << std::endl;
            std::cerr << std::endl;
            std::cerr << "        Solutions:" << std::endl;
            std::cerr << "        1. Switch to integrated mode: nx-envycontrol --switch integrated" << std::endl;
            std::cerr << "        2. Blacklist nvidia driver: echo 'blacklist nvidia' | sudo tee /etc/modprobe.d/vxm-nvidia.conf" << std::endl;
            std::cerr << "        3. Configure early VFIO binding in initramfs" << std::endl;
            std::cerr << std::endl;
            std::cerr << "        Note: Optimus laptops have limited passthrough support." << std::endl;
            std::cerr << "              The dGPU may not have its own video outputs." << std::endl;
        } else if (finalDriver == "amdgpu" || finalDriver == "radeon") {
            std::cerr << "        The AMD driver is refusing to release the GPU." << std::endl;
            std::cerr << std::endl;
            std::cerr << "        Solutions:" << std::endl;
            std::cerr << "        1. Ensure this is NOT your primary/boot GPU" << std::endl;
            std::cerr << "        2. Configure early VFIO binding in initramfs" << std::endl;
            std::cerr << "        3. Add 'vfio-pci.ids=<vendor>:<device>' to kernel parameters" << std::endl;
        } else if (finalDriver == "i915" || finalDriver == "xe") {
            std::cerr << "        Intel integrated GPU cannot be passed through." << std::endl;
            std::cerr << "        VxM requires a discrete GPU for passthrough." << std::endl;
        } else {
            std::cerr << "        The " << finalDriver << " driver is refusing to release the GPU." << std::endl;
        }
    } else {
        std::cerr << "        Device has no driver but vfio-pci binding failed." << std::endl;
        std::cerr << std::endl;
        std::cerr << "        Possible causes:" << std::endl;
        std::cerr << "        - IOMMU not properly enabled" << std::endl;
        std::cerr << "        - vfio-pci module not loaded" << std::endl;
        std::cerr << "        - Permission denied (are you running as root?)" << std::endl;
    }

    std::cerr << std::endl;
    return false;
}

bool DeviceManager::rebindToHost()
{
    if (!isBoundToVfio()) {
        return true; // Already not vfio
    }

    std::cout << "[VxM] Releasing control of " << m_pciAddress << "..." << std::endl;

    // Unbind from vfio-pci
    std::filesystem::path unbindPath = "/sys/bus/pci/drivers/vfio-pci/unbind";
    writeSysfs(unbindPath, m_pciAddress);

    // Trigger driver probe
    std::filesystem::path probePath = "/sys/bus/pci/drivers_probe";
    writeSysfs(probePath, m_pciAddress);
    
    return true;
}

bool DeviceManager::writeSysfs(const std::filesystem::path &path, const std::string &value) const
{
    std::ofstream file(path);
    if (!file.is_open()) return false;
    file << value;
    return file.good();
}

std::string DeviceManager::readSysfs(const std::filesystem::path &path) const
{
    std::ifstream file(path);
    std::string content;
    std::getline(file, content);
    return content;
}

} // namespace VxM
