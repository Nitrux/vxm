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
#include <cctype>

namespace VxM
{

DeviceManager::DeviceManager(const std::string &pciAddress)
    : m_pciAddress(pciAddress)
    , m_fullAddress(normalizePciAddress(pciAddress))
{
    if (m_fullAddress.empty()) {
        throw std::runtime_error("Invalid PCI address format: " + pciAddress);
    }
    m_sysPath = std::filesystem::path("/sys/bus/pci/devices") / m_fullAddress;

    if (!std::filesystem::exists(m_sysPath)) {
        throw std::runtime_error("PCI device does not exist: " + m_fullAddress);
    }
}

std::string DeviceManager::getDeviceId() const
{
    // /sys/bus/pci/devices/.../vendor and .../device
    // Returns canonical format: "vvvv:dddd" (e.g., "1002:73bf")
    std::string vendor = readSysfs(m_sysPath / "vendor");
    std::string device = readSysfs(m_sysPath / "device");

    // Remove "0x" prefix if present and newlines
    auto clean = [](std::string &s) {
        if (s.rfind("0x", 0) == 0) s.erase(0, 2);
        if (!s.empty() && s.back() == '\n') s.pop_back();
    };
    clean(vendor);
    clean(device);

    // Return canonical format with colon separator
    return vendor + ":" + device;
}

bool DeviceManager::isBoundToVfio() const
{
    // CRITICAL FIX: Only return true if the device is ACTUALLY bound to vfio-pci.
    // Previously, this returned true if driver_override was set, even if binding failed.
    // This caused a false positive where VxM would skip binding and QEMU would crash.
    //
    // The driver_override is just a hint to the kernel about which driver to prefer.
    // The actual binding status is determined by the driver symlink.
    return getCurrentDriver() == "vfio-pci";
}

std::string DeviceManager::getCurrentDriver() const
{
    std::filesystem::path driverPath = m_sysPath / "driver";
    if (std::filesystem::exists(driverPath)) {
        try {
            return std::filesystem::read_symlink(driverPath).filename().string();
        } catch (const std::filesystem::filesystem_error &e) {
            std::cerr << "[Warning] Failed to read driver symlink for " << m_fullAddress
                      << ": " << e.what() << std::endl;
            return "";
        }
    }
    return "";
}

bool DeviceManager::bindToVfio(bool isMobileGpu)
{
    if (isBoundToVfio()) {
        return true;
    }

    std::cout << "[VxM] Seizing control of " << m_pciAddress << "..." << std::endl;

    // Check if this is a mobile GPU - refuse dynamic binding
    if (isMobileGpu) {
        std::cerr << "[Error] Mobile/Laptop GPU detected (" << m_pciAddress << ")" << std::endl;
        std::cerr << "        Dynamic unbinding is not supported for mobile GPUs." << std::endl;
        std::cerr << std::endl;
        std::cerr << "        Mobile GPUs (NVIDIA Optimus, AMD Switchable Graphics) are tightly" << std::endl;
        std::cerr << "        integrated with the display system and cannot be hot-unplugged." << std::endl;
        std::cerr << std::endl;

        return false;
    }

    // 1. Ensure vfio-pci module is loaded
    if (!std::filesystem::exists("/sys/bus/pci/drivers/vfio-pci")) {
        std::cout << "[VxM] Loading vfio-pci kernel module..." << std::endl;
        int ret = std::system("modprobe vfio-pci 2>/dev/null");
        if (ret != 0) {
            std::cerr << "[Warning] Failed to load vfio-pci module. It may already be built-in." << std::endl;
        }
    }

    // 2. Set driver_override to vfio-pci (per-device binding)
    std::filesystem::path overridePath = m_sysPath / "driver_override";
    if (!writeSysfs(overridePath, "vfio-pci")) {
        std::cerr << "[Error] Failed to set driver_override for " << m_fullAddress << std::endl;
        std::cerr << "        Are you running as root?" << std::endl;
        return false;
    }

    // 3. Unbind from current driver (if any)
    std::string currentDriver = getCurrentDriver();
    if (!currentDriver.empty()) {
        // NVIDIA-specific: Check for usage count before attempting unbind
        // The NVIDIA driver will fail with "non-zero usage count" if the GPU is in use
        if (currentDriver == "nvidia") {
            // Check if nvidia-drm is loaded with modeset enabled
            std::filesystem::path modesetPath = "/sys/module/nvidia_drm/parameters/modeset";
            if (std::filesystem::exists(modesetPath)) {
                std::string modesetValue = readSysfs(modesetPath);
                if (modesetValue == "Y" || modesetValue == "1") {
                    std::cerr << "[Error] NVIDIA DRM modeset is active on " << m_fullAddress << std::endl;
                    std::cerr << "        The GPU is being used as a display device (nvidia-drm modeset=1)." << std::endl;
                    std::cerr << std::endl;
                    std::cerr << "        This means:" << std::endl;
                    std::cerr << "        - This GPU is actively driving your display" << std::endl;
                    std::cerr << "        - The NVIDIA driver has a non-zero usage count" << std::endl;
                    std::cerr << "        - Dynamic unbinding will fail with 'non-zero usage count' error" << std::endl;
                    std::cerr << std::endl;
                    std::cerr << "        Solutions:" << std::endl;
                    std::cerr << "        1. Use 'nx-envycontrol --switch integrated' to disable this GPU" << std::endl;
                    std::cerr << "        2. Ensure this is NOT your primary display GPU" << std::endl;
                    std::cerr << "        3. Enable Static Binding (run 'sudo vxm start' and choose 'y')" << std::endl;
                    std::cerr << std::endl;

                    // Clear driver_override on failure
                    writeSysfs(overridePath, "\n");
                    return false;
                }
            }
        }

        std::filesystem::path unbindPath = m_sysPath / "driver" / "unbind";
        if (!writeSysfs(unbindPath, m_fullAddress)) {
            std::cerr << "[Error] Failed to unbind " << m_fullAddress << " from " << currentDriver << std::endl;
            std::cerr << "        GPU is bound to " << currentDriver << " and refusing to release." << std::endl;
            std::cerr << std::endl;

            // For NVIDIA, provide specific guidance about the usage count issue
            if (currentDriver == "nvidia") {
                std::cerr << "        NVIDIA driver error: Device has non-zero usage count." << std::endl;
                std::cerr << std::endl;
                std::cerr << "        This typically means:" << std::endl;
                std::cerr << "        - An X11/Wayland session is using this GPU" << std::endl;
                std::cerr << "        - CUDA or other NVIDIA processes are running" << std::endl;
                std::cerr << "        - This is your primary/boot GPU" << std::endl;
                std::cerr << std::endl;
                std::cerr << "        Solutions:" << std::endl;
                std::cerr << "        1. Close all applications using the GPU" << std::endl;
                std::cerr << "        2. Use 'nx-envycontrol --switch integrated' to disable this GPU" << std::endl;
                std::cerr << "        3. Enable Static Binding for boot-time isolation" << std::endl;
            } else {
                std::cerr << "        This is likely because:" << std::endl;
                std::cerr << "        - This is the primary/boot GPU" << std::endl;
                std::cerr << "        - The driver does not support runtime unbinding" << std::endl;
                std::cerr << "        - The device is actively in use" << std::endl;
            }
            std::cerr << std::endl;

            // Clear driver_override on failure
            writeSysfs(overridePath, "\n");
            return false;
        }
    }

    // 4. Trigger drivers_probe to bind to vfio-pci
    std::filesystem::path probePath = "/sys/bus/pci/drivers_probe";
    if (!writeSysfs(probePath, m_fullAddress)) {
        std::cerr << "[Warning] Failed to trigger drivers_probe for " << m_fullAddress << std::endl;
    }

    // 5. Poll to verify binding succeeded
    for (int i = 0; i < 20; i++) {
        if (isBoundToVfio()) {
            std::cout << "[VxM] Device " << m_pciAddress << " is now under VxM control." << std::endl;
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    // 6. Binding failed - provide detailed diagnostics
    std::string finalDriver = getCurrentDriver();
    std::cerr << "[Error] Failed to bind " << m_fullAddress << " to vfio-pci." << std::endl;
    std::cerr << std::endl;

    if (!finalDriver.empty()) {
        std::cerr << "        Device is still bound to: " << finalDriver << std::endl;
        std::cerr << std::endl;

        if (finalDriver == "nvidia" || finalDriver == "nouveau") {
            std::cerr << "        NVIDIA GPU detected - passthrough may require additional setup." << std::endl;
            std::cerr << std::endl;
            std::cerr << "        Common causes:" << std::endl;
            std::cerr << "        - Optimus laptop (dGPU has no direct outputs)" << std::endl;
            std::cerr << "        - Driver does not support runtime unbinding" << std::endl;
            std::cerr << std::endl;
            std::cerr << "        Possible solutions:" << std::endl;
            std::cerr << "        1. Use 'nx-envycontrol --switch integrated' to disable dGPU" << std::endl;
            std::cerr << "        2. Configure early VFIO binding (Static Binding)" << std::endl;
        } else if (finalDriver == "amdgpu" || finalDriver == "radeon") {
            std::cerr << "        AMD GPU detected - runtime binding failed." << std::endl;
            std::cerr << std::endl;
            std::cerr << "        Possible solutions:" << std::endl;
            std::cerr << "        1. Ensure this is NOT your primary/boot GPU" << std::endl;
            std::cerr << "        2. Configure early VFIO binding (Static Binding)" << std::endl;
        } else if (finalDriver == "i915" || finalDriver == "xe") {
            std::cerr << "        Intel integrated GPU cannot be passed through." << std::endl;
            std::cerr << "        VxM requires a discrete GPU for passthrough." << std::endl;
        } else {
            std::cerr << "        The " << finalDriver << " driver is refusing to release the GPU." << std::endl;
            std::cerr << "        Consider using Static Binding for early VFIO binding." << std::endl;
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

    // Clear driver_override on failure
    writeSysfs(overridePath, "\n");
    return false;
}

bool DeviceManager::rebindToHost()
{
    if (!isBoundToVfio()) {
        return true; // Already not vfio
    }

    std::cout << "[VxM] Releasing control of " << m_pciAddress << "..." << std::endl;

    std::string currentDriver = getCurrentDriver();
    bool needsUnbind = (currentDriver == "vfio-pci");

    // 1. Clear driver_override to allow automatic driver selection
    std::filesystem::path overridePath = m_sysPath / "driver_override";
    if (!writeSysfs(overridePath, "\n")) {
        std::cerr << "[Warning] Failed to clear driver_override for " << m_fullAddress << std::endl;
    }

    // 2. Unbind from vfio-pci (only if actually bound)
    if (needsUnbind) {
        std::filesystem::path unbindPath = "/sys/bus/pci/drivers/vfio-pci/unbind";
        if (!writeSysfs(unbindPath, m_fullAddress)) {
            std::cerr << "[Error] Failed to unbind " << m_fullAddress << " from vfio-pci" << std::endl;
            return false;
        }
    }

    // 3. Trigger driver probe to rebind to host driver
    std::filesystem::path probePath = "/sys/bus/pci/drivers_probe";
    if (!writeSysfs(probePath, m_fullAddress)) {
        std::cerr << "[Warning] Failed to trigger drivers_probe for " << m_fullAddress << std::endl;
        // Not a critical failure - device is unbound which may be acceptable
    }

    // 4. Poll to verify cleanup succeeded
    for (int i = 0; i < 20; i++) {
        if (!isBoundToVfio()) {
            std::string newDriver = getCurrentDriver();
            if (!newDriver.empty()) {
                std::cout << "[VxM] Device " << m_pciAddress << " rebound to " << newDriver << std::endl;
            } else {
                std::cout << "[VxM] Device " << m_pciAddress << " released (no driver bound)" << std::endl;
            }
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    std::cerr << "[Error] Failed to release " << m_fullAddress << " from vfio-pci" << std::endl;
    return false;
}

bool DeviceManager::writeSysfs(const std::filesystem::path &path, const std::string &value) const
{
    std::ofstream file(path);
    if (!file.is_open()) {
        return false;
    }
    file << value;
    file.flush();

    if (!file.good()) {
        return false;
    }

    return true;
}

std::string DeviceManager::readSysfs(const std::filesystem::path &path) const
{
    std::ifstream file(path);
    if (!file.is_open()) {
        std::cerr << "[Warning] Failed to open sysfs file: " << path << std::endl;
        return "";
    }

    std::string content;
    if (!std::getline(file, content)) {
        std::cerr << "[Warning] Failed to read sysfs file: " << path << std::endl;
        return "";
    }

    return content;
}

std::string DeviceManager::normalizePciAddress(const std::string &addr)
{
    // Expected formats:
    //   Short:  BB:DD.F  (e.g., "01:00.0")
    //   Full:   DDDD:BB:DD.F  (e.g., "0000:01:00.0")
    //
    // We need to normalize to canonical form: 0000:BB:DD.F

    if (addr.empty()) {
        return "";
    }

    // Trim leading and trailing whitespace
    std::string trimmed = addr;
    size_t start = trimmed.find_first_not_of(" \t\n\r");
    size_t end = trimmed.find_last_not_of(" \t\n\r");

    if (start == std::string::npos) {
        return ""; // All whitespace
    }

    trimmed = trimmed.substr(start, end - start + 1);

    // Count colons to determine format
    size_t colonCount = 0;
    for (char c : trimmed) {
        if (c == ':') colonCount++;
    }

    // Validate basic structure
    size_t dotPos = trimmed.find('.');
    if (dotPos == std::string::npos) {
        std::cerr << "[Error] Invalid PCI address (missing dot): " << trimmed << std::endl;
        return "";
    }

    std::string normalized;

    if (colonCount == 1) {
        // Short form: BB:DD.F
        // Validate format more strictly
        size_t firstColon = trimmed.find(':');
        if (firstColon == std::string::npos || firstColon > 2 ||
            dotPos - firstColon - 1 > 2 || trimmed.length() - dotPos - 1 != 1) {
            std::cerr << "[Error] Invalid PCI address format: " << trimmed << std::endl;
            return "";
        }

        // Check all characters are hex digits or separators
        for (size_t i = 0; i < trimmed.length(); i++) {
            char c = trimmed[i];
            if (c != ':' && c != '.' && !std::isxdigit(static_cast<unsigned char>(c))) {
                std::cerr << "[Error] Invalid character in PCI address: " << trimmed << std::endl;
                return "";
            }
        }

        normalized = "0000:" + trimmed;
    } else if (colonCount == 2) {
        // Full form: DDDD:BB:DD.F
        size_t firstColon = trimmed.find(':');
        size_t secondColon = trimmed.find(':', firstColon + 1);

        if (firstColon > 4 || secondColon - firstColon - 1 > 2 ||
            dotPos - secondColon - 1 > 2 || trimmed.length() - dotPos - 1 != 1) {
            std::cerr << "[Error] Invalid PCI address format: " << trimmed << std::endl;
            return "";
        }

        // Check all characters are hex digits or separators
        for (size_t i = 0; i < trimmed.length(); i++) {
            char c = trimmed[i];
            if (c != ':' && c != '.' && !std::isxdigit(static_cast<unsigned char>(c))) {
                std::cerr << "[Error] Invalid character in PCI address: " << trimmed << std::endl;
                return "";
            }
        }

        normalized = trimmed;

        // Pad domain to 4 digits if needed
        if (firstColon < 4) {
            std::string domain = trimmed.substr(0, firstColon);
            while (domain.length() < 4) {
                domain = "0" + domain;
            }
            normalized = domain + trimmed.substr(firstColon);
        }
    } else {
        std::cerr << "[Error] Invalid PCI address (wrong colon count): " << trimmed << std::endl;
        return "";
    }

    return normalized;
}

} // namespace VxM
