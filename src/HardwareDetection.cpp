/*
 * Copyright (C) 2026 Nitrux Latinoamericana S.C.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "HardwareDetection.h"

#include <fstream>
#include <filesystem>
#include <iostream>
#include <vector>
#include <thread>
#include <random>
#include <algorithm>
#include <sstream>
#include <cstdio>

namespace fs = std::filesystem;

namespace VxM
{

// Helper: Read a single line from a sysfs file
static std::string sysRead(const fs::path &path)
{
    std::ifstream file(path);
    std::string content;
    if (file >> content) {
        return content;
    }
    return "";
}

std::vector<GpuInfo> HardwareDetection::listGpus() const
{
    std::vector<GpuInfo> gpus;

    for (const auto &entry : fs::recursive_directory_iterator("/sys/bus/pci/devices")) {
        if (entry.is_symlink()) continue;

        // Check if device class is VGA (0x0300) or 3D Controller (0x0302)
        fs::path classPath = entry.path() / "class";
        std::string classId = sysRead(classPath);
        
        // 0x030000 = VGA, 0x030200 = 3D Controller
        if (classId.find("0x0300") == 0 || classId.find("0x0302") == 0) {
            GpuInfo info;
            info.pciAddress = entry.path().filename().string();

            // Get Vendor/Device IDs
            info.vendorId = sysRead(entry.path() / "vendor");
            info.deviceId = sysRead(entry.path() / "device");
            info.name = "PCI Device " + info.vendorId + ":" + info.deviceId;

            // Check boot_vga
            info.isBootVga = (sysRead(entry.path() / "boot_vga") == "1");

            // Audio Logic
            info.audioPciAddress = info.pciAddress;
            size_t dotPos = info.audioPciAddress.find_last_of('.');
            if (dotPos != std::string::npos) {
                info.audioPciAddress.replace(dotPos + 1, 1, "1");
            }

            // ROM detection for reset bug
            info.needsRom = false;
            info.romPath = "";

            // AMD cards (vendor 0x1002) with known reset bugs
            // Polaris (RX 4xx/5xx): 0x67df, 0x67ef, 0x67c4, 0x67ff
            // Vega 56/64: 0x687f, 0x6867
            // Vega VII: 0x66af
            if (info.vendorId == "0x1002") {
                if (info.deviceId == "0x67df" || info.deviceId == "0x67ef" ||
                    info.deviceId == "0x67c4" || info.deviceId == "0x67ff" ||
                    info.deviceId == "0x687f" || info.deviceId == "0x6867" ||
                    info.deviceId == "0x66af") {
                    info.needsRom = true;

                    // Look for ROM file in roms directory
                    std::string romFileName = info.deviceId + ".rom";
                    fs::path romFile = fs::path(std::getenv("HOME")) / "VxM" / "roms" / romFileName;
                    if (fs::exists(romFile)) {
                        info.romPath = romFile.string();
                    }
                }
            }

            gpus.push_back(info);
        }
    }
    return gpus;
}

std::optional<GpuInfo> HardwareDetection::findGpuByString(const std::string &query) const
{
    auto gpus = listGpus();
    
    for (const auto &gpu : gpus) {
        // Check exact PCI ID match
        if (gpu.pciAddress.find(query) != std::string::npos) {
            return gpu;
        }
        // Check Name match (if we had full names)
        // Check Vendor/Device ID match
    }

    return std::nullopt;
}

GpuInfo HardwareDetection::findPassthroughGpu() const
{
    GpuInfo info;
    bool found = false;

    // Iterate PCI devices to find one where boot_vga == 0
    // Original script logic: find /sys/devices/pci* -name boot_vga
    for (const auto &entry : fs::recursive_directory_iterator("/sys/bus/pci/devices")) {
        if (entry.is_symlink()) {
            continue;
        }

        fs::path bootVgaPath = entry.path() / "boot_vga";
        if (fs::exists(bootVgaPath)) {
            std::string isBoot = sysRead(bootVgaPath);

            // If boot_vga is 0, this is likely our guest GPU
            if (isBoot == "0") {
                // pciId format is usually 0000:03:00.0
                std::string pciId = entry.path().filename().string();

                // Strip domain (0000:) for QEMU if needed, though QEMU accepts full ID
                // Logic based on original script stripping chars
                if (pciId.rfind("0000:", 0) == 0) {
                    info.pciAddress = pciId.substr(5);
                } else {
                    info.pciAddress = pciId;
                }

                // Assume Audio is function .1 on same slot
                info.audioPciAddress = info.pciAddress;
                size_t dotPos = info.audioPciAddress.find_last_of('.');
                if (dotPos != std::string::npos) {
                    info.audioPciAddress.replace(dotPos + 1, 1, "1");
                }

                // Get vendor and device IDs for ROM detection
                info.vendorId = sysRead(entry.path() / "vendor");
                info.deviceId = sysRead(entry.path() / "device");
                info.name = "PCI Device " + info.vendorId + ":" + info.deviceId;

                // ROM detection for reset bug
                info.needsRom = false;
                info.romPath = "";

                // AMD cards with known reset bugs
                if (info.vendorId == "0x1002") {
                    if (info.deviceId == "0x67df" || info.deviceId == "0x67ef" ||
                        info.deviceId == "0x67c4" || info.deviceId == "0x67ff" ||
                        info.deviceId == "0x687f" || info.deviceId == "0x6867" ||
                        info.deviceId == "0x66af") {
                        info.needsRom = true;

                        // Look for ROM file in roms directory
                        std::string romFileName = info.deviceId + ".rom";
                        fs::path romFile = fs::path(std::getenv("HOME")) / "VxM" / "roms" / romFileName;
                        if (fs::exists(romFile)) {
                            info.romPath = romFile.string();
                        }
                    }
                }

                found = true;
                break;
            }
        }
    }

    if (!found) {
        throw std::runtime_error("No secondary GPU found. VxM requires a dual-GPU setup.");
    }

    return info;
}

CpuInfo HardwareDetection::detectCpuTopology() const
{
    CpuInfo cpu;

    // Get total hardware threads
    unsigned int totalThreads = std::thread::hardware_concurrency();

    // Detect actual physical cores and threads per core from /proc/cpuinfo
    std::ifstream cpuinfo("/proc/cpuinfo");
    std::string line;
    int coreCount = 0;
    int siblingCount = 0;
    cpu.isRyzen = false;

    while (std::getline(cpuinfo, line)) {
        if (line.find("model name") != std::string::npos) {
            if (line.find("Ryzen") != std::string::npos) {
                cpu.isRyzen = true;
            }
        } else if (line.find("cpu cores") != std::string::npos) {
            // Extract number after colon
            size_t colonPos = line.find(':');
            if (colonPos != std::string::npos) {
                coreCount = std::stoi(line.substr(colonPos + 1));
            }
        } else if (line.find("siblings") != std::string::npos) {
            size_t colonPos = line.find(':');
            if (colonPos != std::string::npos) {
                siblingCount = std::stoi(line.substr(colonPos + 1));
            }
            break; // We have all the info we need from first processor entry
        }
    }

    // Calculate physical cores and threads per core
    unsigned int physicalCores;
    if (coreCount > 0 && siblingCount > 0) {
        physicalCores = coreCount;
        cpu.threadsPerCore = siblingCount / coreCount;
    } else {
        // Fallback: assume SMT if totalThreads looks even
        if (totalThreads % 2 == 0 && totalThreads > 2) {
            physicalCores = totalThreads / 2;
            cpu.threadsPerCore = 2;
        } else {
            // No SMT detected
            physicalCores = totalThreads;
            cpu.threadsPerCore = 1;
        }
    }

    // Logic from vmetal_hardware_detection
    if (physicalCores >= 10) {
        cpu.allocatedCores = 8;
    } else if (physicalCores >= 4) {
        cpu.allocatedCores = physicalCores - 2;
    } else {
        throw std::runtime_error("Insufficient CPU cores to run VxM.");
    }

    return cpu;
}

uint64_t HardwareDetection::getSafeRamAmount() const
{
    // Read MemTotal from /proc/meminfo
    // Return 50% of available RAM in GB
    std::ifstream meminfo("/proc/meminfo");
    std::string line;
    uint64_t kb = 0;

    if (std::getline(meminfo, line)) { // First line is MemTotal
        // Format: MemTotal:        32805680 kB
        std::string label, unit;
        std::stringstream ss(line);
        ss >> label >> kb >> unit;
    }

    // Convert kB to GB, then take 50%
    // kb -> MB (divide by 1024) -> GB (divide by 1024) -> 50% (divide by 2)
    // Use double for precision, then round to nearest GB
    double gb = static_cast<double>(kb) / (1024.0 * 1024.0);
    uint64_t halfGb = static_cast<uint64_t>(gb / 2.0 + 0.5); // Round to nearest

    // Ensure at least 4GB
    if (halfGb < 4) {
        halfGb = 4;
    }

    return halfGb;
}

std::string HardwareDetection::generateMacAddress() const
{
    // Generate MAC ending in random octets. Prefix from original script: 00:60:2F
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);

    char mac[18];
    snprintf(mac, sizeof(mac), "00:60:2F:%02X:%02X:%02X",
             dis(gen), dis(gen), dis(gen));
    return std::string(mac);
}

} // namespace VxM
