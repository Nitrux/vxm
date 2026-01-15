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
#include <set>
#include <map>
#include <pwd.h>
#include <unistd.h>

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

// Helper: Check if device class matches GPU (VGA or 3D controller)
static bool isGpuClass(const fs::path &devicePath)
{
    fs::path classPath = devicePath / "class";
    std::string classId = sysRead(classPath);
    // 0x030000 = VGA compatible controller
    // 0x030200 = 3D controller
    return classId.find("0x0300") == 0 || classId.find("0x0302") == 0;
}

// Helper: Check if device class matches audio (HDA controller)
static bool isAudioClass(const fs::path &devicePath)
{
    fs::path classPath = devicePath / "class";
    std::string classId = sysRead(classPath);
    // 0x040300 = HDA audio controller
    return classId.find("0x0403") == 0;
}

// Helper: Get HOME directory safely
static std::string getHomeDir()
{
    const char* home = std::getenv("HOME");
    if (home && home[0] != '\0') {
        return std::string(home);
    }

    // Fallback: try to get from /etc/passwd
    uid_t uid = getuid();
    struct passwd* pw = getpwuid(uid);
    if (pw && pw->pw_dir) {
        return std::string(pw->pw_dir);
    }

    return "/root"; // Last resort fallback
}

std::vector<GpuInfo> HardwareDetection::listGpus() const
{
    std::vector<GpuInfo> gpus;

    for (const auto &entry : fs::directory_iterator("/sys/bus/pci/devices")) {
        // Check if device class is VGA (0x0300) or 3D Controller (0x0302)
        if (!isGpuClass(entry.path())) {
            continue;
        }

        GpuInfo info;
        // Always store full BDF format (0000:BB:DD.F)
        info.pciAddress = entry.path().filename().string();

        // Get Vendor/Device IDs
        info.vendorId = sysRead(entry.path() / "vendor");
        info.deviceId = sysRead(entry.path() / "device");

        // Use lspci to get the full device name
        // Strip domain prefix (0000:) for lspci if present
        std::string lspciAddress = info.pciAddress;
        if (lspciAddress.rfind("0000:", 0) == 0) {
            lspciAddress = lspciAddress.substr(5);
        }
        std::string lspciCmd = "lspci -s " + lspciAddress + " 2>/dev/null";
        FILE* pipe = popen(lspciCmd.c_str(), "r");
        if (pipe) {
            char buffer[512];
            if (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
                std::string lspciOutput = buffer;
                // Remove trailing newline
                if (!lspciOutput.empty() && lspciOutput.back() == '\n') {
                    lspciOutput.pop_back();
                }

                // Format: "03:00.0 VGA compatible controller: Vendor Device Name"
                // Extract everything after the first colon
                size_t colonPos = lspciOutput.find(':');
                if (colonPos != std::string::npos) {
                    // Find the second colon (after device type)
                    size_t secondColonPos = lspciOutput.find(':', colonPos + 1);
                    if (secondColonPos != std::string::npos) {
                        info.name = lspciOutput.substr(secondColonPos + 2); // +2 to skip ": "
                    } else {
                        info.name = lspciOutput.substr(colonPos + 2);
                    }
                } else {
                    info.name = lspciOutput;
                }
            }
            pclose(pipe);
        }

        // Fallback if lspci fails
        if (info.name.empty()) {
            std::string vendorName;
            if (info.vendorId == "0x1002") {
                vendorName = "AMD/ATI";
            } else if (info.vendorId == "0x10de") {
                vendorName = "NVIDIA";
            } else if (info.vendorId == "0x8086") {
                vendorName = "Intel";
            } else {
                vendorName = "Unknown";
            }
            info.name = vendorName + " GPU [" + info.vendorId + ":" + info.deviceId + "]";
        }

        // Check boot_vga
        info.isBootVga = (sysRead(entry.path() / "boot_vga") == "1");

        // Audio Logic: assume .1 function, but verify it exists and is audio class
        info.audioPciAddress = info.pciAddress;
        size_t dotPos = info.audioPciAddress.find_last_of('.');
        if (dotPos != std::string::npos) {
            info.audioPciAddress.replace(dotPos + 1, 1, "1");

            // Verify audio function exists and is actually audio class
            fs::path audioDevicePath = fs::path("/sys/bus/pci/devices") / info.audioPciAddress;
            if (!fs::exists(audioDevicePath) || !isAudioClass(audioDevicePath)) {
                // Audio function doesn't exist or isn't audio class
                // Clear it so we don't try to bind it later
                info.audioPciAddress = "";
            }
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

                // Look for ROM file in roms directory (try both with and without 0x prefix)
                fs::path romsDir = fs::path(getHomeDir()) / "VxM" / "roms";

                // Try with 0x prefix first
                fs::path romFileWith0x = romsDir / (info.deviceId + ".rom");
                if (fs::exists(romFileWith0x)) {
                    info.romPath = romFileWith0x.string();
                } else {
                    // Try without 0x prefix (e.g., "67df.rom")
                    std::string deviceIdNoPrefix = info.deviceId.substr(2); // Remove "0x"
                    fs::path romFileWithout0x = romsDir / (deviceIdNoPrefix + ".rom");
                    if (fs::exists(romFileWithout0x)) {
                        info.romPath = romFileWithout0x.string();
                    }
                }
            }
        }

        gpus.push_back(info);
    }
    return gpus;
}

std::optional<GpuInfo> HardwareDetection::findGpuByString(const std::string &query) const
{
    auto gpus = listGpus();
    std::vector<GpuInfo> matches;

    for (const auto &gpu : gpus) {
        // Check PCI address match (supports both 03:00.0 and 0000:03:00.0)
        if (gpu.pciAddress.find(query) != std::string::npos) {
            matches.push_back(gpu);
        }
        // Check case-insensitive name match
        else {
            std::string lowerQuery = query;
            std::string lowerName = gpu.name;
            std::transform(lowerQuery.begin(), lowerQuery.end(), lowerQuery.begin(), ::tolower);
            std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);

            if (lowerName.find(lowerQuery) != std::string::npos) {
                matches.push_back(gpu);
            }
        }
    }

    // If we found exactly one match, return it
    if (matches.size() == 1) {
        return matches[0];
    }

    // If multiple matches, print them and return nullopt
    if (matches.size() > 1) {
        std::cerr << "[Error] Multiple GPUs match '" << query << "':\n";
        for (const auto &gpu : matches) {
            std::cerr << "  " << gpu.pciAddress << " " << gpu.name << "\n";
        }
        std::cerr << "Please use a more specific PCI address (e.g., '03:00.0')." << std::endl;
    }

    return std::nullopt;
}

GpuInfo HardwareDetection::findPassthroughGpu() const
{
    GpuInfo info;
    bool found = false;

    // Iterate PCI devices to find a GPU (not boot VGA)
    for (const auto &entry : fs::directory_iterator("/sys/bus/pci/devices")) {
        // First check if this is actually a GPU device
        if (!isGpuClass(entry.path())) {
            continue;
        }

        fs::path bootVgaPath = entry.path() / "boot_vga";
        if (fs::exists(bootVgaPath)) {
            std::string isBoot = sysRead(bootVgaPath);

            // If boot_vga is 0, this is a secondary GPU suitable for passthrough
            if (isBoot == "0") {
                // Always use full BDF format for consistency
                info.pciAddress = entry.path().filename().string();

                // Audio: assume .1 function, but verify it exists and is audio class
                info.audioPciAddress = info.pciAddress;
                size_t dotPos = info.audioPciAddress.find_last_of('.');
                if (dotPos != std::string::npos) {
                    info.audioPciAddress.replace(dotPos + 1, 1, "1");

                    // Verify audio function exists and is actually audio class
                    fs::path audioDevicePath = fs::path("/sys/bus/pci/devices") / info.audioPciAddress;
                    if (!fs::exists(audioDevicePath) || !isAudioClass(audioDevicePath)) {
                        info.audioPciAddress = "";
                    }
                }

                // Get vendor and device IDs for ROM detection
                info.vendorId = sysRead(entry.path() / "vendor");
                info.deviceId = sysRead(entry.path() / "device");

                // Use lspci to get the full device name
                std::string fullPciAddress = entry.path().filename().string();
                // Strip domain prefix (0000:) for lspci if present
                std::string lspciAddress = fullPciAddress;
                if (lspciAddress.rfind("0000:", 0) == 0) {
                    lspciAddress = lspciAddress.substr(5);
                }
                std::string lspciCmd = "lspci -s " + lspciAddress + " 2>/dev/null";
                FILE* pipe = popen(lspciCmd.c_str(), "r");
                if (pipe) {
                    char buffer[512];
                    if (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
                        std::string lspciOutput = buffer;
                        if (!lspciOutput.empty() && lspciOutput.back() == '\n') {
                            lspciOutput.pop_back();
                        }

                        size_t colonPos = lspciOutput.find(':');
                        if (colonPos != std::string::npos) {
                            size_t secondColonPos = lspciOutput.find(':', colonPos + 1);
                            if (secondColonPos != std::string::npos) {
                                info.name = lspciOutput.substr(secondColonPos + 2);
                            } else {
                                info.name = lspciOutput.substr(colonPos + 2);
                            }
                        }
                    }
                    pclose(pipe);
                }

                // Fallback if lspci fails
                if (info.name.empty()) {
                    std::string vendorName;
                    if (info.vendorId == "0x1002") {
                        vendorName = "AMD/ATI";
                    } else if (info.vendorId == "0x10de") {
                        vendorName = "NVIDIA";
                    } else if (info.vendorId == "0x8086") {
                        vendorName = "Intel";
                    } else {
                        vendorName = "Unknown";
                    }
                    info.name = vendorName + " GPU [" + info.vendorId + ":" + info.deviceId + "]";
                }

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

                        // Look for ROM file in roms directory (try both with and without 0x prefix)
                        fs::path romsDir = fs::path(getHomeDir()) / "VxM" / "roms";

                        // Try with 0x prefix first
                        fs::path romFileWith0x = romsDir / (info.deviceId + ".rom");
                        if (fs::exists(romFileWith0x)) {
                            info.romPath = romFileWith0x.string();
                        } else {
                            // Try without 0x prefix (e.g., "67df.rom")
                            std::string deviceIdNoPrefix = info.deviceId.substr(2); // Remove "0x"
                            fs::path romFileWithout0x = romsDir / (deviceIdNoPrefix + ".rom");
                            if (fs::exists(romFileWithout0x)) {
                                info.romPath = romFileWithout0x.string();
                            }
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
    CpuInfo cpu{};
    cpu.isRyzen = false;

    auto readLine = [](const fs::path &p) -> std::string {
        std::ifstream f(p);
        std::string s;
        std::getline(f, s);
        return s;
    };

    auto trim = [](std::string s) {
        while (!s.empty() && (s.back() == '\n' || s.back() == '\r' || s.back() == ' ' || s.back() == '\t')) s.pop_back();
        std::size_t i = 0;
        while (i < s.size() && (s[i] == ' ' || s[i] == '\t')) ++i;
        return s.substr(i);
    };

    auto parseInt = [&](const fs::path &p) -> int {
        std::string s = trim(readLine(p));
        if (s.empty()) return -1;
        return std::stoi(s);
    };

    auto parseCpuList = [](const std::string &s) -> std::vector<int> {
        std::vector<int> out;
        std::size_t i = 0;
        while (i < s.size()) {
            while (i < s.size() && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r' || s[i] == ',')) ++i;
            if (i >= s.size()) break;

            std::size_t j = i;
            while (j < s.size() && std::isdigit(static_cast<unsigned char>(s[j]))) ++j;
            if (j == i) break;
            int a = std::stoi(s.substr(i, j - i));
            i = j;

            if (i < s.size() && s[i] == '-') {
                ++i;
                std::size_t k = i;
                while (k < s.size() && std::isdigit(static_cast<unsigned char>(s[k]))) ++k;
                if (k == i) break;
                int b = std::stoi(s.substr(i, k - i));
                i = k;
                if (b < a) std::swap(a, b);
                for (int x = a; x <= b; ++x) out.push_back(x);
            } else {
                out.push_back(a);
            }
        }
        std::sort(out.begin(), out.end());
        out.erase(std::unique(out.begin(), out.end()), out.end());
        return out;
    };

    // Detect actual physical cores and threads per core from sysfs

    fs::path cpuRoot = "/sys/devices/system/cpu";
    std::string onlineStr = trim(readLine(cpuRoot / "online"));
    if (onlineStr.empty()) {
        throw std::runtime_error("Cannot read /sys/devices/system/cpu/online");
    }

    std::vector<int> cpus = parseCpuList(onlineStr);
    if (cpus.empty()) {
        throw std::runtime_error("No online CPUs detected");
    }

    struct CoreKey {
        int pkg;
        int core;
        bool operator<(const CoreKey &o) const {
            if (pkg != o.pkg) return pkg < o.pkg;
            return core < o.core;
        }
    };

    std::set<CoreKey> uniqueCores;
    std::map<CoreKey, int> coreThreads;

    for (int cpuId : cpus) {
        fs::path topo = cpuRoot / ("cpu" + std::to_string(cpuId)) / "topology";
        int pkg = parseInt(topo / "physical_package_id");
        int core = parseInt(topo / "core_id");
        if (pkg < 0 || core < 0) {
            continue;
        }

        CoreKey key{pkg, core};
        uniqueCores.insert(key);

        std::string sibs = trim(readLine(topo / "thread_siblings_list"));
        if (!sibs.empty()) {
            int count = static_cast<int>(parseCpuList(sibs).size());
            if (count > coreThreads[key]) coreThreads[key] = count;
        }
    }

    if (uniqueCores.empty()) {
        throw std::runtime_error("Could not determine CPU core topology from sysfs");
    }

    // Calculate physical cores and threads per core

    unsigned int physicalCores = static_cast<unsigned int>(uniqueCores.size());

    int maxThreads = 1;
    for (const auto &kv : coreThreads) {
        if (kv.second > maxThreads) maxThreads = kv.second;
    }
    cpu.threadsPerCore = static_cast<unsigned int>(maxThreads);

    {
        std::ifstream cpuinfo("/proc/cpuinfo");
        std::string line;
        while (std::getline(cpuinfo, line)) {
            if (line.find("model name") != std::string::npos && line.find("Ryzen") != std::string::npos) {
                cpu.isRyzen = true;
                break;
            }
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

uint64_t HardwareDetection::getSafeRamAmount(uint64_t maxGb) const
{
    // Read MemTotal from /proc/meminfo
    std::ifstream meminfo("/proc/meminfo");
    std::string line;
    uint64_t kb = 0;

    // Search for MemTotal line (don't assume it's first)
    while (std::getline(meminfo, line)) {
        if (line.find("MemTotal:") == 0) {
            // Format: MemTotal:        32805680 kB
            std::string label, unit;
            std::stringstream ss(line);
            ss >> label >> kb >> unit;
            break;
        }
    }

    // Convert kB to GB, then take 50%
    // kb -> MB (divide by 1024) -> GB (divide by 1024) -> 50% (divide by 2)
    // Use double for precision, then round to nearest GB
    double gb = static_cast<double>(kb) / (1024.0 * 1024.0);
    uint64_t halfGb = static_cast<uint64_t>(gb / 2.0 + 0.5); // Round to nearest

    // Cap at configurable maximum (prevents excessive allocation)
    if (halfGb > maxGb) {
        halfGb = maxGb;
    }

    // Ensure at least 4GB minimum
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

std::string HardwareDetection::getSystemFingerprint() const
{
    // Read DMI UUID from sysfs
    std::ifstream file("/sys/class/dmi/id/product_uuid");
    std::string uuid;
    if (file >> uuid) {
        return uuid;
    }

    // Fallback: try reading from dmidecode output if sysfs fails
    FILE* pipe = popen("dmidecode -s system-uuid 2>/dev/null", "r");
    if (pipe) {
        char buffer[128];
        if (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
            uuid = buffer;
            // Remove trailing newline
            if (!uuid.empty() && uuid.back() == '\n') {
                uuid.pop_back();
            }
        }
        pclose(pipe);
    }

    return uuid;
}

} // namespace VxM
