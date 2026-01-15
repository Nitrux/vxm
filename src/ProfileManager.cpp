/*
 * Copyright (C) 2026 Nitrux Latinoamericana S.C.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "ProfileManager.h"
#include <fstream>
#include <iostream>
#include <sstream>
#include <algorithm>
#include <unistd.h>
#include <pwd.h>
#include <cstdlib>

namespace VxM
{

// Helper: Get the effective user's home directory (works with sudo)
static std::string getEffectiveHomeDir()
{
    // If running as root, check if we were invoked via sudo
    if (geteuid() == 0) {
        const char* sudoUser = std::getenv("SUDO_USER");
        if (sudoUser && sudoUser[0] != '\0') {
            // Get the original user's home directory from /etc/passwd
            struct passwd* pw = getpwnam(sudoUser);
            if (pw && pw->pw_dir) {
                return std::string(pw->pw_dir);
            }
        }
    }

    // Try HOME environment variable
    const char* home = std::getenv("HOME");
    if (home && home[0] != '\0') {
        // Validate that HOME is not /root when we have a SUDO_USER
        const char* sudoUser = std::getenv("SUDO_USER");
        if (sudoUser && std::string(home) == "/root") {
            // HOME is /root but we have SUDO_USER - this is wrong
            // Fall through to getpwuid fallback
        } else {
            return std::string(home);
        }
    }

    // Fallback: get home from current UID
    uid_t uid = getuid();
    struct passwd* pw = getpwuid(uid);
    if (pw && pw->pw_dir) {
        return std::string(pw->pw_dir);
    }

    // Last resort
    return "/tmp";
}

// Helper: Trim leading and trailing whitespace
static std::string trim(const std::string& str)
{
    size_t start = str.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) {
        return "";
    }
    size_t end = str.find_last_not_of(" \t\r\n");
    return str.substr(start, end - start + 1);
}

// Helper: Parse boolean from string (accepts: true/false, 1/0, yes/no, on/off)
static bool parseBool(const std::string& value)
{
    std::string lower = value;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    return lower == "true" || lower == "1" || lower == "yes" || lower == "on";
}

ProfileManager::ProfileManager()
{
    std::string home = getEffectiveHomeDir();
    m_configPath = std::filesystem::path(home) / ".config" / "vxm" / "vxm.conf";
}

Profile ProfileManager::loadProfile() const
{
    Profile p;
    if (!std::filesystem::exists(m_configPath)) {
        return p;
    }

    std::ifstream file(m_configPath);
    if (!file) {
        std::cerr << "[Warning] Failed to open profile: " << m_configPath << std::endl;
        return p;
    }

    std::string line;
    while (std::getline(file, line)) {
        // Trim whitespace and \r from line
        line = trim(line);

        // Skip blank lines and comments
        if (line.empty() || line[0] == '#' || line[0] == ';') {
            continue;
        }

        // Parse key=value
        size_t eqPos = line.find('=');
        if (eqPos == std::string::npos) {
            continue;
        }

        std::string key = trim(line.substr(0, eqPos));
        std::string value = trim(line.substr(eqPos + 1));

        // Strip inline comments from value (e.g., "gpu=01:00.0 # my GPU")
        size_t commentPos = value.find('#');
        if (commentPos != std::string::npos) {
            value = trim(value.substr(0, commentPos));
        }

        if (key == "gpu") {
            p.selectedGpuPci = value;
        } else if (key == "mac") {
            p.macAddress = value;
        } else if (key == "max_ram") {
            try {
                uint64_t ram = std::stoull(value);
                // Clamp to sane range: 4GB minimum, 256GB maximum
                if (ram < 4) ram = 4;
                if (ram > 256) ram = 256;
                p.maxRam = ram;
            } catch (...) {
                p.maxRam = 16; // Default on parse error
            }
        } else if (key == "looking_glass") {
            p.lookingGlassEnabled = parseBool(value);
        } else if (key == "ddc_enabled") {
            p.ddcEnabled = parseBool(value);
        } else if (key == "ddc_monitor") {
            p.ddcMonitor = value;
        } else if (key == "ddc_host_input") {
            try {
                p.ddcHostInput = static_cast<uint8_t>(std::stoul(value, nullptr, 0));
            } catch (...) {}
        } else if (key == "ddc_guest_input") {
            try {
                p.ddcGuestInput = static_cast<uint8_t>(std::stoul(value, nullptr, 0));
            } catch (...) {}
        }
    }
    return p;
}

void ProfileManager::saveProfile(const Profile &profile)
{
    if (m_configPath.empty()) {
        std::cerr << "[Error] Config path is empty. Cannot save profile." << std::endl;
        return;
    }

    // Create parent directory if needed
    if (!std::filesystem::exists(m_configPath.parent_path())) {
        try {
            std::filesystem::create_directories(m_configPath.parent_path());
        } catch (const std::filesystem::filesystem_error& e) {
            std::cerr << "[Error] Failed to create config directory: " << e.what() << std::endl;
            return;
        }
    }

    // Write to temporary file first (atomic write pattern)
    std::filesystem::path tempPath = m_configPath;
    tempPath += ".tmp";

    std::ofstream file(tempPath);
    if (!file) {
        std::cerr << "[Error] Failed to open config file for writing: " << tempPath << std::endl;
        return;
    }

    // Write profile with comments
    file << "# VxM Configuration File\n";
    file << "# This file is automatically generated by VxM\n";
    file << "\n";

    if (!profile.selectedGpuPci.empty()) {
        file << "gpu=" << profile.selectedGpuPci << "\n";
    }
    if (!profile.macAddress.empty()) {
        file << "mac=" << profile.macAddress << "\n";
    }
    if (profile.maxRam != 16) { // Only save if non-default
        file << "max_ram=" << profile.maxRam << "\n";
    }
    if (profile.lookingGlassEnabled) {
        file << "looking_glass=true\n";
    }
    if (profile.ddcEnabled) {
        file << "ddc_enabled=true\n";
        if (!profile.ddcMonitor.empty()) {
            file << "ddc_monitor=" << profile.ddcMonitor << "\n";
        }
        // Write hex values with explicit formatting
        {
            std::ostringstream oss;
            oss << "ddc_host_input=0x" << std::hex << static_cast<int>(profile.ddcHostInput);
            file << oss.str() << "\n";
        }
        {
            std::ostringstream oss;
            oss << "ddc_guest_input=0x" << std::hex << static_cast<int>(profile.ddcGuestInput);
            file << oss.str() << "\n";
        }
    }

    file.flush();
    if (!file.good()) {
        std::cerr << "[Error] Failed to write profile to " << tempPath << std::endl;
        return;
    }
    file.close();

    // Atomic rename to final path
    try {
        std::filesystem::rename(tempPath, m_configPath);
    } catch (const std::filesystem::filesystem_error& e) {
        std::cerr << "[Error] Failed to save profile: " << e.what() << std::endl;
        std::filesystem::remove(tempPath); // Clean up temp file
        return;
    }

    std::cout << "[VxM] Profile saved to " << m_configPath << std::endl;
}

bool ProfileManager::selectGpu(const std::string &gpuQuery)
{
    HardwareDetection hw;
    auto gpu = hw.findGpuByString(gpuQuery);

    if (!gpu) {
        std::cerr << "[Error] GPU not found matching: " << gpuQuery << std::endl;
        return false;
    }

    if (gpu->isBootVga) {
        std::cout << "[Warning] You are selecting the GPU currently driving the host display.\n"
                  << "          VxM will kill the display session when started." << std::endl;
    }

    Profile p = loadProfile();
    p.selectedGpuPci = gpu->pciAddress; // pciAddress is always canonical BDF from HardwareDetection
    saveProfile(p);

    std::cout << "[VxM] Selected GPU: " << gpu->pciAddress << std::endl;
    return true;
}

} // namespace VxM
