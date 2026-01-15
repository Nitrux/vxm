/*
 * Copyright (C) 2026 Nitrux Latinoamericana S.C.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "ProfileManager.h"
#include <fstream>
#include <iostream>

namespace VxM
{

ProfileManager::ProfileManager()
{
    const char *home = std::getenv("HOME");
    if (home) {
        m_configPath = std::filesystem::path(home) / ".config" / "vxm" / "vxm.conf";
    }
}

Profile ProfileManager::loadProfile() const
{
    Profile p;
    if (!std::filesystem::exists(m_configPath)) {
        return p;
    }

    std::ifstream file(m_configPath);
    std::string line;
    while (std::getline(file, line)) {
        if (line.find("gpu=") == 0) {
            p.selectedGpuPci = line.substr(4);
        } else if (line.find("mac=") == 0) {
            p.macAddress = line.substr(4);
        } else if (line.find("max_ram=") == 0) {
            try {
                p.maxRam = std::stoull(line.substr(8));
            } catch (...) {
                p.maxRam = 16; // Default on parse error
            }
        }
    }
    return p;
}

void ProfileManager::saveProfile(const Profile &profile)
{
    if (!std::filesystem::exists(m_configPath.parent_path())) {
        std::filesystem::create_directories(m_configPath.parent_path());
    }

    std::ofstream file(m_configPath);
    if (!profile.selectedGpuPci.empty()) {
        file << "gpu=" << profile.selectedGpuPci << "\n";
    }
    if (!profile.macAddress.empty()) {
        file << "mac=" << profile.macAddress << "\n";
    }
    if (profile.maxRam != 16) { // Only save if non-default
        file << "max_ram=" << profile.maxRam << "\n";
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
    p.selectedGpuPci = gpu->pciAddress;
    saveProfile(p);
    
    std::cout << "[VxM] Selected GPU: " << gpu->pciAddress << std::endl;
    return true;
}

} // namespace VxM
