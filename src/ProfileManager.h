/*
 * Copyright (C) 2026 Nitrux Latinoamericana S.C.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef PROFILEMANAGER_H
#define PROFILEMANAGER_H

#include <string>
#include <filesystem>
#include <cstdint>
#include "HardwareDetection.h"

namespace VxM
{

struct Profile
{
    std::string selectedGpuPci;   // The manually selected GPU
    std::string macAddress;       // Persistent MAC address for VM
    bool overrideCpu = false;
    int cpuCores = 0;
    bool overrideRam = false;
    uint64_t ramSize = 0;
};

class ProfileManager
{
public:
    ProfileManager();

    /**
     * @brief Loads the profile from disk. Returns default if none exists.
     */
    Profile loadProfile() const;

    /**
     * @brief Saves the current profile to disk.
     */
    void saveProfile(const Profile &profile);

    /**
     * @brief Sets the GPU preference by string (PCI ID or Name).
     * Validates against actual hardware before saving.
     */
    bool selectGpu(const std::string &gpuQuery);

private:
    std::filesystem::path m_configPath;
};

} // namespace VxM

#endif // PROFILEMANAGER_H
