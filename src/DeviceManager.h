/*
 * Copyright (C) 2026 Nitrux Latinoamericana S.C.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef DEVICEMANAGER_H
#define DEVICEMANAGER_H

#include <string>
#include <filesystem>

namespace VxM
{

class DeviceManager
{
public:
    explicit DeviceManager(const std::string &pciAddress);

    /**
     * @brief Checks if the device is currently bound to vfio-pci.
     */
    bool isBoundToVfio() const;

    /**
     * @brief Forces the device to unbind from current driver and bind to vfio-pci.
     * @return true if successful.
     */
    bool bindToVfio();

    /**
     * @brief Rebinds the device to its original driver (or allows kernel to probe).
     */
    bool rebindToHost();

    /**
     * @brief Gets the Vendor:Device ID (e.g., "1002:73bf") for the device.
     */
    std::string getDeviceId() const;

private:
    std::string m_pciAddress;
    std::filesystem::path m_sysPath;

    bool writeSysfs(const std::filesystem::path &path, const std::string &value) const;
    std::string readSysfs(const std::filesystem::path &path) const;
    std::string getCurrentDriver() const;
};

} // namespace VxM

#endif // DEVICEMANAGER_H
