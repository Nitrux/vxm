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
     * @brief Releases the device from vfio-pci and rebinds to host driver.
     * Clears driver_override, unbinds from vfio-pci, triggers driver probe,
     * and verifies the device is no longer bound to vfio-pci.
     * @return true if device was successfully released from vfio-pci.
     */
    bool rebindToHost();

    /**
     * @brief Gets the Vendor:Device ID in canonical format (e.g., "1002:73bf").
     * @return Vendor and device IDs as "vvvv:dddd" (hex, lowercase, no 0x prefix).
     */
    std::string getDeviceId() const;

private:
    std::string m_pciAddress;       // Original address as provided (may be short form)
    std::string m_fullAddress;      // Normalized BDF format (0000:BB:DD.F)
    std::filesystem::path m_sysPath;

    bool writeSysfs(const std::filesystem::path &path, const std::string &value) const;
    std::string readSysfs(const std::filesystem::path &path) const;
    std::string getCurrentDriver() const;

    /**
     * @brief Normalizes a PCI address to canonical BDF format (0000:BB:DD.F).
     * Accepts short form (BB:DD.F) or full form (DDDD:BB:DD.F).
     * Validates format and rejects invalid addresses.
     * @param addr The PCI address to normalize.
     * @return Normalized address in canonical form, or empty string if invalid.
     */
    static std::string normalizePciAddress(const std::string &addr);
};

} // namespace VxM

#endif // DEVICEMANAGER_H
