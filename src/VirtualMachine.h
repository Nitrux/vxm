/*
 * Copyright (C) 2026 Nitrux Latinoamericana S.C.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef VIRTUALMACHINE_H
#define VIRTUALMACHINE_H

#include <string>
#include <vector>
#include <cstdint>

namespace VxM
{

class VirtualMachine
{
public:
    VirtualMachine();
    ~VirtualMachine();

    /**
     * @brief Checks strict requirements (IOMMU, disk space, ISOs).
     * @return true if environment is valid.
     */
    bool checkRequirements() const;

    /**
     * @brief Initializes storage (creates disks if missing).
     */
    void initializeCrate();

    /**
     * @brief Starts the virtual machine (Starts QEMU).
     * This function calls execvp and does not return on success.
     */
    void start();

    /**
     * @brief Cleanup bound devices (called on error or exit).
     */
    void cleanup();

    /**
     * @brief Reset VxM by removing all created files and directories.
     * This removes the entire VxM directory including disks, ISOs, config, etc.
     */
    static void reset();

private:
    std::vector<std::string> buildQemuArgs() const;

    /**
     * @brief Validates that the GPU is in an isolated IOMMU group.
     * @param pciAddress The PCI address of the device to validate.
     * @return true if the device is in a suitable IOMMU group.
     */
    bool validateIommuGroup(const std::string &pciAddress) const;

    /**
     * @brief Acquires an instance lock to prevent multiple VMs running.
     * @return true if lock was acquired successfully.
     */
    bool acquireInstanceLock() const;

    /**
     * @brief Releases the instance lock file.
     */
    void releaseInstanceLock() const;

    /**
     * @brief Starts the TPM 2.0 emulator (swtpm).
     * @return Process ID of swtpm, or -1 on failure.
     */
    pid_t startTpmEmulator() const;

    /**
     * @brief Reserves hugepages for VM memory.
     * @param ramGb Amount of RAM in GB to reserve hugepages for.
     */
    void reserveHugepages(uint64_t ramGb) const;

    // Track bound devices for cleanup
    mutable std::vector<std::string> m_boundDevices;
    mutable pid_t m_tpmPid = -1;
};

} // namespace VxM

#endif // VIRTUALMACHINE_H
