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
#include <sys/types.h>  // pid_t

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
     * @brief Starts the virtual machine by forking and executing QEMU.
     * The parent process waits for QEMU to exit and performs cleanup.
     * This function returns after QEMU terminates.
     */
    void start();

    /**
     * @brief Cleanup bound devices (called on error or exit).
     * Releases GPU bindings, stops TPM emulator, and switches monitor back to host.
     */
    void cleanup();

    /**
     * @brief Reset VxM by removing all created files and directories.
     * This removes the entire VxM directory including disks, ISOs, config, etc.
     * Does NOT automatically disable static binding - use 'vxm config --disable-static' for that.
     * Should not be called while a VM instance is running.
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
    bool acquireInstanceLock();

    /**
     * @brief Releases the instance lock file.
     */
    void releaseInstanceLock();

    /**
     * @brief Starts the TPM 2.0 emulator (swtpm).
     * @return Process ID of swtpm, or -1 on failure.
     */
    pid_t startTpmEmulator();

    /**
     * @brief Reserves hugepages for VM memory.
     * Saves the original hugepage count for restoration in cleanup.
     * @param ramGb Amount of RAM in GB to reserve hugepages for.
     * @return true if hugepages were successfully allocated, false if fallback to standard memory needed.
     */
    bool reserveHugepages(uint64_t ramGb);

    /**
     * @brief Checks if Looking Glass kvmfr kernel module is available.
     * @return true if /dev/kvmfr0 exists or module can be loaded.
     */
    bool detectLookingGlass() const;

    /**
     * @brief Creates the Looking Glass shared memory file.
     * @param sizeMb Size of the shared memory region in MB.
     * @return true if shared memory was created successfully.
     */
    bool createLookingGlassShm(uint64_t sizeMb) const;

    /**
     * @brief Switches monitor input using DDC/CI.
     * @param monitor Monitor identifier (e.g., bus number from ddcutil).
     * @param inputValue The VCP input value to switch to.
     * @return true if switch was successful.
     */
    bool switchMonitorInput(const std::string &monitor, uint8_t inputValue) const;

    /**
     * @brief Fixes file ownership when running as root via sudo.
     * @param path The file or directory path to fix ownership for.
     */
    void fixFileOwnership(const std::filesystem::path& path) const;

    // Track bound devices and state for cleanup
    std::vector<std::string> m_boundDevices;
    pid_t m_tpmPid;
    bool m_ddcEnabled;
    std::string m_ddcMonitor;
    uint8_t m_ddcHostInput;

    // Track hugepages for cleanup
    uint64_t m_originalHugepages;
    bool m_hugepagesModified;
};

} // namespace VxM

#endif // VIRTUALMACHINE_H
