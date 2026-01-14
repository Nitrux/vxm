/*
 * Copyright (C) 2026 Nitrux Latinoamericana S.C.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef CONFIG_H
#define CONFIG_H

#include <string>
#include <filesystem>
#include <vector>

namespace VxM
{

namespace Config
{
    // Paths
    const std::string HomeDir = std::getenv("HOME");
    const std::filesystem::path VxmDir = std::filesystem::path(HomeDir) / "VxM";
    const std::filesystem::path ImageDir = VxmDir / "images";
    const std::filesystem::path IsoDir = VxmDir / "iso";
    const std::filesystem::path RomsDir = VxmDir / "roms";

    // Files
    const std::filesystem::path WindowsImage = ImageDir / "win.img";
    const std::filesystem::path WindowsIso = IsoDir / "win_install.iso";
    const std::filesystem::path VirtioIso = IsoDir / "virtio_drivers.iso";

    // OVMF Firmware Paths - Multiple possible locations
    // Different distributions use different paths/cases
    const std::vector<std::filesystem::path> OvmfCodeSearchPaths = {
        "/usr/share/OVMF/OVMF_CODE_4M.fd",        // 4M variant (all caps)
        "/usr/share/OVMF/OVMF_CODE.fd",           // Standard (all caps)
        "/usr/share/ovmf/OVMF_CODE_4M.fd",        // 4M variant (lowercase directory)
        "/usr/share/ovmf/OVMF_CODE.fd",           // Lowercase directory
        "/usr/share/ovmf/OVMF.fd",                // Alternative name
        "/usr/share/qemu/OVMF.fd",                // QEMU directory
        "/usr/share/edk2/ovmf/OVMF_CODE.fd"       // EDK2 structure
    };

    const std::vector<std::filesystem::path> OvmfVarsSearchPaths = {
        "/usr/share/OVMF/OVMF_VARS_4M.fd",        // 4M variant (all caps)
        "/usr/share/OVMF/OVMF_VARS.fd",           // Standard (all caps)
        "/usr/share/ovmf/OVMF_VARS_4M.fd",        // 4M variant (lowercase directory)
        "/usr/share/ovmf/OVMF_VARS.fd",           // Lowercase directory
        "/usr/share/edk2/ovmf/OVMF_VARS.fd",      // EDK2 structure
        "/usr/share/qemu/OVMF_VARS.fd"            // QEMU directory
    };

    // These will be set at runtime by findOvmfPaths()
    inline std::filesystem::path OvmfCodePath;
    inline std::filesystem::path OvmfVarsTemplatePath;
    const std::filesystem::path OvmfVarsPath = VxmDir / "OVMF_VARS.fd";

    // VM Defaults
    const std::string VmName = "VxM_Guest_Instance";
    const uint64_t DiskSizeGb = 64;

    // Network configuration
    const std::string NetworkBackend = "user"; // SLIRP user networking

    // ISO Download URLs
    const std::string VirtioDriversUrl = "https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/stable-virtio/virtio-win.iso";

    // TPM configuration
    const std::filesystem::path TpmSocketPath = VxmDir / "swtpm.sock";
    const std::filesystem::path TpmStateDir = VxmDir / "tpm";

    // Instance lock
    const std::filesystem::path InstanceLockFile = VxmDir / ".vxm.lock";

    // Audio backend
    const std::string AudioBackend = "pa"; // PulseAudio (works with PipeWire)

    /**
     * @brief Finds OVMF firmware files in common distribution paths.
     * @return true if both CODE and VARS files are found.
     */
    inline bool findOvmfPaths()
    {
        // Find OVMF_CODE.fd
        bool foundCode = false;
        for (const auto &path : OvmfCodeSearchPaths) {
            if (std::filesystem::exists(path)) {
                OvmfCodePath = path;
                foundCode = true;
                break;
            }
        }

        // Find OVMF_VARS.fd
        bool foundVars = false;
        for (const auto &path : OvmfVarsSearchPaths) {
            if (std::filesystem::exists(path)) {
                OvmfVarsTemplatePath = path;
                foundVars = true;
                break;
            }
        }

        return foundCode && foundVars;
    }

} // namespace Config

} // namespace VxM

#endif // CONFIG_H
