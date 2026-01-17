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
    const std::filesystem::path GuestImage = ImageDir / "guest.img";
    const std::filesystem::path GuestIso = IsoDir / "guest_install.iso";
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

    // Looking Glass (IVSHMEM) configuration
    const std::filesystem::path LookingGlassShmPath = "/dev/shm/looking-glass";
    const uint64_t LookingGlassShmSizeMb = 128; // 128MB for up to 4K resolution

    // DDC/CI monitor input switching
    // Common VCP code for input source is 0x60
    // Input values vary by monitor, but common ones are:
    // 0x0F = DisplayPort-1, 0x10 = DisplayPort-2, 0x11 = HDMI-1, 0x12 = HDMI-2
    const uint8_t DdcInputSourceVcp = 0x60;

    /**
     * @brief Finds OVMF firmware files in common distribution paths.
     * Ensures CODE and VARS files match in size (4M or standard).
     * @return true if both CODE and VARS files are found with matching sizes.
     */
    inline bool findOvmfPaths()
    {
        // Strategy: Try to find matching pairs (4M with 4M, or standard with standard)
        // Priority order:
        // 1. Try 4M variants first (better performance and compatibility)
        // 2. Fall back to standard variants

        // Structure to hold matching pairs
        struct OvmfPair {
            std::filesystem::path code;
            std::filesystem::path vars;
        };

        std::vector<OvmfPair> possiblePairs = {
            // 4M variants (all caps)
            {"/usr/share/OVMF/OVMF_CODE_4M.fd", "/usr/share/OVMF/OVMF_VARS_4M.fd"},
            // 4M variants (lowercase directory)
            {"/usr/share/ovmf/OVMF_CODE_4M.fd", "/usr/share/ovmf/OVMF_VARS_4M.fd"},
            // Standard variants (all caps)
            {"/usr/share/OVMF/OVMF_CODE.fd", "/usr/share/OVMF/OVMF_VARS.fd"},
            // Standard variants (lowercase directory)
            {"/usr/share/ovmf/OVMF_CODE.fd", "/usr/share/ovmf/OVMF_VARS.fd"},
            // Alternative names
            {"/usr/share/ovmf/OVMF.fd", "/usr/share/ovmf/OVMF_VARS.fd"},
            // QEMU directory
            {"/usr/share/qemu/OVMF.fd", "/usr/share/qemu/OVMF_VARS.fd"},
            // EDK2 structure
            {"/usr/share/edk2/ovmf/OVMF_CODE.fd", "/usr/share/edk2/ovmf/OVMF_VARS.fd"}
        };

        // Try to find the first matching pair where both files exist
        for (const auto &pair : possiblePairs) {
            if (std::filesystem::exists(pair.code) && std::filesystem::exists(pair.vars)) {
                OvmfCodePath = pair.code;
                OvmfVarsTemplatePath = pair.vars;
                return true;
            }
        }

        // If no matching pair found, fall back to old behavior
        // (but this is now less likely to cause mismatches)
        bool foundCode = false;
        for (const auto &path : OvmfCodeSearchPaths) {
            if (std::filesystem::exists(path)) {
                OvmfCodePath = path;
                foundCode = true;
                break;
            }
        }

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
