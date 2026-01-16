/*
 * Copyright (C) 2026 Nitrux Latinoamericana S.C.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef HARDWAREDETECTION_H
#define HARDWAREDETECTION_H

#include <string>
#include <vector>
#include <optional>
#include <cstdint>

namespace VxM
{

struct GpuInfo
{
    std::string pciAddress;           // Always full BDF format: "0000:BB:DD.F" (e.g., "0000:03:00.0")
    std::string audioPciAddress;      // Full BDF of audio function: "0000:BB:DD.F" (e.g., "0000:03:00.1"), empty if none
    std::string name;                 // Human-readable name (e.g., "NVIDIA Corporation AD102 [GeForce RTX 4090]")
    std::string vendorId;             // Vendor ID with 0x prefix (e.g., "0x1002" for AMD, "0x10de" for NVIDIA)
    std::string deviceId;             // Device ID with 0x prefix (e.g., "0x67df" for RX 580)
    bool isBootVga = false;           // True if this is the primary/boot GPU
    bool needsRom = false;            // True if GPU requires a patched ROM file (AMD reset bug)
    std::string romPath;              // Path to ROM file if needsRom is true and ROM found
    bool isMobileGpu = false;         // True if this is a mobile/laptop GPU (Optimus, etc.)
};

struct CpuInfo
{
    uint32_t allocatedCores = 0;
    uint32_t threadsPerCore = 1;
    bool isRyzen = false;
    std::string vendor;
};

class HardwareDetection
{
public:
    HardwareDetection() = default;

    /**
     * @brief Returns a list of all detected GPUs on the system.
     */
    std::vector<GpuInfo> listGpus() const;

    /**
     * @brief Finds a GPU by a partial string match (e.g., "7900" or "03:00.0").
     * Returns std::nullopt if not found or ambiguous.
     */
    std::optional<GpuInfo> findGpuByString(const std::string &query) const;

    /**
     * @brief Finds a suitable GPU for passthrough (non-boot VGA).
     * Throws std::runtime_error if no suitable GPU is found.
     * @return GpuInfo for the passthrough GPU.
     */
    GpuInfo findPassthroughGpu() const;

    /**
     * @brief Calculates optimal core count for the guest.
     * Logic derived from original vmetal scripts.
     */
    CpuInfo detectCpuTopology() const;

    /**
     * @brief Returns safe RAM allocation (50% of host, capped at maxGb).
     * @param maxGb Maximum RAM cap in GB (default: 16)
     */
    uint64_t getSafeRamAmount(uint64_t maxGb = 16) const;

    /**
     * @brief Generates a persistent-style MAC address.
     */
    std::string generateMacAddress() const;

    /**
     * @brief Returns the system fingerprint (DMI UUID).
     */
    std::string getSystemFingerprint() const;
};

} // namespace VxM

#endif // HARDWAREDETECTION_H
