/*
 * Copyright (C) 2026 Nitrux Latinoamericana S.C.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef INPUTMANAGER_H
#define INPUTMANAGER_H

#include <string>
#include <vector>
#include <filesystem>

namespace VxM
{

/**
 * @brief Type of input device for passthrough.
 */
enum class InputType
{
    Keyboard,
    Mouse
};

/**
 * @brief Represents a physical input device suitable for QEMU passthrough.
 */
struct InputDevice
{
    std::string path;  // Resolved path to /dev/input/eventX (e.g., "/dev/input/event12")
    InputType type;    // Device type (Keyboard or Mouse)
};

class InputManager
{
public:
    InputManager();

    /**
     * @brief Auto-detects keyboards and mice suitable for QEMU input-linux passthrough.
     *
     * Discovery process:
     * 1. Scans /dev/input/by-id for devices ending in -event-kbd and -event-mouse
     * 2. Resolves symlinks to actual /dev/input/eventX device paths
     * 3. Verifies each device is readable (O_RDONLY) by the current user
     * 4. Filters out duplicate physical devices (same eventX from multiple symlinks)
     * 5. Skips composite device interfaces (if01, if02, etc.) to avoid duplicates
     *
     * Selection rules:
     * - Returns ALL detected keyboards and mice that pass validation
     * - Keyboards are sorted before mice (important for grab_all ordering)
     * - Within each type, devices are sorted by path for stability
     *
     * @return Vector of InputDevice with resolved eventX paths, keyboards first.
     *         Returns empty vector if /dev/input/by-id does not exist.
     */
    std::vector<InputDevice> detectDevices() const;

    /**
     * @brief Generates QEMU arguments for input-linux device passthrough.
     *
     * Behavior:
     * - First keyboard receives: grab_all=on, repeat=on, grab_toggle=ctrl-ctrl
     *   - grab_all: captures all other input devices when toggled
     *   - repeat: enables key repeat in guest
     *   - grab_toggle: Left Ctrl + Right Ctrl toggles capture
     * - Subsequent devices receive no special flags (grabbed by first keyboard)
     * - Generates unique object IDs: input0, input1, input2, etc.
     *
     * QEMU compatibility:
     * - Requires QEMU with input-linux object support (typically QEMU 2.10+)
     * - grab_toggle=ctrl-ctrl requires QEMU 2.12+ (may fail on older versions)
     * - If QEMU rejects options, check QEMU version and input-linux feature support
     *
     * @param devices Vector of InputDevice (typically from detectDevices())
     * @return Vector of QEMU arguments: ["-object", "input-linux,id=...", ...]
     *         Emits warnings to stderr if no keyboard or mouse is present.
     */
    std::vector<std::string> generateQemuArgs(const std::vector<InputDevice> &devices) const;
};

} // namespace VxM

#endif // INPUTMANAGER_H
