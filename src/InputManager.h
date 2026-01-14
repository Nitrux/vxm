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

struct InputDevice
{
    std::string path; // e.g., /dev/input/by-id/usb-Logitech_Keyboard-event-kbd
    std::string type; // "keyboard" or "mouse"
};

class InputManager
{
public:
    InputManager();

    /**
     * @brief Auto-detects the primary keyboard and mouse.
     * Looks into /dev/input/by-id for devices ending in -event-kbd and -event-mouse.
     */
    std::vector<InputDevice> detectDevices() const;

    /**
     * @brief Generates the QEMU arguments for input-linux object.
     * Enables the toggle behavior (Left Ctrl + Right Ctrl).
     */
    std::vector<std::string> generateQemuArgs(const std::vector<InputDevice> &devices) const;
};

} // namespace VxM

#endif // INPUTMANAGER_H
