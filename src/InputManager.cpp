/*
 * Copyright (C) 2026 Nitrux Latinoamericana S.C.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "InputManager.h"
#include <iostream>
#include <algorithm>
#include <set>
#include <fcntl.h>
#include <unistd.h>

namespace fs = std::filesystem;

namespace VxM
{

InputManager::InputManager()
{
}

std::vector<InputDevice> InputManager::detectDevices() const
{
    std::vector<InputDevice> devices;
    const fs::path inputDir = "/dev/input/by-id";

    if (!fs::exists(inputDir)) {
        std::cerr << "[Warning] Input directory /dev/input/by-id not found. Input passthrough may fail." << std::endl;
        return devices;
    }

    // Track resolved eventX paths to avoid duplicates (same physical device with multiple symlinks)
    std::set<std::string> seenDevices;

    // Use error_code to avoid throwing on transient filesystem issues
    std::error_code ec;
    for (const auto &entry : fs::directory_iterator(inputDir, ec)) {
        if (ec) {
            std::cerr << "[Warning] Error iterating /dev/input/by-id: " << ec.message() << std::endl;
            break;
        }

        std::string name = entry.path().filename().string();

        // Skip "if01", "if02" extra interfaces often found on composite devices
        // Also skip "if03", "if04", etc. to be more robust
        if (name.find("if0") != std::string::npos) {
            size_t ifPos = name.find("if0");
            if (ifPos != std::string::npos && ifPos + 3 < name.length() &&
                std::isdigit(static_cast<unsigned char>(name[ifPos + 3]))) {
                continue;
            }
        }

        // Resolve symlink to actual /dev/input/eventX device
        std::string resolvedPath;
        try {
            fs::path canonical = fs::canonical(entry.path());
            resolvedPath = canonical.string();
        } catch (const fs::filesystem_error &e) {
            std::cerr << "[Warning] Failed to resolve symlink " << entry.path() << ": " << e.what() << std::endl;
            continue;
        }

        // Skip if we've already seen this physical device
        if (seenDevices.count(resolvedPath) > 0) {
            continue;
        }

        // Verify we can open the device (read permission check)
        int fd = open(resolvedPath.c_str(), O_RDONLY | O_NONBLOCK);
        if (fd < 0) {
            std::cerr << "[Warning] Cannot access " << resolvedPath << " (permission denied). Skipping." << std::endl;
            continue;
        }
        close(fd);

        // Categorize device by name
        InputType deviceType;
        if (name.find("-event-kbd") != std::string::npos) {
            deviceType = InputType::Keyboard;
        } else if (name.find("-event-mouse") != std::string::npos) {
            deviceType = InputType::Mouse;
        } else {
            // Skip other device types (joysticks, touchpads, etc.)
            continue;
        }

        // Store both the friendly by-id path and resolved eventX path
        devices.push_back({resolvedPath, deviceType});
        seenDevices.insert(resolvedPath);
    }

    // Sort devices: keyboards first, then mice
    // This ensures keyboard is added to QEMU first (important for grab_all)
    std::sort(devices.begin(), devices.end(), [](const InputDevice &a, const InputDevice &b) {
        if (a.type != b.type) {
            return a.type == InputType::Keyboard; // keyboards before mice
        }
        return a.path < b.path; // stable ordering within same type
    });

    return devices;
}

std::vector<std::string> InputManager::generateQemuArgs(const std::vector<InputDevice> &devices) const
{
    std::vector<std::string> args;
    bool hasKeyboard = false;
    bool hasMouse = false;
    size_t idx = 0; // Separate counter for object IDs

    for (const auto &device : devices) {
        std::string id = "input" + std::to_string(idx++);
        std::string arg = "input-linux,id=" + id + ",evdev=" + device.path;

        if (device.type == InputType::Keyboard && !hasKeyboard) {
            // First keyboard acts as the toggle master
            // grab_all=on means it grabs other devices (like the mouse) when toggled
            // repeat=on enables key repeat in guest
            // grab_toggle=ctrl-ctrl allows Left Ctrl + Right Ctrl to toggle grab
            arg += ",grab_all=on,repeat=on,grab_toggle=ctrl-ctrl";
            hasKeyboard = true;
        } else if (device.type == InputType::Mouse) {
            hasMouse = true;
        }

        args.push_back("-object");
        args.push_back(arg);
    }

    // Warn if essential devices are missing
    if (!hasKeyboard) {
        std::cerr << "[Warning] No keyboard detected for passthrough. You will not be able to toggle input capture!" << std::endl;
        std::cerr << "          Input capture toggle requires: Left Ctrl + Right Ctrl" << std::endl;
    }
    if (!hasMouse) {
        std::cerr << "[Warning] No mouse detected for passthrough. Mouse input may not work correctly." << std::endl;
    }

    return args;
}

} // namespace VxM
