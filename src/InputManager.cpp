/*
 * Copyright (C) 2026 Nitrux Latinoamericana S.C.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "InputManager.h"
#include <iostream>
#include <algorithm>

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

    // Heuristic: Look for persistent symlinks
    for (const auto &entry : fs::directory_iterator(inputDir)) {
        std::string name = entry.path().filename().string();
        
        // Skip "if01", "if02" extra interfaces often found on gaming keyboards to avoid duplicates
        if (name.find("if01") != std::string::npos || name.find("if02") != std::string::npos) {
            continue;
        }

        if (name.find("-event-kbd") != std::string::npos) {
            devices.push_back({entry.path().string(), "keyboard"});
        } 
        else if (name.find("-event-mouse") != std::string::npos) {
            devices.push_back({entry.path().string(), "mouse"});
        }
    }

    // Sort to ensure stability (e.g., always pick the same one first if multiple exist)
    std::sort(devices.begin(), devices.end(), [](const InputDevice &a, const InputDevice &b) {
        return a.path < b.path;
    });

    return devices;
}

std::vector<std::string> InputManager::generateQemuArgs(const std::vector<InputDevice> &devices) const
{
    std::vector<std::string> args;
    bool hasKeyboard = false;
    bool hasMouse = false;

    for (const auto &device : devices) {
        std::string id = "input" + std::to_string(args.size()); // unique ID based on count
        std::string arg = "input-linux,id=" + id + ",evdev=" + device.path;

        if (device.type == "keyboard" && !hasKeyboard) {
            // First keyboard acts as the toggle master
            // grab_all=on means it grabs other devices (like the mouse) when toggled
            // repeat=on enables key repeat in guest
            arg += ",grab_all=on,repeat=on";
            hasKeyboard = true;
        } else if (device.type == "mouse") {
            hasMouse = true;
        }

        args.push_back("-object");
        args.push_back(arg);
    }

    if (!hasKeyboard) {
        std::cerr << "[Warning] No keyboard detected for passthrough. You might not be able to toggle inputs!" << std::endl;
    }

    return args;
}

} // namespace VxM
