/*
 * Copyright (C) 2026 Nitrux Latinoamericana S.C.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "VirtualMachine.h"
#include "ProfileManager.h"
#include "HardwareDetection.h"
#include <iostream>
#include <string>
#include <csignal>
#include <cstdlib>

using namespace VxM;

// Global pointer for signal handler
static VirtualMachine* g_vm = nullptr;

void signalHandler(int signum)
{
    std::cout << "\n[VxM] Received signal " << signum << ", cleaning up..." << std::endl;
    if (g_vm) {
        g_vm->cleanup();
    }
    exit(signum);
}

void printUsage()
{
    std::cout << "VxM (Virtual x Metal) - Twin Engine Manager\n"
              << "Usage:\n"
              << "  vxm init         Initialize the crate (disks, directories)\n"
              << "  vxm list-gpus    List available GPUs\n"
              << "  vxm config       Configure VxM settings\n"
              << "  vxm start        Start the Guest Engine\n"
              << "  vxm status       Check engine status\n";
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        printUsage();
        return 1;
    }

    std::string command = argv[1];
    VirtualMachine vm;

    // Setup signal handlers for cleanup
    g_vm = &vm;
    std::signal(SIGINT, signalHandler);
    std::signal(SIGTERM, signalHandler);

    try {
        if (command == "init") {
            vm.initializeCrate();
            std::cout << "VxM Crate Initialized." << std::endl;
        } else if (command == "list-gpus") {
            VxM::HardwareDetection hw;
            auto gpus = hw.listGpus();
            std::cout << "Available GPUs:" << std::endl;
            for (const auto &gpu : gpus) {
                std::cout << "  [" << gpu.pciAddress << "] "
                        << (gpu.isBootVga ? "(Host Boot VGA) " : "")
                        << gpu.name << std::endl;
            }
            return 0;
        } else if (command == "config") {
            if (argc >= 4 && std::string(argv[2]) == "--set-gpu") {
                VxM::ProfileManager pm;
                if (!pm.selectGpu(argv[3])) {
                    std::cerr << "Failed to configure GPU." << std::endl;
                    return 1;
                }
                return 0;
            }
            std::cerr << "Usage: vxm config --set-gpu <PCI_ID or String>" << std::endl;
            return 1;
        } else if (command == "start") {
            if (vm.checkRequirements()) {
                vm.start();
            }
        } else if (command == "status") {
            // Placeholder for checking /proc for qemu process
            std::cout << "Status: Ready." << std::endl;
        } else {
            printUsage();
            return 1;
        }
    } catch (const std::exception &e) {
        std::cerr << "[Fatal] " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
