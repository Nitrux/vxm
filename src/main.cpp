/*
 * Copyright (C) 2026 Nitrux Latinoamericana S.C.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "VirtualMachine.h"
#include "ProfileManager.h"
#include "HardwareDetection.h"
#include "Config.h"
#include <iostream>
#include <string>
#include <csignal>
#include <cstdlib>
#include <unistd.h>
#include <fstream>
#include <filesystem>

using namespace VxM;

// Global pointer for signal handler
static VirtualMachine* g_vm = nullptr;

void signalHandler(int signum)
{
    // Signal handlers should be async-signal-safe
    // Using write() instead of std::cout for safety
    const char msg[] = "\n[VxM] Interrupt received, cleaning up...\n";
    write(STDOUT_FILENO, msg, sizeof(msg) - 1);

    if (g_vm) {
        g_vm->cleanup();
    }

    // Use _exit() instead of exit() in signal handlers
    _exit(128 + signum);
}

void printUsage()
{
    std::cout << "VxM - Run a hardware-accelerated VM\n"
              << "Copyright (C) " << VXM_COPYRIGHT_YEAR << " Nitrux Latinoamericana S.C.\n\n"
              << "Usage:\n"
              << "  vxm [COMMAND] <options>\n\n"
              << "Commands:\n"
              << "  init          Initialize storage, directory structure, and download required drivers.\n"
              << "  start         Boot the virtual machine using the active hardware profile. (requires root)\n"
              << "  status        Show current VM status and hardware binding state.\n"
              << "  list-gpus     Scan system for available GPUs and display PCI addresses.\n"
              << "  config        Update configuration and hardware profiles.\n"
              << "  reset         Remove all VxM files and configuration (clean slate). (requires root)\n\n"
              << "Options:\n"
              << "  --set-gpu <PCI_ADDRESS>    Set the GPU for passthrough by PCI address.\n";
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
            std::cout << "VxM storage initialized." << std::endl;
        } else if (command == "list-gpus") {
            VxM::HardwareDetection hw;
            auto gpus = hw.listGpus();
            std::cout << "Available GPUs:" << std::endl;
            for (const auto &gpu : gpus) {
                std::cout << "  " << gpu.pciAddress << " " << gpu.name;
                if (gpu.isBootVga) {
                    std::cout << " [PRIMARY/HOST GPU - DO NOT USE FOR PASSTHROUGH]";
                }
                std::cout << std::endl;
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
            // Check for root permissions required for GPU binding
            if (geteuid() != 0) {
                std::cerr << "[Error] The 'start' command requires root permissions to bind GPU devices.\n"
                          << "        Please run: sudo -E vxm start\n"
                          << "        (The -E flag preserves your user environment)" << std::endl;
                return 1;
            }

            // Warn if running as root without preserving user environment
            const char* sudoUser = std::getenv("SUDO_USER");
            const char* home = std::getenv("HOME");
            if (sudoUser && home && std::string(home) == "/root") {
                std::cerr << "[Warning] Running as root with HOME=/root\n"
                          << "          VxM files should be in the user's home directory.\n"
                          << "          Please use: sudo -E vxm start\n"
                          << "          Or set HOME manually: sudo HOME=/home/" << sudoUser << " vxm start" << std::endl;
                return 1;
            }

            if (vm.checkRequirements()) {
                vm.start();
            }
        } else if (command == "status") {
            // Check if VxM is running by reading the lock file
            if (std::filesystem::exists(Config::InstanceLockFile)) {
                std::ifstream lockFile(Config::InstanceLockFile);
                pid_t pid = 0;
                if (lockFile >> pid) {
                    // Check if the process is still running
                    if (kill(pid, 0) == 0) {
                        std::cout << "[VxM] Status: Running (PID: " << pid << ")" << std::endl;

                        // Try to get more details from /proc
                        std::string procPath = "/proc/" + std::to_string(pid) + "/cmdline";
                        if (std::filesystem::exists(procPath)) {
                            std::ifstream cmdline(procPath);
                            std::string cmd;
                            std::getline(cmdline, cmd);
                            // Replace null bytes with spaces for readability
                            for (char &c : cmd) {
                                if (c == '\0') c = ' ';
                            }
                            if (!cmd.empty() && cmd.find("qemu") != std::string::npos) {
                                std::cout << "      Process: qemu-system-x86_64" << std::endl;
                            }
                        }

                        // Check which GPU is bound to vfio-pci
                        ProfileManager pm;
                        Profile profile = pm.loadProfile();
                        if (!profile.selectedGpuPci.empty()) {
                            std::cout << "      GPU: " << profile.selectedGpuPci << std::endl;
                        }
                    } else {
                        std::cout << "[VxM] Status: Stopped (stale lock file found)" << std::endl;
                        std::cout << "      Run 'vxm start' to launch a new instance" << std::endl;
                    }
                }
            } else {
                std::cout << "[VxM] Status: Stopped" << std::endl;
                std::cout << "      No active VxM instance found" << std::endl;
                std::cout << "      Run 'vxm start' to launch" << std::endl;
            }
        } else if (command == "reset") {
            // Check for root permissions
            if (geteuid() != 0) {
                std::cerr << "[Error] The 'reset' command requires root permissions.\n"
                          << "        Some VxM files may have been created by root during 'vxm start'.\n"
                          << "        Please run: sudo vxm reset" << std::endl;
                return 1;
            }

            std::cout << "WARNING: This will delete all VxM files including:\n"
                      << "  - Virtual machine disk images\n"
                      << "  - Downloaded ISOs and drivers\n"
                      << "  - Configuration files\n"
                      << "  - ROM files\n\n"
                      << "Are you sure you want to continue? (yes/no): ";
            std::string response;
            std::getline(std::cin, response);
            if (response == "yes") {
                VirtualMachine::reset();
            } else {
                std::cout << "Reset cancelled." << std::endl;
            }
            return 0;
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
