/*
 * Copyright (C) 2026 Nitrux Latinoamericana S.C.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "VirtualMachine.h"
#include "ProfileManager.h"
#include "HardwareDetection.h"
#include "DeviceManager.h"
#include "Config.h"
#include <iostream>
#include <string>
#include <csignal>
#include <cstdlib>
#include <unistd.h>
#include <fstream>
#include <filesystem>
#include <sys/wait.h>
#include <cerrno>
#include <cstring>

using namespace VxM;

namespace fs = std::filesystem;

// Global pointer for signal handler
static VirtualMachine* g_vm = nullptr;

// Global child PID for signal forwarding (parent-supervisor model)
static volatile sig_atomic_t g_gotSignal = 0;
static volatile sig_atomic_t g_lastSignal = 0;
static pid_t g_childPid = -1;

static std::string jsonEscape(std::string s)
{
    std::string out;
    out.reserve(s.size() + 16);
    for (unsigned char c : s) {
        switch (c) {
            case '\"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20) {
                    char buf[7];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else {
                    out += static_cast<char>(c);
                }
                break;
        }
    }
    return out;
}

static bool cmdlineHasStaticBinding()
{
    std::ifstream cmdLineFile("/proc/cmdline");
    std::string cmdLineContent;
    if (!std::getline(cmdLineFile, cmdLineContent)) {
        return false;
    }
    return (cmdLineContent.find("vxm.static_bind=1") != std::string::npos) ||
           (cmdLineContent.find("vxm.static_bind=yes") != std::string::npos) ||
           (cmdLineContent.find("vxm.static_bind=true") != std::string::npos) ||
           (cmdLineContent.find("vxm.static_bind=on") != std::string::npos);
}

static std::string normalizeBdf(std::string bdf)
{
    while (!bdf.empty() && (bdf.back() == '\n' || bdf.back() == '\r' || bdf.back() == ' ' || bdf.back() == '\t')) bdf.pop_back();
    std::size_t i = 0;
    while (i < bdf.size() && (bdf[i] == ' ' || bdf[i] == '\t')) ++i;
    bdf = bdf.substr(i);

    if (bdf.rfind("0000:", 0) == 0) {
        return bdf;
    }
    if (bdf.find(':') != std::string::npos && bdf.size() >= 7) {
        return "0000:" + bdf;
    }
    return bdf;
}

static std::string computeAudioFunctionBdf(const std::string &gpuBdf)
{
    std::string bdf = normalizeBdf(gpuBdf);
    auto dot = bdf.find_last_of('.');
    if (dot == std::string::npos) {
        return "";
    }
    bdf.replace(dot + 1, 1, "1");
    return bdf;
}

static void bestEffortReleaseVfioDevices()
{
    // This is a best-effort safety net for the parent-supervisor model.
    // The VM child process performs binding and then execs into QEMU.
    // We read the runtime state file to find out which devices were ACTUALLY bound,
    // not what the config says (which might have changed while VM was running).
    try {
        fs::path statePath = fs::path(Config::HomeDir) / "VxM" / ".runtime_state";

        std::string gpuBdf, audioBdf;
        if (fs::exists(statePath)) {
            std::ifstream stateFile(statePath);
            pid_t tpmPid;
            uint64_t hugepages;

            // Read runtime state: tpmPid, hugepages, gpuBdf, audioBdf
            if (stateFile >> tpmPid >> hugepages) {
                std::getline(stateFile, gpuBdf); // Consume newline
                std::getline(stateFile, gpuBdf); // GPU BDF
                std::getline(stateFile, audioBdf); // Audio BDF
            }
        }

        // If runtime state is missing or incomplete, fall back to detection
        // (but DO NOT use config file which may have changed)
        if (gpuBdf.empty()) {
            HardwareDetection hw;
            GpuInfo gpu = hw.findPassthroughGpu();
            gpuBdf = gpu.pciAddress;
            audioBdf = gpu.audioPciAddress;
        }

        gpuBdf = normalizeBdf(gpuBdf);
        audioBdf = normalizeBdf(audioBdf);

        if (!gpuBdf.empty()) {
            DeviceManager dm(gpuBdf);
            if (dm.isBoundToVfio()) {
                dm.rebindToHost();
                std::cout << "[VxM] Released GPU " << gpuBdf << std::endl;
            }
        }

        if (!audioBdf.empty()) {
            DeviceManager am(audioBdf);
            if (am.isBoundToVfio()) {
                am.rebindToHost();
                std::cout << "[VxM] Released GPU Audio " << audioBdf << std::endl;
            }
        }
    } catch (const std::exception &e) {
        std::cerr << "[Warning] Best-effort VFIO release failed: " << e.what() << std::endl;
    }
}

void signalHandler(int signum)
{
    // Signal handlers should be async-signal-safe
    // Using write() instead of std::cout for safety
    const char msg[] = "\n[VxM] Interrupt received, forwarding to VM...\n";
    write(STDOUT_FILENO, msg, sizeof(msg) - 1);

    g_gotSignal = 1;
    g_lastSignal = signum;

    // Forward to child if we are supervising one.
    // Do not call cleanup() here: it is not async-signal-safe.
    if (g_childPid > 0) {
        kill(g_childPid, signum);
    }
}

void printUsage()
{
    std::cout << "VxM - Run a hardware-accelerated VM in Nitrux\n"
              << "Copyright (C) " << VXM_COPYRIGHT_YEAR << " Nitrux Latinoamericana S.C.\n\n"
              << "Usage:\n"
              << "  vxm [COMMAND] <options>\n\n"
              << "Commands:\n"
              << "  init                     Initialize storage, directory structure, and download required drivers.\n"
              << "  start                    Boot the virtual machine. (requires root)\n"
              << "  status                   Show current VM status and hardware binding state.\n"
              << "  list-gpus                Scan system for available GPUs and display PCI addresses.\n"
              << "  fingerprint              Display the system fingerprint (DMI UUID). (requires root)\n"
              << "  config                   Update configuration and hardware profiles.\n"
              << "  reset                    Remove all VxM files and configuration.\n\n"
              << "Config options:\n"
              << "  vxm config --set-gpu <PCI_ADDRESS|NAME>   Set specific GPU for passthrough\n"
              << "  vxm config --enable-binding               Enable Static Binding (requires root + reboot)\n"
              << "  vxm config --disable-binding              Disable Static Binding (requires root + reboot)\n\n"
              << "Other options:\n"
              << "  vxm list-gpus [--json]\n"
              << "  vxm fingerprint [--json]\n"
              << "  vxm status [--json]\n\n"
              << "Notes:\n"
              << "  - Commands requiring root: start, fingerprint, config --enable/disable-binding\n"
              << "  - Use 'sudo -E vxm <command>' to preserve the user environment.\n"
              << "  - Static Binding is REQUIRED for VxM. Enable it before first use.\n";
}

// Helper to enable static binding via overlayroot-chroot
bool enableStaticBinding() {
    std::cout << "[VxM] Enabling Static Binding via overlayroot-chroot..." << std::endl;
    std::cout << "      This involves updating GRUB and initramfs. Please wait." << std::endl;

    std::string cmd = "overlayroot-chroot /bin/sh -c '"
                      "mount -t devtmpfs dev /dev && "
                      "mount -t auto $(findfs LABEL=NX_VAR_LIB) /var/lib && "
                      "if ! grep -q vxm.static_bind=1 /etc/default/grub; then "
                      "sed -i \"s/^GRUB_CMDLINE_LINUX_DEFAULT=[\\\"'\\'']/&vxm.static_bind=1 /\" /etc/default/grub; "
                      "fi && "
                      "update-grub && "
                      "update-initramfs -u && "
                      "sync && "
                      "umount /dev /var/lib'";

    int ret = std::system(cmd.c_str());
    if (ret != 0) {
        int exitCode = ret;
        if (WIFEXITED(ret)) {
            exitCode = WEXITSTATUS(ret);
        }
        std::cerr << "[Error] Failed to enable static binding. Command returned: " << exitCode << std::endl;
        return false;
    }

    std::cout << "\n[VxM] Static Binding ENABLED." << std::endl;
    std::cout << "\n      Please REBOOT your system." << std::endl;
    std::cout << "      The GPU will be isolated automatically during the next boot." << std::endl;
    return true;
}

// Helper to disable static binding via overlayroot-chroot
bool disableStaticBinding() {
    std::cout << "[VxM] Disabling Static Binding via overlayroot-chroot..." << std::endl;
    std::cout << "      This involves updating GRUB and initramfs. Please wait." << std::endl;

    // Command to remove the parameter from /etc/default/grub inside the writable chroot
    // Updated to use specific devtmpfs and findfs mounts for Nitrux compatibility
    std::string cmd = "overlayroot-chroot /bin/sh -c \""
                      "mount -t devtmpfs dev /dev && "
                      "mount -t auto $(findfs LABEL=NX_VAR_LIB) /var/lib && "
                      "sed -i 's/ vxm.static_bind=1//g' /etc/default/grub && "
                      "sed -i 's/vxm.static_bind=1//g' /etc/default/grub && "
                      "update-grub && "
                      "update-initramfs -u && "
                      "sync && "
                      "umount /dev /var/lib\"";

    int ret = std::system(cmd.c_str());
    if (ret != 0) {
        int exitCode = ret;
        if (WIFEXITED(ret)) {
            exitCode = WEXITSTATUS(ret);
        }
        std::cerr << "[Error] Failed to disable static binding. Command returned: " << exitCode << std::endl;
        return false;
    }

    std::cout << "[VxM] Static binding DISABLED." << std::endl;
    std::cout << "      The GPU will be returned to the host OS on the next boot." << std::endl;
    std::cout << "      Please REBOOT your system." << std::endl;
    return true;
}

static std::string currentDriverForBdf(const std::string &bdf)
{
    std::string full = normalizeBdf(bdf);
    if (full.empty()) return "";

    fs::path driverLink = fs::path("/sys/bus/pci/devices") / full / "driver";
    std::error_code ec;
    if (!fs::exists(driverLink, ec)) {
        return "";
    }

    fs::path target = fs::read_symlink(driverLink, ec);
    if (ec) {
        return "";
    }
    return target.filename().string();
}

// Signal handler for supervisor process to forward signals to QEMU
static volatile sig_atomic_t g_supervisorGotSignal = 0;
static volatile pid_t g_qemuPid = -1;

static void supervisorSignalHandler(int signum)
{
    g_supervisorGotSignal = signum;

    // Forward signal to QEMU grandchild
    if (g_qemuPid > 0) {
        kill(g_qemuPid, signum);
    }
}

static int runStartSupervised(VirtualMachine &vm)
{
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

    if (!vm.checkRequirements()) {
        return 1;
    }

    // Parent-supervisor model:
    // - Supervisor child performs binding and execs into QEMU.
    // - Supervisor catches signals, forwards them to QEMU, and waits for QEMU to exit.
    // - Parent forwards signals to supervisor and performs best-effort cleanup after supervisor exits.

    // CRITICAL FIX: Block signals before fork() to prevent race condition
    // where signal arrives between fork() and setting g_qemuPid
    sigset_t newmask, oldmask;
    sigemptyset(&newmask);
    sigaddset(&newmask, SIGINT);
    sigaddset(&newmask, SIGTERM);
    sigprocmask(SIG_BLOCK, &newmask, &oldmask);

    pid_t supervisorPid = fork();
    if (supervisorPid < 0) {
        std::cerr << "[Error] Failed to fork supervisor process." << std::endl;
        sigprocmask(SIG_SETMASK, &oldmask, nullptr); // Restore signal mask
        return 1;
    }

    if (supervisorPid == 0) {
        // Supervisor process:
        // Install signal handlers to forward signals to QEMU and wait for it to exit
        std::signal(SIGINT, supervisorSignalHandler);
        std::signal(SIGTERM, supervisorSignalHandler);

        // Fork again to create QEMU process (signals still blocked)
        pid_t qemuPid = fork();
        if (qemuPid < 0) {
            std::cerr << "[Error] Failed to fork QEMU process." << std::endl;
            _exit(1);
        }

        if (qemuPid == 0) {
            // QEMU process (grandchild):
            // Reset signal handlers to default for QEMU
            std::signal(SIGINT, SIG_DFL);
            std::signal(SIGTERM, SIG_DFL);

            // Unblock signals for QEMU
            sigprocmask(SIG_SETMASK, &oldmask, nullptr);

            try {
                vm.start();
            } catch (const std::exception &e) {
                std::cerr << "[Error] VM Start Failed: " << e.what() << std::endl;
                _exit(1);
            }
            _exit(127); // Should not be reached if execvp succeeds
        }

        // Supervisor: Store QEMU PID BEFORE unblocking signals (prevents race)
        g_qemuPid = qemuPid;

        // Now unblock signals - handler can safely forward to QEMU
        sigprocmask(SIG_SETMASK, &oldmask, nullptr);

        int qemuStatus = 0;
        int gracefulAttempts = 0;
        const int MAX_GRACEFUL_ATTEMPTS = 150; // 15 seconds total (100ms * 150)
        bool forcedKill = false;

        while (true) {
            pid_t w = waitpid(qemuPid, &qemuStatus, WNOHANG);
            if (w == qemuPid) {
                // QEMU has exited
                break;
            }
            if (w == -1) {
                if (errno == EINTR) {
                    continue;
                }
                std::cerr << "[Error] Supervisor waitpid() failed: " << strerror(errno) << std::endl;
                break;
            }

            // QEMU is still running (w == 0)
            if (g_supervisorGotSignal != 0) {
                gracefulAttempts++;
                if (gracefulAttempts >= MAX_GRACEFUL_ATTEMPTS) {
                    // QEMU refused to die gracefully, escalate to SIGKILL
                    const char msg[] = "[VxM] QEMU did not respond to shutdown signal, forcing termination...\n";
                    write(STDOUT_FILENO, msg, sizeof(msg) - 1);
                    kill(qemuPid, SIGKILL);
                    forcedKill = true;
                    // Now block until it dies
                    waitpid(qemuPid, &qemuStatus, 0);
                    break;
                }
            }

            // Sleep 100ms before checking again
            usleep(100000);
        }

        if (forcedKill) {
            const char msg[] = "[VxM] QEMU was forcefully terminated.\n";
            write(STDOUT_FILENO, msg, sizeof(msg) - 1);
        }

        // QEMU has exited, now supervisor can exit safely
        if (WIFEXITED(qemuStatus)) {
            _exit(WEXITSTATUS(qemuStatus));
        }
        if (WIFSIGNALED(qemuStatus)) {
            int sig = WTERMSIG(qemuStatus);
            _exit(128 + sig);
        }
        _exit(1);
    }

    // Parent process: Store supervisor PID BEFORE unblocking signals
    g_childPid = supervisorPid;

    // Unblock signals now that PID is stored
    sigprocmask(SIG_SETMASK, &oldmask, nullptr);

    int status = 0;
    while (true) {
        pid_t w = waitpid(supervisorPid, &status, 0);
        if (w == -1) {
            if (errno == EINTR) {
                continue;
            }
            std::cerr << "[Error] Parent waitpid() failed." << std::endl;
            break;
        }
        break;
    }

    // Supervisor has exited, which means QEMU has finished its shutdown.
    // Now it's safe to perform cleanup and unbind devices.
    bestEffortReleaseVfioDevices();

    // Also invoke VM cleanup for lock removal and any other non-VFIO cleanups that may be tracked in this process.
    // If the parent did not bind devices itself, this may be a no-op, but it is safe here.
    vm.cleanup();

    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }
    if (WIFSIGNALED(status)) {
        int sig = WTERMSIG(status);
        return 128 + sig;
    }
    return 1;
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
        } else if (command == "list-gpus") {
            VxM::HardwareDetection hw;
            auto gpus = hw.listGpus();
            bool jsonOutput = (argc > 2 && std::string(argv[2]) == "--json");

            if (jsonOutput) {
                std::cout << "[\n";
                for (size_t i = 0; i < gpus.size(); ++i) {
                    const auto &gpu = gpus[i];
                    std::cout << "  {\n";
                    std::cout << "    \"pci\": \"" << jsonEscape(gpu.pciAddress) << "\",\n";
                    std::cout << "    \"name\": \"" << jsonEscape(gpu.name) << "\",\n";
                    std::cout << "    \"is_boot_vga\": " << (gpu.isBootVga ? "true" : "false") << ",\n";
                    std::cout << "    \"vendor_id\": \"" << jsonEscape(gpu.vendorId) << "\",\n";
                    std::cout << "    \"device_id\": \"" << jsonEscape(gpu.deviceId) << "\",\n";
                    std::cout << "    \"needs_rom\": " << (gpu.needsRom ? "true" : "false");
                    if (gpu.needsRom && !gpu.romPath.empty()) {
                        std::cout << ",\n    \"rom_path\": \"" << jsonEscape(gpu.romPath) << "\"";
                    }
                    std::cout << "\n  }";
                    if (i < gpus.size() - 1) std::cout << ",";
                    std::cout << "\n";
                }
                std::cout << "]" << std::endl;
            } else {
                std::cout << "Available GPUs:" << std::endl;
                for (const auto &gpu : gpus) {
                    std::cout << "  " << gpu.pciAddress << " " << gpu.name;
                    if (gpu.isBootVga) {
                        std::cout << " [PRIMARY/HOST GPU - DO NOT USE FOR PASSTHROUGH]";
                    }
                    std::cout << std::endl;
                }
            }
            return 0;
        } else if (command == "fingerprint") {
            // Check for root permissions (required to read DMI UUID)
            if (geteuid() != 0) {
                std::cerr << "[Error] The 'fingerprint' command requires root permissions.\n"
                          << "        Please run: sudo vxm fingerprint" << std::endl;
                return 1;
            }

            VxM::HardwareDetection hw;
            if (argc > 2 && std::string(argv[2]) == "--json") {
                std::cout << "{\"fingerprint\": \"" << jsonEscape(hw.getSystemFingerprint()) << "\"}" << std::endl;
            } else {
                std::cout << hw.getSystemFingerprint() << std::endl;
            }
            return 0;
        } else if (command == "config") {
            if (argc >= 3 && std::string(argv[2]) == "--enable-binding") {
                // This requires root because we modify GRUB via chroot
                if (geteuid() != 0) {
                    std::cerr << "[Error] Enabling static binding requires root permissions." << std::endl;
                    std::cerr << "        Please run: sudo vxm config --enable-binding" << std::endl;
                    return 1;
                }

                if (!enableStaticBinding()) {
                    return 1;
                }
                return 0;
            }

            if (argc >= 3 && std::string(argv[2]) == "--disable-binding") {
                // This requires root because we modify GRUB via chroot
                if (geteuid() != 0) {
                    std::cerr << "[Error] Disabling static binding requires root permissions." << std::endl;
                    std::cerr << "        Please run: sudo vxm config --disable-binding" << std::endl;
                    return 1;
                }

                if (!disableStaticBinding()) {
                    return 1;
                }
                return 0;
            }

            if (argc >= 4 && std::string(argv[2]) == "--set-gpu") {
                VxM::ProfileManager pm;
                if (!pm.selectGpu(argv[3])) {
                    std::cerr << "Failed to configure GPU." << std::endl;
                    return 1;
                }
                return 0;
            }

            std::cerr << "Usage: vxm config [options]\n"
                      << "  --set-gpu <PCI_ID|NAME>   Set specific GPU for passthrough\n"
                      << "  --enable-binding          Enable Static Binding (requires root + reboot)\n"
                      << "  --disable-binding         Disable Static Binding (requires root + reboot)" << std::endl;
            return 1;

        } else if (command == "start") {
            return runStartSupervised(vm);
        } else if (command == "status") {
            bool jsonOutput = (argc > 2 && std::string(argv[2]) == "--json");
            std::string state = "stopped";
            pid_t pid = 0;
            std::string gpu;
            std::string gpuDriver;
            std::string audioDriver;

            // Check for Static Binding by reading kernel command line
            bool staticActive = cmdlineHasStaticBinding();

            // Check if VxM is running by reading the lock file
            if (std::filesystem::exists(Config::InstanceLockFile)) {
                std::ifstream lockFile(Config::InstanceLockFile);
                if (lockFile >> pid) {
                    // Check if the process is still running
                    if (kill(pid, 0) == 0) {
                        state = "running";

                        // Check which GPU is configured
                        ProfileManager pm;
                        Profile profile = pm.loadProfile();
                        gpu = profile.selectedGpuPci;
                    } else {
                        state = "stale";
                        pid = 0;
                    }
                }
            }

            // Hardware binding state (best-effort, independent of VM process)
            try {
                HardwareDetection hw;
                GpuInfo gi{};

                if (!gpu.empty()) {
                    auto m = hw.findGpuByString(gpu);
                    if (m) gi = *m;
                } else {
                    gi = hw.findPassthroughGpu();
                    gpu = gi.pciAddress;
                }

                if (!gi.pciAddress.empty()) {
                    gpuDriver = currentDriverForBdf(gi.pciAddress);
                }
                if (!gi.audioPciAddress.empty()) {
                    audioDriver = currentDriverForBdf(gi.audioPciAddress);
                }
            } catch (...) {
            }

            if (jsonOutput) {
                std::cout << "{\n";
                std::cout << "  \"state\": \"" << jsonEscape(state) << "\",\n";
                std::cout << "  \"static_binding\": " << (staticActive ? "true" : "false");
                if (pid > 0) {
                    std::cout << ",\n  \"pid\": " << pid;
                }
                if (!gpu.empty()) {
                    std::cout << ",\n  \"gpu\": \"" << jsonEscape(gpu) << "\"";
                }
                if (!gpuDriver.empty()) {
                    std::cout << ",\n  \"gpu_driver\": \"" << jsonEscape(gpuDriver) << "\"";
                }
                if (!audioDriver.empty()) {
                    std::cout << ",\n  \"gpu_audio_driver\": \"" << jsonEscape(audioDriver) << "\"";
                }
                std::cout << "\n}" << std::endl;
            } else {
                if (state == "running") {
                    std::cout << "[VxM] Status: Running (PID: " << pid << ")" << std::endl;

                    // Try to get more details from /proc
                    std::string procPath = "/proc/" + std::to_string(pid) + "/cmdline";
                    if (std::filesystem::exists(procPath)) {
                        std::ifstream cmdline(procPath, std::ios::binary);
                        std::string cmd((std::istreambuf_iterator<char>(cmdline)), std::istreambuf_iterator<char>());
                        for (char &c : cmd) {
                            if (c == '\0') c = ' ';
                        }
                        if (!cmd.empty() && cmd.find("qemu") != std::string::npos) {
                            std::cout << "      Process: qemu-system-x86_64" << std::endl;
                        }
                    }

                    if (!gpu.empty()) {
                        std::cout << "      GPU: " << gpu << std::endl;
                    }
                } else if (state == "stale") {
                    std::cout << "[VxM] Status: Stopped (stale lock file found)" << std::endl;
                    std::cout << "      Run 'vxm start' to launch a new instance" << std::endl;
                } else {
                    std::cout << "[VxM] Status: Stopped" << std::endl;
                    std::cout << "      No active VxM instance found" << std::endl;
                    std::cout << "      Run 'vxm start' to launch" << std::endl;
                }

                if (staticActive) {
                    std::cout << "      Mode: Static Binding (Enabled in Kernel Cmdline)" << std::endl;
                }

                if (!gpuDriver.empty()) {
                    std::cout << "      GPU Driver: " << gpuDriver << std::endl;
                }
                if (!audioDriver.empty()) {
                    std::cout << "      GPU Audio Driver: " << audioDriver << std::endl;
                }
            }
            return 0;
        } else if (command == "reset") {
            // If running with sudo, ensure user environment is preserved
            const char* sudoUser = std::getenv("SUDO_USER");
            const char* home = std::getenv("HOME");
            if (geteuid() == 0 && sudoUser && home && std::string(home) == "/root") {
                std::cerr << "[Error] Running as root with HOME=/root\n"
                          << "        VxM files are in the user's home directory, not /root.\n"
                          << "        Please use: sudo -E vxm reset\n"
                          << "        Or set HOME manually: sudo HOME=/home/" << sudoUser << " vxm reset" << std::endl;
                return 1;
            }

            std::cout << "WARNING: This will delete all VxM files including:\n"
                      << "  - Virtual machine disk images\n"
                      << "  - Downloaded ISOs and drivers\n"
                      << "  - Configuration files\n"
                      << "  - ROM files\n"
                      << "  - Static binding configuration (reverts GPU to host)\n\n"
                      << "Are you sure you want to continue? (yes/no): ";
            std::string response;
            std::getline(std::cin, response);
            if (response == "yes") {
                VirtualMachine::reset();

                // Clean up static binding if enabled
                // Check if currently enabled via cmdline
                bool needsCleanup = cmdlineHasStaticBinding();

                if (needsCleanup) {
                    // Attempt to disable it
                    if (geteuid() != 0) {
                         std::cerr << "[Warning] Could not remove Static Binding (requires root)." << std::endl;
                         std::cerr << "          Run 'sudo vxm config --disable-static' to finish cleanup." << std::endl;
                    } else {
                        disableStaticBinding();
                    }
                }
            } else {
                std::cout << "Reset cancelled." << std::endl;
            }
            return 0;
        } else {
            printUsage();
            return 1;
        }
    } catch (const std::exception &e) {
        // Check if --json flag was passed to determine output format
        bool jsonMode = false;
        for (int i = 1; i < argc; i++) {
            if (std::string(argv[i]) == "--json") {
                jsonMode = true;
                break;
            }
        }

        if (jsonMode) {
            std::cout << "{\"error\": \"" << jsonEscape(e.what()) << "\"}" << std::endl;
        } else {
            std::cerr << "[Fatal] " << e.what() << std::endl;
        }
        return 1;
    }

    return 0;
}
