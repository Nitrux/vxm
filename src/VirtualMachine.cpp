/*
 * Copyright (C) 2026 Nitrux Latinoamericana S.C.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "VirtualMachine.h"
#include "HardwareDetection.h"
#include "ProfileManager.h"
#include "DeviceManager.h"
#include "InputManager.h"
#include "Config.h"

#include <iostream>
#include <filesystem>
#include <sstream>
#include <fstream>
#include <unistd.h> // execvp, fork, chown
#include <sys/wait.h>
#include <sys/stat.h> // lchown
#include <pwd.h>    // getpwnam
#include <cstdlib>  // system
#include <cctype>   // isdigit
#include <signal.h> // kill
#include <cerrno>   // errno
#include <cstring>  // strerror

namespace fs = std::filesystem;

namespace VxM
{

VirtualMachine::VirtualMachine()
    : m_tpmPid(-1)
    , m_ddcEnabled(false)
    , m_ddcMonitor()
    , m_ddcHostInput(0x0F)
    , m_originalHugepages(0)
    , m_hugepagesModified(false)
{
}

VirtualMachine::~VirtualMachine()
{
    cleanup();
}

// Helper to fix file ownership when running as root via sudo
void VirtualMachine::fixFileOwnership(const std::filesystem::path& path) const
{
    const char* sudoUser = std::getenv("SUDO_USER");
    if (!sudoUser || !fs::exists(path)) {
        return;
    }

    // Convert username to UID/GID
    struct passwd* pwd = getpwnam(sudoUser);
    if (!pwd) {
        std::cerr << "[Warning] Failed to lookup user " << sudoUser << std::endl;
        return;
    }

    uid_t uid = pwd->pw_uid;
    gid_t gid = pwd->pw_gid;

    // Recursively chown if directory, single chown if file
    if (fs::is_directory(path)) {
        for (const auto& entry : fs::recursive_directory_iterator(path, fs::directory_options::skip_permission_denied)) {
            // Use lchown to not follow symlinks (security best practice)
            if (lchown(entry.path().c_str(), uid, gid) != 0) {
                std::cerr << "[Warning] Failed to chown " << entry.path() << ": " << strerror(errno) << std::endl;
            }
        }
    }

    // Always chown the path itself (whether file or directory)
    if (lchown(path.c_str(), uid, gid) != 0) {
        std::cerr << "[Warning] Failed to chown " << path << ": " << strerror(errno) << std::endl;
    }
}

void VirtualMachine::cleanup()
{
    // Switch monitor back to host input if DDC/CI was enabled
    if (m_ddcEnabled && !m_ddcMonitor.empty()) {
        std::cout << "[VxM] Switching monitor back to host input..." << std::endl;
        switchMonitorInput(m_ddcMonitor, m_ddcHostInput);
    }

    // STATE RECOVERY:
    // If we are the Parent process cleaning up after the Child (QEMU) exited,
    // our in-memory state (m_tpmPid, etc.) is empty because setup happened in the Child.
    // We try to recover state from the .runtime_state file.
    std::string savedGpuBdf, savedAudioBdf;
    if (m_tpmPid == -1 && !m_hugepagesModified) {
        fs::path statePath = Config::VxmDir / ".runtime_state";
        if (fs::exists(statePath)) {
            std::ifstream stateFile(statePath);
            uint64_t savedHugepages = 0;
            std::string dummyLine;
            std::getline(stateFile, dummyLine); // Read TPM PID (first line)
            stateFile.seekg(0); // Reset to beginning
            if (stateFile >> m_tpmPid >> savedHugepages) {
                std::getline(stateFile, savedGpuBdf); // Consume newline
                std::getline(stateFile, savedGpuBdf); // GPU BDF
                std::getline(stateFile, savedAudioBdf); // Audio BDF

                if (savedHugepages > 0) {
                    m_originalHugepages = savedHugepages;
                    m_hugepagesModified = true;
                }
            }
            stateFile.close();
            // Remove the file now that we've claimed the state
            fs::remove(statePath);
        }
    }

    // Release instance lock FIRST - must always happen regardless of state
    releaseInstanceLock();

    if (m_boundDevices.empty() && m_tpmPid == -1 && !m_hugepagesModified) {
        return;
    }

    // Note: GPU cleanup is primarily handled by main.cpp's bestEffortReleaseVfioDevices()
    // but we keep this here for completeness if running in-process.
    if (!m_boundDevices.empty()) {
        std::cout << "[VxM] Cleaning up bound devices..." << std::endl;
        for (const auto &pciAddress : m_boundDevices) {
            try {
                DeviceManager dm(pciAddress);
                if (dm.isBoundToVfio()) {
                    dm.rebindToHost();
                    std::cout << "[VxM] Released " << pciAddress << std::endl;
                }
            } catch (const std::exception &e) {
                std::cerr << "[Warning] Failed to release " << pciAddress << ": " << e.what() << std::endl;
            }
        }
        m_boundDevices.clear();
    }

    // Kill TPM emulator if running
    if (m_tpmPid > 0) {
        std::cout << "[VxM] Stopping TPM emulator (PID " << m_tpmPid << ")..." << std::endl;
        if (kill(m_tpmPid, SIGTERM) == 0) {
            waitpid(m_tpmPid, nullptr, 0);
        } else {
             std::cerr << "[Warning] Failed to stop TPM emulator: " << strerror(errno) << std::endl;
        }
        m_tpmPid = -1;
    }

    // Restore hugepages to original value if we modified them
    if (m_hugepagesModified) {
        std::cout << "[VxM] Restoring hugepages to original value (" << m_originalHugepages << ")..." << std::endl;
        std::ofstream hugepagesFile("/proc/sys/vm/nr_hugepages");
        if (hugepagesFile) {
            hugepagesFile << m_originalHugepages;
            hugepagesFile.close();
            std::cout << "[VxM] Hugepages restored." << std::endl;
        } else {
            std::cerr << "[Warning] Failed to restore hugepages. They will remain at current allocation." << std::endl;
        }
        m_hugepagesModified = false;
    }
}

bool VirtualMachine::checkRequirements() const
{
    // 1. Find and validate OVMF firmware paths
    std::cout << "[VxM] Searching for OVMF firmware files..." << std::endl;
    if (!Config::findOvmfPaths()) {
        std::cerr << "[Error] OVMF firmware files not found." << std::endl;
        std::cerr << "        Searched paths:" << std::endl;
        std::cerr << "        CODE: ";
        for (const auto &path : Config::OvmfCodeSearchPaths) {
            std::cerr << path << " ";
        }
        std::cerr << std::endl;
        std::cerr << "        VARS: ";
        for (const auto &path : Config::OvmfVarsSearchPaths) {
            std::cerr << path << " ";
        }
        std::cerr << std::endl;
        std::cerr << std::endl;
        std::cerr << "        NOTE: Some distributions use different paths:" << std::endl;
        std::cerr << "              - /usr/share/OVMF/ (all caps directory)" << std::endl;
        std::cerr << "              - /usr/share/ovmf/ (lowercase directory)" << std::endl;
        std::cerr << "              - /usr/share/edk2/ovmf/ (EDK2 structure)" << std::endl;
        std::cerr << "              This is the #1 reason QEMU fails to start." << std::endl;
        return false;
    }
    std::cout << "[VxM] Found OVMF CODE: " << Config::OvmfCodePath << std::endl;
    std::cout << "[VxM] Found OVMF VARS: " << Config::OvmfVarsTemplatePath << std::endl;

    // 2. Check Windows ISO
    if (!fs::exists(Config::WindowsIso)) {
        std::cerr << "[Error] Windows ISO not found at: " << Config::WindowsIso << std::endl;
        return false;
    }

    // 3. Check VirtIO ISO
    if (!fs::exists(Config::VirtioIso)) {
        std::cerr << "[Error] VirtIO ISO not found at: " << Config::VirtioIso << std::endl;
        return false;
    }

    // 4. Check IOMMU groups
    if (!fs::exists("/sys/kernel/iommu_groups")) {
        std::cerr << "[Error] IOMMU not enabled in kernel." << std::endl;
        std::cerr << "        Enable VT-d (Intel) or AMD-Vi (AMD) in BIOS." << std::endl;
        return false;
    }

    // 5. Validate IOMMU group isolation for GPU
    std::cout << "[VxM] Validating GPU IOMMU isolation..." << std::endl;
    HardwareDetection hw;
    ProfileManager pm;
    Profile profile = pm.loadProfile();
    GpuInfo gpu;

    try {
        if (!profile.selectedGpuPci.empty()) {
            auto manualGpu = hw.findGpuByString(profile.selectedGpuPci);
            if (manualGpu) {
                gpu = *manualGpu;
            } else {
                gpu = hw.findPassthroughGpu();
            }
        } else {
            gpu = hw.findPassthroughGpu();
        }

        if (!validateIommuGroup(gpu.pciAddress)) {
            std::cerr << "[Error] GPU is not in an isolated IOMMU group." << std::endl;
            std::cerr << "        Passthrough may fail or require additional devices to be passed through." << std::endl;
            return false;
        }
    } catch (const std::exception &e) {
        std::cerr << "[Error] Failed to validate GPU: " << e.what() << std::endl;
        return false;
    }

    return true;
}

bool VirtualMachine::validateIommuGroup(const std::string &pciAddress) const
{
    try {
        // Find the IOMMU group for this device
        std::string fullAddress = pciAddress;
        if (fullAddress.find(':') != std::string::npos && fullAddress.length() < 10) {
            fullAddress = "0000:" + fullAddress;
        }

        fs::path devicePath = fs::path("/sys/bus/pci/devices") / fullAddress;
        fs::path iommuGroupLink = devicePath / "iommu_group";

        if (!fs::exists(iommuGroupLink)) {
            std::cerr << "[Error] Device " << pciAddress << " has no IOMMU group." << std::endl;
            return false;
        }

        // read_symlink returns a relative path, resolve it to absolute path
        fs::path iommuGroupPath = fs::canonical(iommuGroupLink);
        fs::path devicesInGroup = iommuGroupPath / "devices";

        // Count devices in the IOMMU group
        int deviceCount = 0;
        for (const auto &entry : fs::directory_iterator(devicesInGroup)) {
            deviceCount++;
        }

        // Allow up to 4 devices (VGA + Audio + USB-C + Serial on modern cards)
        if (deviceCount > 4) {
            std::cerr << "[Error] IOMMU group contains " << deviceCount << " devices (expected 1-4)." << std::endl;
            std::cerr << "        Devices in group:" << std::endl;
            for (const auto &entry : fs::directory_iterator(devicesInGroup)) {
                std::cerr << "        - " << entry.path().filename().string() << std::endl;
            }
            std::cerr << std::endl;
            std::cerr << "        This GPU is NOT properly isolated for passthrough." << std::endl;
            std::cerr << "        You may need to enable ACS override patches in the kernel." << std::endl;
            return false;
        }

        return true;
    } catch (const fs::filesystem_error &e) {
        std::cerr << "[Error] Failed to resolve IOMMU group path: " << e.what() << std::endl;
        return false;
    } catch (const std::exception &e) {
        std::cerr << "[Error] IOMMU validation failed: " << e.what() << std::endl;
        return false;
    }
}

bool VirtualMachine::acquireInstanceLock()
{
    // Check if lock file exists
    if (fs::exists(Config::InstanceLockFile)) {
        // Read PID from lock file
        std::ifstream lockFile(Config::InstanceLockFile);
        pid_t existingPid = 0;
        if (lockFile >> existingPid) {
            // Check if process is still running
            if (kill(existingPid, 0) == 0) {
                std::cerr << "[Error] Another VxM instance is already running (PID: " << existingPid << ")." << std::endl;
                std::cerr << "        Running multiple instances can cause system instability or crashes." << std::endl;
                std::cerr << "        If you're sure no instance is running, remove: " << Config::InstanceLockFile << std::endl;
                return false;
            } else {
                // Stale lock file, remove it
                std::cout << "[VxM] Removing stale lock file..." << std::endl;
                fs::remove(Config::InstanceLockFile);
            }
        }
    }

    // Create lock file with current PID
    std::ofstream lockFile(Config::InstanceLockFile);
    if (!lockFile) {
        std::cerr << "[Error] Failed to create instance lock file." << std::endl;
        return false;
    }
    lockFile << getpid();
    lockFile.close();

    return true;
}

void VirtualMachine::releaseInstanceLock()
{
    if (fs::exists(Config::InstanceLockFile)) {
        fs::remove(Config::InstanceLockFile);
    }
}

pid_t VirtualMachine::startTpmEmulator()
{
    // Create TPM state directory
    fs::create_directories(Config::TpmStateDir);
    fixFileOwnership(Config::TpmStateDir);

    // Remove old socket if it exists
    if (fs::exists(Config::TpmSocketPath)) {
        fs::remove(Config::TpmSocketPath);
    }

    std::cout << "[VxM] Starting TPM 2.0 emulator..." << std::endl;

    pid_t pid = fork();
    if (pid == -1) {
        std::cerr << "[Error] Failed to fork for TPM emulator." << std::endl;
        return -1;
    } else if (pid == 0) {
        // Child process - start swtpm
        execlp("swtpm", "swtpm", "socket",
               "--tpmstate", ("dir=" + Config::TpmStateDir.string()).c_str(),
               "--ctrl", ("type=unixio,path=" + Config::TpmSocketPath.string()).c_str(),
               "--tpm2",
               "--log", "level=20",
               nullptr);
        // If execlp returns, it failed
        std::cerr << "[Error] Failed to execute swtpm. Is it installed?" << std::endl;
        exit(1);
    }

    // Parent process - wait a moment for socket to be created
    for (int i = 0; i < 20; i++) {
        if (fs::exists(Config::TpmSocketPath)) {
            std::cout << "[VxM] TPM emulator started (PID: " << pid << ")." << std::endl;

            // Fix ownership of files created by swtpm (socket, etc)
            usleep(100000); // give it a moment
            fixFileOwnership(Config::TpmStateDir);

            return pid;
        }
        usleep(100000); // 100ms
    }

    std::cerr << "[Warning] TPM socket not created after 2 seconds." << std::endl;
    return pid;
}

bool VirtualMachine::reserveHugepages(uint64_t ramGb)
{
    // Calculate required 2MB hugepages
    // RAM in GB -> MB -> number of 2MB pages
    uint64_t ramMb = ramGb * 1024;
    uint64_t requiredPages = ramMb / 2;

    std::cout << "[VxM] Reserving " << requiredPages << " hugepages (2MB each)..." << std::endl;

    // Check current hugepages
    std::ifstream meminfoFile("/proc/meminfo");
    std::string line;
    uint64_t currentPages = 0;
    bool foundHugepages = false;

    while (std::getline(meminfoFile, line)) {
        if (line.find("HugePages_Total:") == 0) {
            std::stringstream ss(line);
            std::string label;
            ss >> label >> currentPages;
            foundHugepages = true;
            break;
        }
    }
    meminfoFile.close();

    if (!foundHugepages) {
        std::cerr << "[Warning] Could not detect hugepages in /proc/meminfo." << std::endl;
        std::cerr << "          Falling back to standard memory allocation." << std::endl;
        return false;
    }

    // Save original hugepage count for cleanup
    m_originalHugepages = currentPages;

    if (currentPages >= requiredPages) {
        std::cout << "[VxM] Sufficient hugepages already allocated (" << currentPages << ")." << std::endl;
        return true;
    }

    // Need to allocate more hugepages
    std::cout << "[VxM] Allocating additional hugepages..." << std::endl;

    std::ofstream hugepagesFile("/proc/sys/vm/nr_hugepages");
    if (!hugepagesFile) {
        std::cerr << "[Warning] Failed to write to /proc/sys/vm/nr_hugepages." << std::endl;
        std::cerr << "          Falling back to standard memory allocation." << std::endl;
        return false;
    }

    hugepagesFile << requiredPages;
    hugepagesFile.close();

    // Verify allocation
    std::ifstream verifyFile("/proc/meminfo");
    uint64_t allocatedPages = 0;
    while (std::getline(verifyFile, line)) {
        if (line.find("HugePages_Total:") == 0) {
            std::stringstream ss(line);
            std::string label;
            ss >> label >> allocatedPages;
            break;
        }
    }

    if (allocatedPages >= requiredPages) {
        std::cout << "[VxM] Successfully allocated " << allocatedPages << " hugepages." << std::endl;
        m_hugepagesModified = true;
        return true;
    } else {
        // CRITICAL FIX: If we can't allocate enough hugepages, fail gracefully
        // instead of passing -mem-prealloc/-mem-path which would crash QEMU
        std::cerr << "[Warning] Could only allocate " << allocatedPages << " hugepages (requested " << requiredPages << ")." << std::endl;
        std::cerr << "          This is likely due to memory fragmentation." << std::endl;
        std::cerr << "          Falling back to standard memory allocation (slower but functional)." << std::endl;

        // Still mark as modified if we changed anything (for cleanup)
        if (allocatedPages > currentPages) {
            m_hugepagesModified = true;
        }

        return false;
    }
}

void VirtualMachine::initializeCrate()
{
    // Create directories
    fs::create_directories(Config::ImageDir);
    fs::create_directories(Config::IsoDir);
    fs::create_directories(Config::RomsDir);
    fs::create_directories(Config::TpmStateDir);

    // Create C: Drive using fork/exec to avoid command injection
    if (!fs::exists(Config::WindowsImage)) {
        std::cout << "[VxM] Creating C: Drive (" << Config::DiskSizeGb << "GB)..." << std::endl;

        pid_t pid = fork();
        if (pid == -1) {
            throw std::runtime_error("Failed to fork process.");
        } else if (pid == 0) {
            // Child process
            std::string sizeArg = std::to_string(Config::DiskSizeGb) + "G";
            execlp("qemu-img", "qemu-img", "create", "-f", "raw",
                   "-o", "preallocation=full",
                   Config::WindowsImage.string().c_str(),
                   sizeArg.c_str(), nullptr);
            // If execlp returns, it failed
            std::cerr << "[Error] Failed to execute qemu-img" << std::endl;
            exit(1);
        } else {
            // Parent process
            int status;
            waitpid(pid, &status, 0);
            if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
                throw std::runtime_error("Failed to create disk image.");
            }
            fixFileOwnership(Config::WindowsImage);
        }
    }

    // Download VirtIO drivers ISO if not present
    if (!fs::exists(Config::VirtioIso)) {
        std::cout << "[VxM] VirtIO drivers ISO not found. Downloading..." << std::endl;
        std::cout << "[VxM] Source: " << Config::VirtioDriversUrl << std::endl;

        // Check for curl or wget before forking
        bool hasCurl = (std::system("command -v curl >/dev/null 2>&1") == 0);
        bool hasWget = (std::system("command -v wget >/dev/null 2>&1") == 0);

        if (!hasCurl && !hasWget) {
            std::cerr << "[Error] Neither 'curl' nor 'wget' found. Please install one of them:" << std::endl;
            throw std::runtime_error("No download tool available (curl/wget).");
        }

        pid_t pid = fork();
        if (pid == -1) {
            throw std::runtime_error("Failed to fork process for download.");
        } else if (pid == 0) {
            // Child process - prefer curl, fallback to wget
            if (hasCurl) {
                execlp("curl", "curl", "-L", "-o",
                       Config::VirtioIso.string().c_str(),
                       Config::VirtioDriversUrl.c_str(),
                       "--progress-bar", nullptr);
            }
            if (hasWget) {
                execlp("wget", "wget", "-O",
                       Config::VirtioIso.string().c_str(),
                       Config::VirtioDriversUrl.c_str(), nullptr);
            }
            exit(1);
        } else {
            // Parent process
            int status;
            waitpid(pid, &status, 0);
            if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
                std::cerr << "[Warning] Failed to download VirtIO drivers automatically." << std::endl;
                std::cerr << "          Please download manually from:" << std::endl;
                std::cerr << "          " << Config::VirtioDriversUrl << std::endl;
                std::cerr << "          And place it at: " << Config::VirtioIso << std::endl;
            } else {
                std::cout << "[VxM] VirtIO drivers downloaded successfully." << std::endl;
            }
        }
    }

    // Check for Windows ISO and provide guidance
    if (!fs::exists(Config::WindowsIso)) {
        std::cout << "\n[VxM] Windows ISO not found." << std::endl;
        std::cout << "      Please obtain a Windows installation ISO and place it at:" << std::endl;
        std::cout << "      " << Config::WindowsIso << std::endl;
        std::cout << "\n      You can download Windows 11 from:" << std::endl;
        std::cout << "      https://www.microsoft.com/software-download/windows11" << std::endl;
        std::cout << "\n      For Windows 10:" << std::endl;
        std::cout << "      https://www.microsoft.com/software-download/windows10ISO" << std::endl;
        
        std::cout << "\n      [Tip] For better VM performance, consider using a playbook to" << std::endl;
        std::cout << "            debloat Windows, such as:" << std::endl;
        std::cout << "            - AtlasOS: https://atlasos.net" << std::endl;
        std::cout << "            - ReviOS:  https://revi.cc" << std::endl;
    }

    // Provide guidance about GPU ROM files for reset bug
    std::cout << "\n[VxM] Note: If you have an AMD Polaris or Vega GPU, you may need a patched ROM file." << std::endl;
    std::cout << "      ROM files should be placed in: " << Config::RomsDir << std::endl;
    std::cout << "      Named as: <device_id>.rom (e.g., 0x67df.rom for RX 580)" << std::endl;
    std::cout << "      VxM will automatically detect and warn if your GPU requires a ROM file.\n" << std::endl;

    // Initialize OVMF variables file if it doesn't exist
    if (!fs::exists(Config::OvmfVarsPath)) {
        std::cout << "[VxM] Initializing UEFI variables..." << std::endl;

        // Need to find OVMF paths first
        if (!Config::findOvmfPaths()) {
            throw std::runtime_error("Cannot initialize OVMF variables: firmware files not found.");
        }

        fs::copy_file(Config::OvmfVarsTemplatePath, Config::OvmfVarsPath);
        std::cout << "[VxM] UEFI variables initialized from: " << Config::OvmfVarsTemplatePath.filename() << std::endl;
        fixFileOwnership(Config::OvmfVarsPath);
    }

    // Fix ownership of all VxM directories if running as root
    std::vector<fs::path> dirsToFix = {
        Config::VxmDir,
        Config::ImageDir,
        Config::IsoDir,
        Config::RomsDir,
        Config::TpmStateDir
    };

    for (const auto& dir : dirsToFix) {
        fixFileOwnership(dir);
    }

    std::cout << "\n[VxM] Storage initialization complete!" << std::endl;
}

void VirtualMachine::start()
{
    // 1. Acquire instance lock to prevent concurrent VMs
    if (!acquireInstanceLock()) {
        throw std::runtime_error("Failed to acquire instance lock. Another VM may be running.");
    }

    // Detect Hardware Profile
    HardwareDetection hw;
    ProfileManager pm;
    Profile profile = pm.loadProfile();
    GpuInfo gpu;

    if (!profile.selectedGpuPci.empty()) {
        // User has a specific profile preference
        auto manualGpu = hw.findGpuByString(profile.selectedGpuPci);
        if (manualGpu) {
            gpu = *manualGpu;
            std::cout << "[VxM] Using configured GPU: " << gpu.pciAddress << std::endl;
        } else {
            std::cerr << "[Error] Configured GPU (" << profile.selectedGpuPci << ") not found! Falling back to detection." << std::endl;
            gpu = hw.findPassthroughGpu(); // Fallback
        }
    } else {
        // No profile, use auto-detection
        gpu = hw.findPassthroughGpu();
    }
    CpuInfo cpu = hw.detectCpuTopology();
    uint64_t ram = hw.getSafeRamAmount(profile.maxRam);

    // 2. Reserve hugepages for better performance
    bool useHugepages = reserveHugepages(ram);

    // CRITICAL: Write initial state file NOW to ensure cleanup can happen even if we fail later.
    // This protects against hugepage leaks if GPU binding or TPM startup fails.
    fs::path statePath = Config::VxmDir / ".runtime_state";
    {
        std::ofstream stateFile(statePath);
        if (stateFile) {
            stateFile << "-1\n"; // TPM PID (not started yet)
            stateFile << (m_hugepagesModified ? m_originalHugepages : 0) << "\n";
            stateFile << "\n"; // GPU BDF (not bound yet)
            stateFile << "\n"; // Audio BDF (not bound yet)
            stateFile.close();
        }
    }

    // Get or generate MAC address
    std::string mac;
    if (!profile.macAddress.empty()) {
        mac = profile.macAddress;
    } else {
        mac = hw.generateMacAddress();
        profile.macAddress = mac;
        pm.saveProfile(profile);
        fixFileOwnership(fs::path(Config::HomeDir) / ".config" / "vxm" / "vxm.conf");
    }

    std::cout << "[VxM] Hardware Profile:" << std::endl;
    std::cout << "      GPU Bus: " << gpu.pciAddress << std::endl;
    std::cout << "      GPU ID: " << gpu.vendorId << ":" << gpu.deviceId << std::endl;
    std::cout << "      CPU: " << cpu.allocatedCores << " Cores" << std::endl;
    std::cout << "      RAM: " << ram << " GB" << std::endl;

    // 3. Check for GPU ROM requirements (reset bug)
    if (gpu.needsRom) {
        if (gpu.romPath.empty()) {
            std::cerr << "\n[Warning] Your GPU (" << gpu.vendorId << ":" << gpu.deviceId << ") may require a patched ROM file." << std::endl;
            std::cerr << "          AMD Polaris/Vega cards often suffer from the 'reset bug'." << std::endl;
            std::cerr << "          If the VM fails to start or the host hangs, you need to:" << std::endl;
            std::cerr << "          1. Extract your GPU's ROM: sudo cat /sys/bus/pci/devices/0000:" << gpu.pciAddress << "/rom > ~/VxM/roms/" << gpu.deviceId << ".rom" << std::endl;
            std::cerr << "          2. Patch the ROM using rom-parser or similar tools" << std::endl;
            std::cerr << "          3. Place the patched ROM at: ~/VxM/roms/" << gpu.deviceId << ".rom" << std::endl;
            std::cerr << "\n          Proceeding without ROM file (may cause instability)...\n" << std::endl;
        } else {
            std::cout << "      GPU ROM: " << gpu.romPath << std::endl;
        }
    }

    DeviceManager gpuManager(gpu.pciAddress);
    DeviceManager audioManager(gpu.audioPciAddress);

    if (!gpuManager.bindToVfio()) {
        // Offer static binding as a fallback for laptops/hybrid graphics (only if TTY available)
        if (isatty(STDIN_FILENO)) {
            std::cout << "\n[VxM] Troubleshooting: Laptop / Hybrid Graphics Detected?" << std::endl;
            std::cout << "      On some laptops (Optimus/Muxless), the GPU cannot be detached at runtime." << std::endl;
            std::cout << "      We can enable 'Static Binding' to seize the GPU at boot time instead." << std::endl;
            std::cout << "      (This disables the dGPU for the host OS completely)." << std::endl;
            std::cout << "\n      Would you like to enable Static Binding for the next boot? [y/N]: ";

            std::string answer;
            std::getline(std::cin, answer);

            if (answer == "y" || answer == "Y") {
                std::cout << "[VxM] Enabling Static Binding via overlayroot-chroot..." << std::endl;

                std::string cmd = "overlayroot-chroot /bin/sh -c \""
                                  "mount -t devtmpfs dev /dev && "
                                  "mount -t auto $(findfs LABEL=NX_VAR_LIB) /var/lib && "
                                  "if ! grep -q 'vxm.static_bind=1' /etc/default/grub; then "
                                  "sed -i 's/^GRUB_CMDLINE_LINUX_DEFAULT=[\"\x27]/&vxm.static_bind=1 /' /etc/default/grub; "
                                  "fi && "
                                  "update-grub && "
                                  "update-initramfs -u && "
                                  "sync && "
                                  "umount /dev /var/lib\"";

                int ret = std::system(cmd.c_str());
                if (ret == 0) {
                    std::cout << "\n[VxM] Static Binding ENABLED." << std::endl;
                    std::cout << "\n      Please REBOOT your system." << std::endl;
                    std::cout << "      The GPU will be isolated automatically during the next boot." << std::endl;
                    cleanup();
                    exit(0);
                } else {
                    std::cerr << "[Error] Failed to enable static binding. Command returned: " << ret << std::endl;
                }
            }
        }  // Close isatty check

        cleanup();
        throw std::runtime_error("Failed to bind GPU to VFIO driver.");
    }
    m_boundDevices.push_back(gpu.pciAddress);

    if (!audioManager.bindToVfio()) {
        std::cerr << "[Error] Failed to bind GPU Audio to VFIO." << std::endl;
        std::cerr << "        The Audio device shares the IOMMU group with the GPU." << std::endl;
        std::cerr << "        The VM cannot start unless ALL devices in the group are isolated." << std::endl;
        cleanup();
        throw std::runtime_error("Failed to bind GPU Audio.");
    } else {
        m_boundDevices.push_back(gpu.audioPciAddress);
    }

    InputManager inputMgr;
    auto inputDevices = inputMgr.detectDevices();

    std::cout << "[VxM] Input Devices Detected:" << std::endl;
    for (const auto &dev : inputDevices) {
        std::cout << "      " << (dev.type == InputType::Keyboard ? "[KBD]" : "[MSE]") << " " << dev.path << std::endl;
    }

    if (inputDevices.empty()) {
        std::cerr << "[Warning] No input devices found. You will have no control over the VM!" << std::endl;
    }

    // 4. Start TPM 2.0 emulator for Windows 11 compatibility
    m_tpmPid = startTpmEmulator();
    if (m_tpmPid < 0) {
        std::cerr << "[Warning] Failed to start TPM emulator. Windows 11 may not install." << std::endl;
    }

    // STATE PERSISTENCE:
    // We are about to exec() into QEMU, which will wipe this process memory.
    // We must save critical cleanup state (TPM PID, Hugepages, GPU BDF) to disk so the Parent
    // process can read it when QEMU exits.
    {
        std::ofstream stateFile(statePath);
        if (stateFile) {
            stateFile << m_tpmPid << "\n";
            stateFile << (m_hugepagesModified ? m_originalHugepages : 0) << "\n";
            stateFile << gpu.pciAddress << "\n";
            stateFile << gpu.audioPciAddress << "\n";
            stateFile.close();
        } else {
            std::cerr << "[Warning] Failed to save runtime state. Cleanup might be incomplete." << std::endl;
        }
    }

    // Construct QEMU arguments
    std::vector<std::string> args;
    args.push_back("qemu-system-x86_64");

    // Machine Type
    args.push_back("-name"); args.push_back(Config::VmName);
    args.push_back("-enable-kvm");
    args.push_back("-machine"); args.push_back("q35,accel=kvm,kernel_irqchip=on");

    // CPU
    std::string cpuArg = "host,kvm=off,hv_vendor_id=1234567890ab,hv_vapic,hv_time,hv_relaxed,hv_spinlocks=0x1fff";
    if (cpu.isRyzen) {
        cpuArg += ",+topoext,+ibpb"; // AMD specific flags
    }
    args.push_back("-cpu"); args.push_back(cpuArg);

    // SMP
    std::string smpArg = std::to_string(cpu.allocatedCores * cpu.threadsPerCore) + 
                         ",sockets=1,cores=" + std::to_string(cpu.allocatedCores) + 
                         ",threads=" + std::to_string(cpu.threadsPerCore);
    args.push_back("-smp"); args.push_back(smpArg);

    // Memory (with hugepages if available, standard otherwise)
    args.push_back("-m"); args.push_back(std::to_string(ram) + "G");
    if (useHugepages) {
        args.push_back("-mem-prealloc");
        args.push_back("-mem-path"); args.push_back("/dev/hugepages");
    }

    // Firmware (OVMF)
    args.push_back("-drive");
    args.push_back("if=pflash,format=raw,readonly=on,file=" + Config::OvmfCodePath.string());
    args.push_back("-drive");
    args.push_back("if=pflash,format=raw,file=" + Config::OvmfVarsPath.string());

    // VFIO Passthrough (The "Metal" part)
    args.push_back("-device");
    args.push_back("ioh3420,id=root_port1,chassis=0,slot=0,bus=pcie.0");

    // GPU
    args.push_back("-device");
    std::string gpuDeviceArg = "vfio-pci,host=" + gpu.pciAddress + ",id=hostdev1,bus=root_port1,addr=0x00,multifunction=on";
    if (gpu.needsRom && !gpu.romPath.empty()) {
        gpuDeviceArg += ",romfile=" + gpu.romPath;
    }
    args.push_back(gpuDeviceArg);

    args.push_back("-device");
    args.push_back("vfio-pci,host=" + gpu.audioPciAddress + ",id=hostdev2,bus=root_port1,addr=0x00.1");

    // Disk (using virtio-blk, no SCSI controller needed)
    args.push_back("-drive");
    args.push_back("if=none,id=disk0,cache=none,format=raw,aio=native,file=" + Config::WindowsImage.string());
    args.push_back("-device"); args.push_back("virtio-blk-pci,drive=disk0");

    // ISOs
    args.push_back("-drive");
    args.push_back("file=" + Config::WindowsIso.string() + ",media=cdrom,index=0");
    args.push_back("-drive");
    args.push_back("file=" + Config::VirtioIso.string() + ",media=cdrom,index=1");

    // Network
    args.push_back("-netdev");
    args.push_back(Config::NetworkBackend + ",id=network0");
    args.push_back("-device");
    args.push_back("virtio-net,netdev=network0,mac=" + mac);

    // TPM 2.0
    if (m_tpmPid > 0 && fs::exists(Config::TpmSocketPath)) {
        args.push_back("-chardev");
        args.push_back("socket,id=chrtpm,path=" + Config::TpmSocketPath.string());
        args.push_back("-tpmdev");
        args.push_back("emulator,id=tpm0,chardev=chrtpm");
        args.push_back("-device");
        args.push_back("tpm-tis,tpmdev=tpm0");
    }

    // Audio
    args.push_back("-audiodev");
    args.push_back(Config::AudioBackend + ",id=snd0");
    args.push_back("-device");
    args.push_back("ich9-intel-hda");
    args.push_back("-device");
    args.push_back("hda-duplex,audiodev=snd0");

    // USB Controller (Always present)
    args.push_back("-device"); args.push_back("nec-usb-xhci,id=xhci");

    // Input passthrough
    if (!inputDevices.empty()) {
        auto inputArgs = inputMgr.generateQemuArgs(inputDevices);
        args.insert(args.end(), inputArgs.begin(), inputArgs.end());
    } else {
        // Fallback to USB tablet
        args.push_back("-device"); args.push_back("usb-tablet,bus=xhci.0");
    }

    // Looking Glass
    if (profile.lookingGlassEnabled) {
        if (detectLookingGlass()) {
            if (fs::exists("/dev/kvmfr0")) {
                std::cout << "[VxM] Looking Glass: Using kvmfr kernel module" << std::endl;
                fixFileOwnership("/dev/kvmfr0");

                args.push_back("-object");
                args.push_back("memory-backend-file,id=ivshmem,share=on,mem-path=/dev/kvmfr0,size=" +
                               std::to_string(Config::LookingGlassShmSizeMb) + "M");
                args.push_back("-device");
                args.push_back("ivshmem-plain,memdev=ivshmem,bus=pcie.0");
            } else if (createLookingGlassShm(Config::LookingGlassShmSizeMb)) {
                std::cout << "[VxM] Looking Glass: Using shared memory file" << std::endl;
                args.push_back("-object");
                args.push_back("memory-backend-file,id=ivshmem,share=on,mem-path=" +
                               Config::LookingGlassShmPath.string() + ",size=" +
                               std::to_string(Config::LookingGlassShmSizeMb) + "M");
                args.push_back("-device");
                args.push_back("ivshmem-plain,memdev=ivshmem,bus=pcie.0");
            }
        } else {
            std::cerr << "[Warning] Looking Glass enabled but no IVSHMEM support available." << std::endl;
        }
    }

    // Display
    args.push_back("-vnc"); args.push_back(":0");

    // DDC/CI
    if (profile.ddcEnabled && !profile.ddcMonitor.empty()) {
        std::cout << "[VxM] DDC/CI: Switching monitor to guest input..." << std::endl;
        if (switchMonitorInput(profile.ddcMonitor, profile.ddcGuestInput)) {
            m_ddcEnabled = true;
            m_ddcMonitor = profile.ddcMonitor;
            m_ddcHostInput = profile.ddcHostInput;
        }
    }

    // Execute QEMU
    std::cout << "[VxM] Igniting..." << std::endl;
    std::cout << "      QEMU starting with PID: " << getpid() << std::endl;

    std::vector<char*> argv;
    for (const auto &arg : args) {
        argv.push_back(const_cast<char*>(arg.c_str()));
    }
    argv.push_back(nullptr);

    // CRITICAL SECURITY: Drop root privileges before executing QEMU
    // Running QEMU as root is a severe security risk. If a VM escape occurs,
    // the attacker immediately gains root access to the host.
    const char* sudoUser = std::getenv("SUDO_USER");
    if (geteuid() == 0 && sudoUser && sudoUser[0] != '\0') {
        // Get the original user's UID and GID
        struct passwd* pwd = getpwnam(sudoUser);
        if (!pwd) {
            std::cerr << "[Error] Failed to lookup user " << sudoUser << " for privilege drop." << std::endl;
            throw std::runtime_error("Cannot drop privileges - user lookup failed");
        }

        uid_t targetUid = pwd->pw_uid;
        gid_t targetGid = pwd->pw_gid;

        // AUDIO FIX: Set up PulseAudio environment before dropping privileges
        // This ensures QEMU can connect to the user's PulseAudio server
        std::string runtimeDir = std::string("/run/user/") + std::to_string(targetUid);
        std::string pulseSocket = runtimeDir + "/pulse/native";

        setenv("XDG_RUNTIME_DIR", runtimeDir.c_str(), 1);
        setenv("PULSE_SERVER", ("unix:" + pulseSocket).c_str(), 1);

        // Drop privileges: set GID first, then UID (order matters!)
        if (setgid(targetGid) != 0) {
            std::cerr << "[Error] Failed to drop GID: " << strerror(errno) << std::endl;
            throw std::runtime_error("Failed to drop group privileges");
        }
        if (setuid(targetUid) != 0) {
            std::cerr << "[Error] Failed to drop UID: " << strerror(errno) << std::endl;
            throw std::runtime_error("Failed to drop user privileges");
        }

        std::cout << "[VxM] Dropped privileges: QEMU will run as user " << sudoUser
                  << " (UID=" << targetUid << ", GID=" << targetGid << ")" << std::endl;

        // Verify we can't regain root
        if (setuid(0) == 0) {
            std::cerr << "[Error] Privilege drop failed - still able to become root!" << std::endl;
            throw std::runtime_error("Incomplete privilege drop detected");
        }
    } else if (geteuid() == 0) {
        std::cerr << "[Warning] Running as root without SUDO_USER set - QEMU will run with root privileges!" << std::endl;
        std::cerr << "          This is a SEVERE SECURITY RISK. Please run with: sudo -E vxm start" << std::endl;
    }

    execvp(argv[0], argv.data());

    std::cerr << "[Error] Failed to execute QEMU: " << strerror(errno) << std::endl;
    throw std::runtime_error("Failed to execute QEMU");
}

bool VirtualMachine::detectLookingGlass() const
{
    if (fs::exists("/dev/kvmfr0")) return true;
    int ret = std::system("modprobe kvmfr 2>/dev/null");
    if (ret == 0 && fs::exists("/dev/kvmfr0")) return true;
    if (fs::exists("/dev/shm")) return true;
    return false;
}

bool VirtualMachine::createLookingGlassShm(uint64_t sizeMb) const
{
    uint64_t sizeBytes = sizeMb * 1024 * 1024;

    if (fs::exists(Config::LookingGlassShmPath)) {
        fs::remove(Config::LookingGlassShmPath);
    }

    std::ofstream shmFile(Config::LookingGlassShmPath, std::ios::binary);
    if (!shmFile) {
        std::cerr << "[Error] Failed to create Looking Glass shared memory file." << std::endl;
        return false;
    }
    shmFile.close();

    if (truncate(Config::LookingGlassShmPath.c_str(), sizeBytes) != 0) {
        std::cerr << "[Error] Failed to resize Looking Glass shared memory." << std::endl;
        return false;
    }

    fs::permissions(Config::LookingGlassShmPath,
                    fs::perms::owner_read | fs::perms::owner_write |
                    fs::perms::group_read | fs::perms::group_write);

    fixFileOwnership(Config::LookingGlassShmPath);

    std::cout << "[VxM] Looking Glass shared memory created: " << Config::LookingGlassShmPath
              << " (" << sizeMb << " MB)" << std::endl;
    return true;
}

bool VirtualMachine::switchMonitorInput(const std::string &monitor, uint8_t inputValue) const
{
    if (std::system("command -v ddcutil >/dev/null 2>&1") != 0) {
        std::cerr << "[Warning] ddcutil not found. Cannot switch monitor input." << std::endl;
        return false;
    }

    std::stringstream cmd;
    cmd << "ddcutil ";
    if (!monitor.empty() && std::isdigit(static_cast<unsigned char>(monitor[0]))) {
        cmd << "--bus " << monitor;
    } else if (!monitor.empty()) {
        cmd << "--display " << monitor;
    }

    cmd << " setvcp 0x" << std::hex << static_cast<int>(Config::DdcInputSourceVcp)
        << " 0x" << std::hex << static_cast<int>(inputValue)
        << " 2>/dev/null";

    int ret = std::system(cmd.str().c_str());
    if (ret != 0) {
        std::cerr << "[Warning] Failed to switch monitor input via DDC/CI." << std::endl;
        return false;
    }

    return true;
}

void VirtualMachine::reset()
{
    std::cout << "[VxM] Resetting VxM..." << std::endl;

    std::vector<fs::path> pathsToRemove = {
        Config::VxmDir,
        fs::path(Config::HomeDir) / ".config" / "vxm"
    };

    bool anyErrors = false;
    bool permissionError = false;

    for (const auto &path : pathsToRemove) {
        if (fs::exists(path)) {
            try {
                if (fs::is_directory(path)) {
                    std::cout << "[VxM] Removing directory: " << path << std::endl;
                    fs::remove_all(path);
                } else {
                    std::cout << "[VxM] Removing file: " << path << std::endl;
                    fs::remove(path);
                }
            } catch (const std::exception &e) {
                std::string errorMsg = e.what();
                std::cerr << "[Error] Failed to remove " << path << ": " << errorMsg << std::endl;
                if (errorMsg.find("Permission denied") != std::string::npos ||
                    errorMsg.find("permission") != std::string::npos) {
                    permissionError = true;
                }
                anyErrors = true;
            }
        }
    }

    if (!anyErrors) {
        std::cout << "[VxM] Reset complete. All VxM files have been removed." << std::endl;
    } else {
        if (permissionError) {
            std::cerr << "[VxM] Reset failed due to permission errors.\n"
                      << "      Some files may have been created by root during 'vxm start'.\n"
                      << "      Please run: sudo vxm reset" << std::endl;
        } else {
            std::cerr << "[VxM] Reset completed with errors. Some files may not have been removed." << std::endl;
        }
    }
}

} // namespace VxM
