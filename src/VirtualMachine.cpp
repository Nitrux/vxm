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
#include <unistd.h> // execvp, fork
#include <sys/wait.h>
#include <cstdlib>  // system
#include <signal.h> // kill

namespace fs = std::filesystem;

namespace VxM
{

VirtualMachine::VirtualMachine() : m_tpmPid(-1)
{
}

VirtualMachine::~VirtualMachine()
{
    cleanup();
}

void VirtualMachine::cleanup()
{
    if (m_boundDevices.empty() && m_tpmPid == -1) {
        return;
    }

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

    // Kill TPM emulator if running
    if (m_tpmPid > 0) {
        std::cout << "[VxM] Stopping TPM emulator..." << std::endl;
        kill(m_tpmPid, SIGTERM);
        waitpid(m_tpmPid, nullptr, 0);
        m_tpmPid = -1;
    }

    // Release instance lock
    releaseInstanceLock();
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

    // 6. Network backend sanity check
    std::cout << "[VxM] Network Backend: " << Config::NetworkBackend << " (SLIRP User Networking)" << std::endl;
    std::cout << "      Pros: No root setup required (bridges/taps), works out of the box" << std::endl;
    std::cout << "      Cons: Windows cannot be seen by other LAN devices (no incoming connections)" << std::endl;

    return true;
}

bool VirtualMachine::validateIommuGroup(const std::string &pciAddress) const
{
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

    fs::path iommuGroupPath = fs::read_symlink(iommuGroupLink);
    fs::path devicesInGroup = iommuGroupPath / "devices";

    // Count devices in the IOMMU group
    int deviceCount = 0;
    for (const auto &entry : fs::directory_iterator(devicesInGroup)) {
        deviceCount++;
    }

    // Ideally, the GPU and its audio function should be the only devices in the group
    // Allow up to 2 devices (GPU + audio) as acceptable
    if (deviceCount > 2) {
        std::cerr << "[Warning] IOMMU group contains " << deviceCount << " devices." << std::endl;
        std::cerr << "          Devices in group:" << std::endl;
        for (const auto &entry : fs::directory_iterator(devicesInGroup)) {
            std::cerr << "          - " << entry.path().filename().string() << std::endl;
        }
    }

    return true;
}

bool VirtualMachine::acquireInstanceLock() const
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

void VirtualMachine::releaseInstanceLock() const
{
    if (fs::exists(Config::InstanceLockFile)) {
        fs::remove(Config::InstanceLockFile);
    }
}

pid_t VirtualMachine::startTpmEmulator() const
{
    // Create TPM state directory
    fs::create_directories(Config::TpmStateDir);

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
            return pid;
        }
        usleep(100000); // 100ms
    }

    std::cerr << "[Warning] TPM socket not created after 2 seconds." << std::endl;
    return pid;
}

void VirtualMachine::reserveHugepages(uint64_t ramGb) const
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
        return;
    }

    if (currentPages >= requiredPages) {
        std::cout << "[VxM] Sufficient hugepages already allocated (" << currentPages << ")." << std::endl;
        return;
    }

    // Need to allocate more hugepages
    std::cout << "[VxM] Allocating additional hugepages..." << std::endl;

    std::ofstream hugepagesFile("/proc/sys/vm/nr_hugepages");
    if (!hugepagesFile) {
        std::cerr << "[Warning] Failed to write to /proc/sys/vm/nr_hugepages. Run as root or configure manually." << std::endl;
        std::cerr << "          To allocate hugepages manually: echo " << requiredPages << " | sudo tee /proc/sys/vm/nr_hugepages" << std::endl;
        return;
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
    } else {
        std::cerr << "[Warning] Could only allocate " << allocatedPages << " hugepages (requested " << requiredPages << ")." << std::endl;
        std::cerr << "          VM performance may be reduced. Consider freeing memory or running with fewer resources." << std::endl;
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
        }
    }

    // Download VirtIO drivers ISO if not present
    // TODO: Future enhancement - Replace fork/exec with native libcurl for better UX
    //       Current issues:
    //       - Blocking waitpid() with no timeout (hangs on slow connections)
    //       - Curl progress bar conflicts with VxM's structured output
    //       - No checksum verification or download size validation
    //       - Fallback logic only triggers on exec failure, not download failure
    //       Future implementation should use libcurl with:
    //       - Custom progress callback: "[VxM] Downloading... 245 MB / 512 MB (48%)"
    //       - Timeout support (e.g., 10 minutes max)
    //       - SHA256 checksum verification
    //       - Better error messages: "[Error] Download failed: Connection timeout after 300s"
    if (!fs::exists(Config::VirtioIso)) {
        std::cout << "[VxM] VirtIO drivers ISO not found. Downloading..." << std::endl;
        std::cout << "[VxM] Source: " << Config::VirtioDriversUrl << std::endl;

        pid_t pid = fork();
        if (pid == -1) {
            throw std::runtime_error("Failed to fork process for download.");
        } else if (pid == 0) {
            // Child process - use curl or wget
            execlp("curl", "curl", "-L", "-o",
                   Config::VirtioIso.string().c_str(),
                   Config::VirtioDriversUrl.c_str(),
                   "--progress-bar", nullptr);
            // If curl fails, try wget
            execlp("wget", "wget", "-O",
                   Config::VirtioIso.string().c_str(),
                   Config::VirtioDriversUrl.c_str(), nullptr);
            // If both fail
            std::cerr << "[Error] Failed to execute curl or wget for download" << std::endl;
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
    }

    std::cout << "\n[VxM] Crate initialization complete!" << std::endl;
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
    uint64_t ram = hw.getSafeRamAmount();

    // 2. Reserve hugepages for better performance
    reserveHugepages(ram);

    // Get or generate MAC address
    std::string mac;
    if (!profile.macAddress.empty()) {
        mac = profile.macAddress;
    } else {
        mac = hw.generateMacAddress();
        profile.macAddress = mac;
        pm.saveProfile(profile);
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
        cleanup(); // Cleanup any partially bound devices
        throw std::runtime_error("Failed to bind GPU to VFIO driver.");
    }
    m_boundDevices.push_back(gpu.pciAddress);

    if (!audioManager.bindToVfio()) {
        std::cerr << "[Warning] Failed to bind GPU Audio to VFIO (Audio might fail)." << std::endl;
    } else {
        m_boundDevices.push_back(gpu.audioPciAddress);
    }

    InputManager inputMgr;
    auto inputDevices = inputMgr.detectDevices();

    std::cout << "[VxM] Input Devices Detected:" << std::endl;
    for (const auto &dev : inputDevices) {
        std::cout << "      " << (dev.type == "keyboard" ? "[KBD]" : "[MSE]") << " " << dev.path << std::endl;
    }

    if (inputDevices.empty()) {
        std::cerr << "[Warning] No input devices found. You will have no control over the VM!" << std::endl;
    }

    // 4. Start TPM 2.0 emulator for Windows 11 compatibility
    m_tpmPid = startTpmEmulator();
    if (m_tpmPid < 0) {
        std::cerr << "[Warning] Failed to start TPM emulator. Windows 11 may not install." << std::endl;
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
    // sockets=1,cores=X,threads=2
    std::string smpArg = std::to_string(cpu.allocatedCores * cpu.threadsPerCore) + 
                         ",sockets=1,cores=" + std::to_string(cpu.allocatedCores) + 
                         ",threads=" + std::to_string(cpu.threadsPerCore);
    args.push_back("-smp"); args.push_back(smpArg);

    // Memory with hugepages
    args.push_back("-m"); args.push_back(std::to_string(ram) + "G");
    args.push_back("-mem-prealloc");
    args.push_back("-mem-path"); args.push_back("/dev/hugepages");

    // Firmware (OVMF)
    args.push_back("-drive");
    args.push_back("if=pflash,format=raw,readonly=on,file=" + Config::OvmfCodePath.string());
    args.push_back("-drive");
    args.push_back("if=pflash,format=raw,file=" + Config::OvmfVarsPath.string());

    // VFIO Passthrough (The "Metal" part)
    args.push_back("-device");
    args.push_back("ioh3420,id=root_port1,chassis=0,slot=0,bus=pcie.0");

    // GPU with optional ROM file for reset bug
    args.push_back("-device");
    std::string gpuDeviceArg = "vfio-pci,host=" + gpu.pciAddress + ",id=hostdev1,bus=root_port1,addr=0x00,multifunction=on";
    if (gpu.needsRom && !gpu.romPath.empty()) {
        gpuDeviceArg += ",romfile=" + gpu.romPath;
    }
    args.push_back(gpuDeviceArg);

    args.push_back("-device");
    args.push_back("vfio-pci,host=" + gpu.audioPciAddress + ",id=hostdev2,bus=root_port1,addr=0x00.1");

    // Disks
    args.push_back("-device"); args.push_back("virtio-scsi-pci,id=scsi0");
    args.push_back("-drive");
    args.push_back("if=none,id=disk0,cache=none,format=raw,aio=native,file=" + Config::WindowsImage.string());
    args.push_back("-device"); args.push_back("virtio-blk-pci,drive=disk0");

    // ISOs for installation
    args.push_back("-drive");
    args.push_back("file=" + Config::WindowsIso.string() + ",media=cdrom,index=0");
    args.push_back("-drive");
    args.push_back("file=" + Config::VirtioIso.string() + ",media=cdrom,index=1");

    // Network (SLIRP user networking - no root required)
    args.push_back("-netdev");
    args.push_back(Config::NetworkBackend + ",id=network0");
    args.push_back("-device");
    args.push_back("virtio-net,netdev=network0,mac=" + mac);

    // TPM 2.0 device for Windows 11 compatibility
    if (m_tpmPid > 0 && fs::exists(Config::TpmSocketPath)) {
        args.push_back("-chardev");
        args.push_back("socket,id=chrtpm,path=" + Config::TpmSocketPath.string());
        args.push_back("-tpmdev");
        args.push_back("emulator,id=tpm0,chardev=chrtpm");
        args.push_back("-device");
        args.push_back("tpm-tis,tpmdev=tpm0");
    }

    // Audio backend configuration (PulseAudio/PipeWire)
    args.push_back("-audiodev");
    args.push_back(Config::AudioBackend + ",id=snd0");
    args.push_back("-device");
    args.push_back("ich9-intel-hda");
    args.push_back("-device");
    args.push_back("hda-duplex,audiodev=snd0");

    // Input passthrough using evdev
    if (!inputDevices.empty()) {
        auto inputArgs = inputMgr.generateQemuArgs(inputDevices);
        args.insert(args.end(), inputArgs.begin(), inputArgs.end());
    } else {
        // Fallback to USB tablet if no input devices detected
        args.push_back("-device"); args.push_back("nec-usb-xhci,id=xhci");
        args.push_back("-device"); args.push_back("usb-tablet,bus=xhci.0");
    }

    // Display output (VNC on port 5900)
    args.push_back("-vnc"); args.push_back(":0");

    // Execute
    std::cout << "[VxM] Igniting..." << std::endl;

    // prepare argv for execvp
    std::vector<char*> argv;
    for (const auto &arg : args) {
        argv.push_back(const_cast<char*>(arg.c_str()));
    }
    argv.push_back(nullptr);

    execvp(argv[0], argv.data());

    // If we reach here, exec failed
    std::cerr << "[Error] Failed to start QEMU execution." << std::endl;
    exit(1);
}

} // namespace VxM
