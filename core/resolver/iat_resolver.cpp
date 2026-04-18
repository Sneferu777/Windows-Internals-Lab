#include "iat_resolver.h"

// 1. Walk PEB to find a module base without calling GetModuleHandle
PVOID IATResolver::GetModuleBasePEB(const wchar_t* moduleName) {
    PPEB pPeb = (PPEB)__readgsqword(0x60);
    
    // We start at the head of the list
    PLIST_ENTRY pListHead = &pPeb->Ldr->InMemoryOrderModuleList;
    PLIST_ENTRY pCurrent = pListHead->Flink;

    while (pCurrent != pListHead) {
        // InMemoryOrderLinks is the second entry in the struct (offset 0x10 on x64)
        // We subtract that offset to get the start of the LDR_DATA_TABLE_ENTRY
        PLDR_DATA_TABLE_ENTRY pEntry = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pCurrent - 0x10);

        if (pEntry->BaseDllName.Buffer != nullptr) {
            if (_wcsicmp(pEntry->BaseDllName.Buffer, moduleName) == 0) {
                return pEntry->DllBase;
            }
        }

        pCurrent = pCurrent->Flink;
    }
    return nullptr;
}

// 2. Walk EAT to find function address (The "Custom GetProcAddress")
FARPROC IATResolver::CustomGetProcAddress(const char* moduleName, const char* funcName) {
    // Convert char to wchar for PEB lookup
    wchar_t wModule[MAX_PATH];
    mbstowcs(wModule, moduleName, MAX_PATH);
    
    PBYTE hMod = (PBYTE)GetModuleBasePEB(wModule);
    if (!hMod) hMod = (PBYTE)LoadLibraryA(moduleName); // Fallback if not loaded

    auto* pDos = (PIMAGE_DOS_HEADER)hMod;
    auto* pNt = (PIMAGE_NT_HEADERS64)(hMod + pDos->e_lfanew);
    auto* pExportDir = (PIMAGE_EXPORT_DIRECTORY)(hMod + pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD* names = (DWORD*)(hMod + pExportDir->AddressOfNames);
    DWORD* functions = (DWORD*)(hMod + pExportDir->AddressOfFunctions);
    WORD* ordinals = (WORD*)(hMod + pExportDir->AddressOfNameOrdinals);

    for (DWORD i = 0; i < pExportDir->NumberOfNames; i++) {
        if (strcmp(funcName, (char*)(hMod + names[i])) == 0) {
            return (FARPROC)(hMod + functions[ordinals[i]]);
        }
    }
    return nullptr;
}

// 3. The Main Resolver Logic
bool IATResolver::Resolve(PBYTE pLocalBase, PIMAGE_NT_HEADERS64 pNtHeaders) {
    auto& importDir = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDir.Size == 0) return true;

    auto* pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)(pLocalBase + importDir.VirtualAddress);

    while (pImportDesc->Name != 0) {
        const char* moduleName = (char*)(pLocalBase + pImportDesc->Name);
        
        // OriginalFirstThunk = ILT (Names), FirstThunk = IAT (Addresses to be overwritten)
        auto* pThunk = (PIMAGE_THUNK_DATA64)(pLocalBase + pImportDesc->FirstThunk);
        auto* pOrigThunk = (PIMAGE_THUNK_DATA64)(pLocalBase + pImportDesc->OriginalFirstThunk);

        while (pOrigThunk->u1.AddressOfData != 0) {
            if (IMAGE_SNAP_BY_ORDINAL(pOrigThunk->u1.Ordinal)) {
                // Handle Ordinal imports
                pThunk->u1.Function = (ULONGLONG)CustomGetProcAddress(moduleName, (char*)(pOrigThunk->u1.Ordinal & 0xFFFF));
            } else {
                // Handle Name imports
                auto* pImportByName = (PIMAGE_IMPORT_BY_NAME)(pLocalBase + pOrigThunk->u1.AddressOfData);
                pThunk->u1.Function = (ULONGLONG)CustomGetProcAddress(moduleName, pImportByName->Name);
            }
            pThunk++;
            pOrigThunk++;
        }
        pImportDesc++;
    }
    return true;
}
