#pragma once 
#include "../../common/headers/nt_structs.h"

class IATResolver {
public:
	// Resolves all imported functions for the mapped image
	static bool Resolve(PBYTE pBase, PIMAGE_NT_HEADERS64 pNtHeaders);

private:
	// Your custom GetProcAddress that walks EAT via PEB
	static FARPROC CustomGetProcAddress(const char* moduleName, const char* funcName);
	static PVOID GetModuleBasePEB(const wchar_t* moduleName);

}
