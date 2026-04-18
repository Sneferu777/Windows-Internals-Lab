#pragma once
#include <windows.h>
#include <vector>
#include <cstdint>

// Status codes for better error handling in main.cpp
enum class MAP_STATUS {
    SUCCESS = 0,
    ERR_INVALID_PE,
    ERR_ALLOCATION_FAILED,
    ERR_RELOCATION_FAILED,
    ERR_IAT_FAILED,
    ERR_WRITE_FAILED
};

// The Orchestrator Function
// Takes the handle to the target process and the raw DLL bytes
MAP_STATUS ManualMap(HANDLE hTargetProc, const std::vector<uint8_t>& rawData);

/* * Pro-Tip: If you want to use the entry point later, 
 * you can return the remote address in a struct 
 */
struct MAPPED_IMAGE {
    PVOID RemoteBase;
    PVOID EntryPoint;
    SIZE_T ImageSize;
};
