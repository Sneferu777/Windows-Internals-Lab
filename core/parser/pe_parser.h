#pragma once
#include "../../common/headers/nt_structs.h"
#include <vector>
#include <cstdint>

class PEParser {
public:
    // Constructor takes the raw bytes of the DLL
    PEParser(const std::vector<uint8_t>& buffer);

    // Basic Validation
    bool IsValid();

    // The Magic: Translates file address to memory address
    uint32_t RvaToOffset(uint32_t rva);

    // Getters for our Mapper to use later
    PIMAGE_NT_HEADERS64 GetNtHeaders() { return headers.nt; }
    PIMAGE_SECTION_HEADER GetSections() { return headers.sections; }
    PBYTE GetRawData() { return data; }

private:
    PBYTE data;
    PE_HEADERS headers;
};
