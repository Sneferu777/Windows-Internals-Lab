#include "pe_parser.h"

PEParser::PEParser(const std::vector<uint8_t>& buffer) {
    data = (PBYTE)buffer.data();
    
    // 1. Point to DOS Header (start of buffer)
    headers.dos = (PIMAGE_DOS_HEADER)data;
    
    // 2. Point to NT Headers (Start + e_lfanew)
    headers.nt = (PIMAGE_NT_HEADERS64)(data + headers.dos->e_lfanew);
    
    // 3. Point to Sections (Start of NT Headers + size of NT Headers)
    headers.sections = IMAGE_FIRST_SECTION(headers.nt);
}

bool PEParser::IsValid() {
    if (headers.dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    if (headers.nt->Signature != IMAGE_NT_SIGNATURE) return false;
    return true;
}

uint32_t PEParser::RvaToOffset(uint32_t rva) {
    auto section = headers.sections;
    
    // Loop through all sections (e.g., .text, .data, .rsrc)
    for (int i = 0; i < headers.nt->FileHeader.NumberOfSections; i++) {
        // Check if the RVA falls within this section's boundaries in memory
        if (rva >= section[i].VirtualAddress && 
            rva < (section[i].VirtualAddress + section[i].Misc.VirtualSize)) {
            
            /* The Calculation:
               Offset = RVA - (Where section starts in Memory) + (Where section starts in File)
            */
            return rva - section[i].VirtualAddress + section[i].PointerToRawData;
        }
    }
    return rva; // If it's not in a section, it's likely in the headers (RVA == Offset)
}
