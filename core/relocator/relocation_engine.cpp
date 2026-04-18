#include "reloc.h"

bool Relocator::FixRelocations(PBYTE pBase, PIMAGE_NT_HEADERS64 pNtHeaders, LONGLONG delta){
	// 1. Find the Relocation Directory
	auto& relocDir = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	if(relocDir.Size == 0) return true; // No Relocations Needed. (Rare for DLLs)
					    
	auto* pRelocBlock = (PIMAGE_BASE_RELOCATION) (pBase + relocDir.VirtualAddress);

	// 2. Iterate through all relocations blocks
	while (pRelocBlock->VirtualAddress != 0) {
		// Each block covers 4KB page of memory
		DWORD entryCount = (pRelocBlock->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD); 
		WORD * pRelativeInfo = (WORD *) (pRelocBlock + 1);

		for(DWORD i = 0 ; i < entryCount ; i++){

			// The upper 4 bits are the TYPE, the lower 12 bits are the OFFSET within the page
			WORD type = pRelativeInfo[i] >> 12; 
			WORD offset = pRelativeInfo[i] & 0xFFF;

			// We only care about DIR64 (Type 10) for x64 or HIGHLOW (Type 3) for x86
			if(type == IMAGE_REL_BASED_DIR64) {

				// Calculate the exact address that needs patching
				PBYTE patchAddress = pBase + pRelocBlock + offset; 

				*(LONGLONG*)patchAddress += delta;
			}

		}

		// Move to the next block
        	pRelocBlock = (PIMAGE_BASE_RELOCATION)((PBYTE)pRelocBlock + pRelocBlock->SizeOfBlock);


	}

	return true
}

