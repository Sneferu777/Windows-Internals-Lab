#pragma once
#include "../../common/headers/nt_structs.h"

class Relocator {
public:
	// pBase is the address where your DLL is currently "stretched" in your local buffer
    	// delta is (Target_Address_In_Remote_Process - Preferred_Base_In_Headers)
	static bool FixRelocations(PBYTE pBase, PIMAGE_NT_HEADERS64 pNtHeaders, LONGLONG delta);

};
