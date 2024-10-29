#include "pe.h"

IMAGE_SECTION_HEADER* getSectionForRva(PE* pe, DWORD rva) {
	IMAGE_SECTION_HEADER* sectionHeader = pe->sectionHeader;
	for (DWORD section = 0; section < pe->ntHeader->FileHeader.NumberOfSections; section++) {
		DWORD sectionVirtualStart = sectionHeader[section].VirtualAddress;
		DWORD sectionVirtualEnd = sectionVirtualStart + sectionHeader[section].Misc.VirtualSize;
		if ( sectionVirtualStart <= rva && rva < sectionVirtualEnd) {
			return &sectionHeader[section];
		}
	}
	return NULL;
}

PVOID PERva2Addr(PE* pe, DWORD rva) {
	if (pe->memoryMapped) {
		return (PBYTE)(pe->dosHeader) + rva;
	}
	IMAGE_SECTION_HEADER* section = getSectionForRva(pe, rva);
	if (section == NULL) {
		return NULL;
	}
	return (PBYTE)(pe->dosHeader) + section->PointerToRawData + (rva - section->VirtualAddress);
}

PVOID PEFunction2Addr(PE* pe, LPCSTR functionName) {
	DWORD functionRva = PEGetFunctionRvaFromName(pe, functionName);
	return PERva2Addr(pe, functionRva);
}

VOID parseRelocations(PE* pe) {
	// Get the first realocation block
	IMAGE_BASE_RELOCATION* relocationAddressStart = PERva2Addr(pe, pe->dataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	IMAGE_BASE_RELOCATION* relocationAddressCurrent = PERva2Addr(pe, pe->dataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	DWORD relocationSize = 16;
	pe->relocations = (PERelocation *)calloc(relocationSize, sizeof(PERelocation));
	pe->numberOfRelocations = 0;
	if (pe->relocations == NULL) {
		D(printf("[x] Error during relocations memory allocation\n"));
		ExitProcess(-1);
	}

	// Loop through the relocation block. 
	// The loop end when the next pointer is out of the relocation section.
	while ((SIZE_T)relocationAddressCurrent < (SIZE_T)relocationAddressStart + pe->dataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
		IMAGE_RELOCATION_ENTRY* relocationEntry = (IMAGE_RELOCATION_ENTRY*)&(relocationAddressCurrent[1]);
		IMAGE_BASE_RELOCATION* nextRelocationBlockPtr = (IMAGE_BASE_RELOCATION*)(((PBYTE)relocationAddressCurrent) + relocationAddressCurrent->SizeOfBlock);
		// Loop through the relocation entries
		while ((PBYTE)relocationEntry < (PBYTE)nextRelocationBlockPtr) {
			// Check if the allocated size for the pe->rellocations is enough
			// Realloc otherwise
			if (pe->numberOfRelocations >= relocationSize) {
				relocationSize *= 2;
				PVOID *peRelocations = pe->relocations;
				pe->relocations = (PERelocation *)realloc(peRelocations, relocationSize * sizeof(PERelocation));
				if (pe->relocations == NULL) {
					D(printf("[x] Error during relocation memory reallocation\n"));
					ExitProcess(-1);
				}
			}

			// Get the current realocation block information
			pe->relocations[pe->numberOfRelocations].RVA = relocationAddressCurrent->VirtualAddress + relocationEntry->Offset;
			pe->relocations[pe->numberOfRelocations].Type = relocationEntry->Type;
			pe->numberOfRelocations += 1;

			relocationEntry++;

		}
		// Jump on the next brelocation block
		relocationAddressCurrent = (IMAGE_BASE_RELOCATION*)((PBYTE)relocationAddressCurrent + relocationAddressCurrent->SizeOfBlock);
	}

	// Resize the relocation array
	PVOID peRelocations = pe->relocations;
	pe->relocations = (PERelocation *)realloc(peRelocations, pe->numberOfRelocations * sizeof(PERelocation));
	if (pe->relocations == NULL) {
		D(printf("[x] Error during final relocations memory reallocation\n"));
	}
}

VOID PERebase(PE* pe, LPVOID newImage) {
	DWORD* relocDwAddress;
	QWORD* relocQwAddress;
	if (pe->memoryMapped) {
		D(printf("[-] Impossible to rebase memory mapped PE"));
		return;
	}
	parseRelocations(pe);
	if (pe->relocations == NULL) {
		D(printf("[x] The relocation table is empty\n"));
		ExitProcess(-1);
	}
	PVOID oldBaseAddress = pe->dosHeader;
	pe->baseAddress = newImage;
	for (DWORD i = 0; i < pe->numberOfRelocations; i++) {
		if (pe->relocations[i].Type == IMAGE_REL_BASED_ABSOLUTE) {

		}
		else if (pe->relocations[i].Type == IMAGE_REL_BASED_HIGHLOW) {
			// 32bits address
			DWORD* currentRelocationAddress = (DWORD*)PERva2Addr(pe, pe->relocations[i].RVA);
			DWORD offset = (PBYTE)newImage - (PBYTE)currentRelocationAddress;
			pe->relocations[i].RVA += offset;

			//relocDwAddress = (DWORD*)PERva2Addr(pe, pe->relocations[i].RVA);
			//intptr_t relativeOffset = ((intptr_t)newImage) - ((intptr_t)oldBaseAddress);
			//*relocDwAddress += (DWORD)relativeOffset;
		}
		else if (pe->relocations[i].Type == IMAGE_REL_BASED_DIR64) {
			QWORD* currentRelocationAddress = (QWORD*)PERva2Addr(pe, pe->relocations[i].RVA);
			QWORD offset = (PBYTE)newImage - currentRelocationAddress;
			pe->relocations[i].RVA += offset;
			//relocQwAddress = (QWORD*)PERva2Addr(pe, pe->relocations[i].RVA);
			//*relocQwAddress = ((intptr_t)newImage) - ((intptr_t)oldBaseAddress);
		}
	}
}


PE* PECreate(PVOID imageBase, BOOL isMemoryMapped) {
	PE* pe = (PE*)malloc(sizeof(PE));
	if (pe == NULL) {
		D(printf("[x] Error during PE allocation\n"));
		ExitProcess(-1);
	}
	pe->memoryMapped = isMemoryMapped;
	pe->dosHeader = imageBase;
	pe->ntHeader = (IMAGE_NT_HEADERS*)((PBYTE)imageBase + pe->dosHeader->e_lfanew);
	pe->optionalHeader = &(pe->ntHeader->OptionalHeader);

	if (isMemoryMapped) {
		pe->baseAddress = imageBase;
	}
	else {
		pe->baseAddress = (PVOID)pe->optionalHeader->ImageBase;
	}

	pe->dataDirectory = pe->optionalHeader->DataDirectory;
	pe->sectionHeader = (IMAGE_SECTION_HEADER*)((PBYTE)(pe->optionalHeader) + pe->ntHeader->FileHeader.SizeOfOptionalHeader);

	DWORD exportDirectoryRVA = (DWORD)pe->dataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	if (exportDirectoryRVA == 0) {
		pe->exportDirectory = NULL;
		pe->AddressOfFunctions = NULL;
		pe->AddressOfNames = NULL;
		pe->AddressOfNameOrdinals = NULL;
		pe->NumberOfNames = 0;
	}
	else {
		pe->exportDirectory = PERva2Addr(pe, exportDirectoryRVA);
		pe->AddressOfFunctions = PERva2Addr(pe, pe->exportDirectory->AddressOfFunctions);
		pe->AddressOfNames = PERva2Addr(pe, pe->exportDirectory->AddressOfNames);
		pe->AddressOfNameOrdinals = PERva2Addr(pe, pe->exportDirectory->AddressOfNameOrdinals);
		pe->NumberOfNames = pe->exportDirectory->NumberOfNames;
	}

	pe->relocations = NULL;
	return pe;
}

DWORD PEGetFunctionRvaFromName(PE* pe, LPCSTR functionName) {
	DWORD ordinalLow = 0;
	DWORD ordinalHigh = pe->NumberOfNames;
	DWORD ordinalMedium = 0;
	LPCSTR result = NULL;

	while (ordinalHigh != ordinalLow) {
		ordinalMedium = (ordinalHigh + ordinalLow) / 2;
		result = PERva2Addr(pe, pe->AddressOfNames[ordinalMedium]);
		int state = strcmp(functionName, result);
		if (state == 0) {
			break;
		}
		else if (state > 0) {
			ordinalLow = ordinalMedium;
		}
		else if (state < 0) {
			ordinalHigh = ordinalMedium;
		}
	}

	if (strcmp(functionName, PERva2Addr(pe, pe->AddressOfNames[ordinalMedium])) == 0) {
		return pe->AddressOfFunctions[pe->AddressOfNameOrdinals[ordinalMedium]];
	}
	return 0;

}

IMAGE_SECTION_HEADER* PEGetSectionHeaderFromFunctionRva(PE* pe, DWORD functionRva) {
	for (DWORD section = 0; section < pe->ntHeader->FileHeader.NumberOfSections; section++) {
		DWORD sectionVaStart = pe->sectionHeader[section].VirtualAddress;
		DWORD sectionVaEnd = sectionVaStart + pe->sectionHeader[section].Misc.VirtualSize;
		if (sectionVaStart <= functionRva && functionRva < sectionVaEnd) {
			return (IMAGE_SECTION_HEADER*)&pe->sectionHeader[section];
		}
	}
	return NULL;
}