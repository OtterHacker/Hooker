#pragma once
#include "tebpeb32.h"
#include "crt.h"

#define D(x) x

typedef struct _PERelocation {
	DWORD RVA;
	WORD Type : 4;
} PERelocation;

typedef struct _IMAGE_RELOCATION_ENTRY {
	WORD Offset : 12;
	WORD Type : 4;
} IMAGE_RELOCATION_ENTRY;

typedef struct _PE {
	BOOL memoryMapped;
	IMAGE_DOS_HEADER* dosHeader;
	IMAGE_NT_HEADERS* ntHeader;
	IMAGE_OPTIONAL_HEADER* optionalHeader;
	IMAGE_DATA_DIRECTORY* dataDirectory;
	IMAGE_EXPORT_DIRECTORY* exportDirectory;
	IMAGE_SECTION_HEADER* sectionHeader;
	LPDWORD AddressOfFunctions;
	LPDWORD AddressOfNames;
	LPWORD AddressOfNameOrdinals;
	DWORD NumberOfNames;
	PERelocation* relocations;
	DWORD numberOfRelocations;
	PVOID baseAddress;
} PE;


PE* PECreate(PVOID imageBase, BOOL isMemoryMapped);
DWORD PEGetFunctionRvaFromName(PE* pe, LPCSTR functionName);
IMAGE_SECTION_HEADER* PEGetSectionHeaderFromFunctionRva(PE* pe, DWORD functionRva);
VOID PERebase(PE* pe, LPVOID newImage);
PVOID PERva2Addr(PE* pe, DWORD RVA);
PVOID PEFunction2Addr(PE* pe, LPCSTR functionName);


