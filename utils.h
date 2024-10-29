#pragma once
#include "tebpeb32.h"
#include "crt.h"
#include "pe.h"

#define D(x) x

BOOL FileExistsW(LPCWSTR szPath);
LDR_DATA_TABLE_ENTRY* getNextLoadedModule(LDR_DATA_TABLE_ENTRY* current);
PBYTE ReadFileW(LPCWSTR filename);
BOOL isHooked(LPCSTR function, PE* memoryDll, PE* diskDll);
PBYTE findDiff(PBYTE memory, PBYTE disk, DWORD length, DWORD* patchSize);
PBYTE memmem(PVOID haystack, SIZE_T haystack_len, PVOID needle, SIZE_T needle_len);
