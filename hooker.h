#pragma once
#include "crt.h"
#include "pe.h"

#define D(x) x

typedef struct hook_t {
	PVOID disk_function;
	PVOID mem_function;
	LPCSTR functionName;
	UNICODE_STRING dllName;
	LPCWSTR fullDllName;
	LPVOID dllBase;
} hook;

hook* findHooks(DWORD* hookNumber);
PVOID unhook(PE* memoryDll, PE* diskDll, LPCSTR functionName);
PVOID findEdrJump(PVOID pattern, size_t patternSize, PVOID expectedTarget);
PVOID hookResolver(PBYTE hookAddr);
void loadNtdll(PE* memoryDll, PE* diskDll);