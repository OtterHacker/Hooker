#include "hooker.h"
#include "utils.h"
#include "crt.h"


PVOID hookResolver(PBYTE hookAddr) {
	PBYTE destination = hookAddr;
	BOOL hasFollowedJmp = FALSE;
	while (TRUE) {
		MEMORY_BASIC_INFORMATION mbi;
		VirtualQuery(destination, &mbi, sizeof(mbi));
		if (mbi.State != MEM_COMMIT) {
			return NULL;
		}
		switch (destination[0]) {
		case 0xE9:
		{
			int diff = *((int*)(&destination[1]));
			destination = &destination[5] + diff;
			hasFollowedJmp = TRUE;
			break;
		}
		case 0xFF:
		{
			BYTE selector = destination[1];
			if (selector != 0x25) {
				return NULL;
			}
			int diff = *((int*)(&destination[2]));
			QWORD* offsetPtr = (QWORD*)((&destination[6]) + diff);
			destination = (PBYTE)*offsetPtr;
			hasFollowedJmp = TRUE;
			break;
		}
		default:
			if (!hasFollowedJmp) {
				return NULL;
			}
			else {
				return destination;
			}
		}
	}
}

PVOID findEdrJump(PVOID pattern, size_t patternSize, PVOID expectedTarget)
{
	SIZE_T haystack_len;
	PVOID haystack;
	PBYTE patternInExecutableMemory;
	MEMORY_BASIC_INFORMATION mbi = { 0 };

	for (PBYTE addr = 0; ; addr += mbi.RegionSize)
	{
		if (!VirtualQuery(addr, &mbi, sizeof(mbi))) {
			break;
		}

		if (mbi.State != MEM_COMMIT) {
			continue;
		}
		if (mbi.Protect != PAGE_EXECUTE && mbi.Protect != PAGE_EXECUTE_READ && mbi.Protect != PAGE_EXECUTE_READWRITE) {
			continue;
		}
		haystack = mbi.BaseAddress;
		haystack_len = mbi.RegionSize;
		while (haystack_len)
		{
			patternInExecutableMemory = (PBYTE)memmem(haystack, haystack_len, pattern, patternSize);
			if (!patternInExecutableMemory) {
				break;
			}
			if (hookResolver(&patternInExecutableMemory[patternSize]) == expectedTarget) {
				return patternInExecutableMemory;
			}
			haystack_len -= patternInExecutableMemory + 1 - (PBYTE)haystack;
			haystack = patternInExecutableMemory + 1;
		}
	}
	return NULL;
}

void loadNtdll(PE** memoryDll, PE** diskDll) {
	for (LDR_DATA_TABLE_ENTRY* currentModule = getNextLoadedModule(NULL); currentModule != NULL; currentModule = getNextLoadedModule(currentModule)) {
		// Retrieve the DLL path 
		WCHAR *ntdll = L"ntdll.dll";
		UNICODE_STRING* BaseDllName = (PVOID)((DWORD64)(&(currentModule->FullDllName)) + 0x10);
		if (!wcsicmp(BaseDllName->Buffer, ntdll)) {
			*memoryDll = PECreate(currentModule->DllBase, TRUE);
			if (!FileExistsW(currentModule->FullDllName.Buffer)) {
				continue;
			}
			PBYTE diskDllContent = ReadFileW(currentModule->FullDllName.Buffer);
			*diskDll = PECreate(diskDllContent, FALSE);
			PERebase(*diskDll, currentModule->DllBase);
			return;
		}
	}
}

PVOID unhook(PE* memoryDll, PE* diskDll,  LPCSTR functionName) {
	DWORD patchSize;
	PVOID functionMemory = PEFunction2Addr(memoryDll, functionName);
	PVOID functionDisk = PEFunction2Addr(diskDll, functionName);
	PBYTE startPatch = findDiff(functionMemory, functionDisk, 0x18, &patchSize);
	if (startPatch == NULL) {
		// No hook applied
		return (PVOID)functionMemory;
	}
	PVOID jump = findEdrJump((PBYTE)functionDisk + ((PBYTE)startPatch - (PBYTE)functionMemory), patchSize, (PBYTE)startPatch + patchSize);
	if (jump == NULL) {
		D(printf("[x] Impossible to find %s EDR's jump\n", functionName));
		return NULL;
	}
	return jump;
}

hook* findHooks(DWORD* hookNumber) {
	DWORD sizeHook = 16;
	DWORD hookFound = 0;
	hook* hooks = calloc(sizeHook, sizeof(hook));
	if (hooks == NULL) {
		D(printf("[+] Impossible to allocate hooks memory\n"));
		ExitProcess(-1);
	}
	// Loop through loaded modules
	for (LDR_DATA_TABLE_ENTRY* currentModule = getNextLoadedModule(NULL); currentModule != NULL; currentModule = getNextLoadedModule(currentModule)) {

		// Retrieve the DLL path 
		UNICODE_STRING* BaseDllName = (PVOID)((DWORD64)(&(currentModule->FullDllName)) + 0x10);
		if (BaseDllName->Buffer == NULL) {
			// No need to process ghost DLL
			continue;
		}

		D(printf("[+] 0x%p : %ws (%ws)\n", currentModule->DllBase, BaseDllName->Buffer, currentModule->FullDllName.Buffer));

		// Set the DLL information in an adapted structure
		PE* memoryDll = PECreate(currentModule->DllBase, TRUE);
		if (memoryDll->exportDirectory == NULL) {
			// Only process DLL exporting functions
			continue;
		}

		if (!FileExistsW(currentModule->FullDllName.Buffer)) {
			continue;
		}

		PBYTE diskDllContent = ReadFileW(currentModule->FullDllName.Buffer);
		PE* diskDll = PECreate(diskDllContent, FALSE);
		PERebase(diskDll, currentModule->DllBase);

		for (DWORD nameOrdinal = 0; nameOrdinal < diskDll->NumberOfNames; nameOrdinal++) {
			// Retrieve the function name
			LPCSTR functionName = PERva2Addr(diskDll, diskDll->AddressOfNames[nameOrdinal]);
			// Retrieve the function RVA address to find its section and verify it is a real function
			DWORD functionRvaAddress = PEGetFunctionRvaFromName(diskDll, functionName);
			IMAGE_SECTION_HEADER* sectionHeader = PEGetSectionHeaderFromFunctionRva(diskDll, functionRvaAddress);
			if ((sectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0) {
				// Only functions are processed
				continue;
			}

			PBYTE functionMemory = PEFunction2Addr(memoryDll, functionName);
			PBYTE functionDisk = PEFunction2Addr(diskDll, functionName);

			BOOL alreadyChecked = FALSE;
			for (DWORD i = 0; i < hookFound; i++) {
				if (hooks[i].mem_function == functionMemory && hooks[i].disk_function == functionDisk) {
					alreadyChecked = TRUE;
					break;
				}
			}
			if (alreadyChecked) {
				continue;
			}

			if (isHooked(functionName, memoryDll, diskDll)) {
				if (hookFound >= sizeHook) {
					sizeHook *= 2;
					PVOID _hooks = hooks;
					hooks = (hook*)realloc(hooks, sizeHook * sizeof(hook));
				}
				hooks[hookFound].disk_function = functionDisk;
				hooks[hookFound].mem_function = functionMemory;
				hooks[hookFound].functionName = functionName;
				hooks[hookFound].dllBase = currentModule->DllBase;
				hooks[hookFound].fullDllName = currentModule->FullDllName.Buffer;
				hookFound += 1;

				printf("\t[+] %s\n", functionName);
			}
		}
	}
	*hookNumber = hookFound;
	return hooks;
}