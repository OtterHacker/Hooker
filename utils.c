#include "utils.h"


BOOL FileExistsW(LPCWSTR szPath)
{
	DWORD dwAttrib = GetFileAttributesW(szPath);

	return (dwAttrib != INVALID_FILE_ATTRIBUTES && !(dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}

PBYTE ReadFileW(LPCWSTR filename) {
	HANDLE hFile = CreateFileW(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		return NULL;
	}
	DWORD fileSize = GetFileSize(hFile, NULL);
	DWORD sizeRead = 0;
	PBYTE content = (PBYTE)malloc(fileSize);
	DWORD result = ReadFile(hFile, content, fileSize, &sizeRead, NULL);
	if (!result || sizeRead != fileSize) {
		D(printf("[x] Error during %ls file read\n", filename));
		free(content);
		content = NULL;
	}
	CloseHandle(hFile);
	return content;
}

LDR_DATA_TABLE_ENTRY* getNextLoadedModule(LDR_DATA_TABLE_ENTRY* current) {
	PEB64* peb = (PEB64*)__readgsqword(0x60);
	LDR_DATA_TABLE_ENTRY* start = (LDR_DATA_TABLE_ENTRY*)peb->Ldr->InLoadOrderModuleList.Flink;
	if (current == NULL) {
		return start;
	}
	LDR_DATA_TABLE_ENTRY* next = (LDR_DATA_TABLE_ENTRY*)current->InLoadOrderLinks.Flink;
	if (start == next) {
		return NULL;
	}
	return next;
}

PBYTE findDiff(PBYTE memory, PBYTE disk, DWORD length, DWORD* patchSize) {
	if (patchSize != NULL) {
		*patchSize = 0;
	}
	for (int i = 0; i < length; i++) {
		DWORD a = memory[i];
		DWORD b = disk[i];
		if (memory[i] != disk[i]) {
			while (patchSize != NULL && memory[i + *patchSize] != disk[i + *patchSize]) {
				*patchSize += 1;
			}
			return &memory[i];
		}
	}
	return NULL;
}

BOOL isHooked(LPCSTR function, PE* memoryDll, PE* diskDll) {
	PBYTE functionMemory = (PBYTE)PERva2Addr(memoryDll, PEGetFunctionRvaFromName(memoryDll, function));
	PBYTE functionDisk = (PBYTE)PERva2Addr(diskDll, PEGetFunctionRvaFromName(memoryDll, function));
	return findDiff(functionMemory, functionDisk, 0x18, NULL) != NULL;
}

PBYTE memmem(PVOID haystack, SIZE_T haystack_len, PVOID needle, SIZE_T needle_len)
{
	if (!haystack)
		return NULL;
	if (!haystack_len)
		return NULL;
	if (!needle)
		return NULL;
	if (!needle_len)
		return NULL;
	PBYTE h = haystack;
	while (haystack_len >= needle_len)
	{
		if (!RtlCompareMemory(h, needle, needle_len))
			return h;
		++h;
		--haystack_len;
	}
	return NULL;
}