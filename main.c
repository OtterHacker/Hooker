#include "main.h"
#include "utils.h"
#include "hooker.h"

int main(void) {
	DWORD hookNumber = 0;
	hook* hooks = findHooks(&hookNumber);


	//char hookedFunctions[2][32] = {"NtProtectVirtualMemory", "NtMapViewOfSection"};
	//int numberHookedFunctions = 2;
	//PE* memoryDll = calloc(1, sizeof(PE));
	//PE* diskDll = calloc(1, sizeof(PE));
	//loadNtdll(&memoryDll, &diskDll);
    //
	//for (int i = 0; i < numberHookedFunctions; i++) {
	//	printf("[+] Unhooking %s\n", hookedFunctions[i]);
	//	unhook(memoryDll, diskDll, "NtProtectVirtualMemory");
	//}
    //
	return 0;
}