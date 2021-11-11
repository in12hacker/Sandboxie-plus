
#include "dll.h"

#include <windows.h>
#include <stdlib.h>
typedef BOOL (*P_GetPhysicallyInstalledSystemMemory)(
	PULONGLONG TotalMemoryInKilobytes);

static P_GetPhysicallyInstalledSystemMemory        __sys_GetPhysicallyInstalledSystemMemory = NULL;
extern cJSON* g_deviceConfig;
_FX BOOL Kernel32_GetPhysicallyInstalledSystemMemory(PULONGLONG pTotalMemoryInKilobytes)
{
	cJSON* memSizeItem = cJSON_GetObjectItem(g_deviceConfig, "memsize");
	char* sTotalMemoryInKilobytes = cJSON_GetStringValue(memSizeItem);
	ULONGLONG TotalMemoryInKilobytes = (ULONGLONG)_atoi64(sTotalMemoryInKilobytes);
	if (TotalMemoryInKilobytes)
		*pTotalMemoryInKilobytes = TotalMemoryInKilobytes;
	else
		return __sys_GetPhysicallyInstalledSystemMemory(pTotalMemoryInKilobytes);
	return TRUE;
}
_FX BOOLEAN Kernel32_Init(HMODULE module)
{
	P_GetPhysicallyInstalledSystemMemory GetPhysicallyInstalledSystemMemory;
	GetPhysicallyInstalledSystemMemory = (P_GetPhysicallyInstalledSystemMemory)GetProcAddress(module, "GetPhysicallyInstalledSystemMemory");
	if (GetPhysicallyInstalledSystemMemory)
		SBIEDLL_HOOK(Kernel32_, GetPhysicallyInstalledSystemMemory);
	
	return TRUE;
}
