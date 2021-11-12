#include "dll.h"

#include <windows.h>
#include <stdlib.h>
typedef HANDLE(*P_FindFirstFileW)(LPCWSTR lpFileName,LPWIN32_FIND_DATAW lpFindFileData);

static P_FindFirstFileW        __sys__FindFirstFileW = NULL;
extern cJSON* g_deviceConfig;
_FX BOOL KernelBase__FindFirstFileW(LPCWSTR lpFileName, LPWIN32_FIND_DATAW lpFindFileData)
{
	cJSON* jsonItem = cJSON_GetObjectItem(g_deviceConfig, "running_dir_create_time");
	char* sJsonValue = cJSON_GetStringValue(jsonItem);
	ULONGLONG ullJsonValue = (ULONGLONG)_atoi64(sJsonValue);
	__sys__FindFirstFileW(lpFileName, lpFindFileData);
	if (ullJsonValue)
		lpFindFileData->ftCreationTime = *(FILETIME*)&ullJsonValue;
	return TRUE;
}
_FX BOOLEAN KernelBase_Init(HMODULE module)
{
	P_FindFirstFileW _FindFirstFileW;
	_FindFirstFileW = (P_FindFirstFileW)GetProcAddress(module, "FindFirstFileW");
	if (GetPhysicallyInstalledSystemMemory)
		SBIEDLL_HOOK(KernelBase_, _FindFirstFileW);

	return TRUE;
}
