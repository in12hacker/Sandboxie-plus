#include "dll.h"

#include <windows.h>
#include <stdlib.h>
#include "stringc.h"
typedef HANDLE(*P_FindFirstFileW)(LPCWSTR lpFileName,LPWIN32_FIND_DATAW lpFindFileData);

static P_FindFirstFileW        __sys__FindFirstFileW = NULL;
extern cJSON* g_deviceConfig;
_FX HANDLE KernelBase__FindFirstFileW(LPCWSTR lpFileName, LPWIN32_FIND_DATAW lpFindFileData)
{
	cJSON* jsonItem = cJSON_GetObjectItem(g_deviceConfig, "running_dir_create_time");
	cJSON* jsonRunningPathItem = cJSON_GetObjectItem(g_deviceConfig, "running_dir_path");
	char* sJsonValue = cJSON_GetStringValue(jsonItem);
	char* sRunningPath = cJSON_GetStringValue(jsonRunningPathItem);
	ULONGLONG ullJsonValue = (ULONGLONG)_atoi64(sJsonValue);
	HANDLE Ret = __sys__FindFirstFileW(lpFileName, lpFindFileData);

	if (Utf8EqualUnicode(sRunningPath, lpFileName)
		&& Ret > 0
		&& ullJsonValue)
	{
		lpFindFileData->ftCreationTime = *(FILETIME*)&ullJsonValue;
	}
	
	return Ret;
}
_FX BOOLEAN KernelBase_Init(HMODULE module)
{
	P_FindFirstFileW _FindFirstFileW;
	_FindFirstFileW = (P_FindFirstFileW)GetProcAddress(module, "FindFirstFileW");
	if (_FindFirstFileW)
		SBIEDLL_HOOK(KernelBase_, _FindFirstFileW);

	return TRUE;
}
