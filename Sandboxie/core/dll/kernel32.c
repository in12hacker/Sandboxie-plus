#include "dll.h"

#include <windows.h>
#include <stdlib.h>
#include "imp.h"
#include "stringc.h"

extern cJSON* g_deviceConfig;

typedef BOOL (*P_GetPhysicallyInstalledSystemMemory)(
	PULONGLONG TotalMemoryInKilobytes);
typedef BOOL(*P_GetVolumeInformationA)(LPCSTR lpRootPathName,
	LPSTR lpVolumeNameBuffer, DWORD nVolumeNameSize, LPDWORD lpVolumeSerialNumber,
	LPDWORD lpMaximumComponentLength, LPDWORD lpFileSystemFlags, LPSTR lpFileSystemNameBuffer,
	DWORD nFileSystemNameSize);
typedef BOOL(*P_GetDiskFreeSpaceExW)(LPCWSTR lpDirectoryName, PULARGE_INTEGER lpFreeBytesAvailableToCaller
	, PULARGE_INTEGER lpTotalNumberOfBytes, PULARGE_INTEGER lpTotalNumberOfFreeBytes);

static P_GetPhysicallyInstalledSystemMemory        __sys_GetPhysicallyInstalledSystemMemory = NULL;
static P_GetVolumeInformationA	__sys__GetVolumeInformationA = NULL;
static P_GetDiskFreeSpaceExW	__sys__GetDiskFreeSpaceExW = NULL;


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

_FX BOOL Kernel32__GetVolumeInformationA(LPCSTR lpRootPathName, LPSTR lpVolumeNameBuffer,
	DWORD nVolumeNameSize, LPDWORD lpVolumeSerialNumber, LPDWORD lpMaximumComponentLength,
	LPDWORD lpFileSystemFlags, LPSTR lpFileSystemNameBuffer, DWORD nFileSystemNameSize)
{
	cJSON* jsonItem = cJSON_GetObjectItem(g_deviceConfig, "root_path");
	char* sJsonValue = cJSON_GetStringValue(jsonItem);
	BOOL Ret = __sys__GetVolumeInformationA(lpRootPathName, lpVolumeNameBuffer, nVolumeNameSize, lpVolumeSerialNumber, lpMaximumComponentLength, lpFileSystemFlags, lpFileSystemNameBuffer, nFileSystemNameSize);

	if (sJsonValue && lpRootPathName && !strcmp(sJsonValue, lpRootPathName))
	{
		cJSON* jsonItemVolumeName = cJSON_GetObjectItem(g_deviceConfig, "volume_name");
		cJSON* jsonItemVolumeSerialNumber = cJSON_GetObjectItem(g_deviceConfig, "volume_serial_number");
		cJSON* jsonItemFileSystemNameBuffer = cJSON_GetObjectItem(g_deviceConfig, "file_system_name");
		char* sVolumeName = cJSON_GetStringValue(jsonItemVolumeName);
		char* sVolumeSerialNumber = cJSON_GetStringValue(jsonItemVolumeSerialNumber);
		char* sFileSystemNameBuffer = cJSON_GetStringValue(jsonItemFileSystemNameBuffer);
		DWORD dwVolumeSerialNumber = atoi(sVolumeSerialNumber);
		if (sVolumeName)
		{
			if (strlen(sVolumeName) < nVolumeNameSize)
				strcpy(lpVolumeNameBuffer, sVolumeName);
			else
				strncpy(lpVolumeNameBuffer, sVolumeName, nVolumeNameSize);

			if (dwVolumeSerialNumber)
				*lpVolumeSerialNumber = dwVolumeSerialNumber;

			if (strlen(sFileSystemNameBuffer) < nFileSystemNameSize)
				strcpy(lpFileSystemNameBuffer, sFileSystemNameBuffer);
			else
				strncpy(lpFileSystemNameBuffer, sFileSystemNameBuffer, nVolumeNameSize);
		}
	}
	return Ret;

}

_FX BOOL Kernel32__GetDiskFreeSpaceExW(LPCWSTR lpDirectoryName, PULARGE_INTEGER lpFreeBytesAvailableToCaller,
	PULARGE_INTEGER lpTotalNumberOfBytes, PULARGE_INTEGER lpTotalNumberOfFreeBytes)
{
	ULONGLONG TotalSize = 0;
	char lpKeyName[MAX_PATH] = "disk_space";

	DWORD Utf8Size = Unicode2Utf8Size(lpDirectoryName);
	char* sDirectoryName = Dll_Alloc(Utf8Size);
	Unicode2Utf8(lpDirectoryName, sDirectoryName);
	strcat(lpKeyName, sDirectoryName);
	Dll_Free(sDirectoryName);

	cJSON* jsonItem = cJSON_GetObjectItem(g_deviceConfig, lpKeyName);
	if (jsonItem)
	{
		char* sJsonValue = cJSON_GetStringValue(jsonItem);
		if (sJsonValue)
		{
			TotalSize = _atoi64(sJsonValue);
		}
	}

	BOOL Ret = __sys__GetDiskFreeSpaceExW(lpDirectoryName, lpFreeBytesAvailableToCaller, lpTotalNumberOfBytes, lpTotalNumberOfFreeBytes);
	if (TotalSize)
	{
		lpTotalNumberOfBytes->QuadPart = TotalSize;
	}
	return Ret;
}

_FX BOOLEAN Kernel32_Init(HMODULE module)
{
	// imp
	_MultiByteToWideChar = (P_MultiByteToWideChar)GetProcAddress(module, "MultiByteToWideChar");
	_WideCharToMultiByte = (P_WideCharToMultiByte)GetProcAddress(module, "WideCharToMultiByte");

	P_GetPhysicallyInstalledSystemMemory GetPhysicallyInstalledSystemMemory;
	P_GetVolumeInformationA _GetVolumeInformationA;
	P_GetDiskFreeSpaceExW _GetDiskFreeSpaceExW;

	GetPhysicallyInstalledSystemMemory = (P_GetPhysicallyInstalledSystemMemory)GetProcAddress(module, "GetPhysicallyInstalledSystemMemory");
	if (GetPhysicallyInstalledSystemMemory)
		SBIEDLL_HOOK(Kernel32_, GetPhysicallyInstalledSystemMemory);
	_GetVolumeInformationA = (P_GetVolumeInformationA)GetProcAddress(module, "GetVolumeInformationA");
	if (_GetVolumeInformationA)
		SBIEDLL_HOOK(Kernel32_, _GetVolumeInformationA);
	_GetDiskFreeSpaceExW = (P_GetDiskFreeSpaceExW)GetProcAddress(module, "GetDiskFreeSpaceExW");
	if (_GetDiskFreeSpaceExW)
		SBIEDLL_HOOK(Kernel32_, _GetDiskFreeSpaceExW);

	return TRUE;
}
