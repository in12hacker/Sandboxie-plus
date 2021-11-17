#pragma once
#include <windows.h>
typedef int (*P_MultiByteToWideChar)(UINT CodePage, DWORD dwFlags, LPCCH lpMultiByteStr
	, int cbMultiByte, LPWSTR lpWideCharStr, int cchWideChar);
typedef int (*P_WideCharToMultiByte)(UINT CodePage, DWORD dwFlags, LPCWCH lpWideCharStr
	, int cchWideChar, LPSTR lpMultiByteStr, int cbMultiByte, LPCCH lpDefaultChar, LPBOOL lpUsedDefaultChar);

extern P_MultiByteToWideChar _MultiByteToWideChar;
extern P_WideCharToMultiByte _WideCharToMultiByte;
