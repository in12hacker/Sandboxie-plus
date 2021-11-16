#pragma once
#include <windows.h>
typedef int (*P_MultiByteToWideChar)(UINT CodePage, DWORD dwFlags, LPCCH lpMultiByteStr, int cbMultiByte, LPWSTR lpWideCharStr, int cchWideChar);
extern P_MultiByteToWideChar _MultiByteToWideChar;
