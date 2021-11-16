#pragma once
#include <windows.h>

// words + 1
DWORD Utf8GetLength(const char* str);

// size is enough,dont +1
DWORD Utf8ToUnicode(const char* str, wchar_t* buffer);

BOOL Utf8EqualUnicode(const char* str, const wchar_t* wstr);

