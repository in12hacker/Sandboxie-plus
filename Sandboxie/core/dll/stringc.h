#pragma once
#include <windows.h>

// words + 1
DWORD Utf8GetLength(const char* str);

// size is enough,dont +1
DWORD Utf8ToUnicode(const char* str, wchar_t* buffer);

// utf8 == unicode
BOOL Utf8EqualUnicode(const char* str, const wchar_t* wstr);

// unicode >> utf8 size
DWORD Unicode2Utf8Size(const wchar_t* wstr);

// unicode >> utf8
BOOL Unicode2Utf8(const wchar_t* wstr, char* str);

