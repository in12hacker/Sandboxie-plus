#include "dll.h"
#include "stringc.h"
#include "imp.h"
DWORD Utf8GetLength(const char* str)
{
	return Utf8ToUnicode(str, NULL);
}

DWORD Utf8ToUnicode(const char* str, wchar_t* buffer)
{
	int textlen = 0;
	textlen = _MultiByteToWideChar(CP_UTF8, 0, str, -1, NULL, 0);
	if (!buffer)
		return textlen;


	memset(buffer, 0, textlen * sizeof(wchar_t));
	_MultiByteToWideChar(CP_UTF8, 0, str, -1, buffer, textlen);

	return textlen;
}

BOOL Utf8EqualUnicode(const char* str, const wchar_t* wstr)
{
	BOOL Ret = FALSE;
	DWORD WordsSize = Utf8GetLength(str);
	wchar_t* buffer = (wchar_t*)Dll_Alloc(sizeof(wchar_t) * WordsSize);

	Utf8ToUnicode(str, buffer);

	Ret = !wcscmp(buffer, wstr);

	Dll_Free(buffer);
	return Ret;
}
