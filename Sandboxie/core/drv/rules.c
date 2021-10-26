#include "rules.h"

BOOLEAN Rules_Base_Match(const void* Src, const void* Dest)
{
	return RULES_TRUE;
}

BOOLEAN Rules_Reg_Match(const void* Src, const void* Dest)
{
	return RULES_TRUE;
}

cJSON* Key_ReplaceOpenPathMatch(cJSON* regrules, WCHAR* dst)
{
	INT  flag = 0;
	int len = cJSON_GetArraySize(regrules);
	for (int i = 0; i < len; i++)
	{
		cJSON* regrule = cJSON_GetArrayItem(regrules, i);
		cJSON* path = cJSON_GetObjectItem(regrule, "path");
		char* openPath = cJSON_GetStringValue(path);
		if (openPath)
		{
			ANSI_STRING ascii;
			UNICODE_STRING uni;
			RtlInitAnsiString(&ascii, openPath);
			RtlAnsiStringToUnicodeString(&uni, &ascii, TRUE);
			if (wcsstr(dst, uni.Buffer))
				return regrule;
			RtlFreeUnicodeString(&uni);

		}
	}
	return NULL;
}
