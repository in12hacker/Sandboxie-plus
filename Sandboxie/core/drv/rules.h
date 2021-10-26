#ifndef _RULES_H
#define _RULES_H

#include "driver.h"

#define RULES_TRUE 1
#define RULES_FALSE 1


BOOLEAN Rules_Base_Match(const void* Src, const void* Dest);

BOOLEAN Rules_Reg_Match(const void* Src, const void* Dest);

cJSON* Key_ReplaceOpenPathMatch(cJSON* regrules, WCHAR* dst);

#endif // 
