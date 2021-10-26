/*
 * Copyright 2004-2020 Sandboxie Holdings, LLC 
 *
 * This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

//---------------------------------------------------------------------------
// Box Management
//---------------------------------------------------------------------------


#include "box.h"
#include "util.h"
#include "conf.h"
#include "file.h"
#include "process.h"


//---------------------------------------------------------------------------
// Functions
//---------------------------------------------------------------------------


static BOX *Box_Alloc(POOL *pool, const WCHAR *boxname, ULONG session_id);

static BOOLEAN Box_InitKeys(
    POOL *pool, BOX *box, const WCHAR *sidstring, ULONG session_id);

static BOOLEAN Box_InitConfExpandArgs(POOL *pool, BOX *box);

static BOOLEAN Box_InitPaths(POOL *pool, BOX *box);

static BOOLEAN Box_ExpandString(
    BOX *box, const WCHAR *model, const WCHAR *suffix,
    WCHAR **path, ULONG *path_len);

static BOOLEAN Box_Init_keyValue(BOX* box);

static  NTSTATUS Json_Init_Reg(cJSON* rule,BOX*box);
//---------------------------------------------------------------------------
// Json_Reg_Init
//---------------------------------------------------------------------------


_FX NTSTATUS Json_Init_Reg(cJSON* rules, BOX* box)
{
	int rulesLen = cJSON_GetArraySize(rules);
	OBJECT_ATTRIBUTES obj;
	OBJECT_ATTRIBUTES HiveFile;
	UNICODE_STRING uRegistryPath;


	UNICODE_STRING uRegDatPath;
	UNICODE_STRING uni;
	OBJECT_ATTRIBUTES objattrs;
	HANDLE handle;
	WCHAR* _HiveFileName=L"\\RegHive";
	
	
	RtlInitUnicodeString(&uni, L"\\??\\C:");
	InitializeObjectAttributes(&objattrs,
		&uni, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

	// ZwLoadKey can fail with device path if current process' devicemap is null
	// One workaround is to call ObOpenObjectByName and it will trigger devicemap
	// to be initialized. Note, Using C: is not necessary. The disk volume doesn't
	// need to be there.L"\\??\\A:" works in the tests.

	ULONG hive_path_len = box->file_path_len + wcslen(_HiveFileName) * sizeof(WCHAR);
	WCHAR* hive_path = Mem_Alloc(Driver_Pool, hive_path_len);
	if (!hive_path)
	{
		return STATUS_SUCCESS;
	}

	memcpy(hive_path,box->file_path,box->file_path_len);
	wcscat(hive_path, _HiveFileName);
	if (STATUS_SUCCESS == ObOpenObjectByName(
		&objattrs, *IoFileObjectType, KernelMode, NULL, 0, NULL, &handle))
	{
		ZwClose(handle);
	}
	RtlInitUnicodeString(&uRegistryPath, box->key_path);
	RtlInitUnicodeString(&uRegDatPath, hive_path);
	
	InitializeObjectAttributes(&obj, &uRegistryPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	InitializeObjectAttributes(&HiveFile, &uRegDatPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	
	NTSTATUS status = ZwLoadKey(&obj, &HiveFile);
	if (!NT_SUCCESS(status))
	{

		return status;
	}

	for (int i = 0; i < rulesLen; i++)
	{
		cJSON* rule = cJSON_GetArrayItem(rules, i);
		cJSON* pathObj = cJSON_GetObjectItem(rule, "path");
		cJSON* keyObj = cJSON_GetObjectItem(rule, "key");
		cJSON* valueObj = cJSON_GetObjectItem(rule, "value");
		cJSON* typeObj = cJSON_GetObjectItem(rule, "type");
		ANSI_STRING ansiPath;
		ANSI_STRING ansiKey;
		ANSI_STRING ansiValue;
		UNICODE_STRING uniPath;
		UNICODE_STRING uniKey;
		UNICODE_STRING uniValue;
		OBJECT_ATTRIBUTES target;
		HANDLE handle;
		NTSTATUS status;
		DWORD Des;
		DWORD valueSize = 0;
		unsigned long long  valueData = 0;

		if (pathObj && keyObj && valueObj && typeObj)
		{
			char* path = cJSON_GetStringValue(pathObj);
			char* key = cJSON_GetStringValue(keyObj);
			__int64 type = cJSON_GetNumber64Value(typeObj);
			if (path && key)
			{
				RtlInitAnsiString(&ansiPath, path);
				RtlAnsiStringToUnicodeString(&uniPath, &ansiPath, TRUE);
				InitializeObjectAttributes(&target, &uniPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
				status = ZwCreateKey(&handle, KEY_ALL_ACCESS, &target, 0, 0, REG_OPTION_NON_VOLATILE, &Des);
				RtlFreeUnicodeString(&uniPath);
				if (!NT_SUCCESS(status))
					return status;
				switch (type)
				{
				case REG_SZ:
				{
					char* value = cJSON_GetStringValue(valueObj);
					RtlInitAnsiString(&ansiValue, value);
					RtlAnsiStringToUnicodeString(&uniValue, &ansiValue, TRUE);
					RtlInitAnsiString(&ansiValue, key);
					RtlAnsiStringToUnicodeString(&uniKey, &ansiValue, TRUE);
					status = ZwSetValueKey(handle, &uniKey, 0, REG_BINARY, uniValue.Buffer, uniValue.Length * sizeof(WCHAR) + sizeof(WCHAR));
					RtlFreeUnicodeString(&uniValue);
					RtlFreeUnicodeString(&uniKey);
					break;
				}
				case REG_DWORD:
				{
					unsigned long data = (unsigned long)cJSON_GetNumberValue(valueObj);
					status = ZwSetValueKey(handle, &uniKey, 0, REG_BINARY, &data, sizeof(data));
					break;
				}
				case REG_QWORD:
				{
					unsigned long long data = cJSON_GetNumber64Value(valueObj);
					status = ZwSetValueKey(handle, &uniKey, 0, REG_BINARY, &data, sizeof(data));
					break;
				}
				default:
					break;
				}
				ZwClose(handle);
			}
		}
	}
	status = ZwUnloadKey(&obj);
	
	return STATUS_SUCCESS;
}

//---------------------------------------------------------------------------
// Key_GetSandboxPath2
//---------------------------------------------------------------------------

#define HEADER_USER L"\\REGISTRY\\USER\\"
#define HEADER_MACHINE L"\\REGISTRY\\MACHINE\\"
#define USERS   L"S-1-5-21"
#define CLASSES L"_Classes"
#define MAX_USER_SID_SIZE  128 //in bytes

WCHAR* Key_GetSandboxPath2(PUNICODE_STRING KeyName, BOX* box)
{

	WCHAR* targetName = NULL;
	ULONG targetFound = 0;
	ULONG nSize;

	if (KeyName)
	{
		ULONG path_len = wcslen(box->key_path);
		nSize = KeyName->Length + (path_len << 1) + (wcslen(L"\\user\\current_classes") << 1);
		targetName = (WCHAR*)ExAllocatePoolWithTag(NonPagedPool, nSize + sizeof(WCHAR), tzuk);
		if (targetName)
		{
			ULONG head_len = wcslen(HEADER_USER);
			WCHAR* temp = NULL;
			memset(targetName, 0, nSize + sizeof(WCHAR));
			wcsncpy(targetName, box->key_path, path_len);
			// starts with "\REGISTRY\USER\"
			if (!wcsncmp(KeyName->Buffer, HEADER_USER, head_len))
			{
				temp = wcsstr(&KeyName->Buffer[head_len], L"\\");
				if (temp)
				{
					// Matches "\REGISTRY\USER\S-1-5-21*\"
					if (!_wcsnicmp(&KeyName->Buffer[head_len], USERS, wcslen(USERS)))
					{
						ULONG sidSize = (ULONG)temp - (ULONG)&KeyName->Buffer[head_len];
						if (sidSize < MAX_USER_SID_SIZE)
						{
							// Matches "\REGISTRY\USER\S-1-5-21*_Classes\"
							if (!_wcsnicmp(temp - wcslen(CLASSES), L"_Classes", wcslen(CLASSES)))
							{
								wcscpy(targetName + path_len, L"\\user\\current_classes");
								path_len += wcslen(L"\\user\\current_classes");
							}
							else
							{
								wcscpy(targetName + path_len, L"\\user\\current");
								path_len += wcslen(L"\\user\\current");
							}
							wcscpy(targetName + path_len, temp);
							targetFound = 1;
						}
					}
				}
			}
			// starts with "\REGISTRY\\MACHINE\"
			else if (!_wcsnicmp(KeyName->Buffer, HEADER_MACHINE, wcslen(HEADER_MACHINE)))
			{
				wcscpy(targetName + path_len, KeyName->Buffer + 9);
				targetFound = 1;
			}

			if (!targetFound)
			{
				ExFreePoolWithTag(targetName, tzuk);
				targetName = NULL;
			}
		}
	}

	return targetName;
}

//---------------------------------------------------------------------------
// Box_Init_keyValue  初始化注册表值
//---------------------------------------------------------------------------

_FX BOOLEAN Box_Init_keyValue(BOX* box)
{
	ANSI_STRING ansi;
	UNICODE_STRING uni;
	WCHAR* target;
	if (box->js_regrules)
	{
		int relusLen = cJSON_GetArraySize(box->js_regrules);
		for (int i = 0; i < relusLen; i++)
		{
			cJSON* rule = cJSON_GetArrayItem(box->js_regrules, i);
			cJSON* path = cJSON_GetObjectItem(rule, "path");
			char* key = cJSON_GetStringValue(path);
			if (key)
			{
				RtlInitAnsiString(&ansi, key);
				RtlAnsiStringToUnicodeString(&uni, &ansi,TRUE);
				target = Key_GetSandboxPath2(&uni, box);
				RtlFreeUnicodeString(&uni);
				if (target)
				{
					RtlInitUnicodeString(&uni, target);
					RtlUnicodeStringToAnsiString(&ansi, &uni,TRUE);
					cJSON_SetValuestring(path, ansi.Buffer);
					RtlFreeAnsiString(&ansi);
				}
			}
		}
	}
	return TRUE;
}



//---------------------------------------------------------------------------
// Box_IsValidName
//---------------------------------------------------------------------------


_FX BOOLEAN Box_IsValidName(const WCHAR *name)
{
    int i;

    for (i = 0; i < BOXNAME_MAXLEN; ++i) {
        if (! name[i])
            break;
        if (name[i] >= L'0' && name[i] <= L'9')
            continue;
        if (name[i] >= L'A' && name[i] <= L'Z')
            continue;
        if (name[i] >= L'a' && name[i] <= L'z')
            continue;
        if (name[i] == L'_')
            continue;
        return FALSE;
    }
    if (i == 0 || name[i])
        return FALSE;
    return TRUE;
}


//---------------------------------------------------------------------------
// Box_Alloc
//---------------------------------------------------------------------------


_FX BOX *Box_Alloc(POOL *pool, const WCHAR *boxname, ULONG session_id)
{
    BOX *box = Mem_Alloc(pool, sizeof(BOX));
    if (! box) {

        Log_Status_Ex_Session(
            MSG_BOX_CREATE, 0x10, STATUS_INSUFFICIENT_RESOURCES,
            boxname, session_id);
        return NULL;
    }

    memzero(box, sizeof(BOX));

    wcscpy(box->name, boxname);
    box->name_len = (wcslen(box->name) + 1) * sizeof(WCHAR);

    return box;
}


//---------------------------------------------------------------------------
// Box_Free
//---------------------------------------------------------------------------


_FX void Box_Free(BOX *box)
{
    if (box) {
        if (box->sid)
            Mem_Free(box->sid, box->sid_len);
        if (box->expand_args)
            Mem_Free(box->expand_args, sizeof(CONF_EXPAND_ARGS));
        if (box->file_path)
            Mem_Free(box->file_path, box->file_path_len);
        if (box->key_path)
            Mem_Free(box->key_path, box->key_path_len);
        if (box->ipc_path)
            Mem_Free(box->ipc_path, box->ipc_path_len);
        if (box->pipe_path)
            Mem_Free(box->pipe_path, box->pipe_path_len);
        if (box->system_temp_path)
            Mem_Free(box->system_temp_path, box->system_temp_path_len);
        if (box->user_temp_path)
            Mem_Free(box->user_temp_path, box->user_temp_path_len);
        if (box->spooler_directory)
            Mem_Free(box->spooler_directory, box->spooler_directory_len);
        Mem_Free(box, sizeof(BOX));
    }
}


//---------------------------------------------------------------------------
// Box_CreateEx
//---------------------------------------------------------------------------


_FX BOX *Box_CreateEx(
    POOL *pool, const WCHAR *boxname,
    const WCHAR *sidstring, ULONG session_id,
    BOOLEAN init_paths)
{
    BOX *box;

    box = Box_Alloc(pool, boxname, session_id);
    if (! box)
        return NULL;

    if (! Box_InitKeys(pool, box, sidstring, session_id)) {
        Box_Free(box);
        return NULL;
    }

    if (! Box_InitConfExpandArgs(pool, box)) {
        Box_Free(box);
        return NULL;
    }

    if (init_paths) {

        BOOLEAN ok;
        Conf_AdjustUseCount(TRUE);
        ok = Box_InitPaths(pool, box);
        Conf_AdjustUseCount(FALSE);

        if (! ok) {
            Box_Free(box);
            return NULL;
        }
    }

    return box;
}


//---------------------------------------------------------------------------
// Box_Create
//---------------------------------------------------------------------------


_FX BOX *Box_Create(POOL *pool, const WCHAR *boxname, BOOLEAN init_paths)
{
    BOX *box;

    UNICODE_STRING SidString;
    ULONG SessionId;
    NTSTATUS status = Process_GetSidStringAndSessionId(
                        NtCurrentProcess(), NULL, &SidString, &SessionId);

    if (NT_SUCCESS(status)) {

        box = Box_CreateEx(
                pool, boxname, SidString.Buffer, SessionId, init_paths);
        RtlFreeUnicodeString(&SidString);
		box->js_regrules = Json_Conf_Get(box->name, L"regrules");
		Box_Init_keyValue(box);
		Json_Init_Reg(box->js_regrules,box);

    } else {

        Log_Status_Ex(MSG_BOX_CREATE, 0x11, status, boxname);
        box = NULL;
    }

    return box;
}


//---------------------------------------------------------------------------
// Box_InitKeys
//---------------------------------------------------------------------------


_FX BOOLEAN Box_InitKeys(
    POOL *pool, BOX *box, const WCHAR *sidstring, ULONG session_id)
{
    //
    // copy sidstring
    //

    box->sid_len = (wcslen(sidstring) + 1) * sizeof(WCHAR);
    box->sid = Mem_Alloc(pool, box->sid_len);
    if (! box->sid) {

        Log_Status_Ex_Session(
            MSG_BOX_CREATE, 0x12, STATUS_INSUFFICIENT_RESOURCES,
            box->name, session_id);
        return FALSE;
    }

    memcpy(box->sid, sidstring, box->sid_len);

    //
    // get Terminal Services Session ID from parameter
    //

    box->session_id = session_id;

    return TRUE;
}


//---------------------------------------------------------------------------
// Box_InitConfExpandArgs
//---------------------------------------------------------------------------


_FX BOOLEAN Box_InitConfExpandArgs(POOL *pool, BOX *box)
{
    box->expand_args = Mem_Alloc(pool, sizeof(CONF_EXPAND_ARGS));
    if (! box->expand_args) {

        Log_Status_Ex_Session(
            MSG_BOX_CREATE, 0x13, STATUS_INSUFFICIENT_RESOURCES,
            box->name, box->session_id);
        return FALSE;
    }

    box->expand_args->pool = pool;
    box->expand_args->sandbox = box->name;
    box->expand_args->sid = box->sid;
    box->expand_args->session = &box->session_id;

    if (! Conf_Expand_UserName(box->expand_args, NULL))
        return FALSE;

    return TRUE;
}


//---------------------------------------------------------------------------
// Box_InitPaths
//---------------------------------------------------------------------------


_FX BOOLEAN Box_InitPaths(POOL *pool, BOX *box)
{
    static const WCHAR *_FileRootPath_Default =
        L"\\??\\%SystemDrive%\\Sandbox\\%USER%\\%SANDBOX%";
    static const WCHAR *_KeyRootPath_Default  =
        L"\\REGISTRY\\USER\\Sandbox_%USER%_%SANDBOX%";
    static const WCHAR *_IpcRootPath_Default  =
        L"\\Sandbox\\%USER%\\%SANDBOX%\\Session_%SESSION%";

    const WCHAR *value;
    WCHAR suffix[80];
    BOOLEAN ok;
    WCHAR *ptr1;
    WCHAR KeyPath[256];

    //
    // get the file path.  if we don't have a FileRootPath setting,
    // we look for BoxRootFolder before reverting to the default.
    // if we find it, we use old-style suffix \Sandbox\BoxName.
    //

    suffix[0] = L'\0';

    value = Conf_Get(box->name, L"FileRootPath", 0);
    if (! value) {

        value = Conf_Get(box->name, L"BoxRootFolder", 0);
        if (value) {
            wcscpy(suffix, Driver_Sandbox);     // L"\\Sandbox"
            wcscat(suffix, L"\\");
            wcscat(suffix, box->name);
        }
    }

    if (! value)
        value = _FileRootPath_Default;

    ok = Box_ExpandString(
        box, value, suffix, &box->file_path, &box->file_path_len);
    if (! ok) {

        Log_Status_Ex_Session(
            MSG_BOX_CREATE, 0x21, STATUS_UNSUCCESSFUL,
            box->name, box->session_id);
        return FALSE;
    }

    //
    // get the key paths
    //

    ok = Box_ExpandString(box, L"%SystemTemp%", L"", &box->system_temp_path, &box->system_temp_path_len);
    ok = Box_ExpandString(box, L"%DefaultSpoolDirectory%", L"", &box->spooler_directory, &box->spooler_directory_len);

    if (!ok) {

        Log_Status_Ex_Session(
            MSG_BOX_CREATE, 0x22, STATUS_UNSUCCESSFUL,
            box->name, box->session_id);
        return FALSE;
    }

    // sometimes we get here without a user temp var being set.  Check first to avoid an error popup.
    RtlStringCbPrintfW(KeyPath, sizeof(KeyPath), L"\\REGISTRY\\USER\\%.184s\\Environment", box->sid);
    if (DoesRegValueExist(RTL_REGISTRY_ABSOLUTE, KeyPath, L"temp"))
        Box_ExpandString(box, L"%temp%", L"", &box->user_temp_path, &box->user_temp_path_len);

    suffix[0] = L'\0';

    value = Conf_Get(box->name, L"KeyRootPath", 0);
    if (! value)
        value = _KeyRootPath_Default;

    ok = Box_ExpandString(
        box, value, suffix, &box->key_path, &box->key_path_len);
    if (! ok) {

        Log_Status_Ex_Session(
            MSG_BOX_CREATE, 0x23, STATUS_UNSUCCESSFUL,
            box->name, box->session_id);
        return FALSE;
    }

    //
    // get the ipc path
    //

    suffix[0] = L'\0';

    value = Conf_Get(box->name, L"IpcRootPath", 0);
    if (! value)
        value = _IpcRootPath_Default;

    ok = Box_ExpandString(
        box, value, suffix, &box->ipc_path, &box->ipc_path_len);
    if (! ok) {

        Log_Status_Ex_Session(
            MSG_BOX_CREATE, 0x24, STATUS_UNSUCCESSFUL,
            box->name, box->session_id);
        return FALSE;
    }

    //
    // translate ipc path into pipe path
    //

    box->pipe_path_len = box->ipc_path_len;
    box->pipe_path = Mem_Alloc(pool, box->pipe_path_len);
    if (! box->pipe_path) {

        Log_Status_Ex_Session(
            MSG_BOX_CREATE, 0x25, STATUS_UNSUCCESSFUL,
            box->name, box->session_id);
        return FALSE;
    }

    memcpy(box->pipe_path, box->ipc_path, box->pipe_path_len);
    ptr1 = box->pipe_path;
    while (*ptr1) {
        WCHAR *ptr2 = wcschr(ptr1, L'\\');
        if (ptr2) {
            ptr1 = ptr2;
            *ptr1 = L'_';
        } else
            ptr1 += wcslen(ptr1);
    }

    //
    //  Init Reg Json Rules
    //

    box->js_regrules = Json_Conf_Get(box->name, L"regrules");

    return TRUE;
}


//---------------------------------------------------------------------------
// Box_ExpandString
//---------------------------------------------------------------------------


_FX BOOLEAN Box_ExpandString(
    BOX *box, const WCHAR *model, const WCHAR *suffix,
    WCHAR **path, ULONG *path_len)
{
    WCHAR *value1, *value2, *ptr;
    ULONG suffix_len, len;
    BOOLEAN ok = FALSE;

    value1 = Conf_Expand(box->expand_args, model, NULL);
    if (! value1)
        return FALSE;

    suffix_len = wcslen(suffix);
    while (suffix_len && suffix[suffix_len - 1] == L'\\')
        --suffix_len;

    len = (wcslen(value1) + suffix_len + 1) * sizeof(WCHAR);
    value2 = Mem_Alloc(box->expand_args->pool, len);
    if (value2) {

        wcscpy(value2, value1);
        ptr = value2 + wcslen(value2);
        wmemcpy(ptr, suffix, suffix_len);
        ptr += suffix_len;
        *ptr = L'\0';

        *path = value2;
        *path_len = len;

        //
        // remove duplicate backslashes and the final backslash
        //

        ptr = value2;
        len = wcslen(ptr);

        while (ptr[0]) {
            if (ptr[0] == L'\\' && ptr[1] == L'\\') {

                ULONG move_len = len - (ULONG)(ptr - value2) + 1;
                wmemmove(ptr, ptr + 1, move_len);
                --len;

            } else
                ++ptr;
        }

        if (len && value2[len - 1] == L'\\') {
            value2[len - 1] = L'\0';
            --len;
        }

        //
        // if removal of the backslash caused a change in the length
        // of the string, then re-allocate the output buffer
        //

        if (len) {

            len = (len + 1) * sizeof(WCHAR);
            if (len != *path_len) {

                WCHAR *value3 = Mem_Alloc(box->expand_args->pool, len);
                if (value3) {

                    memcpy(value3, value2, len);
                    Mem_Free(*path, *path_len);

                    *path = value3;
                    *path_len = len;

                    ok = TRUE;
                }

            } else
                ok = TRUE;
        }

        if (! ok) {
            Mem_Free(*path, *path_len);
            *path = NULL;
            *path_len = 0;
        }
    }

    Mem_FreeString(value1);
    return ok;
}


//---------------------------------------------------------------------------
// Box_Clone
//---------------------------------------------------------------------------


_FX BOX *Box_Clone(POOL *pool, const BOX *model)
{
    BOX *box;

    box = Box_Alloc(pool, model->name, model->session_id);
    if (! box)
        return NULL;

#define CLONE_MEMBER(m)                                                 \
    if (model->m) {                                                     \
        box->m = Mem_Alloc(pool, model->m##_len);                       \
        if (! box->m) {                                                 \
            Log_Status_Ex_Session(                                      \
                MSG_BOX_CREATE, 0x20, STATUS_INSUFFICIENT_RESOURCES,    \
                model->name, model->session_id);                        \
            Box_Free(box);                                              \
            return NULL;                                                \
        }                                                               \
        wcscpy(box->m, model->m);                                       \
        box->m##_len = model->m##_len;                                  \
    }

    CLONE_MEMBER(sid);
    CLONE_MEMBER(file_path);
    CLONE_MEMBER(key_path);
    CLONE_MEMBER(ipc_path);
    CLONE_MEMBER(pipe_path);
    CLONE_MEMBER(spooler_directory);
    CLONE_MEMBER(system_temp_path);
    CLONE_MEMBER(user_temp_path);
    box->js_regrules = model->js_regrules;
#undef CLONE_MEMBER

    box->session_id = model->session_id;

    if (! Box_InitConfExpandArgs(pool, box)) {
        Box_Free(box);
        return NULL;
    }

    return box;
}


//---------------------------------------------------------------------------
// Box_NlsStrCmp
//---------------------------------------------------------------------------


_FX int Box_NlsStrCmp(const WCHAR *s1, const WCHAR *s2, ULONG len)
{
    UNICODE_STRING u1, u2;

    u1.Length = u1.MaximumLength = u2.Length = u2.MaximumLength =
        (USHORT)(len * sizeof(WCHAR));
    u1.Buffer = (WCHAR *)s1;
    u2.Buffer = (WCHAR *)s2;

    return RtlCompareUnicodeString(&u1, &u2, TRUE);
}


//---------------------------------------------------------------------------
// Box_IsBoxedPath_Helper
//---------------------------------------------------------------------------


_FX BOOLEAN Box_IsBoxedPath_Helper(
    UNICODE_STRING *uni, const WCHAR *box_path, ULONG box_path_len)
{
    box_path_len -= sizeof(WCHAR);      // remove count of final NULL WCHAR
    if (uni->Length < box_path_len)
        return FALSE;

    box_path_len /= sizeof(WCHAR);      // convert byte count to WCHAR count
    if (Box_NlsStrCmp(uni->Buffer, box_path, box_path_len) != 0)
        return FALSE;

    if (uni->Buffer[box_path_len] != L'\\'
            && uni->Buffer[box_path_len] != L'\0')
        return FALSE;

    return TRUE;
}
