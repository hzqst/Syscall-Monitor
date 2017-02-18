#include <Windows.h>
#include <iostream>
#include <stdio.h>

BOOL AdjustPrivilege(LPCTSTR Privilege)
{
    BOOL bSuccess = FALSE;
    HANDLE hToken;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
    {
        TOKEN_PRIVILEGES tp;
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        if (LookupPrivilegeValue(NULL, Privilege, &tp.Privileges[0].Luid))
        {
            if (AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL))
            {
                bSuccess = TRUE;
            }
        }
        CloseHandle(hToken);
    }
    return bSuccess;
}

BOOL IsAMD64(void)
{
    static BOOL g_bAMD64 = -1;

    if (g_bAMD64 == -1)
    {
        SYSTEM_INFO si;
        GetNativeSystemInfo(&si);

        g_bAMD64 = (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) ? TRUE : FALSE;
    }
    return g_bAMD64;
}

void GetModuleFilePath(HMODULE hModule, LPWSTR szFilePath, DWORD cbSize)
{
    GetModuleFileName(hModule, szFilePath, cbSize);

    for (size_t i = wcslen(szFilePath); i >= 0; --i)
    {
        if (szFilePath[i] == TEXT('\\') || szFilePath[i] == TEXT('/'))
        {
            szFilePath[i] = 0;
            break;
        }
    }
}


BOOL NewWow64DisableWow64FsRedirection(PVOID *v)
{
    static BOOL(WINAPI *pfnWow64DisableWow64FsRedirection)(PVOID *) = (BOOL(WINAPI *)(PVOID *))GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), "Wow64DisableWow64FsRedirection");

    if (pfnWow64DisableWow64FsRedirection)
    {
        return pfnWow64DisableWow64FsRedirection(v);
    }

    return FALSE;
}

BOOL NewWow64RevertWow64FsRedirection(PVOID v)
{
    static BOOL(WINAPI *pfnWow64RevertWow64FsRedirection)(PVOID) = (BOOL(WINAPI *)(PVOID))GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), "Wow64RevertWow64FsRedirection");

    if (pfnWow64RevertWow64FsRedirection)
    {
        return pfnWow64RevertWow64FsRedirection(v);
    }

    return FALSE;
}

LPCTSTR ExtractFileName(LPCTSTR szPath)
{
    SIZE_T len = wcslen(szPath);
    if (len < 2)
        return szPath;

    for (size_t i = len - 2; i >= 0; --i)
    {
        if (szPath[i] == L'\\' || szPath[i] == L'/')
            return &szPath[i + 1];
    }
    return szPath;
}

__time64_t FileTimeToUnixTime(FILETIME *ft)
{
    ULARGE_INTEGER ull;

    ull.LowPart = ft->dwLowDateTime;
    ull.HighPart = ft->dwHighDateTime;

    return ull.QuadPart / 10000000ULL - 11644473600ULL;
}

/*void WriteLog(LPCWSTR fmt, ...)
{
    WCHAR buffer[4096];
    va_list argptr;
    int cnt;
    va_start(argptr, fmt);
    cnt = wvsprintf(buffer, fmt, argptr);
    va_end(argptr);

    FILE *fp = NULL;

    _wfopen_s(&fp, L"SyscallMonLog.txt", L"a+");
    if (fp)
    {
        _wsetlocale(LC_ALL, L"chs");
        fwprintf(fp, L"%s", buffer);
        fclose(fp);
    }
}*/
