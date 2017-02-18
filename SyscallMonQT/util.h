#ifndef UTIL_H
#define UTIL_H

#include <Windows.h>

BOOL AdjustPrivilege(LPCTSTR Privilege);
BOOL IsAMD64(void);
void GetModuleFilePath(HMODULE hModule, LPWSTR szFilePath, DWORD cbSize);
BOOL NewWow64DisableWow64FsRedirection(PVOID *v);
BOOL NewWow64RevertWow64FsRedirection(PVOID v);
LPCTSTR ExtractFileName(LPCTSTR szPath);
__time64_t FileTimeToUnixTime(FILETIME *ft);
void WriteLog(LPCWSTR fmt, ...);
BOOL GetPEInfo(PBYTE pBuf, ULONG uSize, ULONG &ImageSize, bool &bIs64Bit);

#endif // UTIL_H
