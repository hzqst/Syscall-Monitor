#pragma once

#include <Windows.h>
#include <string>

ULONG64 GetKeSystemTime(void);
BOOL GetImageBaseInfoByAddress(ULONG ProcessId, ULONG64 BaseAddress, ULONG64 *ImageBase, ULONG *ImageSize, BOOLEAN *Is64Bit);
BOOL GetImagePathByAddress(ULONG ProcessId, ULONG64 BaseAddress, std::wstring &ImagePath);
BOOL GetProcessBaseInfo(ULONG ProcessId, ULONG *ParentProcessId, ULONG64 *CreateTime, BOOLEAN *Is64Bit, ULONG *SessionId);
BOOL GetProcessImagePath(ULONG ProcessId, std::wstring &ImagePath);
BOOL GetProcessCmdLine(ULONG ProcessId, std::wstring &CmdLine);
BOOL GetProcessCurDir(ULONG ProcessId, std::wstring &CurDir);
BOOL SetCaptureEnable(bool bEnable);
