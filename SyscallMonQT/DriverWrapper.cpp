#include "DriverLoader.h"
#include "util.h"
#include <string>
#include "nt.h"
#include "../Shared/Protocol.h"

BOOL SetCaptureEnable(bool bEnable)
{
    cls_set_capture_enable_data data;
    data.protocol = cls_set_capture_enable;
    data.Enable = bEnable ? 1 : 0;

    return m_Driver.Send(&data, sizeof(data), NULL, 0, NULL);
}

ULONG64 GetKeSystemTime(void)
{
	ULONG64 time = 0;

	UCHAR protocol[1];
	protocol[0] = cls_get_system_time;

    if (m_Driver.Send(protocol, sizeof(protocol), &time, sizeof(time), NULL))
		return time;

	return 0;
}

BOOL GetImageBaseInfoByAddress(ULONG ProcessId, ULONG64 BaseAddress, ULONG64 *ImageBase, ULONG *ImageSize, BOOLEAN *Is64Bit)
{
    cls_get_image_data data;
    cls_get_image_baseinfo_data out = {0};

    data.protocol = cls_get_image_baseinfo;
    data.ProcessId = ProcessId;
    data.BaseAddress = BaseAddress;

    if(m_Driver.Send(&data, sizeof(data), &out, sizeof(out), NULL))
    {
        *ImageBase = out.ImageBase;
        *ImageSize = out.ImageSize;
        *Is64Bit = out.Is64Bit;
        return TRUE;
    }
    return FALSE;
}

BOOL GetImagePathByAddress(ULONG ProcessId, ULONG64 BaseAddress, std::wstring &ImagePath)
{
    cls_get_image_data data;
    WCHAR szImagePath[1024] = {0};

    data.protocol = cls_get_image_path;
    data.ProcessId = ProcessId;
    data.BaseAddress = BaseAddress;

    if(m_Driver.Send(&data, sizeof(data), (LPVOID)szImagePath, sizeof(szImagePath) - sizeof(WCHAR), NULL))
    {
        ImagePath = szImagePath;
        return TRUE;
    }
    return FALSE;
}

BOOL GetProcessBaseInfo(ULONG ProcessId, ULONG *ParentProcessId, ULONG64 *CreateTime, BOOLEAN *Is64Bit, ULONG *SessionId)
{
    cls_pid_data data;

	data.protocol = cls_get_process_baseinfo;;
    data.ProcessId = ProcessId;

	cls_get_process_baseinfo_data out = { 0 };

    if (m_Driver.Send(&data, sizeof(data), &out, sizeof(out), NULL))
	{
		*ParentProcessId = out.ParentProcessId;
        *CreateTime = out.CreateTime;
        *Is64Bit = out.Is64Bit;
        *SessionId = out.SessionId;
		return TRUE;
	}
	return FALSE;
}

BOOL GetProcessImagePath(ULONG ProcessId, std::wstring &ImagePath)
{
    cls_pid_data data;
    WCHAR szImagePath[1024] = {0};

    data.protocol = cls_get_process_path;
    data.ProcessId = ProcessId;

    if(m_Driver.Send(&data, sizeof(data), (LPVOID)szImagePath, sizeof(szImagePath) - sizeof(WCHAR), NULL))
    {
        ImagePath = szImagePath;
        return TRUE;
    }
    return FALSE;
}

BOOL GetProcessCmdLine(ULONG ProcessId, std::wstring &CmdLine)
{
    cls_pid_data data;
    WCHAR szCmdLine[1024] = {0};

    data.protocol = cls_get_process_cmdline;
    data.ProcessId = ProcessId;

    if(m_Driver.Send(&data, sizeof(data), (LPVOID)szCmdLine, sizeof(szCmdLine) - sizeof(WCHAR), NULL))
    {
        CmdLine = szCmdLine;
        return TRUE;
    }
    return FALSE;
}

BOOL GetProcessCurDir(ULONG ProcessId, std::wstring &CurDir)
{
    cls_pid_data data;
    WCHAR szCurDir[1024] = {0};

    data.protocol = cls_get_process_curdir;
    data.ProcessId = ProcessId;

    if(m_Driver.Send(&data, sizeof(data), (LPVOID)szCurDir, sizeof(szCurDir) - sizeof(WCHAR), NULL))
    {
        CurDir = szCurDir;
        return TRUE;
    }
    return FALSE;
}
