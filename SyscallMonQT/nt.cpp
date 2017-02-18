#include <Windows.h>
#include <QObject>
#include <QString>
#include "nt.h"

QString GetNTStatusCodeString(ULONG status)
{
	switch (status)
	{
    case 0x00000000:return "STATUS_SUCCESS";
    case 0x00000102:return "STATUS_TIMEOUT";
    case 0x00000103:return "STATUS_PENDING";
    case 0x00000104:return "STATUS_REPARSE";
    case 0x00000105:return "STATUS_MORE_ENTRIES";
    case 0x0000012A:return "STATUS_FILE_LOCKED_WITH_ONLY_READERS";
    case 0x0000012B:return "STATUS_FILE_LOCKED_WITH_WRITERS";
    case 0x80000005:return "STATUS_BUFFER_OVERFLOW";
    case 0x80000006:return "STATUS_NO_MORE_FILES";
    case 0x8000000D:return "STATUS_PARTIAL_COPY";
    case 0x8000001A:return "STATUS_NO_MORE_ENTRIES";
    case 0xC0000001:return "STATUS_UNSUCCESSFUL";
    case 0xC0000002:return "STATUS_NOT_IMPLEMENTED";
    case 0xC0000003:return "STATUS_INVALID_INFO_CLASS";
    case 0xC0000004:return "STATUS_INFO_LENGTH_MISMATCH";
    case 0xC0000005:return "STATUS_ACCESS_VIOLATION";
    case 0xC0000006:return "STATUS_IN_PAGE_ERROR";
    case 0xC0000007:return "STATUS_PAGEFILE_QUOTA";
    case 0xC0000008:return "STATUS_INVALID_HANDLE";
    case 0xC0000009:return "STATUS_BAD_INITIAL_STACK";
    case 0xC000000A:return "STATUS_BAD_INITIAL_PC";
    case 0xC000000B:return "STATUS_INVALID_CID";
    case 0xC000000C:return "STATUS_TIMER_NOT_CANCELED";
    case 0xC000000D:return "STATUS_INVALID_PARAMETER";
    case 0xC000000E:return "STATUS_NO_SUCH_DEVICE";
    case 0xC000000F:return "STATUS_NO_SUCH_FILE";
    case 0xC0000010:return "STATUS_INVALID_DEVICE_REQUEST";
    case 0xC0000011:return "STATUS_END_OF_FILE";
    case 0xC0000012:return "STATUS_WRONG_VOLUME";
    case 0xC0000013:return "STATUS_NO_MEDIA_IN_DEVICE";
    case 0xC0000014:return "STATUS_UNRECOGNIZED_MEDIA";
    case 0xC0000015:return "STATUS_NONEXISTENT_SECTOR";
    case 0xC0000016:return "STATUS_MORE_PROCESSING_REQUIRED";
    case 0xC0000017:return "STATUS_NO_MEMORY";
    case 0xC0000018:return "STATUS_CONFLICTING_ADDRESSES";
    case 0xC0000019:return "STATUS_NOT_MAPPED_VIEW";
    case 0xC000001A:return "STATUS_UNABLE_TO_FREE_VM";
    case 0xC000001B:return "STATUS_UNABLE_TO_DELETE_SECTION";
    case 0xC000001C:return "STATUS_INVALID_SYSTEM_SERVICE";
    case 0xC000001D:return "STATUS_ILLEGAL_INSTRUCTION";
    case 0xC000001E:return "STATUS_INVALID_LOCK_SEQUENCE";
    case 0xC000001F:return "STATUS_INVALID_VIEW_SIZE";
    case 0xC0000020:return "STATUS_INVALID_FILE_FOR_SECTION";
    case 0xC0000021:return "STATUS_ALREADY_COMMITTED";
    case 0xC0000022:return "STATUS_ACCESS_DENIED";
    case 0xC0000023:return "STATUS_BUFFER_TOO_SMALL";
    case 0xC0000030:return "STATUS_INVALID_PARAMETER_MIX";
    case 0xC0000031:return "STATUS_INVALID_QUOTA_LOWER";
    case 0xC0000032:return "STATUS_DISK_CORRUPT_ERROR";
    case 0xC0000033:return "STATUS_OBJECT_NAME_INVALID";
    case 0xC0000034:return "STATUS_OBJECT_NAME_NOT_FOUND";
    case 0xC0000035:return "STATUS_OBJECT_NAME_COLLISION";

    case 0xC0000039:return "STATUS_OBJECT_PATH_INVALID";
    case 0xC000003A:return "STATUS_OBJECT_PATH_NOT_FOUND";
    case 0xC000003B:return "STATUS_OBJECT_PATH_SYNTAX_BAD";
		
    case 0xC0000043:return "STATUS_SHARING_VIOLATION";
    case 0xC0000044:return "STATUS_QUOTA_EXCEEDED";
    case 0xC0000045:return "STATUS_INVALID_PAGE_PROTECTION";
    case 0xC0000046:return "STATUS_MUTANT_NOT_OWNED";
    case 0xC0000047:return "STATUS_SEMAPHORE_LIMIT_EXCEEDED";
    case 0xC0000048:return "STATUS_PORT_ALREADY_SET";
    case 0xC0000049:return "STATUS_SECTION_NOT_IMAGE";
    case 0xC000004A:return "STATUS_SUSPEND_COUNT_EXCEEDED";
    case 0xC000004B:return "STATUS_THREAD_IS_TERMINATING";

    case 0xC0000054:return "STATUS_FILE_LOCK_CONFLICT";

    case 0xC0000061:return "STATUS_PRIVILEGE_NOT_HELD";

    case 0xC0000096:return "STATUS_PRIVILEGED_INSTRUCTION";

    case 0xC000009A:return "STATUS_INSUFFICIENT_RESOURCES";

    case 0xC00000EF:return "STATUS_INVALID_PARAMETER_1";
    case 0xC00000F0:return "STATUS_INVALID_PARAMETER_2";
    case 0xC00000F1:return "STATUS_INVALID_PARAMETER_3";
    case 0xC00000F2:return "STATUS_INVALID_PARAMETER_4";
    case 0xC00000F3:return "STATUS_INVALID_PARAMETER_5";

    case 0xC0000106:return "STATUS_NAME_TOO_LONG";

    case 0xC01C0001:return"STATUS_FLT_NO_HANDLER_DEFINED";
    case 0xC01C0002:return"STATUS_FLT_CONTEXT_ALREADY_DEFINED";
    case 0xC01C0003:return"STATUS_FLT_INVALID_ASYNCHRONOUS_REQUEST";
    case 0xC01C0004:return"STATUS_FLT_DISALLOW_FAST_IO";
    case 0xC01C0005:return"STATUS_FLT_INVALID_NAME_REQUEST";
    case 0xC01C0006:return"STATUS_FLT_NOT_SAFE_TO_POST_OPERATION";
    case 0xC01C0007:return"STATUS_FLT_NOT_INITIALIZED";
    case 0xC01C0008:return"STATUS_FLT_FILTER_NOT_READY";
    case 0xC01C0009:return"STATUS_FLT_POST_OPERATION_CLEANUP";
    case 0xC01C000A:return"STATUS_FLT_INTERNAL_ERROR";
    case 0xC01C000B:return"STATUS_FLT_DELETING_OBJECT";
    case 0xC01C000C:return"STATUS_FLT_MUST_BE_NONPAGED_POOL";
    case 0xC01C000D:return"STATUS_FLT_DUPLICATE_ENTRY";
	}
    return QObject::tr("Unknown Status Code");
}

QString GetCreateDispositionString(ULONG CreateDisposition)
{
	switch (CreateDisposition)
	{
	case FILE_SUPERSEDE:
        return "FILE_SUPERSEDE";
	case FILE_OPEN:
        return "FILE_OPEN";
	case FILE_CREATE:
        return "FILE_CREATE";
	case FILE_OPEN_IF:
        return "FILE_OPEN_IF";
	case FILE_OVERWRITE:
        return "FILE_OVERWRITE";
	case FILE_OVERWRITE_IF:
        return "FILE_OVERWRITE_IF";
	}
    return QObject::tr("Unknown CreateDisposition");
}

void GetShareAccessString(ULONG ShareAccess, QString &str)
{
	if (ShareAccess & FILE_SHARE_READ)
	{
        if(!str.isEmpty())
            str.append(" | ");
        str.append("FILE_SHARE_READ");
	}
	if (ShareAccess & FILE_SHARE_WRITE)
	{
        if (!str.isEmpty())
            str.append(" | ");
        str.append("FILE_SHARE_WRITE");
	}
	if (ShareAccess & FILE_SHARE_DELETE)
	{
        if (!str.isEmpty())
            str.append(" | ");
        str.append("FILE_SHARE_DELETE");
	}
}

void GetCommonDesiredAccess(ULONG &DesiredAccess, QString &str)
{
    if (DesiredAccess & STANDARD_RIGHTS_ALL)
    {
        DesiredAccess &= ~STANDARD_RIGHTS_ALL;
        if(!str.isEmpty())
            str.append(" | ");
        str.append("STANDARD_RIGHTS_ALL");
    }
    if (DesiredAccess & GENERIC_READ)
    {
        DesiredAccess &= ~GENERIC_READ;
        if(!str.isEmpty())
            str.append(" | ");
        str.append("GENERIC_READ");
    }
    if (DesiredAccess & GENERIC_WRITE)
    {
        DesiredAccess &= ~GENERIC_WRITE;
        if(!str.isEmpty())
            str.append(" | ");
        str.append("GENERIC_WRITE");
    }
    if (DesiredAccess & GENERIC_EXECUTE)
    {
        DesiredAccess &= ~GENERIC_EXECUTE;
        if(!str.isEmpty())
            str.append(" | ");
        str.append("GENERIC_EXECUTE");
    }
    if (DesiredAccess & STANDARD_RIGHTS_REQUIRED)
    {
        DesiredAccess &= ~STANDARD_RIGHTS_REQUIRED;
        if(!str.isEmpty())
            str.append(" | ");
        str.append("STANDARD_RIGHTS_REQUIRED");
    }
    if (DesiredAccess & MAXIMUM_ALLOWED)
    {
        DesiredAccess &= ~MAXIMUM_ALLOWED;
        if(!str.isEmpty())
            str.append(" | ");
        str.append("MAXIMUM_ALLOWED");
    }
    if (DesiredAccess & DELETE)
    {
        DesiredAccess &= ~DELETE;
        if(!str.isEmpty())
            str.append(" | ");
        str.append("DELETE");
    }
    if (DesiredAccess & READ_CONTROL)
    {
        DesiredAccess &= ~READ_CONTROL;
        if(!str.isEmpty())
            str.append(" | ");
        str.append("READ_CONTROL");
    }
    if (DesiredAccess & WRITE_DAC)
    {
        DesiredAccess &= ~WRITE_DAC;
        if(!str.isEmpty())
            str.append(" | ");
        str.append("WRITE_DAC");
    }
    if (DesiredAccess & WRITE_OWNER)
    {
        DesiredAccess &= ~WRITE_OWNER;
        if(!str.isEmpty())
            str.append(" | ");
        str.append("WRITE_OWNER");
    }
    if (DesiredAccess & SYNCHRONIZE)
    {
        DesiredAccess &= ~SYNCHRONIZE;
        if(!str.isEmpty())
            str.append(" | ");
        str.append("SYNCHRONIZE");
    }
    if (DesiredAccess != 0)
        str = QObject::tr("Unknown (0x%1)").arg(FormatHexString(DesiredAccess, 0));
}

void GetCreateFileDesiredAccessString(ULONG DesiredAccess, QString &str)
{
    if (DesiredAccess & FILE_READ_DATA)
    {
        DesiredAccess &= ~FILE_READ_DATA;
        if(!str.isEmpty())
            str.append(" | ");
        str.append("FILE_READ_DATA");
    }
    if (DesiredAccess & FILE_READ_ATTRIBUTES)
    {
        DesiredAccess &= ~FILE_READ_ATTRIBUTES;
        if (!str.isEmpty())
            str.append(" | ");
        str.append("FILE_READ_ATTRIBUTES");
    }
    if (DesiredAccess & FILE_READ_EA)
    {
        DesiredAccess &= ~FILE_READ_EA;
        if (!str.isEmpty())
            str.append(" | ");
        str.append("FILE_READ_EA");
    }
    if (DesiredAccess & FILE_WRITE_DATA)
    {
        DesiredAccess &= ~FILE_WRITE_DATA;
        if (!str.isEmpty())
            str.append(" | ");
        str.append("FILE_WRITE_DATA");
    }
    if (DesiredAccess & FILE_WRITE_ATTRIBUTES)
    {
        DesiredAccess &= ~FILE_WRITE_ATTRIBUTES;
        if (!str.isEmpty())
            str.append(" | ");
        str.append("FILE_WRITE_ATTRIBUTES");
    }
    if (DesiredAccess & FILE_WRITE_EA)
    {
        DesiredAccess &= ~FILE_WRITE_EA;
        if (!str.isEmpty())
            str.append(" | ");
        str.append("FILE_WRITE_EA");
    }
    if (DesiredAccess & FILE_APPEND_DATA)
    {
        DesiredAccess &= ~FILE_APPEND_DATA;
        if (!str.isEmpty())
            str.append(" | ");
        str.append("FILE_APPEND_DATA");
    }
    if (DesiredAccess & FILE_EXECUTE)
    {
        DesiredAccess &= ~FILE_EXECUTE;
        if (!str.isEmpty())
            str.append(" | ");
        str.append("FILE_EXECUTE");
    }

    GetCommonDesiredAccess(DesiredAccess, str);
}

void GetCreateFileOptionsString(ULONG Options, QString &str)
{
    if (Options & FILE_DIRECTORY_FILE)
    {
        if (!str.isEmpty())
            str.append(" | ");
        str.append("FILE_DIRECTORY_FILE");
    }
    if (Options & FILE_NON_DIRECTORY_FILE)
    {
        if (!str.isEmpty())
            str.append(" | ");
        str.append("FILE_NON_DIRECTORY_FILE");
    }
    if (Options & FILE_WRITE_THROUGH)
    {
        if (!str.isEmpty())
            str.append(" | ");
        str.append("FILE_WRITE_THROUGH");
    }
    if (Options & FILE_SEQUENTIAL_ONLY)
    {
        if (!str.isEmpty())
            str.append(" | ");
        str.append("FILE_SEQUENTIAL_ONLY");
    }
    if (Options & FILE_RANDOM_ACCESS)
    {
        if (!str.isEmpty())
            str.append(" | ");
        str.append("FILE_RANDOM_ACCESS");
    }
    if (Options & FILE_NO_INTERMEDIATE_BUFFERING)
    {
        if (!str.isEmpty())
            str.append(" | ");
        str.append("FILE_NO_INTERMEDIATE_BUFFERING");
    }
    if (Options & FILE_SYNCHRONOUS_IO_ALERT)
    {
        if (!str.isEmpty())
            str.append(" | ");
        str.append("FILE_SYNCHRONOUS_IO_ALERT");
    }
    if (Options & FILE_SYNCHRONOUS_IO_NONALERT)
    {
        if (!str.isEmpty())
            str.append(" | ");
        str.append("FILE_SYNCHRONOUS_IO_NONALERT");
    }
    if (Options & FILE_CREATE_TREE_CONNECTION)
    {
        if (!str.isEmpty())
            str.append(" | ");
        str.append("FILE_CREATE_TREE_CONNECTION");
    }
    if (Options & FILE_COMPLETE_IF_OPLOCKED)
    {
        if (!str.isEmpty())
            str.append(" | ");
        str.append("FILE_COMPLETE_IF_OPLOCKED");
    }
    if (Options & FILE_NO_EA_KNOWLEDGE)
    {
        if (!str.isEmpty())
            str.append(" | ");
        str.append("FILE_NO_EA_KNOWLEDGE");
    }
    if (Options & FILE_OPEN_REPARSE_POINT)
    {
        if (!str.isEmpty())
            str.append(" | ");
        str.append("FILE_OPEN_REPARSE_POINT");
    }
    if (Options & FILE_DELETE_ON_CLOSE)
    {
        if (!str.isEmpty())
            str.append(" | ");
        str.append("FILE_DELETE_ON_CLOSE");
    }
    if (Options & FILE_OPEN_BY_FILE_ID)
    {
        if (!str.isEmpty())
            str.append(" | ");
        str.append("FILE_OPEN_BY_FILE_ID");
    }
    if (Options & FILE_OPEN_FOR_BACKUP_INTENT)
    {
        if (!str.isEmpty())
            str.append(" | ");
        str.append("FILE_OPEN_FOR_BACKUP_INTENT");
    }
    if (Options & FILE_RESERVE_OPFILTER)
    {
        if (!str.isEmpty())
            str.append(" | ");
        str.append("FILE_RESERVE_OPFILTER");
    }
    if (Options & FILE_OPEN_REQUIRING_OPLOCK)
    {
        if (!str.isEmpty())
            str.append(" | ");
        str.append("FILE_OPEN_REQUIRING_OPLOCK");
    }
    if (Options & FILE_SESSION_AWARE)
    {
        if (!str.isEmpty())
            str.append(" | ");
        str.append("FILE_SESSION_AWARE");
    }
}

void GetPageProtectionString(ULONG PageProtection, QString &str)
{
	if (PageProtection & PAGE_EXECUTE)
	{
        if (!str.isEmpty())
            str.append(" | ");
        str.append("PAGE_EXECUTE");
	}
	if (PageProtection & PAGE_EXECUTE_READ)
	{
        if (!str.isEmpty())
            str.append(" | ");
        str.append("PAGE_EXECUTE_READ");
	}
	if (PageProtection & PAGE_EXECUTE_READWRITE)
	{
        if (!str.isEmpty())
            str.append(" | ");
        str.append("PAGE_EXECUTE_READWRITE");
	}
	if (PageProtection & PAGE_WRITECOPY)
	{
        if (!str.isEmpty())
            str.append(" | ");
        str.append("PAGE_WRITECOPY");
	}
	if (PageProtection & PAGE_READWRITE)
	{
        if (!str.isEmpty())
            str.append(" | ");
        str.append("PAGE_READWRITE");
	}
	if (PageProtection & PAGE_READONLY)
	{
        if (!str.isEmpty())
            str.append(" | ");
        str.append("PAGE_READONLY");
	}
	if (PageProtection & PAGE_NOACCESS)
	{
        if (!str.isEmpty())
            str.append(" | ");
        str.append("PAGE_NOACCESS");
	}
	if (PageProtection & PAGE_GUARD)
	{
        if (!str.isEmpty())
            str.append(" | ");
        str.append("PAGE_GUARD");
	}
	if (PageProtection & PAGE_NOCACHE)
	{
        if (!str.isEmpty())
            str.append(" | ");
        str.append("PAGE_NOCACHE");
	}
	if (PageProtection & PAGE_WRITECOMBINE)
	{
        if (!str.isEmpty())
            str.append(" | ");
        str.append("PAGE_WRITECOMBINE");
	}
}

void GetProcessDesiredAccessString(ULONG DesiredAccess, QString &str)
{
	if (DesiredAccess == PROCESS_ALL_ACCESS)
	{
        str = "PROCESS_ALL_ACCESS";
		return;
	}
	if (DesiredAccess & PROCESS_TERMINATE)
	{
        DesiredAccess &= ~PROCESS_TERMINATE;
        if (!str.isEmpty())
            str.append(" | ");
        str.append("PROCESS_TERMINATE");
	}
	if (DesiredAccess & PROCESS_CREATE_THREAD)
	{
        DesiredAccess &= ~PROCESS_CREATE_THREAD;
        if (!str.isEmpty())
            str.append(" | ");
        str.append("PROCESS_CREATE_THREAD");
	}
	if (DesiredAccess & PROCESS_SET_SESSIONID)
	{
        DesiredAccess &= ~PROCESS_SET_SESSIONID;
        if (!str.isEmpty())
            str.append(" | ");
        str.append("PROCESS_SET_SESSIONID");
	}
	if (DesiredAccess & PROCESS_VM_OPERATION)
	{
        DesiredAccess &= ~PROCESS_VM_OPERATION;
        if (!str.isEmpty())
            str.append(" | ");
        str.append("PROCESS_VM_OPERATION");
	}
	if (DesiredAccess & PROCESS_VM_READ)
	{
        DesiredAccess &= ~PROCESS_VM_READ;
        if (!str.isEmpty())
            str.append(" | ");
        str.append("PROCESS_VM_READ");
	}
	if (DesiredAccess & PROCESS_VM_WRITE)
	{
        DesiredAccess &= ~PROCESS_VM_WRITE;
        if (!str.isEmpty())
            str.append(" | ");
        str.append("PROCESS_VM_WRITE");
	}
	if (DesiredAccess & PROCESS_DUP_HANDLE)
	{
        DesiredAccess &= ~PROCESS_DUP_HANDLE;
        if (!str.isEmpty())
            str.append(" | ");
        str.append("PROCESS_DUP_HANDLE");
	}
	if (DesiredAccess & PROCESS_CREATE_PROCESS)
	{
        DesiredAccess &= ~PROCESS_CREATE_PROCESS;
        if (!str.isEmpty())
            str.append(" | ");
        str.append("PROCESS_CREATE_PROCESS");
	}
	if (DesiredAccess & PROCESS_SET_QUOTA)
	{
        DesiredAccess &= ~PROCESS_SET_QUOTA;
        if (!str.isEmpty())
            str.append(" | ");
        str.append("PROCESS_SET_QUOTA");
	}
	if (DesiredAccess & PROCESS_SET_INFORMATION)
	{
        DesiredAccess &= ~PROCESS_SET_INFORMATION;
        if (!str.isEmpty())
            str.append(" | ");
        str.append("PROCESS_SET_INFORMATION");
	}
	if (DesiredAccess & PROCESS_QUERY_INFORMATION)
	{
        DesiredAccess &= ~PROCESS_QUERY_INFORMATION;
        if (!str.isEmpty())
            str.append(" | ");
        str.append("PROCESS_QUERY_INFORMATION");
	}
	if (DesiredAccess & PROCESS_SUSPEND_RESUME)
	{
        DesiredAccess &= ~PROCESS_SUSPEND_RESUME;
        if (!str.isEmpty())
            str.append(" | ");
        str.append("PROCESS_SUSPEND_RESUME");
	}
	if (DesiredAccess & PROCESS_QUERY_LIMITED_INFORMATION)
	{
        DesiredAccess &= ~PROCESS_QUERY_LIMITED_INFORMATION;
        if (!str.isEmpty())
            str.append(" | ");
        str.append("PROCESS_QUERY_LIMITED_INFORMATION");
	}
	if (DesiredAccess & PROCESS_SET_LIMITED_INFORMATION)
	{
        DesiredAccess &= ~PROCESS_SET_LIMITED_INFORMATION;
        if (!str.isEmpty())
            str.append(" | ");
        str.append("PROCESS_SET_LIMITED_INFORMATION");
	}

    GetCommonDesiredAccess(DesiredAccess, str);
}

void GetThreadDesiredAccessString(ULONG DesiredAccess, QString &str)
{
    if (DesiredAccess == THREAD_ALL_ACCESS)
    {
        str = "THREAD_ALL_ACCESS";
        return;
    }
    if (DesiredAccess & THREAD_TERMINATE)
    {
        DesiredAccess &= ~THREAD_TERMINATE;
        if (!str.isEmpty())
            str.append(" | ");
        str.append("THREAD_TERMINATE");
    }
    if (DesiredAccess & THREAD_SUSPEND_RESUME)
    {
        DesiredAccess &= ~THREAD_SUSPEND_RESUME;
        if (!str.isEmpty())
            str.append(" | ");
        str.append("THREAD_SUSPEND_RESUME");
    }
    if (DesiredAccess & THREAD_GET_CONTEXT)
    {
        DesiredAccess &= ~THREAD_GET_CONTEXT;
        if (!str.isEmpty())
            str.append(" | ");
        str.append("THREAD_GET_CONTEXT");
    }
    if (DesiredAccess & THREAD_SET_CONTEXT)
    {
        DesiredAccess &= ~THREAD_SET_CONTEXT;
        if (!str.isEmpty())
            str.append(" | ");
        str.append("THREAD_SET_CONTEXT");
    }
    if (DesiredAccess & THREAD_QUERY_INFORMATION)
    {
        DesiredAccess &= ~THREAD_QUERY_INFORMATION;
        if (!str.isEmpty())
            str.append(" | ");
        str.append("THREAD_QUERY_INFORMATION");
    }
    if (DesiredAccess & THREAD_SET_INFORMATION)
    {
        DesiredAccess &= ~THREAD_SET_INFORMATION;
        if (!str.isEmpty())
            str.append(" | ");
        str.append("THREAD_SET_INFORMATION");
    }
    if (DesiredAccess & THREAD_SET_THREAD_TOKEN)
    {
        DesiredAccess &= ~THREAD_SET_THREAD_TOKEN;
        if (!str.isEmpty())
            str.append(" | ");
        str.append("THREAD_SET_THREAD_TOKEN");
    }
    if (DesiredAccess & THREAD_IMPERSONATE)
    {
        DesiredAccess &= ~THREAD_IMPERSONATE;
        if (!str.isEmpty())
            str.append(" | ");
        str.append("THREAD_IMPERSONATE");
    }
    if (DesiredAccess & THREAD_DIRECT_IMPERSONATION)
    {
        DesiredAccess &= ~THREAD_DIRECT_IMPERSONATION;
        if (!str.isEmpty())
            str.append(" | ");
        str.append("THREAD_DIRECT_IMPERSONATION");
    }
    if (DesiredAccess & THREAD_SET_LIMITED_INFORMATION)
    {
        DesiredAccess &= ~THREAD_SET_LIMITED_INFORMATION;
        if (!str.isEmpty())
            str.append(" | ");
        str.append("THREAD_SET_LIMITED_INFORMATION");
    }
    if (DesiredAccess & THREAD_QUERY_LIMITED_INFORMATION)
    {
        DesiredAccess &= ~THREAD_QUERY_LIMITED_INFORMATION;
        if (!str.isEmpty())
            str.append(" | ");
        str.append("THREAD_QUERY_LIMITED_INFORMATION");
    }
    if (DesiredAccess & THREAD_RESUME)
    {
        DesiredAccess &= ~THREAD_RESUME;
        if (!str.isEmpty())
            str.append(" | ");
        str.append("THREAD_RESUME");
    }

    GetCommonDesiredAccess(DesiredAccess, str);
}

QString GetMemoryInformationClassString(ULONG QueryClass)
{
    switch(QueryClass)
    {
    case MemoryBasicInformationEx:
        return "MemoryBasicInformation";
    case MemoryWorkingSetInformation:
        return "MemoryWorkingSetInformation";
    case MemoryMappedFilenameInformation:
        return "MemoryMappedFilenameInformation";
    case MemoryRegionInformation:
        return "MemoryRegionInformation";
    case MemoryWorkingSetExInformation:
        return "MemoryWorkingSetExInformation";
    }
    return QObject::tr("Unknown MemoryInformationClass");
}

QString FormatHexString(ULONG64 addr, int width)
{
    return QString("%1").arg(addr, width, 16, QChar('0')).toUpper();
}

QString GetMemoryStateString(ULONG State)
{
    switch(State)
    {
    case MEM_COMMIT:
        return "MEM_COMMIT";
    case MEM_FREE:
        return "MEM_FREE";
    case MEM_RESERVE:
        return "MEM_RESERVE";
    default:
        return "Unknown MemoryState";
    }
}

QString GetMemoryTypeString(ULONG Type)
{
    switch(Type)
    {
    case MEM_IMAGE:
        return "MEM_IMAGE";
    case MEM_MAPPED:
        return "MEM_MAPPED";
    case MEM_PRIVATE:
        return "MEM_PRIVATE";
    default:
        return "";
    }
}

void NormalizeFilePath(LPCWSTR szFilePath, std::wstring &normalized)
{
    if (!_wcsnicmp(szFilePath, L"\\SystemRoot\\", _ARRAYSIZE(L"\\SystemRoot\\") - 1))
    {
        TCHAR szSystemDirectory[MAX_PATH];
        GetSystemWindowsDirectory(szSystemDirectory, MAX_PATH);
        normalized = szSystemDirectory;
        normalized += L"\\";
        normalized += (LPCWSTR)(szFilePath + _ARRAYSIZE(L"\\SystemRoot\\") - 1);
    }
    else if(!_wcsnicmp(szFilePath, L"\\??\\", _ARRAYSIZE(L"\\??\\") - 1))
    {
        normalized = (LPCWSTR)(szFilePath + _ARRAYSIZE(L"\\??\\") - 1);
    }
    else
    {
        normalized = szFilePath;
    }
}

QString GetWindowsHookTypeString(int type)
{
    switch (type)
    {
    case WH_MSGFILTER:
        return "WH_MSGFILTER";
    case WH_JOURNALRECORD:
        return "WH_JOURNALRECORD";
    case WH_JOURNALPLAYBACK:
        return "WH_JOURNALPLAYBACK";
    case WH_KEYBOARD:
        return "WH_KEYBOARD";
    case WH_GETMESSAGE:
        return "WH_GETMESSAGE";
    case WH_CALLWNDPROC:
        return "WH_CALLWNDPROC";
    case WH_CBT:
        return "WH_CBT";
    case WH_SYSMSGFILTER:
        return "WH_SYSMSGFILTER";
    case WH_MOUSE:
        return "WH_MOUSE";
    case WH_DEBUG:
        return "WH_DEBUG";
    case WH_SHELL:
        return "WH_SHELL";
    case WH_FOREGROUNDIDLE:
        return "WH_FOREGROUNDIDLE";
    case WH_CALLWNDPROCRET:
        return "WH_CALLWNDPROCRET";
    case WH_KEYBOARD_LL:
        return "WH_KEYBOARD_LL";
    case WH_MOUSE_LL:
        return "WH_MOUSE_LL";
    }
    return QObject::tr("Unknown hook type");
}

QString GetFileInformationClass(int queryClass)
{
    switch (queryClass)
    {
    case FileAccessInformation:
        return "FileAccessInformation";
    case FileAlignmentInformation:
        return "FileAlignmentInformation";
    case FileAllInformation:
        return "FileAllInformation";
    case FileAttributeTagInformation:
        return "FileAttributeTagInformation";
    case FileBasicInformation:
        return "FileBasicInformation";
    case FileEaInformation:
        return "FileEaInformation";
    case FileInternalInformation:
        return "FileInternalInformation";
    case FileIoPriorityHintInformation:
        return "FileIoPriorityHintInformation";
    case FileModeInformation:
        return "FileModeInformation";
    case FileNameInformation:
        return "FileNameInformation";
    case FileNetworkOpenInformation:
        return "FileNetworkOpenInformation";
    case FilePositionInformation:
        return "FilePositionInformation";
    case FileStandardInformation:
        return "FileStandardInformation";
    }
    return QObject::tr("Unknown query class %1").arg(queryClass);
}

void GetFileAttributesString(ULONG FileAttributes, QString &str)
{
    if (FileAttributes & FILE_ATTRIBUTE_ARCHIVE)
    {
        if (!str.isEmpty())
            str.append(" | ");
        str.append("FILE_ATTRIBUTE_ARCHIVE");
    }
    if (FileAttributes & FILE_ATTRIBUTE_COMPRESSED)
    {
        if (!str.isEmpty())
            str.append(" | ");
        str.append("FILE_ATTRIBUTE_COMPRESSED");
    }
    if (FileAttributes & FILE_ATTRIBUTE_DEVICE)
    {
        if (!str.isEmpty())
            str.append(" | ");
        str.append("FILE_ATTRIBUTE_DEVICE");
    }
    if (FileAttributes & FILE_ATTRIBUTE_DIRECTORY)
    {
        if (!str.isEmpty())
            str.append(" | ");
        str.append("FILE_ATTRIBUTE_DIRECTORY");
    }
    if (FileAttributes & FILE_ATTRIBUTE_ENCRYPTED)
    {
        if (!str.isEmpty())
            str.append(" | ");
        str.append("FILE_ATTRIBUTE_ENCRYPTED");
    }
    if (FileAttributes & FILE_ATTRIBUTE_HIDDEN)
    {
        if (!str.isEmpty())
            str.append(" | ");
        str.append("FILE_ATTRIBUTE_HIDDEN");
    }
    if (FileAttributes & FILE_ATTRIBUTE_NORMAL)
    {
        if (!str.isEmpty())
            str.append(" | ");
        str.append("FILE_ATTRIBUTE_NORMAL");
    }
    if (FileAttributes & FILE_ATTRIBUTE_NOT_CONTENT_INDEXED)
    {
        if (!str.isEmpty())
            str.append(" | ");
        str.append("FILE_ATTRIBUTE_NOT_CONTENT_INDEXED");
    }
    if (FileAttributes & FILE_ATTRIBUTE_OFFLINE)
    {
        if (!str.isEmpty())
            str.append(" | ");
        str.append("FILE_ATTRIBUTE_OFFLINE");
    }
    if (FileAttributes & FILE_ATTRIBUTE_READONLY)
    {
        if (!str.isEmpty())
            str.append(" | ");
        str.append("FILE_ATTRIBUTE_READONLY");
    }
    if (FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
    {
        if (!str.isEmpty())
            str.append(" | ");
        str.append("FILE_ATTRIBUTE_REPARSE_POINT");
    }
    if (FileAttributes & FILE_ATTRIBUTE_SPARSE_FILE)
    {
        if (!str.isEmpty())
            str.append(" | ");
        str.append("FILE_ATTRIBUTE_SPARSE_FILE");
    }
    if (FileAttributes & FILE_ATTRIBUTE_SYSTEM)
    {
        if (!str.isEmpty())
            str.append(" | ");
        str.append("FILE_ATTRIBUTE_SYSTEM");
    }
    if (FileAttributes & FILE_ATTRIBUTE_TEMPORARY)
    {
        if (!str.isEmpty())
            str.append(" | ");
        str.append("FILE_ATTRIBUTE_TEMPORARY");
    }
    if (FileAttributes & FILE_ATTRIBUTE_VIRTUAL)
    {
        if (!str.isEmpty())
            str.append(" | ");
        str.append("FILE_ATTRIBUTE_VIRTUAL");
    }
}

void GetKeyDesiredAccessString(ULONG DesiredAccess, QString &str)
{
    if (DesiredAccess == KEY_READ)
    {
        str = "KEY_READ";
        return;
    }
    if (DesiredAccess == KEY_WRITE)
    {
        str = "KEY_WRITE";
        return;
    }
    if (DesiredAccess == KEY_ALL_ACCESS)
    {
        str = "KEY_ALL_ACCESS";
        return;
    }

    if (DesiredAccess & KEY_QUERY_VALUE)
    {
        DesiredAccess &= ~KEY_QUERY_VALUE;
        if(!str.isEmpty())
            str.append(" | ");
        str.append("KEY_QUERY_VALUE");
    }
    if (DesiredAccess & KEY_SET_VALUE)
    {
        DesiredAccess &= ~KEY_SET_VALUE;
        if (!str.isEmpty())
            str.append(" | ");
        str.append("KEY_SET_VALUE");
    }
    if (DesiredAccess & KEY_CREATE_SUB_KEY)
    {
        DesiredAccess &= ~KEY_CREATE_SUB_KEY;
        if (!str.isEmpty())
            str.append(" | ");
        str.append("KEY_CREATE_SUB_KEY");
    }
    if (DesiredAccess & KEY_ENUMERATE_SUB_KEYS)
    {
        DesiredAccess &= ~KEY_ENUMERATE_SUB_KEYS;
        if (!str.isEmpty())
            str.append(" | ");
        str.append("KEY_ENUMERATE_SUB_KEYS");
    }
    if (DesiredAccess & KEY_CREATE_LINK)
    {
        DesiredAccess &= ~KEY_CREATE_LINK;
        if (!str.isEmpty())
            str.append(" | ");
        str.append("KEY_CREATE_LINK");
    }
    if (DesiredAccess & KEY_NOTIFY)
    {
        DesiredAccess &= ~KEY_NOTIFY;
        if (!str.isEmpty())
            str.append(" | ");
        str.append("KEY_NOTIFY");
    }

    GetCommonDesiredAccess(DesiredAccess, str);
}

void GetCreateKeyOptionsString(ULONG Options, QString &str)
{
    if (Options & REG_OPTION_VOLATILE)
    {
        if (!str.isEmpty())
            str.append(" | ");
        str.append("REG_OPTION_VOLATILE");
    }
    if (Options & REG_OPTION_NON_VOLATILE)
    {
        if (!str.isEmpty())
            str.append(" | ");
        str.append("REG_OPTION_NON_VOLATILE");
    }
    if (Options & REG_OPTION_CREATE_LINK)
    {
        if (!str.isEmpty())
            str.append(" | ");
        str.append("REG_OPTION_CREATE_LINK");
    }
    if (Options & REG_OPTION_BACKUP_RESTORE)
    {
        if (!str.isEmpty())
            str.append(" | ");
        str.append("REG_OPTION_BACKUP_RESTORE");
    }
}

QString GetCreateKeyDispositionString(ULONG CreateDisposition)
{
    switch (CreateDisposition)
    {
    case REG_CREATED_NEW_KEY:
        return "REG_CREATED_NEW_KEY";
    case REG_OPENED_EXISTING_KEY:
        return "REG_OPENED_EXISTING_KEY";
    }
    return "";
}

QString NumberToCurrencyString(ULONG64 f)
{
    QString strF = QString::number((qlonglong)f);
    int pos = strF.size() - 6;
    while (pos > 0)
    {
        strF = strF.insert(pos, QChar(','));
        pos -= 3;
    }
    return strF;
}

QString FormatFileSizeString(ULONG64 fileSize)
{
    QString str;

    if(fileSize <= 1024ULL)
    {
        return QObject::tr("%1 Bytes").arg(fileSize);
    }
    else if(fileSize <= 1024ULL * 1024ULL)
    {
        str += QObject::tr("%1 KB").arg(fileSize / (double)(1024ULL), 0, 'f', 3);
    }
    else if(fileSize <= 1024ULL * 1024ULL * 1024ULL)
    {
        str += QObject::tr("%1 MB").arg(fileSize / (double)(1024ULL * 1024ULL), 0, 'f', 3);
    }
    else if(fileSize <= 1024ULL * 1024ULL * 1024ULL * 1024ULL)
    {
        str += QObject::tr("%1 GB").arg(fileSize / (double)(1024ULL * 1024ULL * 1024ULL), 0, 'f', 3);
    }
    else if(fileSize <= 1024ULL * 1024ULL * 1024ULL * 1024ULL * 1024ULL)
    {
        str += QObject::tr("%1 TB").arg(fileSize / (double)(1024ULL * 1024ULL * 1024ULL * 1024ULL), 0, 'f', 3);
    }

    str += QObject::tr(" (%1 Bytes)").arg(NumberToCurrencyString(fileSize));
    return str;
}

QString GetRegistryKeyDataType(ULONG DataType)
{
    switch(DataType){
        case REG_NONE: return "REG_NONE";
        case REG_SZ: return "REG_SZ";
        case REG_EXPAND_SZ: return "REG_SZ";

        case REG_BINARY: return "REG_BINARY";
        case REG_DWORD: return "REG_DWORD";
        case REG_DWORD_BIG_ENDIAN: return "REG_DWORD_BIG_ENDIAN";
        case REG_LINK: return "REG_LINK";
        case REG_MULTI_SZ: return "REG_MULTI_SZ";

        case REG_RESOURCE_LIST: return "REG_RESOURCE_LIST";
        case REG_FULL_RESOURCE_DESCRIPTOR: return "REG_FULL_RESOURCE_DESCRIPTOR";
        case REG_RESOURCE_REQUIREMENTS_LIST: return "REG_RESOURCE_REQUIREMENTS_LIST";

        case REG_QWORD: return "REG_QWORD";
    }
    return QString("Unknown DataType(%1)").arg(DataType);
}

int32_t swapInt32(int32_t value)
{
     return ((value & 0x000000FF) << 24) |
               ((value & 0x0000FF00) << 8) |
               ((value & 0x00FF0000) >> 8) |
               ((value & 0xFF000000) >> 24) ;
}

QString GetRegistryQueryValueKeyClass(ULONG QueryClass)
{
    switch(QueryClass){
        case KeyValueBasicInformation: return "KeyValueBasicInformation";
        case KeyValueFullInformation: return "KeyValueFullInformation";
        case KeyValuePartialInformation: return "KeyValuePartialInformation";

        case KeyValueFullInformationAlign64: return "KeyValueFullInformationAlign64";
        case KeyValuePartialInformationAlign64: return "KeyValuePartialInformationAlign64";
    }
    return QString("Unknown QueryClass(%1)").arg(QueryClass);
}

QString GetRegistryQueryKeyClass(ULONG QueryClass)
{
    switch(QueryClass){
        case KeyBasicInformation: return "KeyBasicInformation";
        case KeyNodeInformation: return "KeyNodeInformation";
        case KeyFullInformation: return "KeyFullInformation";
        case KeyNameInformation: return "KeyNameInformation";
        case KeyCachedInformation: return "KeyCachedInformation";
        case KeyFlagsInformation: return "KeyFlagsInformation";
        case KeyVirtualizationInformation: return "KeyVirtualizationInformation";
        case KeyHandleTagsInformation: return "KeyHandleTagsInformation";
        case KeyTrustInformation: return "KeyTrustInformation";
    }
    return QString("Unknown QueryClass(%1)").arg(QueryClass);
}

void GetMutantDesiredAccessString(ULONG DesiredAccess, QString &str)
{
    if (DesiredAccess == MUTANT_ALL_ACCESS)
    {
        str = "MUTANT_ALL_ACCESS";
        return;
    }
    if (DesiredAccess & MUTANT_QUERY_STATE)
    {
        DesiredAccess &= ~MUTANT_QUERY_STATE;
        if(!str.isEmpty())
            str.append(" | ");
        str.append("MUTANT_QUERY_STATE");
    }
    GetCommonDesiredAccess(DesiredAccess, str);
}

void GetDirectoryObjectDesiredAccessString(ULONG DesiredAccess, QString &str)
{
    if (DesiredAccess == DIRECTORY_ALL_ACCESS)
    {
        str = "DIRECTORY_ALL_ACCESS";
        return;
    }
    if (DesiredAccess & DIRECTORY_QUERY)
    {
        DesiredAccess &= ~DIRECTORY_QUERY;
        if(!str.isEmpty())
            str.append(" | ");
        str.append("DIRECTORY_QUERY");
    }
    if (DesiredAccess & DIRECTORY_TRAVERSE)
    {
        DesiredAccess &= ~DIRECTORY_TRAVERSE;
        if(!str.isEmpty())
            str.append(" | ");
        str.append("DIRECTORY_TRAVERSE");
    }
    if (DesiredAccess & DIRECTORY_CREATE_OBJECT)
    {
        DesiredAccess &= ~DIRECTORY_CREATE_OBJECT;
        if(!str.isEmpty())
            str.append(" | ");
        str.append("DIRECTORY_CREATE_OBJECT");
    }
    if (DesiredAccess & DIRECTORY_CREATE_SUBDIRECTORY)
    {
        DesiredAccess &= ~DIRECTORY_CREATE_SUBDIRECTORY;
        if(!str.isEmpty())
            str.append(" | ");
        str.append("DIRECTORY_CREATE_SUBDIRECTORY");
    }
    GetCommonDesiredAccess(DesiredAccess, str);
}
