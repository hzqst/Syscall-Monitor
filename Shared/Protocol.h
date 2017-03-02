#pragma once

enum cls_protocol
{
	cls_nop,
	cls_set_capture_enable,
	cls_get_system_time,
	cls_get_image_path,
	cls_get_image_baseinfo,
	cls_get_process_path,
	cls_get_process_cmdline,
	cls_get_process_curdir,
	cls_get_process_baseinfo,
};

enum svc_protocol
{
	svc_nop,
	svc_callstack,
	svc_ps_create_process,
	svc_ps_create_thread,
	svc_ps_load_image,
	svc_nt_load_driver,
	svc_nt_query_systeminfo,
	svc_nt_open_process,
	svc_nt_open_thread,
	svc_nt_terminate_process,
	svc_nt_alloc_virtual_mem,
	svc_nt_readwrite_virtual_mem,
	svc_nt_protect_virtual_mem,
	svc_nt_query_virtual_mem,
	svc_nt_createopen_mutant,
	svc_nt_createopen_dirobj,
	svc_nt_query_dirobj,
	svc_nt_setwindowshook,
	svc_nt_findwindow,
	svc_nt_getwindowtext,
	svc_nt_getwindowclass,
	svc_fs_create_file,
	svc_fs_close_file,
	svc_fs_readwrite_file,
	svc_fs_createfilemapping,
	svc_fs_queryfileinformation,
	svc_reg_createopenkey,
	svc_reg_setvaluekey,
	svc_reg_queryvaluekey,
	svc_reg_querykey,
	svc_maximum
};

#define MAX_STACK_DEPTH 64

#pragma pack(1)

typedef struct
{
	ULONG txsb;
	ULONG NtUserSetWindowsHookExOffset;
	ULONG NtUserSetWindowsHookAWOffset;
	ULONG NtUserFindWindowExOffset;
	ULONG NtUserInternalGetWindowTextOffset;
	ULONG NtUserGetClassNameOffset;
}symbol_file_data;

typedef struct
{
	ULONG txsb;
	UCHAR ver;
}conn_context_data;

typedef struct
{
	UCHAR protocol;
	BOOLEAN Enable;
}cls_set_capture_enable_data;

typedef struct
{
	UCHAR protocol;
	ULONG ProcessId;
}cls_pid_data;

typedef struct
{
	UCHAR protocol;
	USHORT Length;
	WCHAR Buffer[1];
}cls_file_data;

typedef struct
{
	UCHAR protocol;
	ULONG ProcessId;
	ULONG64 BaseAddress;
}cls_get_image_data;

typedef struct
{
	ULONG64 ImageBase;
	ULONG ImageSize;
	BOOLEAN Is64Bit;
}cls_get_image_baseinfo_data;

typedef struct
{
	ULONG ParentProcessId;
	ULONGLONG CreateTime;
	BOOLEAN Is64Bit;
	ULONG SessionId;
}cls_get_process_baseinfo_data;

typedef struct
{
	WCHAR ImagePath[260];
}cls_get_process_imagepath_data;

//svc

typedef struct
{
	UCHAR protocol;
	ULONG size;
	ULONG64 time;
	ULONG64 eventId;
	ULONG ProcessId;
	ULONG ThreadId;
}svc_nop_data;

typedef struct
{
	UCHAR protocol;
	ULONG size;
	ULONG64 time;
	ULONG64 eventId;
	BOOLEAN Create;
	ULONG ProcessId;
	ULONG ThreadId;
	ULONG ParentProcessId;
	ULONGLONG CreateTime;
	BOOLEAN Is64Bit;
	ULONG SessionId;
	WCHAR ImagePath[260];
	WCHAR CommandLine[256];
	WCHAR CurDirectory[256];
}svc_ps_create_process_data;

typedef union
{
	ULONG All;
	struct 
	{
		ULONG SystemThread : 1;
		ULONG BreakOnTermination : 1;
		ULONG HideFromDebugger : 1;
	}Fields;
}SVC_ThreadFlags;

typedef struct
{
	UCHAR protocol;
	ULONG size;
	ULONG64 time;
	ULONG64 eventId;
	BOOLEAN Create;
	ULONG ProcessId;
	ULONG ThreadId;
	ULONG CurProcessId;
	ULONG CurThreadId;
	ULONG64 ThreadStartAddress;
	SVC_ThreadFlags ThreadFlags;
}svc_ps_create_thread_data;

typedef struct
{
	UCHAR protocol;
	ULONG size;
	ULONG64 time;
	ULONG64 eventId;
	ULONG ProcessId;
	ULONG ThreadId;
	ULONG64 ImageBase;
	ULONG ImageSize;
	WCHAR ImagePath[260];
}svc_ps_load_image_data;

typedef struct
{
	UCHAR protocol;
	ULONG size;
	ULONG64 time;
	ULONG64 eventId;
	ULONG ProcessId;
	ULONG ThreadId;
	ULONG QueryClass;
}svc_nt_query_systeminfo_data;

typedef struct
{
	UCHAR protocol;
	ULONG size;
	ULONG64 time;
	ULONG64 eventId;
	ULONG ProcessId;
	ULONG ThreadId;
	ULONG TargetProcessId;
	ULONG ResultStatus;
}svc_nt_terminate_process_data;

typedef struct
{
	UCHAR protocol;
	ULONG size;
	ULONG64 time;
	ULONG64 eventId;
	ULONG ProcessId;
	ULONG ThreadId;
	ULONG TargetProcessId;
	ULONG DesiredAccess;
	ULONG ResultStatus;
}svc_nt_open_process_data;

typedef struct
{
	UCHAR protocol;
	ULONG size;
	ULONG64 time;
	ULONG64 eventId;
	ULONG ProcessId;
	ULONG ThreadId;
	ULONG TargetProcessId;
	ULONG TargetThreadId;
	ULONG DesiredAccess;
	ULONG ResultStatus;
}svc_nt_open_thread_data;

typedef struct
{
	UCHAR protocol;
	ULONG size;
	ULONG64 time;
	ULONG64 eventId;
	ULONG ProcessId;
	ULONG ThreadId;
	ULONG TargetProcessId;
	ULONG64 OldBaseAddress;
	ULONG64 OldRegionSize;
	ULONG64 NewBaseAddress;
	ULONG64 NewRegionSize;
	ULONG AllocationType;
	ULONG Protect;
	ULONG ResultStatus;
}svc_nt_alloc_virtual_mem_data;

typedef struct
{
	UCHAR protocol;
	ULONG size;
	ULONG64 time;
	ULONG64 eventId;
	ULONG ProcessId;
	ULONG ThreadId;
	BOOLEAN IsWrite;
	ULONG TargetProcessId;
	ULONG64 BaseAddress;
	ULONG64 BufferSize;
	ULONG ResultStatus;
}svc_nt_readwrite_virtual_mem_data;

typedef struct
{
	UCHAR protocol;
	ULONG size;
	ULONG64 time;
	ULONG64 eventId;
	ULONG ProcessId;
	ULONG ThreadId;
	ULONG TargetProcessId;
	ULONG64 OldBaseAddress;
	ULONG64 OldRegionSize;
	ULONG64 NewBaseAddress;
	ULONG64 NewRegionSize;
	ULONG OldProtect;
	ULONG NewProtect;
	ULONG ResultStatus;
}svc_nt_protect_virtual_mem_data;

typedef struct _MEMORY_BASIC_INFORMATION_MY {
	ULONG64 BaseAddress;
	ULONG64 AllocationBase;
	ULONG AllocationProtect;
	ULONG64 RegionSize;
	ULONG State;
	ULONG Protect;
	ULONG Type;
} MEMORY_BASIC_INFORMATION_MY, *PMEMORY_BASIC_INFORMATION_MY;

typedef struct
{
	UCHAR protocol;
	ULONG size;
	ULONG64 time;
	ULONG64 eventId;
	ULONG ProcessId;
	ULONG ThreadId;
	ULONG TargetProcessId;
	ULONG64 BaseAddress;
	ULONG QueryClass;
	ULONG ResultStatus;
	union {
	    MEMORY_BASIC_INFORMATION_MY mbi;
	    WCHAR MappedFileName[260];
	};
}svc_nt_query_virtual_mem_data;

typedef struct
{
	UCHAR protocol;
	ULONG size;
	ULONG64 time;
	ULONG64 eventId;
	ULONG ProcessId;
	ULONG ThreadId;
	ULONG ResultStatus;
	WCHAR RegisterPath[260];
	WCHAR ImagePath[260];
}svc_nt_load_driver_data;

typedef struct
{
	UCHAR protocol;
	ULONG size;
	ULONG64 time;
	ULONG64 eventId;
	ULONG ProcessId;
	ULONG ThreadId;
	BOOLEAN IsOpen;
	BOOLEAN InitialOwner;
	ULONG DesiredAccess;
	ULONG ResultStatus;
	WCHAR MutexName[256];
}svc_nt_createopen_mutant_data;

typedef struct
{
	UCHAR protocol;
	ULONG size;
	ULONG64 time;
	ULONG64 eventId;
	ULONG ProcessId;
	ULONG ThreadId;
	BOOLEAN IsOpen;
	ULONG DesiredAccess;
	ULONG ResultStatus;
	WCHAR ObjectName[256];
}svc_nt_createopen_dirobj_data;

typedef struct
{
	UCHAR protocol;
	ULONG size;
	ULONG64 time;
	ULONG64 eventId;
	ULONG ProcessId;
	ULONG ThreadId;
	ULONG ResultStatus;
	WCHAR ObjectName[256];
}svc_nt_query_dirobj_data;

typedef struct
{
	UCHAR protocol;
	ULONG size;
	ULONG64 time;
	ULONG64 eventId;
	ULONG ProcessId;
	ULONG ThreadId;
	ULONG ResultHHook;
	ULONG HookThreadId;
	int HookType;
	ULONG64 HookProc;
	UCHAR Flags;
	ULONG64 Module;
	WCHAR ModuleName[260];
}svc_nt_setwindowshook_data;

typedef struct
{
	UCHAR protocol;
	ULONG size;
	ULONG64 time;
	ULONG64 eventId;
	ULONG ProcessId;
	ULONG ThreadId;
	ULONG ResultHwnd;
	ULONG HwndParent;
	ULONG HwndChild;
	WCHAR ClassName[256];
	WCHAR WindowName[256];	
}svc_nt_findwindow_data;

typedef struct
{
	UCHAR protocol;
	ULONG size;
	ULONG64 time;
	ULONG64 eventId;
	ULONG ProcessId;
	ULONG ThreadId;
	ULONG Hwnd;
	ULONG MaxCount;
	WCHAR WindowName[256];
	ULONG ResultCount;
}svc_nt_getwindowtext_data;

typedef struct
{
	UCHAR protocol;
	ULONG size;
	ULONG64 time;
	ULONG64 eventId;
	ULONG ProcessId;
	ULONG ThreadId;
	ULONG Hwnd;
	ULONG MaxCount;
	WCHAR WindowClass[256];
	ULONG ResultCount;
}svc_nt_getwindowclass_data;

typedef struct
{
	UCHAR protocol;
	ULONG size;
	ULONG64 time;
	ULONG64 eventId;
	ULONG ProcessId;
	ULONG ThreadId;
	ULONG DesiredAccess;
	ULONG Disposition;
	ULONG Options;
	ULONG ShareAccess;
	ULONG Attributes;
	ULONG ResultStatus;
	WCHAR FilePath[260];
}svc_fs_create_file_data;

typedef struct
{
	UCHAR protocol;
	ULONG size;
	ULONG64 time;
	ULONG64 eventId;
	ULONG ProcessId;
	ULONG ThreadId;
	ULONG ResultStatus;
	WCHAR FilePath[260];
}svc_fs_close_file_data;

typedef struct
{
	UCHAR protocol;
	ULONG size;
	ULONG64 time;
	ULONG64 eventId;
	ULONG ProcessId;
	ULONG ThreadId;
	BOOLEAN IsWrite;
	ULONG Length;
	ULONG64 ByteOffset;
	ULONG ResultStatus;
	WCHAR FilePath[260];
}svc_fs_readwrite_file_data;

typedef struct
{
	UCHAR protocol;
	ULONG size;
	ULONG64 time;
	ULONG64 eventId;
	ULONG ProcessId;
	ULONG ThreadId;
	ULONG SyncType;
	ULONG PageProtection;
	ULONG ResultStatus;
	WCHAR FilePath[260];
}svc_fs_createfilemapping_data;

typedef struct
{
	UCHAR protocol;
	ULONG size;
	ULONG64 time;
	ULONG64 eventId;
	ULONG ProcessId;
	ULONG ThreadId;
	ULONG QueryClass;
	ULONG ResultStatus;
	WCHAR FilePath[260];
	FILE_ALL_INFORMATION AllInfo;
}svc_fs_queryfileinformation_data;

typedef struct
{
	UCHAR protocol;
	ULONG size;
	ULONG64 time;
	ULONG64 eventId;
	ULONG ProcessId;
	ULONG ThreadId;
	BOOLEAN IsOpen;
	ULONG CreateOptions;
	ULONG DesiredAccess;
	ULONG Disposition;
	ULONG ResultStatus;
	WCHAR KeyPath[256];
}svc_reg_createopenkey_data;

typedef struct
{
	UCHAR protocol;
	ULONG size;
	ULONG64 time;
	ULONG64 eventId;
	ULONG ProcessId;
	ULONG ThreadId;
	ULONG ResultStatus;
	ULONG DataType;
	WCHAR ValueName[256];
	WCHAR KeyPath[256];
	ULONG DataSize;
	ULONG CopySize;
	UCHAR CopyData[1];
}svc_reg_setvaluekey_data;

typedef struct
{
	UCHAR protocol;
	ULONG size;
	ULONG64 time;
	ULONG64 eventId;
	ULONG ProcessId;
	ULONG ThreadId;
	ULONG ResultStatus;
	ULONG QueryClass;
	ULONG QueryLength;
	WCHAR ValueName[256];
	WCHAR KeyPath[256];
	//Output
	ULONG DataSize;
	ULONG CopySize;
	UCHAR CopyData[1];
}svc_reg_queryvaluekey_data;

typedef struct
{
	UCHAR protocol;
	ULONG size;
	ULONG64 time;
	ULONG64 eventId;
	ULONG ProcessId;
	ULONG ThreadId;
	ULONG ResultStatus;
	ULONG QueryClass;
	ULONG QueryLength;
	WCHAR KeyPath[256];
	//Output
	ULONG DataSize;
	ULONG CopySize;
	UCHAR CopyData[1];
}svc_reg_querykey_data;

typedef struct
{
	UCHAR protocol;
	ULONG size;
	ULONG64 time;
	ULONG64 eventId;
	ULONG KernelCallerCount;
	ULONG UserCallerCount;
	ULONG64 Callers[1];
}svc_callstack_data;

#pragma pack()
