#pragma once

#include <vector>
#include <list>
#include <set>

typedef struct File_s
{
	UNICODE_STRING DosFileName;
	UNICODE_STRING NtFileName;
	UNICODE_STRING VolumelessFileName;//use same buffer with NtFileName
}File_t;

class CFileList
{
public:
	CFileList();
	~CFileList();

	NTSTATUS AddFile(PUNICODE_STRING DosFileName);
	BOOLEAN FindNtFile(PUNICODE_STRING NtFileName, BOOLEAN CaseInSensitive);
	BOOLEAN FindDosFile(PUNICODE_STRING DosFileName, BOOLEAN CaseInSensitive);
	void FreeAll(void);
private:
	BOOLEAN FindDosFileUnsafe(PUNICODE_STRING DosFileName, BOOLEAN CaseInSensitive);
	BOOLEAN FindNtFileUnsafe(PUNICODE_STRING NtFileName, BOOLEAN CaseInSensitive);
public:
	ERESOURCE m_Lock;
	std::vector<File_t> m_List;
};

class CProcList
{
public:
	CProcList();
	~CProcList();

	void AddProcess(HANDLE ProcessId);
	void RemoveProcess(HANDLE ProcessId);
	BOOLEAN Find(HANDLE ProcessId);
	void FreeAll(void);
public:
	ERESOURCE m_Lock;
	std::set<HANDLE> m_List;
};

class CEventList
{
public:
	CEventList();
	~CEventList();

	void FreeAll(void);
	void Lock(void);
	void Unlock(void);
	void NotifyEvent(void);
	void SendEvent(PVOID pEvent);
	bool IsCapturing(void);
	ULONG64 GetEventId(void);
public:
	FAST_MUTEX m_MsgLock;
	KEVENT m_MsgEvent;
	HANDLE m_hMsgThread;
	LONG m_Stop;
	volatile LONG m_EnableCapture;
	volatile LONG64 m_EventCount;
	std::list<PVOID> m_List;
};

typedef NTSTATUS(*typeFltMessageCallback)(
	IN PVOID InputBuffer OPTIONAL,
	IN ULONG InputBufferLength,
	OUT PVOID OutputBuffer OPTIONAL,
	IN ULONG OutputBufferLength,
	OUT PULONG ReturnOutputBufferLength
	);

typedef struct
{
	UCHAR protocol;
	typeFltMessageCallback fnParse;
}FltClientMessage_Parse_t;

typedef enum _WinVer
{
	WINVER_XP = 0x0510,
	WINVER_XP_SP1 = 0x0511,
	WINVER_XP_SP2 = 0x0512,
	WINVER_XP_SP3 = 0x0513,
	WINVER_VISTA = 0x0600,
	WINVER_7 = 0x0610,
	WINVER_7_SP1 = 0x0611,
	WINVER_8 = 0x0620,
	WINVER_81 = 0x0630,
	WINVER_10 = 0x0A00,
} WinVer;

/// <summary>
/// OS-dependent stuff
/// </summary>
typedef struct _DYNAMIC_DATA
{
	WinVer OsVer;
	ULONG PrevMode;         // KTHREAD::PreviousMode
	ULONG NtAllocIndex;   // NtProtectVirtualMemory SSDT index
	ULONG NtQueryIndex;   // NtQueryVirtualMemory SSDT index
	ULONG NtProtectIndex;   // NtProtectVirtualMemory SSDT index
	ULONG NtWriteIndex;     // NtWriteVirtualMemory SSDT index
	ULONG NtReadIndex;      // NtReadVirtualMemory SSDT index
	ULONG NtTerminateIndex;      // NtTerminateProcess SSDT index
	ULONG NtTermThrdIndex;      // NtTerminatThread SSDT index
	ULONG NtOpenProcIndex;      // NtOpenProcess SSDT index
	ULONG NtOpenThrdIndex;      // NtOpenThread SSDT index
	ULONG NtLoadDrvIndex;      // NtLoadDriver SSDT index
	ULONG NtCreateMutantIndex;      // NtCreateMutant SSDT index
	ULONG NtOpenMutantIndex;      // NtOpenMutant SSDT index
	ULONG NtCreateDirObjIndex;      // NtCreateDirectoryObject SSDT index
	ULONG NtOpenDirObjIndex;      // NtOpenDirectoryObject SSDT index
	ULONG NtQueryDirObjIndex;      // NtQueryDirectoryObject SSDT index
	PVOID pfnKiCallSystemService;
	PVOID pfnKiCallSystemServicePerf;
	PVOID pfnNtQuerySystemInformation;
	PVOID pfnNtTerminateProcess;
	PVOID pfnNtTerminatThread;
	PVOID pfnNtOpenProcess;
	PVOID pfnNtOpenThread;
	PVOID pfnNtAllocateVirtualMemory;
	PVOID pfnNtReadVirtualMemory;
	PVOID pfnNtWriteVirtualMemory;
	PVOID pfnNtQueryVirtualMemory;
	PVOID pfnNtProtectVirtualMemory;
	PVOID pfnNtLoadDriver;
	PVOID pfnNtCreateMutant;
	PVOID pfnNtOpenMutant;
	PVOID pfnNtCreateDirectoryObject;
	PVOID pfnNtOpenDirectoryObject;
	PVOID pfnNtQueryDirectoryObject;
	PVOID pfnNtUserSetWindowsHookEx;
	PVOID pfnNtUserSetWindowsHookAW;
	PVOID pfnNtUserFindWindowEx;
	PVOID pfnNtUserInternalGetWindowText;
	PVOID pfnNtUserGetClassName;
	BOOLEAN EnableVmx;
} DYNAMIC_DATA, *PDYNAMIC_DATA;

#define SYSCALLMON_TOLLEVEL_IRP ((PIRP)4396)