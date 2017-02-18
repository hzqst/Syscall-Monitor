#pragma once

#include <QObject>
#include <QString>
#include <QThread>
#include <QLinkedList>

#include <Windows.h>
#include "ProcessMgr.h"
#include "EventFilter.h"
#include "StringMgr.h"
#include "nt.h"
#include "..\Shared\Protocol.h"

class CRegKeyValue;

enum EventClass_t
{
	EVClass_PsNotify,
	EVClass_Syscall,
	EVClass_FileSystem,
    EVClass_Registry,

    //Do not use
    EVClass_Maximum,
};

enum EventType_t
{
	EV_ProcessCreate = 0,
	EV_ProcessDestroy,
    EV_CreateProcess,
    EV_ThreadCreate,
    EV_ThreadDestroy,
    EV_CreateThread,
	EV_LoadImage,
	EV_LoadDriver,
	EV_EnumProcess,
	EV_EnumSystemModule,
	EV_EnumSystemHandle,
    EV_EnumSystemObject,
	EV_OpenProcess,
    EV_OpenThread,
	EV_TerminateProcess,
    EV_AllocateVirtualMemory,
	EV_ReadVirtualMemory,
	EV_WriteVirtualMemory,
	EV_ProtectVirtualMemory,
    EV_QueryVirtualMemory,
    EV_CreateMutex,
    EV_OpenMutex,
    EV_CreateDirectoryObject,
    EV_OpenDirectoryObject,
    EV_QueryDirectoryObject,
    EV_SetWindowsHook,
    EV_FindWindow,
    EV_GetWindowText,
    EV_GetWindowClass,
	EV_CreateFile,
	EV_CloseFile,
	EV_ReadFile,
	EV_WriteFile,
	EV_CreateFileMapping,
    EV_QueryFileInformation,
    EV_CreateKey,
    EV_OpenKey,
    EV_SetValueKey,
    EV_QueryValueKey,
    EV_QueryKey,
    //do not use
    EV_Maximum,
};

class CCallStack
{
public:
    CCallStack(ULONG64 ReturnAddress, CUniqueModule *um);

    ULONG64 m_ReturnAddress;
    CUniqueModule *m_UniqueModule;
};

typedef QList<CCallStack> CCallStackList;

class CUniqueEvent
{
public:
    CUniqueEvent(CUniqueProcess *up, ULONG ThreadId, ULONG64 KeSystemTime, ULONG64 EventId);
    //void* operator new(size_t size);
    //void operator delete(void*p);

    virtual ULONG64 GetEventId(void) const { return m_EventId; }
    virtual CUniqueProcess *GetUniqueProcess() const { return m_UniqueProcess; }
    virtual ULONG GetThreadId(void) const { return m_ThreadId; }
    virtual ULONG GetProcessId(void) const { return m_UniqueProcess->m_ProcessId; }
    virtual QString GetProcessName(void) const { return m_UniqueProcess->m_ProcessName; }
    virtual QString GetProcessPath(void) const { return m_UniqueProcess->m_ImagePath; }
    virtual QString GetEventPath(void) const { return m_UniqueProcess->m_ImagePath; }
    virtual ULONG64 GetEventTime(void) const { return m_EventTime; }
    virtual QString GetDisplayName(void) const { return m_UniqueProcess->GetDisplayName(); }
    virtual QString GetEventName(void) const;
    virtual QString GetEventClassName(void) const;    
    virtual void GetFullArgument(QString &str) const { str = ""; }
    virtual void GetBriefArgument(QString &str) const { str = ""; }
    virtual void GetBriefResult(QString &str) const { str = ""; }
    virtual EventType_t GetEventType(void) const = 0;
    virtual EventClass_t GetEventClassify(void) const = 0;

protected:
	CUniqueProcess *m_UniqueProcess;
    ULONG m_ThreadId;
    ULONG64 m_EventTime;
    ULONG64 m_EventId;
public:
    ULONG m_KernelCallerCount;
    CCallStackList m_CallStacks;
};

//A link to the CUniqueEvent
class CUniqueEventLink
{
public:
    ULONG64 m_EventTime;
    ULONG64 m_EventId;
};

class CUniqueEvent_WithStatusResult : public CUniqueEvent
{
public:
    CUniqueEvent_WithStatusResult(CUniqueProcess *up, ULONG ThreadId, ULONG ResultStatus, ULONG64 KeSystemTime, ULONG64 EventId);
    virtual void GetBriefResult(QString &str) const;
protected:
    ULONG m_ResultStatus;
};

class CUniqueEvent_WithTargetProcess : public CUniqueEvent_WithStatusResult
{
public:
    CUniqueEvent_WithTargetProcess(CUniqueProcess *up, ULONG ThreadId, CUniqueProcess *TargetProcess, ULONG ResultStatus, ULONG64 KeSystemTime, ULONG64 EventId);
    virtual void GetBriefArgument(QString &str) const;
    virtual void GetFullArgument(QString &str) const;
protected:
    CUniqueProcess *m_TargetProcess;
};

class CUniqueEvent_WithTargetFile : public CUniqueEvent_WithStatusResult
{
public:
    CUniqueEvent_WithTargetFile(CUniqueProcess *up, ULONG ThreadId, std::wstring &filePath, ULONG ResultStatus, ULONG64 KeSystemTime, ULONG64 EventId);
    CUniqueEvent_WithTargetFile(CUniqueProcess *up, ULONG ThreadId, LPCWSTR szFilePath, ULONG ResultStatus, ULONG64 KeSystemTime, ULONG64 EventId);
    virtual QString GetEventPath(void) const { return m_FilePath.GetQString(); }
protected:
    CUniqueString m_FilePath;
};

class CUniqueEvent_ProcessCreate : public CUniqueEvent
{
public:
    CUniqueEvent_ProcessCreate(CUniqueProcess *up, ULONG ThreadId, ULONG64 KeSystemTime, ULONG64 EventId);
    virtual EventType_t GetEventType(void) const { return EV_ProcessCreate; }
    virtual EventClass_t GetEventClassify(void) const { return EVClass_PsNotify; }
    virtual void GetBriefArgument(QString &str) const;
    virtual void GetFullArgument(QString &str) const;
};

class CUniqueEvent_ProcessDestroy : public CUniqueEvent
{
public:
    CUniqueEvent_ProcessDestroy(CUniqueProcess *up, ULONG ThreadId, ULONG64 KeSystemTime, ULONG64 EventId);
    virtual EventType_t GetEventType(void) const { return EV_ProcessDestroy; }
    virtual EventClass_t GetEventClassify(void) const { return EVClass_PsNotify; }
};

class CUniqueEvent_CreateProcess : public CUniqueEvent_WithTargetProcess
{
public:
    CUniqueEvent_CreateProcess(CUniqueProcess *up, ULONG ThreadId, CUniqueProcess *target, ULONG64 KeSystemTime, ULONG64 EventId);
    virtual EventType_t GetEventType(void) const { return EV_CreateProcess; }
    virtual EventClass_t GetEventClassify(void) const { return EVClass_PsNotify; }
    virtual QString GetEventPath(void) const { return m_TargetProcess->m_ImagePath; }
    virtual void GetBriefArgument(QString &str) const;
    virtual void GetFullArgument(QString &str) const;
};

class CUniqueEvent_ThreadCreate : public CUniqueEvent
{
public:
    CUniqueEvent_ThreadCreate(CUniqueProcess *up, ULONG ThreadId, CUniqueProcess *CreatorProcess, ULONG CreatorThreadId,
                              ULONG64 StartAddress, SVC_ThreadFlags ThreadFlags, ULONG64 KeSystemTime, ULONG64 EventId);
    virtual QString GetEventPath(void) const { return ""; }
    virtual EventType_t GetEventType(void) const { return EV_ThreadCreate; }
    virtual EventClass_t GetEventClassify(void) const { return EVClass_PsNotify; }
    virtual void GetBriefArgument(QString &str) const;
    virtual void GetFullArgument(QString &str) const;
private:
    CUniqueProcess *m_CreatorProcess;
    ULONG m_CreatorThreadId;
    ULONG64 m_StartAddress;
    SVC_ThreadFlags m_ThreadFlags;
};

class CUniqueEvent_ThreadDestroy : public CUniqueEvent
{
public:
    CUniqueEvent_ThreadDestroy(CUniqueProcess *up, ULONG ThreadId, ULONG64 KeSystemTime, ULONG64 EventId);
    virtual QString GetEventPath(void) const { return ""; }
    virtual EventType_t GetEventType(void) const { return EV_ThreadDestroy; }
    virtual EventClass_t GetEventClassify(void) const { return EVClass_PsNotify; }
    virtual void GetBriefArgument(QString &str) const;
};

class CUniqueEvent_CreateThread : public CUniqueEvent_WithTargetProcess
{
public:
    CUniqueEvent_CreateThread(CUniqueProcess *up, ULONG ThreadId, CUniqueProcess *target, ULONG NewThreadId, ULONG64 KeSystemTime, ULONG64 EventId);
    virtual EventType_t GetEventType(void) const { return EV_CreateThread; }
    virtual EventClass_t GetEventClassify(void) const { return EVClass_PsNotify; }
    virtual void GetBriefArgument(QString &str) const;
    virtual void GetFullArgument(QString &str) const;
private:
    ULONG m_NewThreadId;
};

class CUniqueEvent_LoadImage : public CUniqueEvent
{
public:
    CUniqueEvent_LoadImage(CUniqueProcess *up, ULONG ThreadId, LPCWSTR szImagePath, ULONG64 ImageBase, ULONG ImageSize, ULONG64 KeSystemTime, ULONG64 EventId);
    virtual QString GetEventPath(void) const { return m_ImagePath; }
    virtual EventType_t GetEventType(void) const { return EV_LoadImage; }
    virtual EventClass_t GetEventClassify(void) const { return EVClass_PsNotify; }
    virtual void GetFullArgument(QString &str) const;
private:
    QString m_ImagePath;
	ULONG64 m_ImageBase;
    ULONG64 m_ImageSize;
};

class CUniqueEvent_LoadDriver : public CUniqueEvent_WithStatusResult
{
public:
    CUniqueEvent_LoadDriver(CUniqueProcess *up, ULONG ThreadId, LPCWSTR szServiceName, LPCWSTR szImagePath, ULONG ResultStatus, ULONG64 KeSystemTime, ULONG64 EventId);
    virtual QString GetEventPath(void) const { return m_ImagePath; }
    virtual EventType_t GetEventType(void) const { return EV_LoadDriver; }
    virtual EventClass_t GetEventClassify(void) const { return EVClass_Syscall; }
    virtual void GetBriefArgument(QString &str) const;
    virtual void GetFullArgument(QString &str) const;
private:
    QString m_ServiceName;
    QString m_ImagePath;
};

class CUniqueEvent_EnumProcess : public CUniqueEvent
{
public:
    CUniqueEvent_EnumProcess(CUniqueProcess *up, ULONG ThreadId, ULONG64 KeSystemTime, ULONG64 EventId);
    virtual QString GetEventPath(void) const { return ""; }
    virtual EventType_t GetEventType(void) const { return EV_EnumProcess; }
    virtual EventClass_t GetEventClassify(void) const { return EVClass_Syscall; }
};

class CUniqueEvent_EnumSystemModule : public CUniqueEvent
{
public:
    CUniqueEvent_EnumSystemModule(CUniqueProcess *up, ULONG ThreadId, ULONG64 KeSystemTime, ULONG64 EventId);
    virtual QString GetEventPath(void) const { return ""; }
    virtual EventType_t GetEventType(void) const { return EV_EnumSystemModule; }
    virtual EventClass_t GetEventClassify(void) const { return EVClass_Syscall; }
};

class CUniqueEvent_EnumSystemHandle : public CUniqueEvent
{
public:
    CUniqueEvent_EnumSystemHandle(CUniqueProcess *up, ULONG ThreadId, ULONG64 KeSystemTime, ULONG64 EventId);
    virtual QString GetEventPath(void) const { return ""; }
    virtual EventType_t GetEventType(void) const { return EV_EnumSystemHandle; }
    virtual EventClass_t GetEventClassify(void) const { return EVClass_Syscall; }
};

class CUniqueEvent_EnumSystemObject : public CUniqueEvent
{
public:
    CUniqueEvent_EnumSystemObject(CUniqueProcess *up, ULONG ThreadId, ULONG64 KeSystemTime, ULONG64 EventId);
    virtual QString GetEventPath(void) const { return ""; }
    virtual EventType_t GetEventType(void) const { return EV_EnumSystemObject; }
    virtual EventClass_t GetEventClassify(void) const { return EVClass_Syscall; }
};

class CUniqueEvent_OpenProcess : public CUniqueEvent_WithTargetProcess
{
public:
    CUniqueEvent_OpenProcess(CUniqueProcess *up, ULONG ThreadId, CUniqueProcess *TargetProcess,
                             ULONG DesireAccess, ULONG ResultStatus, ULONG64 KeSystemTime, ULONG64 EventId);
    virtual QString GetEventPath(void) const { return m_TargetProcess->m_ImagePath; }
    virtual EventType_t GetEventType(void) const { return EV_OpenProcess; }
    virtual EventClass_t GetEventClassify(void) const { return EVClass_Syscall; }
    virtual void GetBriefArgument(QString &str) const;
    virtual void GetFullArgument(QString &str) const;
private:
    ULONG m_DesireAccess;
};

class CUniqueEvent_OpenThread : public CUniqueEvent_WithTargetProcess
{
public:
    CUniqueEvent_OpenThread(CUniqueProcess *up, ULONG ThreadId, CUniqueProcess *target,
                            ULONG TargetThreadId, ULONG DesireAccess,
                            ULONG ResultStatus, ULONG64 KeSystemTime, ULONG64 EventId);
    virtual EventType_t GetEventType(void) const { return EV_OpenThread; }
    virtual EventClass_t GetEventClassify(void) const { return EVClass_PsNotify; }
    virtual void GetBriefArgument(QString &str) const;
    virtual void GetFullArgument(QString &str) const;
private:
    ULONG m_TargetThreadId;
    ULONG m_DesireAccess;
};

class CUniqueEvent_TerminateProcess : public CUniqueEvent_WithTargetProcess
{
public:
    CUniqueEvent_TerminateProcess(CUniqueProcess *up, ULONG ThreadId, CUniqueProcess *TargetProcess, ULONG ResultStatus, ULONG64 KeSystemTime, ULONG64 EventId);
    virtual QString GetEventPath(void) const { return ""; }
    virtual EventType_t GetEventType(void) const { return EV_TerminateProcess; }
    virtual EventClass_t GetEventClassify(void) const { return EVClass_Syscall; }
};

class CUniqueEvent_AllocateVirtualMemory : public CUniqueEvent_WithTargetProcess
{
public:
    CUniqueEvent_AllocateVirtualMemory(CUniqueProcess *up, ULONG ThreadId, CUniqueProcess *TargetProcess,
                                       ULONG64 OldBaseAddress, ULONG64 OldRegionSize, ULONG64 NewBaseAddress,
                                       ULONG64 NewRegionSize, ULONG AllocationType, ULONG Protect,
                                       ULONG ResultStatus, ULONG64 KeSystemTime, ULONG64 EventId);
    virtual QString GetEventPath(void) const { return ""; }
    virtual EventType_t GetEventType(void) const { return EV_AllocateVirtualMemory; }
    virtual EventClass_t GetEventClassify(void) const { return EVClass_Syscall; }
    virtual void GetFullArgument(QString &str) const;
private:
    ULONG64 m_OldBaseAddress;
    ULONG64 m_OldRegionSize;
    ULONG64 m_NewBaseAddress;
    ULONG64 m_NewRegionSize;
    ULONG m_AllocationType;
    ULONG m_Protect;
};

class CUniqueEvent_ReadVirtualMemory : public CUniqueEvent_WithTargetProcess
{
public:
    CUniqueEvent_ReadVirtualMemory(CUniqueProcess *up, ULONG ThreadId, CUniqueProcess *TargetProcess,
                                   ULONG64 BaseAddress, ULONG64 BufferSize, ULONG ResultStatus, ULONG64 KeSystemTime, ULONG64 EventId);
    virtual QString GetEventPath(void) const { return ""; }
    virtual EventType_t GetEventType(void) const { return EV_ReadVirtualMemory; }
    virtual EventClass_t GetEventClassify(void) const { return EVClass_Syscall; }
    virtual void GetFullArgument(QString &str) const;
private:
	ULONG64 m_BaseAddress;
    ULONG64 m_BufferSize;
};

class CUniqueEvent_WriteVirtualMemory : public CUniqueEvent_WithTargetProcess
{
public:
    CUniqueEvent_WriteVirtualMemory(CUniqueProcess *up, ULONG ThreadId, CUniqueProcess *TargetProcess,
                                    ULONG64 BaseAddress, ULONG64 BufferSize, ULONG ResultStatus, ULONG64 KeSystemTime, ULONG64 EventId);
    virtual QString GetEventPath(void) const { return ""; }
    virtual EventType_t GetEventType(void) const { return EV_WriteVirtualMemory; }
    virtual EventClass_t GetEventClassify(void) const { return EVClass_Syscall; }
    virtual void GetFullArgument(QString &str) const;
private:
	ULONG64 m_BaseAddress;
    ULONG64 m_BufferSize;
};

class CUniqueEvent_ProtectVirtualMemory : public CUniqueEvent_WithTargetProcess
{
public:
    CUniqueEvent_ProtectVirtualMemory(CUniqueProcess *up, ULONG ThreadId, CUniqueProcess *TargetProcess,
                                      ULONG64 OldBaseAddress, ULONG64 OldBufferSize, ULONG64 NewBaseAddress,
                                      ULONG64 NewBufferSize, ULONG OldProtect, ULONG NewProtect,
                                      ULONG ResultStatus, ULONG64 KeSystemTime, ULONG64 EventId);
    virtual QString GetEventPath(void) const { return ""; }
    virtual EventType_t GetEventType(void) const { return EV_ProtectVirtualMemory; }
    virtual EventClass_t GetEventClassify(void) const { return EVClass_Syscall; }
    virtual void GetFullArgument(QString &str) const;
private:
	ULONG64 m_OldBaseAddress;
	ULONG64 m_OldBufferSize;
	ULONG64 m_NewBaseAddress;
    ULONG64 m_NewBufferSize;
    ULONG m_OldProtect, m_NewProtect;
};

class CUniqueEvent_QueryVirtualMemory : public CUniqueEvent_WithTargetProcess
{
public:
    CUniqueEvent_QueryVirtualMemory(CUniqueProcess *up, ULONG ThreadId, CUniqueProcess *TargetProcess,
                                    ULONG64 BaseAddress, ULONG QueryClass, ULONG ResultStatus,
                                    ULONG64 KeSystemTime, ULONG64 EventId);
    virtual QString GetEventPath(void) const { return ""; }
    virtual EventType_t GetEventType(void) const { return EV_QueryVirtualMemory; }
    virtual EventClass_t GetEventClassify(void) const { return EVClass_Syscall; }
    virtual void GetBriefArgument(QString &str) const;
    virtual void GetFullArgument(QString &str) const;
private:
    //Input
    ULONG64 m_BaseAddress;
    ULONG m_QueryClass;

    MEMORY_BASIC_INFORMATION_MY m_mbi;
};

class CUniqueEvent_QueryVirtualMemory_BasicInformation : public CUniqueEvent_QueryVirtualMemory
{
public:
    CUniqueEvent_QueryVirtualMemory_BasicInformation(CUniqueProcess *up, ULONG ThreadId, CUniqueProcess *TargetProcess,
                                    ULONG64 BaseAddress, PMEMORY_BASIC_INFORMATION_MY pmbi, ULONG ResultStatus,
                                    ULONG64 KeSystemTime, ULONG64 EventId);
    virtual void GetFullArgument(QString &str) const;
private:
    //Output
    MEMORY_BASIC_INFORMATION_MY m_mbi;
};

class CUniqueEvent_QueryVirtualMemory_MappedFileName : public CUniqueEvent_QueryVirtualMemory
{
public:
    CUniqueEvent_QueryVirtualMemory_MappedFileName(CUniqueProcess *up, ULONG ThreadId, CUniqueProcess *TargetProcess,
                                    ULONG64 BaseAddress, LPCWSTR szMappedFilePath, ULONG ResultStatus,
                                    ULONG64 KeSystemTime, ULONG64 EventId);
    virtual void GetFullArgument(QString &str) const;
private:
    //Output
    QString m_MappedFilePath;
};

//Mutex

class CUniqueEvent_OpenMutex : public CUniqueEvent_WithTargetFile
{
public:
    CUniqueEvent_OpenMutex(CUniqueProcess *up, ULONG ThreadId, LPCWSTR szMutexName,
                                    ULONG DesiredAccess, ULONG ResultStatus,
                                    ULONG64 KeSystemTime, ULONG64 EventId);
    virtual QString GetEventPath(void) const { return m_FilePath.GetQString(); }
    virtual EventType_t GetEventType(void) const { return EV_OpenMutex; }
    virtual EventClass_t GetEventClassify(void) const { return EVClass_Syscall; }
    virtual void GetBriefArgument(QString &str) const;
    virtual void GetFullArgument(QString &str) const;
protected:
    //Input
    ULONG m_DesiredAccess;
};

class CUniqueEvent_CreateMutex : public CUniqueEvent_OpenMutex
{
public:
    CUniqueEvent_CreateMutex(CUniqueProcess *up, ULONG ThreadId, LPCWSTR szMutexName,
                                    ULONG DesiredAccess, bool InitialOwner, ULONG ResultStatus,
                                    ULONG64 KeSystemTime, ULONG64 EventId);
    virtual EventType_t GetEventType(void) const { return EV_CreateMutex; }
    virtual void GetFullArgument(QString &str) const;
private:
    //Input
    bool m_InitialOwner;
};

class CUniqueEvent_OpenDirectoryObject : public CUniqueEvent_WithTargetFile
{
public:
    CUniqueEvent_OpenDirectoryObject(CUniqueProcess *up, ULONG ThreadId, LPCWSTR szObjectName,
                                    ULONG DesiredAccess, ULONG ResultStatus,
                                    ULONG64 KeSystemTime, ULONG64 EventId);
    virtual QString GetEventPath(void) const { return m_FilePath.GetQString(); }
    virtual EventType_t GetEventType(void) const { return EV_OpenDirectoryObject; }
    virtual EventClass_t GetEventClassify(void) const { return EVClass_Syscall; }
    virtual void GetBriefArgument(QString &str) const;
    virtual void GetFullArgument(QString &str) const;
protected:
    //Input
    ULONG m_DesiredAccess;
};

class CUniqueEvent_CreateDirectoryObject : public CUniqueEvent_OpenDirectoryObject
{
public:
    CUniqueEvent_CreateDirectoryObject(CUniqueProcess *up, ULONG ThreadId, LPCWSTR szObjectName,
                                    ULONG DesiredAccess, ULONG ResultStatus,
                                    ULONG64 KeSystemTime, ULONG64 EventId);
    virtual EventType_t GetEventType(void) const { return EV_CreateDirectoryObject; }
private:
    //Input
};

class CUniqueEvent_QueryDirectoryObject : public CUniqueEvent_WithTargetFile
{
public:
    CUniqueEvent_QueryDirectoryObject(CUniqueProcess *up, ULONG ThreadId, LPCWSTR szObjectName,
                                    ULONG ResultStatus, ULONG64 KeSystemTime, ULONG64 EventId);
    virtual QString GetEventPath(void) const { return m_FilePath.GetQString(); }
    virtual EventType_t GetEventType(void) const { return EV_QueryDirectoryObject; }
    virtual EventClass_t GetEventClassify(void) const { return EVClass_Syscall; }
protected:
    //Input
};

class CUniqueEvent_SetWindowsHook : public CUniqueEvent
{
public:
    CUniqueEvent_SetWindowsHook(CUniqueProcess *up, ULONG ThreadId,
                                int HookThreadId, int HookType, ULONG64 HookProc,
                                UCHAR Flags, ULONG64 Module, LPCWSTR szModuleFile,
                                ULONG ResultHHook, ULONG64 KeSystemTime, ULONG64 EventId);
    virtual QString GetEventPath(void) const { return m_ModuleFile; }
    virtual EventType_t GetEventType(void) const { return EV_SetWindowsHook; }
    virtual EventClass_t GetEventClassify(void) const { return EVClass_Syscall; }
    virtual void GetBriefResult(QString &str) const;
    virtual void GetFullArgument(QString &str) const;
private:
    ULONG m_ResultHHook;
    ULONG m_HookThreadId;
    int m_HookType;
    ULONG64 m_HookProc;
    UCHAR m_Flags;
    ULONG64 m_Module;
    QString m_ModuleFile;
};

class CUniqueEvent_FindWindow : public CUniqueEvent
{
public:
    CUniqueEvent_FindWindow(CUniqueProcess *up, ULONG ThreadId,
                            ULONG HwndParent, ULONG HwndChild, LPCWSTR szClassName,
                            LPCWSTR szWindowName, ULONG ResultHwnd,
                            ULONG64 KeSystemTime, ULONG64 EventId);
    virtual QString GetEventPath(void) const { return ""; }
    virtual EventType_t GetEventType(void) const { return EV_FindWindow; }
    virtual EventClass_t GetEventClassify(void) const { return EVClass_Syscall; }
    virtual void GetBriefResult(QString &str) const;
    virtual void GetBriefArgument(QString &str) const;
    virtual void GetFullArgument(QString &str) const;
private:
    ULONG m_HwndParent;
    ULONG m_HwndChild;
    QString m_ClassName;
    QString m_WindowName;
    ULONG m_ResultHwnd;
};

class CUniqueEvent_GetWindowText : public CUniqueEvent
{
public:
    CUniqueEvent_GetWindowText(CUniqueProcess *up, ULONG ThreadId,
                            ULONG Hwnd, ULONG MaxCount, LPCWSTR szWindowName, ULONG ResultCount,
                            ULONG64 KeSystemTime, ULONG64 EventId);
    virtual QString GetEventPath(void) const { return ""; }
    virtual EventType_t GetEventType(void) const { return EV_GetWindowText; }
    virtual EventClass_t GetEventClassify(void) const { return EVClass_Syscall; }
    virtual void GetBriefResult(QString &str) const;
    virtual void GetBriefArgument(QString &str) const;
    virtual void GetFullArgument(QString &str) const;
private:
    ULONG m_Hwnd;
    ULONG m_MaxCount;
    QString m_WindowName;
    ULONG m_ResultCount;
};

class CUniqueEvent_GetWindowClass : public CUniqueEvent
{
public:
    CUniqueEvent_GetWindowClass(CUniqueProcess *up, ULONG ThreadId,
                            ULONG Hwnd, ULONG MaxCount, LPCWSTR szWindowName, ULONG ResultCount,
                            ULONG64 KeSystemTime, ULONG64 EventId);
    virtual QString GetEventPath(void) const { return ""; }
    virtual EventType_t GetEventType(void) const { return EV_GetWindowClass; }
    virtual EventClass_t GetEventClassify(void) const { return EVClass_Syscall; }
    virtual void GetBriefResult(QString &str) const;
    virtual void GetBriefArgument(QString &str) const;
    virtual void GetFullArgument(QString &str) const;
private:
    ULONG m_Hwnd;
    ULONG m_MaxCount;
    QString m_WindowClass;
    ULONG m_ResultCount;
};

class CUniqueEvent_CreateFile : public CUniqueEvent_WithTargetFile
{
public:
    CUniqueEvent_CreateFile(CUniqueProcess *up, ULONG ThreadId,
                            LPCWSTR szFilePath, ULONG DesiredAccess,
                            ULONG Disposition, ULONG Options, ULONG ShareAccess,
                            ULONG Attributes, ULONG ResultStatus,
                            ULONG64 KeSystemTime, ULONG64 EventId);
    virtual EventType_t GetEventType(void) const { return EV_CreateFile; }
    virtual EventClass_t GetEventClassify(void) const { return EVClass_FileSystem; }
    virtual void GetBriefArgument(QString &str) const;
    virtual void GetFullArgument(QString &str) const;
private:
	ULONG m_DesiredAccess;
	ULONG m_Disposition;
	ULONG m_Options;
	ULONG m_ShareAccess;
    ULONG m_Attributes;
};

class CUniqueEvent_CloseFile : public CUniqueEvent_WithTargetFile
{
public:
    CUniqueEvent_CloseFile(CUniqueProcess *up, ULONG ThreadId, LPCWSTR szFilePath, ULONG ResultStatus, ULONG64 KeSystemTime, ULONG64 EventId);
    virtual EventType_t GetEventType(void) const { return EV_CloseFile; }
    virtual EventClass_t GetEventClassify(void) const { return EVClass_FileSystem; }
};

class CUniqueEvent_ReadFile : public CUniqueEvent_WithTargetFile
{
public:
    CUniqueEvent_ReadFile(CUniqueProcess *up, ULONG ThreadId, LPCWSTR szFilePath, ULONG Length, ULONG64 ByteOffset, ULONG ResultStatus, ULONG64 KeSystemTime, ULONG64 EventId);
    virtual EventType_t GetEventType(void) const { return EV_ReadFile; }
    virtual EventClass_t GetEventClassify(void) const { return EVClass_FileSystem; }
    virtual void GetFullArgument(QString &str) const;
private:
    ULONG m_Length;
    ULONG64 m_ByteOffset;
};

class CUniqueEvent_WriteFile : public CUniqueEvent_WithTargetFile
{
public:
    CUniqueEvent_WriteFile(CUniqueProcess *up, ULONG ThreadId, LPCWSTR szFilePath, ULONG Length, ULONG64 ByteOffset, ULONG ResultStatus, ULONG64 KeSystemTime, ULONG64 EventId);
    virtual EventType_t GetEventType(void) const { return EV_WriteFile; }
    virtual EventClass_t GetEventClassify(void) const { return EVClass_FileSystem; }
    virtual void GetFullArgument(QString &str) const;
private:
    ULONG m_Length;
    ULONG64 m_ByteOffset;
};

class CUniqueEvent_CreateFileMapping : public CUniqueEvent_WithTargetFile
{
public:
    CUniqueEvent_CreateFileMapping(CUniqueProcess *up, ULONG ThreadId,
                                   LPCWSTR szFilePath, ULONG SyncType, ULONG PageProtection,
                                   ULONG ResultStatus, ULONG64 KeSystemTime, ULONG64 EventId);
    virtual EventType_t GetEventType(void) const { return EV_CreateFileMapping; }
    virtual EventClass_t GetEventClassify(void) const { return EVClass_FileSystem; }
    virtual void GetBriefArgument(QString &str) const;
    virtual void GetFullArgument(QString &str) const;
private:
	ULONG m_SyncType;
    ULONG m_PageProtection;
};

class CUniqueEvent_QueryFileInformation : public CUniqueEvent_WithTargetFile
{
public:
    CUniqueEvent_QueryFileInformation(CUniqueProcess *up, ULONG ThreadId, LPCWSTR szFilePath,
                                      ULONG QueryClass, FILE_ALL_INFORMATION *allInfo, LPCWSTR szFileNameInfo,
                                      ULONG ResultStatus, ULONG64 KeSystemTime, ULONG64 EventId);
    virtual EventType_t GetEventType(void) const { return EV_QueryFileInformation; }
    virtual EventClass_t GetEventClassify(void) const { return EVClass_FileSystem; }
    virtual void GetBriefArgument(QString &str) const;
    virtual void GetFullArgument(QString &str) const;
protected:
    ULONG m_QueryClass;
    QString m_FileNameInfo;
    FILE_ALL_INFORMATION m_AllInfo;
};

class CUniqueEvent_OpenKey : public CUniqueEvent_WithTargetFile
{
public:
    CUniqueEvent_OpenKey(CUniqueProcess *up, ULONG ThreadId,
                            LPCWSTR szKeyPath, ULONG DesiredAccess,
                            ULONG ResultStatus, ULONG64 KeSystemTime, ULONG64 EventId);
    virtual EventType_t GetEventType(void) const { return EV_OpenKey; }
    virtual EventClass_t GetEventClassify(void) const { return EVClass_Registry; }
    virtual void GetBriefArgument(QString &str) const;
    virtual void GetFullArgument(QString &str) const;
protected:
    ULONG m_DesiredAccess;
};

class CUniqueEvent_CreateKey : public CUniqueEvent_OpenKey
{
public:
    CUniqueEvent_CreateKey(CUniqueProcess *up, ULONG ThreadId,
                            LPCWSTR szKeyPath, ULONG DesiredAccess,
                            ULONG Disposition, ULONG CreateOptions,
                            ULONG ResultStatus,
                            ULONG64 KeSystemTime, ULONG64 EventId);
    virtual EventType_t GetEventType(void) const { return EV_CreateKey; }
    virtual void GetFullArgument(QString &str) const;
private:
    ULONG m_Disposition;
    ULONG m_CreateOptions;
};

class CUniqueEvent_SetValueKey : public CUniqueEvent_WithTargetFile
{
public:
    CUniqueEvent_SetValueKey(CUniqueProcess *up, ULONG ThreadId,
                            LPCWSTR szKeyPath, LPCWSTR szValueName, ULONG DataType, ULONG DataSize, QByteArray &BinaryData,
                            ULONG ResultStatus, ULONG64 KeSystemTime, ULONG64 EventId);
    ~CUniqueEvent_SetValueKey();
    virtual EventType_t GetEventType(void) const { return EV_SetValueKey; }
    virtual EventClass_t GetEventClassify(void) const { return EVClass_Registry; }
    virtual void GetBriefArgument(QString &str) const;
    virtual void GetFullArgument(QString &str) const;
protected:
    CRegKeyValue *m_KeyValue;
};

class CUniqueEvent_QueryValueKey : public CUniqueEvent_WithTargetFile
{
public:
    CUniqueEvent_QueryValueKey(CUniqueProcess *up, ULONG ThreadId,
                            LPCWSTR szKeyPath, LPCWSTR szValueName, ULONG QueryClass, ULONG QueryLength, QByteArray &BinaryData,
                            ULONG ResultStatus, ULONG64 KeSystemTime, ULONG64 EventId);
    virtual EventType_t GetEventType(void) const { return EV_QueryValueKey; }
    virtual EventClass_t GetEventClassify(void) const { return EVClass_Registry; }
    virtual void GetBriefArgument(QString &str) const;
    virtual void GetFullArgument(QString &str) const;
protected:
    //Input
    ULONG m_QueryClass;
    ULONG m_QueryLength;
    CUniqueString m_ValueName;
};

class CUniqueEvent_QueryValueKey_BasicInformation : public CUniqueEvent_QueryValueKey
{
public:
    CUniqueEvent_QueryValueKey_BasicInformation(CUniqueProcess *up, ULONG ThreadId,
                            LPCWSTR szKeyPath, LPCWSTR szValueName, ULONG QueryLength, QByteArray &BinaryData,
                            ULONG ResultStatus, ULONG64 KeSystemTime, ULONG64 EventId);
    virtual void GetFullArgument(QString &str) const;
private:
    //Output (optional)
    ULONG m_KeyType;
    CUniqueString m_KeyName;
};

class CUniqueEvent_QueryValueKey_FullInformation : public CUniqueEvent_QueryValueKey
{
public:
    CUniqueEvent_QueryValueKey_FullInformation(CUniqueProcess *up, ULONG ThreadId,
                            LPCWSTR szKeyPath, LPCWSTR szValueName, ULONG QueryLength, QByteArray &BinaryData,
                            ULONG ResultStatus, ULONG64 KeSystemTime, ULONG64 EventId);
    ~CUniqueEvent_QueryValueKey_FullInformation();
    virtual void GetFullArgument(QString &str) const;
private:
    //Output (optional)
    CRegKeyValue *m_KeyValue;
};

class CUniqueEvent_QueryValueKey_PartialInformation : public CUniqueEvent_QueryValueKey
{
public:
    CUniqueEvent_QueryValueKey_PartialInformation(CUniqueProcess *up, ULONG ThreadId,
                            LPCWSTR szKeyPath, LPCWSTR szValueName, ULONG QueryLength, QByteArray &BinaryData,
                            ULONG ResultStatus, ULONG64 KeSystemTime, ULONG64 EventId);
    ~CUniqueEvent_QueryValueKey_PartialInformation();
    virtual void GetFullArgument(QString &str) const;
private:
    //Output (optional)
    CRegKeyValue *m_KeyValue;
};

class CUniqueEvent_QueryKey : public CUniqueEvent_WithTargetFile
{
public:
    CUniqueEvent_QueryKey(CUniqueProcess *up, ULONG ThreadId,
                            LPCWSTR szKeyPath, ULONG QueryClass, ULONG QueryLength, QByteArray &BinaryData,
                            ULONG ResultStatus, ULONG64 KeSystemTime, ULONG64 EventId);
    virtual EventType_t GetEventType(void) const { return EV_QueryKey; }
    virtual EventClass_t GetEventClassify(void) const { return EVClass_Registry; }
    virtual void GetBriefArgument(QString &str) const;
    virtual void GetFullArgument(QString &str) const;
protected:
    //Input
    ULONG m_QueryClass;
    ULONG m_QueryLength;
};

class CUniqueEvent_QueryKey_BasicInformation : public CUniqueEvent_QueryKey
{
public:
    CUniqueEvent_QueryKey_BasicInformation(CUniqueProcess *up, ULONG ThreadId,
                            LPCWSTR szKeyPath, ULONG QueryLength, QByteArray &BinaryData,
                            ULONG ResultStatus, ULONG64 KeSystemTime, ULONG64 EventId);
    virtual void GetFullArgument(QString &str) const;
protected:
    //Output (optional)
    LARGE_INTEGER m_LastWriteTime;
    CUniqueString m_KeyName;
};

class CUniqueEvent_QueryKey_NodeInformation : public CUniqueEvent_QueryKey
{
public:
    CUniqueEvent_QueryKey_NodeInformation(CUniqueProcess *up, ULONG ThreadId,
                            LPCWSTR szKeyPath, ULONG QueryLength, QByteArray &BinaryData,
                            ULONG ResultStatus, ULONG64 KeSystemTime, ULONG64 EventId);
    virtual void GetFullArgument(QString &str) const;
protected:
    //Output (optional)
    LARGE_INTEGER m_LastWriteTime;
    CUniqueString m_ClassName;
    CUniqueString m_KeyName;
};

class CUniqueEvent_QueryKey_FullInformation : public CUniqueEvent_QueryKey
{
public:
    CUniqueEvent_QueryKey_FullInformation(CUniqueProcess *up, ULONG ThreadId,
                            LPCWSTR szKeyPath, ULONG QueryLength, QByteArray &BinaryData,
                            ULONG ResultStatus, ULONG64 KeSystemTime, ULONG64 EventId);
    virtual void GetFullArgument(QString &str) const;
protected:
    //Output (optional)
    LARGE_INTEGER m_LastWriteTime;
    CUniqueString m_ClassName;
    ULONG   m_SubKeys;
    ULONG   m_MaxNameLen;
    ULONG   m_MaxClassLen;
    ULONG   m_Values;
    ULONG   m_MaxValueNameLen;
    ULONG   m_MaxValueDataLen;
};

class CUniqueEvent_QueryKey_NameInformation : public CUniqueEvent_QueryKey
{
public:
    CUniqueEvent_QueryKey_NameInformation(CUniqueProcess *up, ULONG ThreadId,
                            LPCWSTR szKeyPath, ULONG QueryLength, QByteArray &BinaryData,
                            ULONG ResultStatus, ULONG64 KeSystemTime, ULONG64 EventId);
    virtual void GetFullArgument(QString &str) const;
protected:
    //Output (optional)
    CUniqueString m_KeyName;
};

class CUniqueEvent_QueryKey_CachedInformation : public CUniqueEvent_QueryKey
{
public:
    CUniqueEvent_QueryKey_CachedInformation(CUniqueProcess *up, ULONG ThreadId,
                            LPCWSTR szKeyPath, ULONG QueryLength, QByteArray &BinaryData,
                            ULONG ResultStatus, ULONG64 KeSystemTime, ULONG64 EventId);
    virtual void GetFullArgument(QString &str) const;
protected:
    //Output (optional)
    LARGE_INTEGER m_LastWriteTime;
    ULONG   m_SubKeys;
    ULONG   m_MaxNameLen;
    ULONG   m_Values;
    ULONG   m_MaxValueNameLen;
    ULONG   m_MaxValueDataLen;
    ULONG   m_NameLength;
};

class CUniqueEvent_QueryKey_VirtualizationInformation : public CUniqueEvent_QueryKey
{
public:
    CUniqueEvent_QueryKey_VirtualizationInformation(CUniqueProcess *up, ULONG ThreadId,
                            LPCWSTR szKeyPath, ULONG QueryLength, QByteArray &BinaryData,
                            ULONG ResultStatus, ULONG64 KeSystemTime, ULONG64 EventId);
    virtual void GetFullArgument(QString &str) const;
protected:
    //Output (optional)
    bool m_VirtualizationCandidate;
    bool m_VirtualizationEnabled;
    bool m_VirtualTarget;
    bool m_VirtualStore;
    bool m_VirtualSource;
};

typedef QLinkedList<CUniqueEvent *> QEventLinkedList;
typedef QList<CUniqueEvent *> QEventList;

class CEventWorker : public QObject
{
     Q_OBJECT
public:
    explicit CEventWorker(QObject *parent = Q_NULLPTR);

public slots:
    void OnFilterRoutine(void);
};

class CEventMgr : public QObject
{
    Q_OBJECT
public:
    explicit CEventMgr(QObject *parent = Q_NULLPTR);
    ~CEventMgr();
    void Lock(void);
    void Unlock(void);
    void InsertEvent(CUniqueEvent *ev);
    void SyncKeSystemTime(const ULONG64 KeSystemTime);
    void Initialize(void);
    void Uninitialize(void);
    void StartParsing(void);
    void FixCallStacks(CUniqueEvent *ev, bool bQueryUnknownMods);

    bool DoFilter(const CUniqueEvent *ev);
    void FilterRoutine(void);//run in thread
    void AddEvent(CUniqueEvent *ev);
    CUniqueEvent *FindEventById(ULONG64 EventId);
    void ClearAllEvents(void);
signals:
    void AddEventItem(CUniqueEvent *ev);
    void RefillEventItems(QEventList *evs);
    void FilterUpdatePercent(size_t curEvent, size_t totalEvents);
    void StartFilter(void);
    void ClearAllDisplayingEvents(void);
public:
    CFilterList m_FilterList;
    CFilterList m_KeyFilterList[FltKey_Max];
    QEventLinkedList m_EventList;
	HANDLE m_hReadyEvent;
	ULONG64 m_u64KeSystemTimeStart;
	ULONG64 m_u64UnixTimeStart;
    QString m_EventClassNames[EVClass_Maximum];
    QString m_EventNames[EV_Maximum];
    QString m_FltKeyTable[FltKey_Max];
    QString m_FltRelTable[FltRel_Max];
    QString m_FltIncTable[2];
    BOOL m_CaptureEnable;
    BOOL m_DropExclude;
private:
    CRITICAL_SECTION m_Lock;
    QThread m_workerThread;

public slots:
    void OnCallStack(QByteArray data);
    void OnPsCreateProcess(QByteArray data);
    void OnPsCreateThread(QByteArray data);
    void OnPsLoadImage(QByteArray data);
    void OnNtLoadDriver(QByteArray data);
    void OnNtQuerySystemInfo(QByteArray data);
    void OnNtOpenProcess(QByteArray data);
    void OnNtOpenThread(QByteArray data);
    void OnNtTerminateProcess(QByteArray data);
    void OnNtAllocateVirtualMemory(QByteArray data);
    void OnNtReadWriteVirtualMemory(QByteArray data);
    void OnNtProtectVirtualMemory(QByteArray data);
    void OnNtQueryVirtualMemory(QByteArray data);
    void OnNtCreateOpenMutant(QByteArray data);
    void OnNtCreateOpenDirectoryObject(QByteArray data);
    void OnNtQueryDirectoryObject(QByteArray data);
    void OnNtUserSetWindowsHook(QByteArray data);
    void OnNtUserFindWindow(QByteArray data);
    void OnNtUserInternalGetWindowText(QByteArray data);
    void OnNtUserGetClassName(QByteArray data);
    void OnFsCreateFile(QByteArray data);
    void OnFsCloseFile(QByteArray data);
    void OnFsReadWriteFile(QByteArray data);
    void OnFsCreateFileMapping(QByteArray data);
    void OnFsQueryFileInformation(QByteArray data);
    void OnRgCreateOpenKey(QByteArray data);
    void OnRgSetValueKey(QByteArray data);
    void OnRgQueryValueKey(QByteArray data);
    void OnRgQueryKey(QByteArray data);
};

extern CEventMgr *m_EventMgr;
