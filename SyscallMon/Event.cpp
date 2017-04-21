#include <QTranslator>
#include <QDateTime>
#include <Windows.h>
#include "ProcessMgr.h"
#include "EventMgr.h"
#include "util.h"
#include "nt.h"
#include "registry.h"

//WithStatusResult

void GetThreadFlagsString(SVC_ThreadFlags flags, QString &str)
{
    if (flags.Fields.SystemThread)
    {
        if (!str.isEmpty())
            str.append(" | ");
        str.append("SystemThread");
    }
    if (flags.Fields.BreakOnTermination)
    {
        if (!str.isEmpty())
            str.append(" | ");
        str.append("BreakOnTermination");
    }
    if (flags.Fields.HideFromDebugger)
    {
        if (!str.isEmpty())
            str.append(" | ");
        str.append("HideFromDebugger");
    }
}

CUniqueEvent_WithStatusResult::CUniqueEvent_WithStatusResult(CUniqueProcess *up, ULONG ThreadId, ULONG ResultStatus, ULONG64 KeSystemTime, ULONG64 EventId)
    : CUniqueEvent(up, ThreadId, KeSystemTime, EventId)
{
    m_ResultStatus = ResultStatus;
}

void CUniqueEvent_WithStatusResult::GetBriefResult(QString &str) const
{
    str = QString("0x%1 (%2)").arg(
                FormatHexString(m_ResultStatus, 8),
                 GetNTStatusCodeString(m_ResultStatus));
}

//WithTargetFile

CUniqueEvent_WithTargetFile::CUniqueEvent_WithTargetFile(CUniqueProcess *up, ULONG ThreadId, std::wstring &filePath, ULONG ResultStatus, ULONG64 KeSystemTime, ULONG64 EventId) :
    CUniqueEvent_WithStatusResult(up, ThreadId, ResultStatus, KeSystemTime, EventId)
{
    m_FilePath = m_StringMgr->GetString(filePath.c_str());
}

CUniqueEvent_WithTargetFile::CUniqueEvent_WithTargetFile(CUniqueProcess *up, ULONG ThreadId, LPCWSTR szFilePath, ULONG ResultStatus, ULONG64 KeSystemTime, ULONG64 EventId) :
    CUniqueEvent_WithStatusResult(up, ThreadId, ResultStatus, KeSystemTime, EventId)
{
    m_FilePath = m_StringMgr->GetString(szFilePath);
}

//WithTargetProcess

CUniqueEvent_WithTargetProcess::CUniqueEvent_WithTargetProcess(CUniqueProcess *up, ULONG ThreadId, CUniqueProcess *TargetProcess, ULONG ResultStatus, ULONG64 KeSystemTime, ULONG64 EventId) :
    CUniqueEvent_WithStatusResult(up, ThreadId, ResultStatus, KeSystemTime, EventId)
{
    m_TargetProcess = TargetProcess;
}

void CUniqueEvent_WithTargetProcess::GetBriefArgument(QString &str) const
{
    str = m_TargetProcess->GetDisplayName();
}

void CUniqueEvent_WithTargetProcess::GetFullArgument(QString &str) const
{
    str = QObject::tr("Process:\t%1").arg(m_TargetProcess->GetDisplayNameWithPID());
}

//ProcessCreate

CUniqueEvent_ProcessCreate::CUniqueEvent_ProcessCreate(CUniqueProcess *up, ULONG ThreadId, ULONG64 KeSystemTime, ULONG64 EventId) :
    CUniqueEvent(up, ThreadId, KeSystemTime, EventId)
{
}

void CUniqueEvent_ProcessCreate::GetBriefArgument(QString &str) const
{
    if(m_UniqueProcess->m_pParentProcess)
        str = QObject::tr("Parent Process:%1").arg(m_UniqueProcess->m_pParentProcess->GetDisplayName());
}

void CUniqueEvent_ProcessCreate::GetFullArgument(QString &str) const
{
    str = QObject::tr("Parent Process:\t%1\nCommand Line:\t%2")
            .arg(m_UniqueProcess->m_pParentProcess ? m_UniqueProcess->m_pParentProcess->GetDisplayNameWithPID() : QString(),
                 m_UniqueProcess->m_CommandLine);
}

//ProcessDestroy

CUniqueEvent_ProcessDestroy::CUniqueEvent_ProcessDestroy(CUniqueProcess *up, ULONG ThreadId, ULONG64 KeSystemTime, ULONG64 EventId) :
    CUniqueEvent(up, ThreadId, KeSystemTime, EventId)
{
}

//CreateProcess

CUniqueEvent_CreateProcess::CUniqueEvent_CreateProcess(CUniqueProcess *up, ULONG ThreadId, CUniqueProcess *target, ULONG64 KeSystemTime, ULONG64 EventId) :
    CUniqueEvent_WithTargetProcess(up, ThreadId, target, 0, KeSystemTime, EventId)
{
}

void CUniqueEvent_CreateProcess::GetBriefArgument(QString &str) const
{
    str = QObject::tr("Create Process:%1").arg(m_TargetProcess->GetDisplayName());
}

void CUniqueEvent_CreateProcess::GetFullArgument(QString &str) const
{
    str = QObject::tr("Create Process:\t%1\nCommand Line:\t%2")
            .arg(m_TargetProcess->GetDisplayNameWithPID(),
            m_TargetProcess->m_CommandLine);
}

//ThreadCreate

CUniqueEvent_ThreadCreate::CUniqueEvent_ThreadCreate(CUniqueProcess *up, ULONG ThreadId, CUniqueProcess *CreatorProcess, ULONG CreatorThreadId,
                          ULONG64 StartAddress, SVC_ThreadFlags ThreadFlags, ULONG64 KeSystemTime, ULONG64 EventId) :
    CUniqueEvent(up, ThreadId, KeSystemTime, EventId)
{
    m_CreatorProcess = CreatorProcess;
    m_CreatorThreadId = CreatorThreadId;
    m_StartAddress = StartAddress;
    m_ThreadFlags = ThreadFlags;
}

void CUniqueEvent_ThreadCreate::GetBriefArgument(QString &str) const
{
    str = QObject::tr("ThreadID: #%1").arg(m_ThreadId);
}

void CUniqueEvent_ThreadCreate::GetFullArgument(QString &str) const
{
    QString ThreadFlagsString;
    GetThreadFlagsString(m_ThreadFlags, ThreadFlagsString);
    str = QObject::tr("Parent Process:\t%1\nParent Thread:\t#%2\nStart Address:\t0x%3\nThread Flags:\t%4")
            .arg(m_CreatorProcess->GetDisplayNameWithPID(),
                 QString::number(m_CreatorThreadId),
                 FormatHexString(m_StartAddress, (m_UniqueProcess->m_bIs64Bit) ? 16 : 8),
                 ThreadFlagsString);
}

//ThreadDestroy

CUniqueEvent_ThreadDestroy::CUniqueEvent_ThreadDestroy(CUniqueProcess *up, ULONG ThreadId, ULONG64 KeSystemTime, ULONG64 EventId)
    : CUniqueEvent(up, ThreadId, KeSystemTime, EventId)
{
}

void CUniqueEvent_ThreadDestroy::GetBriefArgument(QString &str) const
{
    str = QObject::tr("ThreadID: #%1").arg(m_ThreadId);
}

//CreateThread

CUniqueEvent_CreateThread::CUniqueEvent_CreateThread(CUniqueProcess *up, ULONG ThreadId, CUniqueProcess *target, ULONG NewThreadId, ULONG64 KeSystemTime, ULONG64 EventId) :
    CUniqueEvent_WithTargetProcess(up, ThreadId, target, 0, KeSystemTime, EventId)
{
    m_NewThreadId = NewThreadId;
}

void CUniqueEvent_CreateThread::GetBriefArgument(QString &str) const
{
    str = QObject::tr("Create Thread #%1 in Process %2").arg(
                QString::number(m_NewThreadId),
                m_TargetProcess->GetDisplayName()
                );
}

void CUniqueEvent_CreateThread::GetFullArgument(QString &str) const
{
    CUniqueEvent_WithTargetProcess::GetBriefArgument(str);

    str += QObject::tr("\nThreadId:\t%1").arg(m_NewThreadId);
}

//LoadImage

CUniqueEvent_LoadImage::CUniqueEvent_LoadImage(CUniqueProcess *up, ULONG ThreadId, LPCWSTR szImagePath, ULONG64 ImageBase, ULONG ImageSize, ULONG64 KeSystemTime, ULONG64 EventId) :
    CUniqueEvent(up, ThreadId, KeSystemTime, EventId)
{
    m_ImagePath = m_StringMgr->GetString(szImagePath);
    m_ImageBase = ImageBase;
    m_ImageSize = ImageSize;
}

void CUniqueEvent_LoadImage::GetFullArgument(QString &str) const
{
    str = QObject::tr("ImageBase:\t0x%1\nImageSize:\t0x%2").arg(
                FormatHexString(m_ImageBase, (m_UniqueProcess->m_bIs64Bit) ? 16 : 8),
                FormatHexString(m_ImageSize, 0));
}

//LoadDriver

CUniqueEvent_LoadDriver::CUniqueEvent_LoadDriver(CUniqueProcess *up, ULONG ThreadId, LPCWSTR szServiceName, LPCWSTR szImagePath, ULONG ResultStatus, ULONG64 KeSystemTime, ULONG64 EventId) :
    CUniqueEvent_WithStatusResult(up, ThreadId, ResultStatus, KeSystemTime, EventId)
{
    m_ServiceName = QString::fromWCharArray(szServiceName);
    m_ImagePath = QString::fromWCharArray(szImagePath);
}

void CUniqueEvent_LoadDriver::GetBriefArgument(QString &str) const
{
    str = m_ServiceName;
}

void CUniqueEvent_LoadDriver::GetFullArgument(QString &str) const
{
    str = QObject::tr("ServiceName:\t%1\nImagePath:\t%2")
            .arg(m_ServiceName, m_ImagePath);
}

//Enum

CUniqueEvent_EnumProcess::CUniqueEvent_EnumProcess(CUniqueProcess *up, ULONG ThreadId, ULONG64 KeSystemTime, ULONG64 EventId) :
    CUniqueEvent(up, ThreadId, KeSystemTime, EventId)
{
}

CUniqueEvent_EnumSystemModule::CUniqueEvent_EnumSystemModule(CUniqueProcess *up, ULONG ThreadId, ULONG64 KeSystemTime, ULONG64 EventId) :
    CUniqueEvent(up, ThreadId, KeSystemTime, EventId)
{
}

CUniqueEvent_EnumSystemHandle::CUniqueEvent_EnumSystemHandle(CUniqueProcess *up, ULONG ThreadId, ULONG64 KeSystemTime, ULONG64 EventId) :
    CUniqueEvent(up, ThreadId, KeSystemTime, EventId)
{
}

CUniqueEvent_EnumSystemObject::CUniqueEvent_EnumSystemObject(CUniqueProcess *up, ULONG ThreadId, ULONG64 KeSystemTime, ULONG64 EventId) :
    CUniqueEvent(up, ThreadId, KeSystemTime, EventId)
{
}

//OpenProcess

CUniqueEvent_OpenProcess::CUniqueEvent_OpenProcess(CUniqueProcess *up, ULONG ThreadId, CUniqueProcess *TargetProcess, ULONG DesireAccess,
                                                   ULONG ResultStatus, ULONG64 KeSystemTime, ULONG64 EventId) :
    CUniqueEvent_WithTargetProcess(up, ThreadId, TargetProcess, ResultStatus, KeSystemTime, EventId)
{
    m_DesireAccess = DesireAccess;
}

void CUniqueEvent_OpenProcess::GetBriefArgument(QString &str) const
{
    CUniqueEvent_WithTargetProcess::GetBriefArgument(str);

    QString desiredAccess;
    GetProcessDesiredAccessString(m_DesireAccess, desiredAccess);

    str += ", ";
    str += desiredAccess;
}

void CUniqueEvent_OpenProcess::GetFullArgument(QString &str) const
{
    CUniqueEvent_WithTargetProcess::GetFullArgument(str);

    QString desiredAccess;
    GetProcessDesiredAccessString(m_DesireAccess, desiredAccess);

    str += QObject::tr("\nDesiredAccess:\t%1").arg(desiredAccess);
}

//OpenThread

CUniqueEvent_OpenThread::CUniqueEvent_OpenThread(CUniqueProcess *up, ULONG ThreadId, CUniqueProcess *target,
                                                 ULONG TargetThreadId, ULONG DesireAccess,
                                                 ULONG ResultStatus, ULONG64 KeSystemTime, ULONG64 EventId) :
    CUniqueEvent_WithTargetProcess(up, ThreadId, target, ResultStatus, KeSystemTime, EventId)
{
    m_TargetThreadId = TargetThreadId;
    m_DesireAccess = DesireAccess;
}

void CUniqueEvent_OpenThread::GetBriefArgument(QString &str) const
{
    CUniqueEvent_WithTargetProcess::GetBriefArgument(str);

    QString desiredAccess;
    GetThreadDesiredAccessString(m_DesireAccess, desiredAccess);

    str += QObject::tr(", ThreadId: #%1, %2").arg(QString::number(m_TargetThreadId), desiredAccess);
}

void CUniqueEvent_OpenThread::GetFullArgument(QString &str) const
{
    CUniqueEvent_WithTargetProcess::GetFullArgument(str);

    QString desiredAccess;
    GetThreadDesiredAccessString(m_DesireAccess, desiredAccess);

    str += QObject::tr("\nThreadId:\t%1\nDesiredAccess:\t%2").arg(QString::number(m_TargetThreadId), desiredAccess);
}

//TerminateProcess

CUniqueEvent_TerminateProcess::CUniqueEvent_TerminateProcess(CUniqueProcess *up, ULONG ThreadId, CUniqueProcess *TargetProcess, ULONG ResultStatus, ULONG64 KeSystemTime, ULONG64 EventId) :
    CUniqueEvent_WithTargetProcess(up, ThreadId, TargetProcess, ResultStatus, KeSystemTime, EventId)
{
}

//AllocateVirtualMemory

CUniqueEvent_AllocateVirtualMemory::CUniqueEvent_AllocateVirtualMemory(CUniqueProcess *up, ULONG ThreadId, CUniqueProcess *TargetProcess,
                                   ULONG64 OldBaseAddress, ULONG64 OldRegionSize, ULONG64 NewBaseAddress,
                                   ULONG64 NewRegionSize, ULONG AllocationType, ULONG Protect,
                                   ULONG ResultStatus, ULONG64 KeSystemTime, ULONG64 EventId) :
    CUniqueEvent_WithTargetProcess(up, ThreadId, TargetProcess, ResultStatus, KeSystemTime, EventId)
{
    m_OldBaseAddress = OldBaseAddress;
    m_OldRegionSize = OldRegionSize;
    m_NewBaseAddress = NewBaseAddress;
    m_NewRegionSize = NewRegionSize;
    m_AllocationType = AllocationType;
    m_Protect = Protect;
}

void CUniqueEvent_AllocateVirtualMemory::GetFullArgument(QString &str) const
{
    QString str1, protect;
    GetPageProtectionString(m_Protect, protect);
    CUniqueEvent_WithTargetProcess::GetFullArgument(str1);
    str = str1+QObject::tr("\nBaseAddress:\t0x%1\nBufferSize:\t0x%2\nNewBaseAddress:\t0x%3\nNewBufferSize:\t0x%4\nMemType:\t%5\nProtect:\t%6")
            .arg(FormatHexString(m_OldBaseAddress, (m_TargetProcess->m_bIs64Bit || m_OldBaseAddress > 0xffffffff) ? 16 : 8),
            FormatHexString(m_OldRegionSize, 0),
            FormatHexString(m_NewBaseAddress, (m_TargetProcess->m_bIs64Bit || m_NewBaseAddress > 0xffffffff) ? 16 : 8),
            FormatHexString(m_NewRegionSize, 0),
            GetMemoryTypeString(m_AllocationType), protect);
}

//Read

CUniqueEvent_ReadVirtualMemory::CUniqueEvent_ReadVirtualMemory(CUniqueProcess *up, ULONG ThreadId, CUniqueProcess *TargetProcess,
                               ULONG64 BaseAddress, ULONG64 BufferSize, ULONG ResultStatus, ULONG64 KeSystemTime, ULONG64 EventId) :
    CUniqueEvent_WithTargetProcess(up, ThreadId, TargetProcess, ResultStatus, KeSystemTime, EventId)
{
    m_BaseAddress = BaseAddress;
    m_BufferSize = BufferSize;
}

void CUniqueEvent_ReadVirtualMemory::GetFullArgument(QString &str) const
{
    QString str1;
    CUniqueEvent_WithTargetProcess::GetFullArgument(str1);
    str = str1+QObject::tr("\nBaseAddress:\t0x%1\nBufferSize:\t0x%2")
            .arg(FormatHexString(m_BaseAddress, (m_TargetProcess->m_bIs64Bit || m_BaseAddress > 0xffffffff) ? 16 : 8),
            FormatHexString(m_BufferSize, 0));
}

//Write

CUniqueEvent_WriteVirtualMemory::CUniqueEvent_WriteVirtualMemory(CUniqueProcess *up, ULONG ThreadId, CUniqueProcess *TargetProcess,
                                ULONG64 BaseAddress, ULONG64 BufferSize, ULONG ResultStatus, ULONG64 KeSystemTime, ULONG64 EventId) :
    CUniqueEvent_WithTargetProcess(up, ThreadId, TargetProcess, ResultStatus, KeSystemTime, EventId)
{
    m_BaseAddress = BaseAddress;
    m_BufferSize = BufferSize;
}

void CUniqueEvent_WriteVirtualMemory::GetFullArgument(QString &str) const
{
    QString str1;
    CUniqueEvent_WithTargetProcess::GetFullArgument(str1);
    str = str1+QObject::tr("\nBaseAddress:\t0x%1\nBufferSize:\t0x%2")
            .arg(FormatHexString(m_BaseAddress, (m_TargetProcess->m_bIs64Bit || m_BaseAddress > 0xffffffff) ? 16 : 8),
            FormatHexString(m_BufferSize, 0));
}

//Protect

CUniqueEvent_ProtectVirtualMemory::CUniqueEvent_ProtectVirtualMemory(CUniqueProcess *up, ULONG ThreadId, CUniqueProcess *TargetProcess,
                                  ULONG64 OldBaseAddress, ULONG64 OldBufferSize, ULONG64 NewBaseAddress,
                                  ULONG64 NewBufferSize, ULONG OldProtect, ULONG NewProtect,
                                  ULONG ResultStatus, ULONG64 KeSystemTime, ULONG64 EventId) :
    CUniqueEvent_WithTargetProcess(up, ThreadId, TargetProcess, ResultStatus, KeSystemTime, EventId)
{
    m_OldBaseAddress = OldBaseAddress;
    m_OldBufferSize = OldBufferSize;
    m_NewBaseAddress = NewBaseAddress;
    m_NewBufferSize = NewBufferSize;
    m_OldProtect = OldProtect;
    m_NewProtect = NewProtect;
}

void CUniqueEvent_ProtectVirtualMemory::GetFullArgument(QString &str) const
{
    QString str1, oldProtect, newProtect;
    GetPageProtectionString(m_OldProtect, oldProtect);
    GetPageProtectionString(m_NewProtect, newProtect);
    CUniqueEvent_WithTargetProcess::GetFullArgument(str1);
    str = str1+QObject::tr("\nBaseAddress:\t0x%1\nBufferSize:\t0x%2\nNewBaseAddress:\t0x%3\nNewBufferSize:\t0x%4\nOldProtect:\t%5\nNewProtect:\t%6")
            .arg(FormatHexString(m_OldBaseAddress, (m_TargetProcess->m_bIs64Bit || m_OldBaseAddress > 0xffffffff) ? 16 : 8),
            FormatHexString(m_OldBufferSize, 0),
            FormatHexString(m_NewBaseAddress, (m_TargetProcess->m_bIs64Bit || m_NewBaseAddress > 0xffffffff) ? 16 : 8),
            FormatHexString(m_NewBufferSize, 0),
            oldProtect, newProtect);
}

//Query

CUniqueEvent_QueryVirtualMemory::CUniqueEvent_QueryVirtualMemory(
        CUniqueProcess *up, ULONG ThreadId, CUniqueProcess *TargetProcess,
        ULONG64 BaseAddress, ULONG QueryClass, ULONG ResultStatus,
        ULONG64 KeSystemTime, ULONG64 EventId) :
    CUniqueEvent_WithTargetProcess(up, ThreadId, TargetProcess, ResultStatus, KeSystemTime, EventId)
{
    m_BaseAddress = BaseAddress;
    m_QueryClass = QueryClass;
}

void CUniqueEvent_QueryVirtualMemory::GetBriefArgument(QString &str) const
{
    CUniqueEvent_WithTargetProcess::GetBriefArgument(str);

    str += ", ";
    str += GetMemoryInformationClassString(m_QueryClass);
}

void CUniqueEvent_QueryVirtualMemory::GetFullArgument(QString &str) const
{
    CUniqueEvent_WithTargetProcess::GetFullArgument(str);

    int hexWidth = (m_TargetProcess->m_bIs64Bit) ? 16 : 8;

    str += QObject::tr("\nBaseAddress:\t0x%1\nQueryClass:\t%2")
            .arg(FormatHexString(m_BaseAddress, hexWidth),
            GetMemoryInformationClassString(m_QueryClass));
}

//QueryVirtualMemory - basic

CUniqueEvent_QueryVirtualMemory_BasicInformation::CUniqueEvent_QueryVirtualMemory_BasicInformation(
        CUniqueProcess *up, ULONG ThreadId, CUniqueProcess *TargetProcess,
        ULONG64 BaseAddress, PMEMORY_BASIC_INFORMATION_MY pmbi, ULONG ResultStatus,
        ULONG64 KeSystemTime, ULONG64 EventId) :
    CUniqueEvent_QueryVirtualMemory(up, ThreadId, TargetProcess,
                                    BaseAddress, MemoryBasicInformationEx, ResultStatus,
                                    KeSystemTime, EventId)
{
    memcpy(&m_mbi, pmbi, sizeof(MEMORY_BASIC_INFORMATION_MY));
}

void CUniqueEvent_QueryVirtualMemory_BasicInformation::GetFullArgument(QString &str) const
{
    CUniqueEvent_QueryVirtualMemory::GetFullArgument(str);

    QString allocProtect;
    GetPageProtectionString(m_mbi.AllocationProtect, allocProtect);

    QString protect;
    GetPageProtectionString(m_mbi.Protect, protect);

    str += QObject::tr("\n\nmbi.BaseAddress:\t0x%1\nmbi.AllocationBase:\t0x%2\nmbi.AllocationProtect:\t%3\nmbi.State:\t%4\nmbi.Protect:\t%5\nmbi.Type:\t%6\n")
        .arg(FormatHexString(m_mbi.BaseAddress, m_mbi.BaseAddress > 0xffffffff ? 16 : 8),
        FormatHexString(m_mbi.AllocationBase, m_mbi.AllocationBase > 0xffffffff ? 16 : 8),
        allocProtect,
        GetMemoryStateString(m_mbi.State),
        protect,
        GetMemoryTypeString(m_mbi.Type));
}

CUniqueEvent_QueryVirtualMemory_MappedFileName::CUniqueEvent_QueryVirtualMemory_MappedFileName(
        CUniqueProcess *up, ULONG ThreadId, CUniqueProcess *TargetProcess,
        ULONG64 BaseAddress, LPCWSTR szMappedFilePath, ULONG ResultStatus,
        ULONG64 KeSystemTime, ULONG64 EventId) :
    CUniqueEvent_QueryVirtualMemory(up, ThreadId, TargetProcess,
                                    BaseAddress, MemoryMappedFilenameInformation, ResultStatus,
                                    KeSystemTime, EventId)
{
    m_MappedFilePath = QString::fromWCharArray(szMappedFilePath);
}

void CUniqueEvent_QueryVirtualMemory_MappedFileName::GetFullArgument(QString &str) const
{
    CUniqueEvent_QueryVirtualMemory::GetFullArgument(str);

    str += QObject::tr("\n\nImageFileName:\t%1")
        .arg(m_MappedFilePath);
}

//createmutex

CUniqueEvent_OpenMutex::CUniqueEvent_OpenMutex(CUniqueProcess *up, ULONG ThreadId, LPCWSTR szMutexName,
    ULONG DesiredAccess, ULONG ResultStatus, ULONG64 KeSystemTime, ULONG64 EventId) :
    CUniqueEvent_WithTargetFile(up, ThreadId, szMutexName, ResultStatus, KeSystemTime, EventId)
{
    m_DesiredAccess = DesiredAccess;
}

void CUniqueEvent_OpenMutex::GetBriefArgument(QString &str) const
{
    QString desiredAccess;
    GetMutantDesiredAccessString(m_DesiredAccess, desiredAccess);

    str = desiredAccess;
}

void CUniqueEvent_OpenMutex::GetFullArgument(QString &str) const
{
    QString desiredAccess;
    GetMutantDesiredAccessString(m_DesiredAccess, desiredAccess);

    str = QObject::tr("DesiredAccess:\t%1").arg(desiredAccess);
}

CUniqueEvent_CreateMutex::CUniqueEvent_CreateMutex(CUniqueProcess *up, ULONG ThreadId, LPCWSTR szMutexName,
    ULONG DesiredAccess, bool InitialOwner, ULONG ResultStatus, ULONG64 KeSystemTime, ULONG64 EventId) :
    CUniqueEvent_OpenMutex(up, ThreadId, szMutexName, DesiredAccess, ResultStatus, KeSystemTime, EventId)
{
    m_InitialOwner = InitialOwner;
}

void CUniqueEvent_CreateMutex::GetFullArgument(QString &str) const
{
    CUniqueEvent_OpenMutex::GetFullArgument(str);

    str += QObject::tr("\nInitialOwner:\t%1").arg(m_InitialOwner ? QObject::tr("true") : QObject::tr("false"));
}

//CreateDirectoryObject

CUniqueEvent_OpenDirectoryObject::CUniqueEvent_OpenDirectoryObject(CUniqueProcess *up, ULONG ThreadId, LPCWSTR szObjectName,
    ULONG DesiredAccess, ULONG ResultStatus, ULONG64 KeSystemTime, ULONG64 EventId) :
    CUniqueEvent_WithTargetFile(up, ThreadId, szObjectName, ResultStatus, KeSystemTime, EventId)
{
    m_DesiredAccess = DesiredAccess;
}

void CUniqueEvent_OpenDirectoryObject::GetBriefArgument(QString &str) const
{
    QString desiredAccess;
    GetDirectoryObjectDesiredAccessString(m_DesiredAccess, desiredAccess);

    str = desiredAccess;
}

void CUniqueEvent_OpenDirectoryObject::GetFullArgument(QString &str) const
{
    QString desiredAccess;
    GetDirectoryObjectDesiredAccessString(m_DesiredAccess, desiredAccess);

    str = QObject::tr("DesiredAccess:\t%1").arg(desiredAccess);
}

CUniqueEvent_CreateDirectoryObject::CUniqueEvent_CreateDirectoryObject(CUniqueProcess *up, ULONG ThreadId, LPCWSTR szObjectName,
    ULONG DesiredAccess, ULONG ResultStatus, ULONG64 KeSystemTime, ULONG64 EventId) :
    CUniqueEvent_OpenDirectoryObject(up, ThreadId, szObjectName, DesiredAccess, ResultStatus, KeSystemTime, EventId)
{
}

//QueryDirectoryObject

CUniqueEvent_QueryDirectoryObject::CUniqueEvent_QueryDirectoryObject(CUniqueProcess *up, ULONG ThreadId, LPCWSTR szObjectName,
    ULONG ResultStatus, ULONG64 KeSystemTime, ULONG64 EventId) :
    CUniqueEvent_WithTargetFile(up, ThreadId, szObjectName, ResultStatus, KeSystemTime, EventId)
{

}


//setwindowshook

CUniqueEvent_SetWindowsHook::CUniqueEvent_SetWindowsHook(CUniqueProcess *up, ULONG ThreadId,
                            int HookThreadId, int HookType, ULONG64 HookProc,
                            UCHAR Flags, ULONG64 Module, LPCWSTR szModuleFile,
                            ULONG ResultHHook, ULONG64 KeSystemTime, ULONG64 EventId) :
    CUniqueEvent(up, ThreadId, KeSystemTime, EventId)
{
    m_ResultHHook = ResultHHook;
    m_HookThreadId = HookThreadId;
    m_HookType = HookType;
    m_HookProc = HookProc;
    m_Flags = Flags;
    m_Module = Module;
    m_ModuleFile = m_StringMgr->GetString(szModuleFile);
}

void CUniqueEvent_SetWindowsHook::GetBriefResult(QString &str) const
{
    str = QObject::tr("HHook: %1").arg((m_ResultHHook) ?FormatHexString(m_ResultHHook, 8) : "NULL");
}

void CUniqueEvent_SetWindowsHook::GetFullArgument(QString &str) const
{
    QString hookProc;
    CUniqueModule *um = m_UniqueProcess->GetModuleFromAddress(m_HookProc);
    if(um) {
        hookProc = QString("%1+0x%2 (0x%3)")
            .arg(um->m_UniqueImage->m_FileName,
            FormatHexString(m_HookProc - um->m_ImageBase, 0),
            FormatHexString(m_HookProc, m_UniqueProcess->m_bIs64Bit ? 16 : 8));
    } else {
        hookProc = QString("0x%1").arg(
                    FormatHexString(m_HookProc, m_UniqueProcess->m_bIs64Bit ? 16 : 8));
    }
    QString moduleInfo;
    if(m_Module) {
        um = m_UniqueProcess->GetModuleFromAddress(m_Module);
        if(um && m_Module == um->m_ImageBase)
        {
            moduleInfo = QString("%1 (0x%2)")
                    .arg(um->m_UniqueImage->m_FileName,
                    FormatHexString(m_Module, m_UniqueProcess->m_bIs64Bit ? 16 : 8));
        } else {
            moduleInfo = QString("0x%1").arg(FormatHexString(m_Module, m_UniqueProcess->m_bIs64Bit ? 16 : 8));
        }
    } else{
       moduleInfo = "NULL";
    }
    str = QObject::tr("Hook Type:\t%1\nHook ThreadId:\t%2\nHook Procedure:\t%3\nFlags:\t%4\nModule:\t%5\nModule File:\t%6")
            .arg(GetWindowsHookTypeString(m_HookType),
            m_HookThreadId ? QString("%1").arg(m_HookThreadId) : QObject::tr("0 (Global)"),
            hookProc,
            QString("%1").arg(m_Flags),
            moduleInfo,
            m_ModuleFile.GetQString());
}

//FindWindow

CUniqueEvent_FindWindow::CUniqueEvent_FindWindow(CUniqueProcess *up, ULONG ThreadId,
                        ULONG HwndParent, ULONG HwndChild, LPCWSTR szClassName,
                        LPCWSTR szWindowName, ULONG ResultHwnd,
                        ULONG64 KeSystemTime, ULONG64 EventId) : CUniqueEvent(up, ThreadId, KeSystemTime, EventId)
{
    m_HwndParent = HwndParent;
    m_HwndChild = HwndChild;
    m_ClassName = m_StringMgr->GetString(szClassName);
    m_WindowName = m_StringMgr->GetString(szWindowName);
    m_ResultHwnd = ResultHwnd;
}

void CUniqueEvent_FindWindow::GetBriefResult(QString &str) const
{
    str = QObject::tr("Hwnd: %1").arg((m_ResultHwnd) ? FormatHexString(m_ResultHwnd, 8) : "NULL");
}

void CUniqueEvent_FindWindow::GetBriefArgument(QString &str) const
{
    str = QObject::tr("Class:%1, Window:%2")
            .arg(m_ClassName.GetQString(), m_WindowName.GetQString() );
}

void CUniqueEvent_FindWindow::GetFullArgument(QString &str) const
{
    str = QObject::tr("Hwnd Parent:\t%1\nHwnd Child:\t%2\nWindow Class:\t%3\nWindow Name:\t%4")
            .arg(
                (m_HwndParent) ? FormatHexString(m_HwndParent,8) : "NULL",
                (m_HwndChild) ? FormatHexString(m_HwndChild,8) : "NULL",
                m_ClassName.GetQString(),
                m_WindowName.GetQString()
            );
}

//GetWindowText

CUniqueEvent_GetWindowText::CUniqueEvent_GetWindowText(CUniqueProcess *up, ULONG ThreadId,
                        ULONG Hwnd, ULONG MaxCount, LPCWSTR szWindowName, ULONG ResultCount,
                        ULONG64 KeSystemTime, ULONG64 EventId) : CUniqueEvent(up, ThreadId, KeSystemTime, EventId)
{
    m_Hwnd = Hwnd;
    m_MaxCount = MaxCount;
    m_WindowName = m_StringMgr->GetString(szWindowName);
    m_ResultCount = ResultCount;
}

void CUniqueEvent_GetWindowText::GetBriefResult(QString &str) const
{
    str = m_WindowName.GetQString();
}

void CUniqueEvent_GetWindowText::GetBriefArgument(QString &str) const
{
    str = QObject::tr("Hwnd: %1").arg((m_Hwnd) ? FormatHexString(m_Hwnd, 8) : "NULL");
}

void CUniqueEvent_GetWindowText::GetFullArgument(QString &str) const
{
    str = QObject::tr("Hwnd:\t%1\nMaxCount:\t%2\n\nWindow Name:\t%3\nResult Count:\t%4")
            .arg(
                (m_Hwnd) ? FormatHexString(m_Hwnd,8) : "NULL",
                QString::number(m_MaxCount),
                m_WindowName.GetQString(),
                QString::number(m_ResultCount)
            );
}

//GetWindowClass

CUniqueEvent_GetWindowClass::CUniqueEvent_GetWindowClass(CUniqueProcess *up, ULONG ThreadId,
                        ULONG Hwnd, ULONG MaxCount, LPCWSTR szWindowClass, ULONG ResultCount,
                        ULONG64 KeSystemTime, ULONG64 EventId) : CUniqueEvent(up, ThreadId, KeSystemTime, EventId)
{
    m_Hwnd = Hwnd;
    m_MaxCount = MaxCount;
    m_WindowClass = m_StringMgr->GetString(szWindowClass);
    m_ResultCount = ResultCount;
}

void CUniqueEvent_GetWindowClass::GetBriefResult(QString &str) const
{
    str = m_WindowClass.GetQString();
}

void CUniqueEvent_GetWindowClass::GetBriefArgument(QString &str) const
{
    str = QObject::tr("Hwnd: %1").arg((m_Hwnd) ? FormatHexString(m_Hwnd, 8) : "NULL");
}

void CUniqueEvent_GetWindowClass::GetFullArgument(QString &str) const
{
    str = QObject::tr("Hwnd:\t%1\nMaxCount:\t%2\n\nWindow Class:\t%3\nResult Count:\t%4")
            .arg(
                (m_Hwnd) ? FormatHexString(m_Hwnd,8) : "NULL",
                QString::number(m_MaxCount),
                m_WindowClass.GetQString(),
                QString::number(m_ResultCount)
            );
}

//CreateFile

CUniqueEvent_CreateFile::CUniqueEvent_CreateFile(CUniqueProcess *up, ULONG ThreadId,
                        LPCWSTR szFilePath, ULONG DesiredAccess,
                        ULONG Disposition, ULONG Options, ULONG ShareAccess,
                        ULONG Attributes, ULONG ResultStatus,
                        ULONG64 KeSystemTime, ULONG64 EventId) :
    CUniqueEvent_WithTargetFile(up, ThreadId, szFilePath, ResultStatus, KeSystemTime, EventId)
{
    m_DesiredAccess = DesiredAccess;
    m_Disposition = Disposition;
    m_Options = Options;
    m_ShareAccess = ShareAccess;
    m_Attributes = Attributes;
}

void CUniqueEvent_CreateFile::GetBriefArgument(QString &str) const
{
    str = GetCreateDispositionString(m_Disposition);
}

void CUniqueEvent_CreateFile::GetFullArgument(QString &str) const
{
    QString shareAccess;
    GetShareAccessString(m_ShareAccess, shareAccess);

    QString desiredAccess;
    GetCreateFileDesiredAccessString(m_DesiredAccess, desiredAccess);

    QString options;
    GetCreateFileOptionsString(m_Options, options);
    str = QObject::tr("CreateDisposition:\t%1\nDesiredAccess:\t%2\nShareAccess:\t%3\nOptions:\t%4")
            .arg(GetCreateDispositionString(m_Disposition),
            desiredAccess,
            shareAccess,
            options);
}

//CloseFile

CUniqueEvent_CloseFile::CUniqueEvent_CloseFile(CUniqueProcess *up, ULONG ThreadId,
                       LPCWSTR szFilePath, ULONG ResultStatus,
                       ULONG64 KeSystemTime, ULONG64 EventId) :
    CUniqueEvent_WithTargetFile(up, ThreadId, szFilePath, ResultStatus, KeSystemTime, EventId)
{
}

//ReadFile
CUniqueEvent_ReadFile::CUniqueEvent_ReadFile(CUniqueProcess *up, ULONG ThreadId,
                      LPCWSTR szFilePath, ULONG Length, ULONG64 ByteOffset,
                      ULONG ResultStatus, ULONG64 KeSystemTime, ULONG64 EventId) :
    CUniqueEvent_WithTargetFile(up, ThreadId, szFilePath, ResultStatus, KeSystemTime, EventId)
{
    m_Length = Length;
    m_ByteOffset = ByteOffset;
}

void CUniqueEvent_ReadFile::GetFullArgument(QString &str) const
{
    str = QObject::tr("Length:\t0x%1\nByteOffset:\t0x%2")
            .arg(FormatHexString(m_Length, 0),
            FormatHexString(m_ByteOffset, 0));
}

//WriteFile

CUniqueEvent_WriteFile::CUniqueEvent_WriteFile(CUniqueProcess *up, ULONG ThreadId,
                       LPCWSTR szFilePath, ULONG Length, ULONG64 ByteOffset,
                       ULONG ResultStatus, ULONG64 KeSystemTime, ULONG64 EventId) :
    CUniqueEvent_WithTargetFile(up, ThreadId, szFilePath, ResultStatus, KeSystemTime, EventId)
{
    m_Length = Length;
    m_ByteOffset = ByteOffset;
}

void CUniqueEvent_WriteFile::GetFullArgument(QString &str) const
{
    str = QObject::tr("Length:\t0x%1\nByteOffset:\t0x%2")
            .arg(FormatHexString(m_Length, 0),
            FormatHexString(m_ByteOffset, 0));
}

//CreateFileMapping

CUniqueEvent_CreateFileMapping::CUniqueEvent_CreateFileMapping(CUniqueProcess *up, ULONG ThreadId,
                                                               LPCWSTR szFilePath, ULONG SyncType, ULONG PageProtection,
                                                               ULONG ResultStatus, ULONG64 KeSystemTime, ULONG64 EventId) :
    CUniqueEvent_WithTargetFile(up, ThreadId, szFilePath, ResultStatus, KeSystemTime, EventId)
{
    m_SyncType = SyncType;
    m_PageProtection = PageProtection;
}

void CUniqueEvent_CreateFileMapping::GetBriefArgument(QString &str) const
{
    QString syncType;
    switch (m_SyncType)
    {
    case 0:syncType = "SyncTypeOther"; break;
    case 1:syncType = "SyncTypeCreateSection"; break;
    }

    QString protection;
    GetPageProtectionString(m_PageProtection, protection);

    str = QString("%1, %2").arg(syncType, protection);
}

void CUniqueEvent_CreateFileMapping::GetFullArgument(QString &str) const
{
    QString syncType;
    switch (m_SyncType)
    {
    case 0:syncType = "SyncTypeOther"; break;
    case 1:syncType = "SyncTypeCreateSection"; break;
    }

    QString protection;
    GetPageProtectionString(m_PageProtection, protection);

    str = QObject::tr("SyncType:\t%1\nPageProtect:\t%2")
            .arg(syncType,
            protection);
}

//QueryFileInformation

CUniqueEvent_QueryFileInformation::CUniqueEvent_QueryFileInformation(CUniqueProcess *up, ULONG ThreadId, LPCWSTR szFilePath,
                                  ULONG QueryClass, FILE_ALL_INFORMATION *allInfo, LPCWSTR szFileNameInfo,
                                  ULONG ResultStatus, ULONG64 KeSystemTime, ULONG64 EventId) :
    CUniqueEvent_WithTargetFile(up, ThreadId, szFilePath, ResultStatus, KeSystemTime, EventId)
{
    m_QueryClass = QueryClass;
    memcpy(&m_AllInfo, allInfo, sizeof(m_AllInfo));
    m_FileNameInfo = m_StringMgr->GetString(szFileNameInfo);
}

void CUniqueEvent_QueryFileInformation::GetBriefArgument(QString &str) const
{
    str = GetFileInformationClass(m_QueryClass);
}

void CUniqueEvent_QueryFileInformation::GetFullArgument(QString &str) const
{
    str = QObject::tr("Query Class:\t%1").arg(GetFileInformationClass(m_QueryClass));

    if(m_QueryClass == FileNameInformation || m_QueryClass == FileAllInformation){
        str += QObject::tr("\nFileNameInformation:\t%1").arg(m_FileNameInfo.GetQString());
    }
    if(m_QueryClass == FileBasicInformation){
        QDateTime date;
        QString crt, lat, lwt, cht, fa;
        date.setTime_t(FileTimeToUnixTime((FILETIME *)&m_AllInfo.BasicInformation.CreationTime));
        crt = date.toString("yyyy-MM-dd HH:mm:ss");
        date.setTime_t(FileTimeToUnixTime((FILETIME *)&m_AllInfo.BasicInformation.LastAccessTime));
        lat = date.toString("yyyy-MM-dd HH:mm:ss");
        date.setTime_t(FileTimeToUnixTime((FILETIME *)&m_AllInfo.BasicInformation.LastWriteTime));
        lwt = date.toString("yyyy-MM-dd HH:mm:ss");
        date.setTime_t(FileTimeToUnixTime((FILETIME *)&m_AllInfo.BasicInformation.ChangeTime));
        cht = date.toString("yyyy-MM-dd HH:mm:ss");
        GetFileAttributesString(m_AllInfo.BasicInformation.FileAttributes, fa);
        str += QObject::tr("\nCreationTime:\t%1\nLastAccessTime:\t%2\nLastWriteTime:\t%3\nChangeTime:\t%4\nFileAttributes:\t%5").arg(crt, lat, lwt, cht, fa);
    }
    if(m_QueryClass == FileStandardInformation){
        str += QObject::tr("\nAllocationSize:\t%1\nEndOfFile:\t%2\nDeletePending:\t%3\nDirectory:\t%4").arg(
                    FormatFileSizeString(m_AllInfo.StandardInformation.AllocationSize.QuadPart),
                    FormatFileSizeString(m_AllInfo.StandardInformation.EndOfFile.QuadPart),
                    m_AllInfo.StandardInformation.DeletePending ? QObject::tr("true") : QObject::tr("false"),
                    m_AllInfo.StandardInformation.Directory ? QObject::tr("true") : QObject::tr("false")
                    );
    }
}

//CreateKey

CUniqueEvent_OpenKey::CUniqueEvent_OpenKey(CUniqueProcess *up, ULONG ThreadId,
                         LPCWSTR szKeyPath, ULONG DesiredAccess,
                         ULONG ResultStatus, ULONG64 KeSystemTime, ULONG64 EventId) :
    CUniqueEvent_WithTargetFile(up, ThreadId, szKeyPath, ResultStatus, KeSystemTime, EventId)
{
    m_DesiredAccess = DesiredAccess;
}

void CUniqueEvent_OpenKey::GetBriefArgument(QString &str) const
{
    QString desiredAccess;
    GetKeyDesiredAccessString(m_DesiredAccess, desiredAccess);

    str = desiredAccess;
}

void CUniqueEvent_OpenKey::GetFullArgument(QString &str) const
{
    QString desiredAccess;
    GetKeyDesiredAccessString(m_DesiredAccess, desiredAccess);

    str = QObject::tr("DesiredAccess:\t%1").arg(desiredAccess);
}

//CreateKey

CUniqueEvent_CreateKey::CUniqueEvent_CreateKey(CUniqueProcess *up, ULONG ThreadId,
                        LPCWSTR szKeyPath, ULONG DesiredAccess, ULONG Disposition, ULONG CreateOptions,
                        ULONG ResultStatus, ULONG64 KeSystemTime, ULONG64 EventId)
    : CUniqueEvent_OpenKey(up, ThreadId, szKeyPath, DesiredAccess,
                           ResultStatus, KeSystemTime, EventId)
{
    m_Disposition = Disposition;
    m_CreateOptions = CreateOptions;
}

void CUniqueEvent_CreateKey::GetFullArgument(QString &str) const
{
    CUniqueEvent_OpenKey::GetFullArgument(str);

    QString options;
    GetCreateKeyOptionsString(m_CreateOptions, options);

    str = QObject::tr("\nDisposition:\t%1\nCreateOptions:\t%2")
            .arg(GetCreateKeyDispositionString(m_Disposition),
            options);
}

//SetValueKey

CUniqueEvent_SetValueKey::CUniqueEvent_SetValueKey(CUniqueProcess *up, ULONG ThreadId,
                        LPCWSTR szKeyPath, LPCWSTR szValueName, ULONG DataType, ULONG DataSize, QByteArray &BinaryData,
                        ULONG ResultStatus, ULONG64 KeSystemTime, ULONG64 EventId) :
    CUniqueEvent_WithTargetFile(up, ThreadId, szKeyPath, ResultStatus, KeSystemTime, EventId)
{
    m_KeyValue = NULL;

    if(DataType == REG_DWORD_LITTLE_ENDIAN || DataType == REG_DWORD_BIG_ENDIAN || DataType == REG_QWORD) {
        m_KeyValue = new CRegKeyValueNumber(DataType, DataSize, szValueName, BinaryData);
    } else if(DataType == REG_SZ || DataType == REG_EXPAND_SZ || DataType == REG_MULTI_SZ) {
        m_KeyValue = new CRegKeyValueString(DataType, DataSize, szValueName, BinaryData);
    } else {
        m_KeyValue = new CRegKeyValueBinary(DataType, DataSize, szValueName, BinaryData);
    }
}

CUniqueEvent_SetValueKey::~CUniqueEvent_SetValueKey()
{
    if(m_KeyValue)
        delete m_KeyValue;
}

void CUniqueEvent_SetValueKey::GetBriefArgument(QString &str) const
{
    str = GetRegistryKeyDataType(m_KeyValue->GetType());
}

void CUniqueEvent_SetValueKey::GetFullArgument(QString &str) const
{
    str = QObject::tr("ValueName:\t%1\n\nDataType:\t%2\nDataSize:\t%3\nData:").arg(
                m_KeyValue->GetValueName(),
                GetRegistryKeyDataType(m_KeyValue->GetType()),
                FormatFileSizeString(m_KeyValue->GetSize())
                );

    str += (m_KeyValue->NeedBreak()) ? "\n" : "\t";

    m_KeyValue->PrintFull(str);
}

//QueryValueKey

CUniqueEvent_QueryValueKey::CUniqueEvent_QueryValueKey(CUniqueProcess *up, ULONG ThreadId,
                                                       LPCWSTR szKeyPath, LPCWSTR szValueName, ULONG QueryClass, ULONG QueryLength, QByteArray &BinaryData,
                                                       ULONG ResultStatus, ULONG64 KeSystemTime, ULONG64 EventId) :
    CUniqueEvent_WithTargetFile(up, ThreadId, szKeyPath, ResultStatus, KeSystemTime, EventId)
{
    UNREFERENCED_PARAMETER(BinaryData);

    m_QueryClass = QueryClass;
    m_QueryLength = QueryLength;
    m_ValueName = m_StringMgr->GetString(szValueName);
}

void CUniqueEvent_QueryValueKey::GetBriefArgument(QString &str) const
{
    str = GetRegistryQueryValueKeyClass(m_QueryClass);
}

void CUniqueEvent_QueryValueKey::GetFullArgument(QString &str) const
{
    str = QObject::tr("ValueName:\t%1\nKeyValueInformationClass:\t%2\nLength:\t0x%3\n\n").arg(
                m_ValueName.GetQString(),
                GetRegistryQueryValueKeyClass(m_QueryClass),
                FormatHexString(m_QueryLength, 0)
                );
}

inline ULONG GetByteArrayMaxLength(QByteArray &ba, ULONG myOffset, ULONG myLength)
{
    if(myOffset == (ULONG)-1 || (ULONG)ba.size() <= myOffset )
        return 0;

    return min(myLength, ba.size() - myOffset);
}

//QueryValueKey-basic

CUniqueEvent_QueryValueKey_BasicInformation::CUniqueEvent_QueryValueKey_BasicInformation(
        CUniqueProcess *up, ULONG ThreadId,
        LPCWSTR szKeyPath, LPCWSTR szValueName, ULONG QueryLength, QByteArray &BinaryData,
        ULONG ResultStatus, ULONG64 KeSystemTime, ULONG64 EventId) :
    CUniqueEvent_QueryValueKey(up, ThreadId,
                               szKeyPath, szValueName, KeyValueBasicInformation, QueryLength, BinaryData,
                               ResultStatus, KeSystemTime, EventId)
{
    m_KeyType = (ULONG)-1;
    if(BinaryData.size() >= offsetof(KEY_VALUE_BASIC_INFORMATION, Name)) {
        PKEY_VALUE_BASIC_INFORMATION p = (PKEY_VALUE_BASIC_INFORMATION)BinaryData.data();
        m_KeyType = p->Type;

        int len = GetByteArrayMaxLength(BinaryData, offsetof(KEY_VALUE_BASIC_INFORMATION, Name), p->NameLength);
        if(len > 0)
            m_KeyName = m_StringMgr->GetString( p->Name, len / sizeof(WCHAR) );
    }
}

void CUniqueEvent_QueryValueKey_BasicInformation::GetFullArgument(QString &str) const
{
    CUniqueEvent_QueryValueKey::GetFullArgument(str);

    if(m_KeyType != (ULONG)-1){
        str += QObject::tr("Type:\t%1\nName:\t%2").arg(
                    GetRegistryKeyDataType(m_KeyType),
                    m_KeyName.GetQString());
    }
}

//QueryValueKey-full

CUniqueEvent_QueryValueKey_FullInformation::CUniqueEvent_QueryValueKey_FullInformation(
        CUniqueProcess *up, ULONG ThreadId,
        LPCWSTR szKeyPath, LPCWSTR szValueName, ULONG QueryLength, QByteArray &BinaryData,
        ULONG ResultStatus, ULONG64 KeSystemTime, ULONG64 EventId) :
    CUniqueEvent_QueryValueKey(up, ThreadId,
                               szKeyPath, szValueName, KeyValueFullInformation, QueryLength, BinaryData,
                               ResultStatus, KeSystemTime, EventId)
{
    PKEY_VALUE_FULL_INFORMATION p = (PKEY_VALUE_FULL_INFORMATION)BinaryData.data();

    QByteArray tempData;
    int len = GetByteArrayMaxLength(BinaryData, p->DataOffset, p->DataLength);
    if(len > 0)
        tempData = QByteArray((PCHAR)p + p->DataOffset, len);

    CUniqueString keyName;
    len = GetByteArrayMaxLength(BinaryData, offsetof(KEY_VALUE_FULL_INFORMATION, Name), p->NameLength);
    if(len > 0)
        keyName = m_StringMgr->GetString(p->Name, len / sizeof(WCHAR));

    if(p->Type == REG_DWORD_LITTLE_ENDIAN || p->Type == REG_DWORD_BIG_ENDIAN || p->Type == REG_QWORD) {
        m_KeyValue = new CRegKeyValueNumber(p->Type, p->DataLength, keyName.GetString(), tempData);
    } else if(p->Type == REG_SZ || p->Type == REG_EXPAND_SZ || p->Type == REG_MULTI_SZ) {
        m_KeyValue = new CRegKeyValueString(p->Type, p->DataLength, keyName.GetString(), tempData);
    } else {
        m_KeyValue = new CRegKeyValueBinary(p->Type, p->DataLength, keyName.GetString(), tempData);
    }
}

CUniqueEvent_QueryValueKey_FullInformation::~CUniqueEvent_QueryValueKey_FullInformation()
{
    if(m_KeyValue)
        delete m_KeyValue;
}

void CUniqueEvent_QueryValueKey_FullInformation::GetFullArgument(QString &str) const
{
    CUniqueEvent_QueryValueKey::GetFullArgument(str);
    if(m_KeyValue){
        str += QObject::tr("Type:\t%1\nName:\t%2\nDataLength:\t0x%3\nData:").arg(
                    GetRegistryKeyDataType(m_KeyValue->GetType()),
                    m_KeyValue->GetValueName(),
                    FormatHexString(m_KeyValue->GetSize(), 0) );
        str += (m_KeyValue->NeedBreak()) ? "\n" : "\t";
        m_KeyValue->PrintFull(str);
    }
}

//QueryValueKey--partial

CUniqueEvent_QueryValueKey_PartialInformation::CUniqueEvent_QueryValueKey_PartialInformation(
        CUniqueProcess *up, ULONG ThreadId,
        LPCWSTR szKeyPath, LPCWSTR szValueName, ULONG QueryLength, QByteArray &BinaryData,
        ULONG ResultStatus, ULONG64 KeSystemTime, ULONG64 EventId) :
    CUniqueEvent_QueryValueKey(up, ThreadId,
                               szKeyPath, szValueName, KeyValuePartialInformation, QueryLength, BinaryData,
                               ResultStatus, KeSystemTime, EventId)
{
    PKEY_VALUE_PARTIAL_INFORMATION p = (PKEY_VALUE_PARTIAL_INFORMATION)BinaryData.data();

    QByteArray tempData;

    int len = GetByteArrayMaxLength(BinaryData, offsetof(KEY_VALUE_PARTIAL_INFORMATION, Data), p->DataLength);
    if(len > 0)
        tempData = QByteArray((PCHAR)p->Data, len);

    if(p->Type == REG_DWORD_LITTLE_ENDIAN || p->Type == REG_DWORD_BIG_ENDIAN || p->Type == REG_QWORD) {
        m_KeyValue = new CRegKeyValueNumber(p->Type, p->DataLength, L"", tempData);
    } else if(p->Type == REG_SZ || p->Type == REG_EXPAND_SZ || p->Type == REG_MULTI_SZ) {
        m_KeyValue = new CRegKeyValueString(p->Type, p->DataLength, L"", tempData);
    } else {
        m_KeyValue = new CRegKeyValueBinary(p->Type, p->DataLength, L"", tempData);
    }
}

CUniqueEvent_QueryValueKey_PartialInformation::~CUniqueEvent_QueryValueKey_PartialInformation()
{
    if(m_KeyValue)
        delete m_KeyValue;
}

void CUniqueEvent_QueryValueKey_PartialInformation::GetFullArgument(QString &str) const
{
    CUniqueEvent_QueryValueKey::GetFullArgument(str);
    if(m_KeyValue){
        str += QObject::tr("Type:\t%1\nDataLength:\t0x%2\nData:").arg(
                    GetRegistryKeyDataType(m_KeyValue->GetType()),
                    FormatHexString(m_KeyValue->GetSize(), 0) );
        str += (m_KeyValue->NeedBreak()) ? "\n" : "\t";
        m_KeyValue->PrintFull(str);
    }
}

//QueryKey

CUniqueEvent_QueryKey::CUniqueEvent_QueryKey(CUniqueProcess *up, ULONG ThreadId,
                        LPCWSTR szKeyPath, ULONG QueryClass, ULONG QueryLength, QByteArray &BinaryData,
                        ULONG ResultStatus, ULONG64 KeSystemTime, ULONG64 EventId) :
    CUniqueEvent_WithTargetFile(up, ThreadId, szKeyPath, ResultStatus, KeSystemTime, EventId)
{
    UNREFERENCED_PARAMETER(BinaryData);

    m_QueryClass = QueryClass;
    m_QueryLength = QueryLength;
}

void CUniqueEvent_QueryKey::GetBriefArgument(QString &str) const
{
    str = GetRegistryQueryKeyClass(m_QueryClass);
}

void CUniqueEvent_QueryKey::GetFullArgument(QString &str) const
{
    str = QObject::tr("KeyInformationClass:\t%1\nLength:\t0x%2\n\n").arg(
                GetRegistryQueryKeyClass(m_QueryClass),
                FormatHexString(m_QueryLength, 0) );
}

//QueryKey - basic

CUniqueEvent_QueryKey_BasicInformation::CUniqueEvent_QueryKey_BasicInformation(
    CUniqueProcess *up, ULONG ThreadId,
    LPCWSTR szKeyPath, ULONG QueryLength, QByteArray &BinaryData,
    ULONG ResultStatus, ULONG64 KeSystemTime, ULONG64 EventId) :
    CUniqueEvent_QueryKey(
        up, ThreadId,
        szKeyPath, KeyBasicInformation, QueryLength, BinaryData,
        ResultStatus, KeSystemTime, EventId)
{
    PKEY_BASIC_INFORMATION p = (PKEY_BASIC_INFORMATION)BinaryData.data();
    m_LastWriteTime = p->LastWriteTime;

    int len = GetByteArrayMaxLength(BinaryData, offsetof(KEY_BASIC_INFORMATION, Name), p->NameLength);
    if(len > 0)
        m_KeyName = m_StringMgr->GetString(p->Name, len / sizeof(WCHAR));
}

void CUniqueEvent_QueryKey_BasicInformation::GetFullArgument(QString &str) const
{
    CUniqueEvent_QueryKey::GetFullArgument(str);

    QDateTime date;
    date.setTime_t(FileTimeToUnixTime((FILETIME *)&m_LastWriteTime));
    QString dateStr = date.toString("yyyy-MM-dd HH:mm:ss");

    str += QObject::tr("LastWriteTime:\t%1\nKeyName:\t%2").arg(dateStr, m_KeyName.GetQString());
}

//QueryKey - node

CUniqueEvent_QueryKey_NodeInformation::CUniqueEvent_QueryKey_NodeInformation(
    CUniqueProcess *up, ULONG ThreadId,
    LPCWSTR szKeyPath, ULONG QueryLength, QByteArray &BinaryData,
    ULONG ResultStatus, ULONG64 KeSystemTime, ULONG64 EventId) :
    CUniqueEvent_QueryKey(
        up, ThreadId,
        szKeyPath, KeyNodeInformation, QueryLength, BinaryData,
        ResultStatus, KeSystemTime, EventId)
{
    PKEY_NODE_INFORMATION p = (PKEY_NODE_INFORMATION)BinaryData.data();
    m_LastWriteTime = p->LastWriteTime;

    int len = GetByteArrayMaxLength(BinaryData, offsetof(KEY_NODE_INFORMATION, Name), p->NameLength);
    if(len > 0)
        m_KeyName = m_StringMgr->GetString(p->Name, len / sizeof(WCHAR));

    len = GetByteArrayMaxLength(BinaryData, p->ClassOffset, p->ClassLength);
    if(len>0)
        m_ClassName = m_StringMgr->GetString((LPCWSTR)((PCHAR)p + p->ClassOffset), len / 2);
}

void CUniqueEvent_QueryKey_NodeInformation::GetFullArgument(QString &str) const
{
    CUniqueEvent_QueryKey::GetFullArgument(str);

    QDateTime date;
    date.setTime_t(FileTimeToUnixTime((FILETIME *)&m_LastWriteTime));
    QString dateStr = date.toString("yyyy-MM-dd HH:mm:ss");

    str += QObject::tr("LastWriteTime:\t%1\nKeyName:\t%2\nClassName:\t%3").arg(dateStr, m_ClassName.GetQString());
}

//QueryKey - full

CUniqueEvent_QueryKey_FullInformation::CUniqueEvent_QueryKey_FullInformation(
    CUniqueProcess *up, ULONG ThreadId,
    LPCWSTR szKeyPath, ULONG QueryLength, QByteArray &BinaryData,
    ULONG ResultStatus, ULONG64 KeSystemTime, ULONG64 EventId) :
    CUniqueEvent_QueryKey(
        up, ThreadId,
        szKeyPath, KeyFullInformation, QueryLength, BinaryData,
        ResultStatus, KeSystemTime, EventId)
{
    PKEY_FULL_INFORMATION p = (PKEY_FULL_INFORMATION)BinaryData.data();
    m_LastWriteTime = p->LastWriteTime;
    int len = GetByteArrayMaxLength(BinaryData, p->ClassOffset, p->ClassLength);
    if(len > 0)
        m_ClassName = m_StringMgr->GetString((LPCWSTR)((PCHAR)p + p->ClassOffset), len / sizeof(WCHAR));

    m_SubKeys = p->SubKeys;
    m_MaxNameLen = p->MaxNameLen;
    m_MaxClassLen = p->MaxClassLen;
    m_Values = p->Values;
    m_MaxValueNameLen = p->MaxValueNameLen;
    m_MaxValueDataLen = p->MaxValueDataLen;
}

void CUniqueEvent_QueryKey_FullInformation::GetFullArgument(QString &str) const
{
    CUniqueEvent_QueryKey::GetFullArgument(str);

    QDateTime date;
    date.setTime_t(FileTimeToUnixTime((FILETIME *)&m_LastWriteTime));
    QString dateStr = date.toString("yyyy-MM-dd HH:mm:ss");

    str += QObject::tr("LastWriteTime:\t%1\nClassName:\t%2\nSubKeys:\t%3\nMaxNameLen:\t%4\nMaxClassLen:\t%5\nValues:\t%6\nMaxValueNameLen:\t%7\nMaxValueDataLen:\t%8").arg(
                dateStr, m_ClassName.GetQString(),
                QString::number(m_SubKeys),
                QString::number(m_MaxNameLen),
                QString::number(m_MaxClassLen),
                QString::number(m_Values),
                QString::number(m_MaxValueNameLen),
                QString::number(m_MaxValueDataLen));
}

//QueryKey - name

CUniqueEvent_QueryKey_NameInformation::CUniqueEvent_QueryKey_NameInformation(
    CUniqueProcess *up, ULONG ThreadId,
    LPCWSTR szKeyPath, ULONG QueryLength, QByteArray &BinaryData,
    ULONG ResultStatus, ULONG64 KeSystemTime, ULONG64 EventId) :
    CUniqueEvent_QueryKey(
        up, ThreadId,
        szKeyPath, KeyNameInformation, QueryLength, BinaryData,
        ResultStatus, KeSystemTime, EventId)
{
    PKEY_NAME_INFORMATION p = (PKEY_NAME_INFORMATION)BinaryData.data();
    int len = GetByteArrayMaxLength(BinaryData, offsetof(KEY_NAME_INFORMATION, Name), p->NameLength);
    if(len > 0)
        m_KeyName = m_StringMgr->GetString(p->Name, len / sizeof(WCHAR));
}

void CUniqueEvent_QueryKey_NameInformation::GetFullArgument(QString &str) const
{
    CUniqueEvent_QueryKey::GetFullArgument(str);

    str += QObject::tr("Name:\t%1").arg(m_KeyName.GetQString());
}

//QueryKey - cached

CUniqueEvent_QueryKey_CachedInformation::CUniqueEvent_QueryKey_CachedInformation(
    CUniqueProcess *up, ULONG ThreadId,
    LPCWSTR szKeyPath, ULONG QueryLength, QByteArray &BinaryData,
    ULONG ResultStatus, ULONG64 KeSystemTime, ULONG64 EventId) :
    CUniqueEvent_QueryKey(
        up, ThreadId,
        szKeyPath, KeyCachedInformation, QueryLength, BinaryData,
        ResultStatus, KeSystemTime, EventId)
{
    PKEY_CACHED_INFORMATION p = (PKEY_CACHED_INFORMATION)BinaryData.data();
    m_LastWriteTime = p->LastWriteTime;
    m_SubKeys = p->SubKeys;
    m_MaxNameLen = p->MaxNameLen;
    m_Values = p->Values;
    m_MaxValueNameLen = p->MaxValueNameLen;
    m_MaxValueDataLen = p->MaxValueDataLen;
    m_NameLength = p->NameLength;
}

void CUniqueEvent_QueryKey_CachedInformation::GetFullArgument(QString &str) const
{
    CUniqueEvent_QueryKey::GetFullArgument(str);

    QDateTime date;
    date.setTime_t(FileTimeToUnixTime((FILETIME *)&m_LastWriteTime));
    QString dateStr = date.toString("yyyy-MM-dd HH:mm:ss");

    str += QObject::tr("LastWriteTime:\t%1\nSubKeys:\t%2\nMaxNameLen:\t%3\nValues:\t%4\nMaxValueNameLen:\t%5\nMaxValueDataLen:\t%6\nNameLength:\t%7").arg(
                dateStr,
                QString::number(m_SubKeys),
                QString::number(m_MaxNameLen),
                QString::number(m_Values),
                QString::number(m_MaxValueNameLen),
                QString::number(m_MaxValueDataLen),
                QString::number(m_NameLength));
}

//QueryKey - virtualization

CUniqueEvent_QueryKey_VirtualizationInformation::CUniqueEvent_QueryKey_VirtualizationInformation(
    CUniqueProcess *up, ULONG ThreadId,
    LPCWSTR szKeyPath, ULONG QueryLength, QByteArray &BinaryData,
    ULONG ResultStatus, ULONG64 KeSystemTime, ULONG64 EventId) :
    CUniqueEvent_QueryKey(
        up, ThreadId,
        szKeyPath, KeyVirtualizationInformation, QueryLength, BinaryData,
        ResultStatus, KeSystemTime, EventId)
{
    PKEY_VIRTUALIZATION_INFORMATION p = (PKEY_VIRTUALIZATION_INFORMATION)BinaryData.data();
    m_VirtualizationCandidate = p->VirtualizationCandidate;
    m_VirtualizationEnabled = p->VirtualizationEnabled;
    m_VirtualTarget = p->VirtualTarget;
    m_VirtualStore = p->VirtualStore;
    m_VirtualSource = p->VirtualSource;
}

void CUniqueEvent_QueryKey_VirtualizationInformation::GetFullArgument(QString &str) const
{
    CUniqueEvent_QueryKey::GetFullArgument(str);

    str += QObject::tr("VirtualizationCandidate:\t%1\nVirtualizationEnabled:\t%2\nVirtualTarget:\t%3\nVirtualStore:\t%4\nVirtualSource:\t%5").arg(
                m_VirtualizationCandidate ? "true" : "false",
                m_VirtualizationEnabled ? "true" : "false",
                m_VirtualTarget ? "true" : "false",
                m_VirtualStore ? "true" : "false",
                m_VirtualSource ? "true" : "false");
}
