#include <Windows.h>
#include "syscallmon.h"
#include "DriverWrapper.h"
#include "ProcessMgr.h"
#include "EventMgr.h"
#include "util.h"

void CMonitorWorker::Quit(void)
{
    if (m_hQuitEvent != NULL){
        SetEvent(m_hQuitEvent);
    }
}

void CMonitorWorker::Uninitialize(void)
{
    if (m_hQuitEvent != NULL){
        CloseHandle(m_hQuitEvent);
    }
}

Q_DECLARE_METATYPE(QSharedPointer<QByteArray>)

void CMonitorWorker::Initialize(void)
{
    m_hQuitEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    qRegisterMetaType<QSharedPointer<QByteArray>>("QSharedPointer<QByteArray>");

#define BIND_MESSAGE_PARSER(msgname) connect(this, &CMonitorWorker::##msgname, m_EventMgr, &CEventMgr::On##msgname, Qt::QueuedConnection);
#define BIND_MESSAGE_PARSER_BLOCK(msgname) connect(this, &CMonitorWorker::##msgname, m_EventMgr, &CEventMgr::On##msgname, Qt::BlockingQueuedConnection);

    BIND_MESSAGE_PARSER(CallStack);
    BIND_MESSAGE_PARSER_BLOCK(PsCreateProcess);
    BIND_MESSAGE_PARSER(PsCreateThread);
    BIND_MESSAGE_PARSER_BLOCK(PsLoadImage);
    BIND_MESSAGE_PARSER(NtLoadDriver);
    BIND_MESSAGE_PARSER(NtQuerySystemInfo);
    BIND_MESSAGE_PARSER(NtOpenProcess);
    BIND_MESSAGE_PARSER(NtOpenThread);
    BIND_MESSAGE_PARSER(NtTerminateProcess);
    BIND_MESSAGE_PARSER(NtAllocateVirtualMemory);
    BIND_MESSAGE_PARSER(NtReadWriteVirtualMemory);
    BIND_MESSAGE_PARSER(NtProtectVirtualMemory);
    BIND_MESSAGE_PARSER(NtQueryVirtualMemory);
    BIND_MESSAGE_PARSER(NtCreateOpenMutant);
    BIND_MESSAGE_PARSER(NtCreateOpenDirectoryObject);
    BIND_MESSAGE_PARSER(NtQueryDirectoryObject);
    BIND_MESSAGE_PARSER(NtUserSetWindowsHook);
    BIND_MESSAGE_PARSER(NtUserFindWindow);
    BIND_MESSAGE_PARSER(NtUserInternalGetWindowText);
    BIND_MESSAGE_PARSER(NtUserGetClassName);
    BIND_MESSAGE_PARSER(FsCreateFile);
    BIND_MESSAGE_PARSER(FsCloseFile);
    BIND_MESSAGE_PARSER(FsReadWriteFile);
    BIND_MESSAGE_PARSER(FsCreateFileMapping);
    BIND_MESSAGE_PARSER(FsQueryFileInformation);
    BIND_MESSAGE_PARSER(RgCreateOpenKey);
    BIND_MESSAGE_PARSER(RgSetValueKey);
    BIND_MESSAGE_PARSER(RgQueryValueKey);
    BIND_MESSAGE_PARSER(RgQueryKey);
}

bool CMonitorWorker::ParseMessage(PUCHAR data)
{
    bool bParsed = true;
    svc_nop_data *header = (svc_nop_data *)data;

    m_EventMgr->Lock();

    QSharedPointer<QByteArray> ba(new QByteArray((const char *)data, header->size));

    switch(header->protocol){
    case svc_callstack:
        CallStack(ba);
        break;
    case svc_ps_create_thread:
        PsCreateThread(ba);
        break;
    case svc_ps_create_process:
        PsCreateProcess(ba);
        break;
    case svc_ps_load_image:
        PsLoadImage(ba);
        break;
    case svc_nt_load_driver:
        NtLoadDriver(ba);
        break;
    case svc_nt_query_systeminfo:
        NtQuerySystemInfo(ba);
        break;
    case svc_nt_open_process:
        NtOpenProcess(ba);
        break;
    case svc_nt_open_thread:
        NtOpenThread(ba);
        break;
    case svc_nt_terminate_process:
        NtTerminateProcess(ba);
        break;
    case svc_nt_alloc_virtual_mem:
        NtAllocateVirtualMemory(ba);
        break;
    case svc_nt_readwrite_virtual_mem:
        NtReadWriteVirtualMemory(ba);
        break;
    case svc_nt_protect_virtual_mem:
        NtProtectVirtualMemory(ba);
        break;
    case svc_nt_query_virtual_mem:
        NtQueryVirtualMemory(ba);
        break;
    case svc_nt_createopen_mutant:
        NtCreateOpenMutant(ba);
        break;
    case svc_nt_createopen_dirobj:
        NtCreateOpenDirectoryObject(ba);
        break;
    case svc_nt_query_dirobj:
        NtQueryDirectoryObject(ba);
        break;
    case svc_nt_setwindowshook:
        NtUserSetWindowsHook(ba);
        break;
    case svc_nt_findwindow:
        NtUserFindWindow(ba);
        break;
    case svc_nt_getwindowtext:
        NtUserInternalGetWindowText(ba);
        break;
    case svc_nt_getwindowclass:
        NtUserGetClassName(ba);
        break;
    case svc_fs_create_file:
        FsCreateFile(ba);
        break;
    case svc_fs_close_file:
        FsCloseFile(ba);
        break;
    case svc_fs_readwrite_file:
        FsReadWriteFile(ba);
        break;
    case svc_fs_createfilemapping:
        FsCreateFileMapping(ba);
        break;
    case svc_fs_queryfileinformation:
        FsQueryFileInformation(ba);
        break;
    case svc_reg_createopenkey:
        RgCreateOpenKey(ba);
        break;
    case svc_reg_setvaluekey:
        RgSetValueKey(ba);
        break;
    case svc_reg_queryvaluekey:
        RgQueryValueKey(ba);
        break;
    case svc_reg_querykey:
        RgQueryKey(ba);
        break;
    default:
        bParsed = false;
        break;
    }

    m_EventMgr->Unlock();

    return bParsed;
}
