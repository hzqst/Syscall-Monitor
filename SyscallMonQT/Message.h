#pragma once

#include <QObject>
#include <boost/unordered_map.hpp>
#include <Windows.h>
#include "nt.h"
#include "../shared/protocol.h"

class CUniqueEvent;

class CMessageParser : public QObject
{
    Q_OBJECT
public:
    explicit CMessageParser(QObject *parent = Q_NULLPTR) : QObject(parent)
    {

    }
    virtual void ParseBytes(svc_nop_data *buf) = 0;
};

class CCallStack_Params
{
public:
    svc_callstack_data data;
    ULONG KernelCallerCount;
    ULONG UserCallerCount;
    std::vector<ULONG64> Callers;
};

class CMessageParser_CallStack : public CMessageParser
{
    Q_OBJECT
public:
    explicit CMessageParser_CallStack(QObject *parent);

    void ParseBytes(svc_nop_data *buf);
signals:
    void SendEventData(CCallStack_Params *param);
};

class CPsCreateProcess_Params
{
public:
    svc_ps_create_process_data data;
    std::wstring NormalizedImagePath;
    QIcon *Icon;
};

class CMessageParser_PsCreateProcess : public CMessageParser
{
    Q_OBJECT
public:
    explicit CMessageParser_PsCreateProcess(QObject *parent);

    void ParseBytes(svc_nop_data *buf);

signals:
    void SendEventData(CPsCreateProcess_Params *param);
};

class CPsCreateThread_Params
{
public:
    svc_ps_create_thread_data data;
};

class CMessageParser_PsCreateThread : public CMessageParser
{
    Q_OBJECT
public:
    explicit CMessageParser_PsCreateThread(QObject *parent);

    void ParseBytes(svc_nop_data *buf);
signals:
    void SendEventData(CPsCreateThread_Params *param);
};

class CPsLoadImage_Params
{
public:
    svc_ps_load_image_data data;
    std::wstring NormalizedImagePath;
};

class CMessageParser_PsLoadImage : public CMessageParser
{
    Q_OBJECT
public:
    explicit CMessageParser_PsLoadImage(QObject *parent);

    void ParseBytes(svc_nop_data *buf);
signals:
    void SendEventData(CPsLoadImage_Params *param);
};

class CNtLoadDriver_Params
{
public:
    svc_nt_load_driver_data data;
};

class CMessageParser_NtLoadDriver : public CMessageParser
{
    Q_OBJECT
public:
    explicit CMessageParser_NtLoadDriver(QObject *parent);

    void ParseBytes(svc_nop_data *buf);
signals:
    void SendEventData(CNtLoadDriver_Params *param);
};

class CNtQuerySystemInfo_Params
{
public:
    svc_nt_query_systeminfo_data data;
};

class CMessageParser_NtQuerySystemInfo : public CMessageParser
{
    Q_OBJECT
public:
    explicit CMessageParser_NtQuerySystemInfo(QObject *parent);

    void ParseBytes(svc_nop_data *buf);
signals:
    void SendEventData(CNtQuerySystemInfo_Params *param);
};

class CNtOpenProcess_Params
{
public:
    svc_nt_open_process_data data;
};

class CMessageParser_NtOpenProcess : public CMessageParser
{
    Q_OBJECT
public:
    explicit CMessageParser_NtOpenProcess(QObject *parent);

    void ParseBytes(svc_nop_data *buf);
signals:
    void SendEventData(CNtOpenProcess_Params *param);
};

class CNtOpenThread_Params
{
public:
    svc_nt_open_thread_data data;
};

class CMessageParser_NtOpenThread : public CMessageParser
{
    Q_OBJECT
public:
    explicit CMessageParser_NtOpenThread(QObject *parent);

    void ParseBytes(svc_nop_data *buf);
signals:
    void SendEventData(CNtOpenThread_Params *param);
};

class CNtTerminateProcess_Params
{
public:
    svc_nt_terminate_process_data data;
};

class CMessageParser_NtTerminateProcess : public CMessageParser
{
    Q_OBJECT
public:
    explicit CMessageParser_NtTerminateProcess(QObject *parent);

    void ParseBytes(svc_nop_data *buf);
signals:
    void SendEventData(CNtTerminateProcess_Params *param);
};

class CNtAllocateVirtualMemory_Params
{
public:
    svc_nt_alloc_virtual_mem_data data;
};

class CMessageParser_NtAllocateVirtualMemory : public CMessageParser
{
    Q_OBJECT
public:
    explicit CMessageParser_NtAllocateVirtualMemory(QObject *parent);

    void ParseBytes(svc_nop_data *buf);
signals:
    void SendEventData(CNtAllocateVirtualMemory_Params *param);
};


class CNtReadWriteVirtualMemory_Params
{
public:
    svc_nt_readwrite_virtual_mem_data data;
};

class CMessageParser_NtReadWriteVirtualMemory : public CMessageParser
{
    Q_OBJECT
public:
    explicit CMessageParser_NtReadWriteVirtualMemory(QObject *parent);

    void ParseBytes(svc_nop_data *buf);
signals:
    void SendEventData(CNtReadWriteVirtualMemory_Params *param);
};

class CNtProtectVirtualMemory_Params
{
public:
    svc_nt_protect_virtual_mem_data data;
};

class CMessageParser_NtProtectVirtualMemory : public CMessageParser
{
    Q_OBJECT
public:
    explicit CMessageParser_NtProtectVirtualMemory(QObject *parent);

    void ParseBytes(svc_nop_data *buf);
signals:
    void SendEventData(CNtProtectVirtualMemory_Params *param);
};

class CNtQueryVirtualMemory_Params
{
public:
    svc_nt_query_virtual_mem_data data;
};

class CMessageParser_NtQueryVirtualMemory : public CMessageParser
{
    Q_OBJECT
public:
    explicit CMessageParser_NtQueryVirtualMemory(QObject *parent);

    void ParseBytes(svc_nop_data *buf);
signals:
    void SendEventData(CNtQueryVirtualMemory_Params *param);
};

class CNtUserSetWindowsHook_Params
{
public:
    svc_nt_setwindowshook_data data;
};

class CMessageParser_NtUserSetWindowsHook : public CMessageParser
{
    Q_OBJECT
public:
    explicit CMessageParser_NtUserSetWindowsHook(QObject *parent);

    void ParseBytes(svc_nop_data *buf);
signals:
    void SendEventData(CNtUserSetWindowsHook_Params *param);
};

class CNtUserFindWindow_Params
{
public:
    svc_nt_findwindow_data data;
};

class CMessageParser_NtUserFindWindow : public CMessageParser
{
    Q_OBJECT
public:
    explicit CMessageParser_NtUserFindWindow(QObject *parent);

    void ParseBytes(svc_nop_data *buf);
signals:
    void SendEventData(CNtUserFindWindow_Params *param);
};

class CNtUserInternalGetWindowText_Params
{
public:
    svc_nt_getwindowtext_data data;
};

class CMessageParser_NtUserInternalGetWindowText : public CMessageParser
{
    Q_OBJECT
public:
    explicit CMessageParser_NtUserInternalGetWindowText(QObject *parent);

    void ParseBytes(svc_nop_data *buf);
signals:
    void SendEventData(CNtUserInternalGetWindowText_Params *param);
};

class CNtUserGetClassName_Params
{
public:
    svc_nt_getwindowclass_data data;
};

class CMessageParser_NtUserGetClassName : public CMessageParser
{
    Q_OBJECT
public:
    explicit CMessageParser_NtUserGetClassName(QObject *parent);

    void ParseBytes(svc_nop_data *buf);
signals:
    void SendEventData(CNtUserGetClassName_Params *param);
};

class CFsCreateFile_Params
{
public:
    svc_fs_create_file_data data;
};

class CMessageParser_FsCreateFile : public CMessageParser
{
    Q_OBJECT
public:
    explicit CMessageParser_FsCreateFile(QObject *parent);

    void ParseBytes(svc_nop_data *buf);
signals:
    void SendEventData(CFsCreateFile_Params *param);
};

class CFsCloseFile_Params
{
public:
    svc_fs_close_file_data data;
};

class CMessageParser_FsCloseFile : public CMessageParser
{
    Q_OBJECT
public:
    explicit CMessageParser_FsCloseFile(QObject *parent);

    void ParseBytes(svc_nop_data *buf);
signals:
    void SendEventData(CFsCloseFile_Params *param);
};

class CFsReadWriteFile_Params
{
public:
    svc_fs_readwrite_file_data data;
};

class CMessageParser_FsReadWriteFile : public CMessageParser
{
    Q_OBJECT
public:
    explicit CMessageParser_FsReadWriteFile(QObject *parent);

    void ParseBytes(svc_nop_data *buf);
signals:
    void SendEventData(CFsReadWriteFile_Params *param);
};

class CFsCreateFileMapping_Params
{
public:
    svc_fs_createfilemapping_data data;
};

class CMessageParser_FsCreateFileMapping : public CMessageParser
{
    Q_OBJECT
public:
    explicit CMessageParser_FsCreateFileMapping(QObject *parent);

    void ParseBytes(svc_nop_data *buf);
signals:
    void SendEventData(CFsCreateFileMapping_Params *param);
};

class CFsQueryFileInformation_Params
{
public:
    svc_fs_queryfileinformation_data data;
    std::wstring fileNameInfo;
};

class CMessageParser_FsQueryFileInformation : public CMessageParser
{
    Q_OBJECT
public:
    explicit CMessageParser_FsQueryFileInformation(QObject *parent);

    void ParseBytes(svc_nop_data *buf);
signals:
    void SendEventData(CFsQueryFileInformation_Params *param);
};

class CRgCreateOpenKey_Params
{
public:
    svc_reg_createopenkey_data data;
};

class CMessageParser_RgCreateOpenKey : public CMessageParser
{
    Q_OBJECT
public:
    explicit CMessageParser_RgCreateOpenKey(QObject *parent);

    void ParseBytes(svc_nop_data *buf);
signals:
    void SendEventData(CRgCreateOpenKey_Params *param);
};

class CRgSetValueKey_Params
{
public:
    svc_reg_setvaluekey_data data;
    QByteArray binaryData;
};

class CMessageParser_RgSetValueKey : public CMessageParser
{
    Q_OBJECT
public:
    explicit CMessageParser_RgSetValueKey(QObject *parent);

    void ParseBytes(svc_nop_data *buf);
signals:
    void SendEventData(CRgSetValueKey_Params *param);
};

class CRgQueryValueKey_Params
{
public:
    svc_reg_queryvaluekey_data data;
    QByteArray binaryData;
};

class CMessageParser_RgQueryValueKey : public CMessageParser
{
    Q_OBJECT
public:
    explicit CMessageParser_RgQueryValueKey(QObject *parent);

    void ParseBytes(svc_nop_data *buf);
signals:
    void SendEventData(CRgQueryValueKey_Params *param);
};

class CRgQueryKey_Params
{
public:
    svc_reg_querykey_data data;
    QByteArray binaryData;
};

class CMessageParser_RgQueryKey : public CMessageParser
{
    Q_OBJECT
public:
    explicit CMessageParser_RgQueryKey(QObject *parent);

    void ParseBytes(svc_nop_data *buf);
signals:
    void SendEventData(CRgQueryKey_Params *param);
};

typedef boost::unordered_map<int, CMessageParser *> CMessageParsers;
