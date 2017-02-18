#include <QMessageBox>
#include <QTranslator>

#include <Windows.h>
#include <shlwapi.h>
#include "syscallmon.h"
#include "driverloader.h"
#include "DriverWrapper.h"
#include "ProcessMgr.h"
#include "EventMgr.h"
#include "ModuleMgr.h"
#include "StringMgr.h"
#include "util.h"
#include "../Shared/Protocol.h"
#include "symloaddialog.h"

#define STATUS_HV_FEATURE_UNAVAILABLE    ((NTSTATUS)0xC035001EL)

CSyscallMon *m_SyscallMon;

CMonitorWorker::CMonitorWorker(QObject *parent) : QThread(parent)
{
    m_hQuitEvent = NULL;
}

void CMonitorWorker::run(void)
{
    HANDLE hEvents[2];
    PUCHAR buf = new UCHAR[0x4000];

    setPriority(HighestPriority);

    hEvents[0] = m_ProcessMgr->m_hReadyEvent;
    hEvents[1] = m_EventMgr->m_hReadyEvent;
    WaitForMultipleObjects(2, hEvents, TRUE, INFINITE);

    OVERLAPPED ovlp;
    ovlp.hEvent = ::CreateEvent(NULL, FALSE, FALSE, NULL);
    ovlp.Internal = 0;
    ovlp.InternalHigh = 0;
    ovlp.Pointer = 0;
    ovlp.Offset = 0;
    ovlp.OffsetHigh = 0;

    hEvents[0] = ovlp.hEvent;
    hEvents[1] = m_hQuitEvent;

    while (1)
    {
        if (WaitForSingleObject(m_hQuitEvent, 0) == WAIT_OBJECT_0)
            break;

        memset(buf, 0, 0x4000);
        HRESULT hres = m_Driver.Read(buf, 0x4000, &ovlp);
        if (hres == HRESULT_FROM_WIN32(ERROR_IO_PENDING) || hres == S_OK)
        {
            if (hres == HRESULT_FROM_WIN32(ERROR_IO_PENDING))
            {
                if (WaitForMultipleObjects(2, hEvents, FALSE, INFINITE) == (WAIT_OBJECT_0 + 1))//time to quit
                    break;
            }

            PUCHAR dataBuf = buf + 16;

            ParseMessage(dataBuf);
        }
        else//if driver errors, wait and try again
        {
            Sleep(100);
        }
    }

    delete buf;

    CloseHandle(ovlp.hEvent);
}

CSyscallMon::CSyscallMon(QObject *parent) : QObject(parent)
{
    m_hMutex = NULL;

    new CEventMgr(this);
    new CProcessMgr(this);
    new CModuleMgr(this);
    new CStringMgr(this);
}

bool CSyscallMon::Initialize(void)
{
    m_hMutex = CreateMutex(NULL, TRUE, L"SyscallMonitorMutex");
    if (GetLastError() == ERROR_ALREADY_EXISTS)
    {
        CloseHandle(m_hMutex);
        QMessageBox::critical(NULL, tr("Fatal Error"), tr("Syscall Monitor is already running!"), QMessageBox::Yes);
        return false;
    }

    if (!AdjustPrivilege(SE_DEBUG_NAME))
    {
        QMessageBox::critical(NULL, tr("Fatal Error"), tr("Failed to get SE_DEBUG_NAME privilege!"), QMessageBox::Yes);
        return false;
    }

    if (!AdjustPrivilege(SE_LOAD_DRIVER_NAME))
    {
        QMessageBox::critical(NULL, tr("Fatal Error"), tr("Failed to get SE_LOAD_DRIVER_NAME privilege!"), QMessageBox::Yes);
        return false;
    }

    TCHAR szDirectory[MAX_PATH];
    GetModuleFilePath(NULL, szDirectory, MAX_PATH);

    QString drvFileName = IsAMD64() ? "SyscallMon64.sys" : "SyscallMon32.sys";
    QString drvFilePath = QString("%1\\%2").arg(QString::fromWCharArray(szDirectory), drvFileName);

    if (!PathFileExists((LPCWSTR)drvFilePath.utf16()))
    {
        QString err = QString(tr("Could not found %1!")).arg(drvFilePath);
        QMessageBox::critical(NULL, tr("Fatal Error"), err, QMessageBox::Yes);
        return false;
    }

    m_ModuleMgr->Initialize();

    SymLoadDialog *symLoadDialog = new SymLoadDialog();
    symLoadDialog->exec();

    //Load driver later...

    QString drvSymLink = QString("\\??\\%1").arg(drvFilePath);

    conn_context_data conn;
    conn.txsb = 'TXSB';
    conn.ver = 1;

    if (!m_Driver.Connect(L"\\SyscallMonPort", &conn, sizeof(conn)))
    {
        if (!m_Driver.Install((LPCWSTR)drvSymLink.utf16(), L"SyscallMon", L"SyscallMon"))
        {
            if(STATUS_HV_FEATURE_UNAVAILABLE == m_Driver.m_ErrorCode)
            {
                QMessageBox::critical(NULL, tr("Fatal Error"), tr("Intel VT-x/EPT is not support or not enabled in your system!"), QMessageBox::Yes);
                return false;
            }

            QMessageBox::critical(NULL, tr("Fatal Error"), QString::fromWCharArray(m_Driver.m_szErrorInfo), QMessageBox::Yes);
            return false;
        }
        if (!m_Driver.Connect(L"\\SyscallMonPort", &conn, sizeof(conn)))
        {
            QMessageBox::critical(NULL, tr("Fatal Error"), QString::fromWCharArray(m_Driver.m_szErrorInfo), QMessageBox::Yes);
            return false;
        }
    }
    else
    {
        wcscpy(m_Driver.m_pServiceName, L"SyscallMon");
        wcscpy(m_Driver.m_pDisplayName, L"SyscallMon");
    }

    m_MonitorWorker.Initialize();
    m_MonitorWorker.start();

    SetCaptureEnable(true);

    m_ProcessMgr->Initialize();
    m_EventMgr->Initialize();

    return true;
}

void CSyscallMon::Uninitialize(void)
{
    m_MonitorWorker.Quit();
    m_MonitorWorker.wait();

    m_Driver.Disconnect();
    m_Driver.Uninstall();

    if(m_hMutex != INVALID_HANDLE_VALUE)
        CloseHandle(m_hMutex);

    m_MonitorWorker.Uninitialize();
    m_ModuleMgr->Uninitialize();
    m_EventMgr->Uninitialize();
    m_ProcessMgr->Uninitialize();
}
