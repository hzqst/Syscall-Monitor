#ifndef SYSCALLMON_H
#define SYSCALLMON_H

#pragma once

#include <QObject>
#include <QThread>
#include <Windows.h>

class CMonitorWorker : public QThread
{
    Q_OBJECT
public:
    explicit CMonitorWorker(QObject *parent = Q_NULLPTR);

    virtual void run();

    void Initialize(void);
    void Quit(void);
    void Uninitialize(void);
    bool ParseMessage(PUCHAR data);
signals:
    void CallStack(QByteArray data);
    void PsCreateProcess(QByteArray data);
    void PsCreateThread(QByteArray data);
    void PsLoadImage(QByteArray data);
    void NtLoadDriver(QByteArray data);
    void NtQuerySystemInfo(QByteArray data);
    void NtOpenProcess(QByteArray data);
    void NtOpenThread(QByteArray data);
    void NtTerminateProcess(QByteArray data);
    void NtAllocateVirtualMemory(QByteArray data);
    void NtReadWriteVirtualMemory(QByteArray data);
    void NtProtectVirtualMemory(QByteArray data);
    void NtQueryVirtualMemory(QByteArray data);
    void NtCreateOpenMutant(QByteArray data);
    void NtCreateOpenDirectoryObject(QByteArray data);
    void NtQueryDirectoryObject(QByteArray data);
    void NtUserSetWindowsHook(QByteArray data);
    void NtUserFindWindow(QByteArray data);
    void NtUserInternalGetWindowText(QByteArray data);
    void NtUserGetClassName(QByteArray data);
    void FsCreateFile(QByteArray data);
    void FsCloseFile(QByteArray data);
    void FsReadWriteFile(QByteArray data);
    void FsCreateFileMapping(QByteArray data);
    void FsQueryFileInformation(QByteArray data);
    void RgCreateOpenKey(QByteArray data);
    void RgSetValueKey(QByteArray data);
    void RgQueryValueKey(QByteArray data);
    void RgQueryKey(QByteArray data);
private:    
    HANDLE m_hQuitEvent;
};

class CSyscallMon : public QObject
{
    Q_OBJECT
public:
    explicit CSyscallMon(QObject *parent = Q_NULLPTR);

    bool Initialize(void);
    void Uninitialize(void);

private:
    HANDLE m_hMutex;

    CMonitorWorker m_MonitorWorker;
};

extern CSyscallMon *m_SyscallMon;

#endif // SYSCALLMON_H
