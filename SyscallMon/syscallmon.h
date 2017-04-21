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
    void CallStack(QSharedPointer<QByteArray> data);
    void PsCreateProcess(QSharedPointer<QByteArray> data);
    void PsCreateThread(QSharedPointer<QByteArray> data);
    void PsLoadImage(QSharedPointer<QByteArray> data);
    void NtLoadDriver(QSharedPointer<QByteArray> data);
    void NtQuerySystemInfo(QSharedPointer<QByteArray> data);
    void NtOpenProcess(QSharedPointer<QByteArray> data);
    void NtOpenThread(QSharedPointer<QByteArray> data);
    void NtTerminateProcess(QSharedPointer<QByteArray> data);
    void NtAllocateVirtualMemory(QSharedPointer<QByteArray> data);
    void NtReadWriteVirtualMemory(QSharedPointer<QByteArray> data);
    void NtProtectVirtualMemory(QSharedPointer<QByteArray> data);
    void NtQueryVirtualMemory(QSharedPointer<QByteArray> data);
    void NtCreateOpenMutant(QSharedPointer<QByteArray> data);
    void NtCreateOpenDirectoryObject(QSharedPointer<QByteArray> data);
    void NtQueryDirectoryObject(QSharedPointer<QByteArray> data);
    void NtUserSetWindowsHook(QSharedPointer<QByteArray> data);
    void NtUserFindWindow(QSharedPointer<QByteArray> data);
    void NtUserInternalGetWindowText(QSharedPointer<QByteArray> data);
    void NtUserGetClassName(QSharedPointer<QByteArray> data);
    void FsCreateFile(QSharedPointer<QByteArray> data);
    void FsCloseFile(QSharedPointer<QByteArray> data);
    void FsReadWriteFile(QSharedPointer<QByteArray> data);
    void FsCreateFileMapping(QSharedPointer<QByteArray> data);
    void FsQueryFileInformation(QSharedPointer<QByteArray> data);
    void RgCreateOpenKey(QSharedPointer<QByteArray> data);
    void RgSetValueKey(QSharedPointer<QByteArray> data);
    void RgQueryValueKey(QSharedPointer<QByteArray> data);
    void RgQueryKey(QSharedPointer<QByteArray> data);
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
