#include <windows.h>
#include <QString>
#include <QTime>
#include <QMessageBox>
#include <dbghelp.h>
#include "nt.h"

LONG WINAPI MinidumpCallback(EXCEPTION_POINTERS* pException)
{
    QString timeStr = "minidump_" + QTime::currentTime().toString("HH_mm_ss") + ".mdmp";
    HANDLE hDumpFile = CreateFile((LPCWSTR)timeStr.utf16(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if( hDumpFile != INVALID_HANDLE_VALUE){

        MINIDUMP_EXCEPTION_INFORMATION dumpInfo;
        dumpInfo.ExceptionPointers = pException;
        dumpInfo.ThreadId = GetCurrentThreadId();
        dumpInfo.ClientPointers = TRUE;

        MiniDumpWriteDump(GetCurrentProcess(), GetCurrentProcessId(), hDumpFile,(MINIDUMP_TYPE)(MiniDumpNormal | MiniDumpWithFullMemory), &dumpInfo, NULL, NULL);
        CloseHandle(hDumpFile);
    }

    QMessageBox::critical(NULL,QObject::tr("Fatal Error"),QObject::tr("A fatal error occured, sorry but we have to terminate this program.\nSee minidump for more information."), QMessageBox::Ok);
    exit(-1);

    return EXCEPTION_EXECUTE_HANDLER;
}
