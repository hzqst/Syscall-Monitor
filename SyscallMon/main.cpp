#include "mainwindow.h"
#include <QApplication>
#include <QTranslator>
#include "syscallmon.h"

extern CSyscallMon *m_SyscallMon;

LONG WINAPI MinidumpCallback(EXCEPTION_POINTERS* excp);

int main(int argc, char *argv[])
{
    SetUnhandledExceptionFilter(MinidumpCallback);

    QApplication a(argc, argv);

    QTranslator translator;
    if(translator.load("cn.qm"))
        a.installTranslator(&translator);

    m_SyscallMon = new CSyscallMon(&a);

    int result = 0;
    if(m_SyscallMon->Initialize())
    {
        MainWindow w;
        w.show();
        result = a.exec();
    }
    else
    {
        m_SyscallMon->Uninitialize();
    }
    return result;
}
