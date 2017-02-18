#include "mainwindow.h"
#include <QApplication>
#include <QTranslator>
#include "syscallmon.h"

extern CSyscallMon *m_SyscallMon;

LONG WINAPI MinidumpCallback(EXCEPTION_POINTERS* excp);

int main(int argc, char *argv[])
{
    int result = 0;

    SetUnhandledExceptionFilter(MinidumpCallback);

    QApplication a(argc, argv);

    QTranslator translator;
    if(translator.load("cn.qm"))
      a.installTranslator(&translator);

    m_SyscallMon = new CSyscallMon(&a);

    //Load symbols before loading the driver...

    if(m_SyscallMon->Initialize())
    {
        MainWindow w;
        w.show();

        result = a.exec();
    }

    m_SyscallMon->Uninitialize();

    delete m_SyscallMon;

    return result;
}
