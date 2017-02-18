#-------------------------------------------------
#
# Project created by QtCreator 2016-11-03T13:34:52
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = SyscallMonQT
TEMPLATE = app

SOURCES += main.cpp\
        mainwindow.cpp \
    syscallmon.cpp \
    driverloader.cpp \
    util.cpp \
    EventFilter.cpp \
    EventMgr.cpp \
    ProcessMgr.cpp \
    DriverWrapper.cpp \
    Encode.cpp \
    Message.cpp \
    nt.cpp \
    ps.cpp \
    Image.cpp \
    eventtable.cpp \
    filterdialog.cpp \
    filtertable.cpp \
    filterloadingdialog.cpp \
    eventinfodialog.cpp \
    StringMgr.cpp \
    callstacktable.cpp \
    symloaddialog.cpp \
    ProcessTree.cpp \
    ModuleMgr.cpp \
    Event.cpp \
    registry.cpp \
    minidump.cpp \
    processinfodialog.cpp \
    clickablelineedit.cpp

HEADERS  += mainwindow.h \
    driverloader.h \
    syscallmon.h \
    util.h \
    EventFilter.h \
    EventMgr.h \
    ProcessMgr.h \
    DriverWrapper.h \
    Encode.h \
    nt.h \
    ps.h \
    filterdialog.h \
    filtertable.h \
    filterloadingdialog.h \
    eventinfodialog.h \
    StringMgr.h \
    ModuleMgr.h \
    callstacktable.h \
    symloaddialog.h \
    ProcessTree.h \
    EventTable.h \
    registry.h \
    processinfodialog.h \
    clickablelineedit.h

FORMS    += mainwindow.ui \
    filterdialog.ui \
    filterloadingdialog.ui \
    eventinfodialog.ui \
    symloaddialog.ui \
    processinfodialog.ui

RESOURCES += resource.qrc

RC_FILE += SyscallMonForm.rc

QMAKE_LFLAGS += /MANIFESTUAC:\"level=\'requireAdministrator\' uiAccess=\'false\'\"

TRANSLATIONS+=cn.ts

LIBS += -lgdi32\
-ladvapi32\
-luser32\
-lshlwapi\
-lole32

INCLUDEPATH += $$PWD/../boost
DEPENDPATH += $$PWD/../boost
