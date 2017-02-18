#ifndef REGISTRY_H
#define REGISTRY_H

#include <QTranslator>
#include <QString>
#include <QStringList>
#include <Windows.h>
#include "StringMgr.h"

class CRegKeyValue
{
public:
    CRegKeyValue(ULONG Type, ULONG Size, LPCWSTR szValueName);
    //void* operator new(size_t size);
    //void operator delete(void*p);
    ULONG GetType(void) const{return m_Type;}
    ULONG GetSize(void) const{return m_Size;}
    QString GetValueName(void) const{return m_ValueName.GetQString();}

    virtual void PrintFull(QString &str) const = 0;
    virtual bool NeedBreak(void) const = 0;
    virtual bool IsDummy(void) const {return false;}
protected:
    ULONG m_Type;
    ULONG m_Size;
    CUniqueString m_ValueName;
};

class CRegKeyValueBinary : public CRegKeyValue
{
public:
    CRegKeyValueBinary(ULONG Type, ULONG Size, LPCWSTR szValueName, QByteArray &BinaryData);

    virtual void PrintFull(QString &str) const;
    virtual bool NeedBreak(void) const;
private:
    QByteArray m_Data;
};

class CRegKeyValueString : public CRegKeyValue
{
public:
    CRegKeyValueString(ULONG Type, ULONG Size, LPCWSTR szValueName, QByteArray &BinaryData);

    virtual void PrintFull(QString &str) const;
    virtual bool NeedBreak(void) const;
private:
    QStringList m_Data;
    bool m_More;
};

class CRegKeyValueNumber : public CRegKeyValue
{
public:
    CRegKeyValueNumber(ULONG Type, ULONG Size, LPCWSTR szValueName, QByteArray &BinaryData);

    virtual void PrintFull(QString &str) const;
    virtual bool NeedBreak(void) const;
private:
    ULONG64 m_Data;
};


#endif // REGISTRY_H
