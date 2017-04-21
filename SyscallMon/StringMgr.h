#ifndef PATHMGR_H
#define PATHMGR_H

#pragma once

#include <Windows.h>
#include <string>
#include <QObject>
#include <QString>
#include <boost/unordered_map.hpp>

class CUniqueString
{
public:
    CUniqueString()
    {
        m_str = NULL;
    }

    CUniqueString(LPCWSTR str);
    CUniqueString(LPCWSTR str, size_t len);
    CUniqueString(const CUniqueString &c)
    {
        m_str=c.m_str;
    }

    LPCWSTR GetString() const
    {
        if(!m_str)
            return L"";
        return m_str;
    }

    QString GetQString() const
    {
        if(!m_str)
            return QString("");
        return QString::fromWCharArray(m_str);
    }

    bool operator==(const CUniqueString &key) const
    {
        if(!m_str || !key.m_str)
            return false;

        if (!wcscmp(key.m_str, m_str))
            return true;

        return false;
    }

    WCHAR *m_str;
};

class CTempString
{
public:
    CTempString(LPCWSTR str){
        m_str = str;
        m_len = wcslen(str);
    }
    CTempString(LPCWSTR str, size_t len){
        m_str = str;
        m_len = len;
    }

    LPCWSTR m_str;
    size_t m_len;
};

class CTempStringHasher
{
public:
    std::size_t operator()(const CTempString key) const;
};

class CTempStringComparer
{
public:
    bool operator()(const CTempString &key1, const CTempString &key2) const;
};

typedef boost::unordered_map<CTempString, CUniqueString, CTempStringHasher, CTempStringComparer> CUniqueStringMap;

class CStringMgr : public QObject
{
    Q_OBJECT
public:
    explicit CStringMgr(QObject *parent = NULL);
    ~CStringMgr();
    void Lock();
    void Unlock();
    CUniqueString GetString(LPCWSTR str);
    CUniqueString GetString(LPCWSTR str, size_t len);
    CUniqueStringMap m_StringMap;
    CRITICAL_SECTION m_Lock;
};

extern CStringMgr *m_StringMgr;

#endif // PATHMGR_H
