#include "registry.h"
#include "nt.h"

//CRegKeyValue

//extern size_t g_total;

CRegKeyValue::CRegKeyValue(ULONG Type, ULONG Size, LPCWSTR szValueName)
{
    m_Type = Type;
    m_Size = Size;
    m_ValueName = m_StringMgr->GetString(szValueName);
}

/*void* CRegKeyValue::operator new(size_t size)
{
    g_total += size;
    //OutputDebugString((LPCWSTR)QString("CRegKeyValue alloc %1 / %2 bytes").arg(size).arg(g_total).utf16());
    return dlmalloc(size);
}

void CRegKeyValue::operator delete(void*p)
{
    dlfree(p);
}*/

//RegKeyValueBinary

CRegKeyValueBinary::CRegKeyValueBinary(ULONG Type, ULONG Size, LPCWSTR szValueName, QByteArray &BinaryData)
    : CRegKeyValue(Type, Size, szValueName)
{
    m_Data = BinaryData;
}

void CRegKeyValueBinary::PrintFull(QString &str) const
{
    for(int i = 0;i < m_Data.size(); ++i) {
        str += QString("%1").arg((BYTE)m_Data.at(i), 2, 16, QChar('0')).toUpper();
        if(i != m_Data.size() - 1) {
            str += (i != 0 && i % 8 == 7) ? "\n" : " ";
        }
    }

    if((ULONG)m_Data.size() < m_Size)
        str += QObject::tr("\n...More");
}

bool CRegKeyValueBinary::NeedBreak(void) const
{
    return true;
}

//CRegKeyValueString

CRegKeyValueString::CRegKeyValueString(ULONG Type, ULONG Size, LPCWSTR szValueName, QByteArray &BinaryData)
    : CRegKeyValue(Type, Size, szValueName)
{
    m_More = ((ULONG)BinaryData.size() < Size);

    PWCH raw = (PWCH)BinaryData.data();
    for(int i = 0, j = 0;i < BinaryData.size() / 2; ++i)
    {
        if(raw[i] == L'\0' || i == BinaryData.size() / 2 - 1){
            QString str = QString::fromUtf16((const ushort *)&raw[j], i - j);
            m_Data.append(str);

            j = i+1;
        }
    }
}

void CRegKeyValueString::PrintFull(QString &str) const
{
    if(m_Data.size() == 1){
        str += m_Data.at(0);
    }else{
        for(int i = 0;i < m_Data.size(); ++i){
            str += m_Data.at(i);
            str += "\n";
        }
    }
    if(m_More)
        str += QObject::tr(" ...More");
}

bool CRegKeyValueString::NeedBreak(void) const
{
    return (m_Data.size() > 1);
}

//RegKeyValueNumber

CRegKeyValueNumber::CRegKeyValueNumber(ULONG Type, ULONG Size, LPCWSTR szValueName, QByteArray &BinaryData)
    : CRegKeyValue(Type, Size, szValueName)
{
    ULONG64 NumberData = 0;
    if(BinaryData.size() >= sizeof(ULONG64)) {
        memcpy(&NumberData, BinaryData.data(), sizeof(ULONG64));
    } else if(BinaryData.size() >= sizeof(DWORD)) {
        if(Type == REG_DWORD){
            memcpy(&NumberData, BinaryData.data(), sizeof(DWORD));
        }else{
            ULONG temp;
            memcpy(&temp, BinaryData.data(), sizeof(DWORD));
            NumberData = swapInt32(temp);
        }
    }

    m_Data = NumberData;
}

void CRegKeyValueNumber::PrintFull(QString &str) const
{
    str += QObject::tr("%1 (0x%2)").arg(QString::number(m_Data), FormatHexString(m_Data, m_Data > 0xffffffff ? 16 : 8));
}

bool CRegKeyValueNumber::NeedBreak(void) const
{
    return false;
}
