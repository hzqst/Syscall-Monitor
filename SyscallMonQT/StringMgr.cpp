#include "StringMgr.h"

//#define USE_LOCKS 1
//#define USE_DL_PREFIX
//#include "malloc.h"

CUniqueString::CUniqueString(LPCWSTR str)
{
    size_t len = wcslen(str);
    m_str = (WCHAR *)malloc((len + 1) * sizeof(WCHAR));
    wcscpy(m_str, str);
}

CUniqueString::CUniqueString(LPCWSTR str, size_t len)
{
    m_str = (WCHAR *)malloc((len + 1) * sizeof(WCHAR));
    wcsncpy(m_str, str, len);
    m_str[len] = 0;
}

DWORD BLZ_CryptTable[0x500];

void BLZ_InitCryptTable(void)
{
    DWORD seed = 0x00100001, index1 = 0, index2 = 0, i;

    for (index1 = 0; index1 < 0x100; index1++)
    {
        for (index2 = index1, i = 0; i < 5; i++, index2 += 0x100)
        {
            DWORD temp1, temp2;

            seed = (seed * 125 + 3) % 0x2AAAAB;
            temp1 = (seed & 0xFFFF) << 0x10;

            seed = (seed * 125 + 3) % 0x2AAAAB;
            temp2 = (seed & 0xFFFF);

            BLZ_CryptTable[index2 % 0x500] = (temp1 | temp2);
        }
    }
}

template<typename T>
DWORD BLZ_HashString(const T *lpszString, DWORD dwHashType, size_t nLength, bool bICase)
{
    T *key = (T *)lpszString;
    DWORD seed1 = 0x7FED7FED;
    DWORD seed2 = 0xEEEEEEEE;
    int ch;
    size_t i = 0;

    while (*key != 0 && i < nLength)
    {
        ch = (*key++);
        i++;

        if (bICase) ch = towupper(ch);

        seed1 = BLZ_CryptTable[((dwHashType << 8) + ch) % 0x500] ^ (seed1 + seed2);
        seed2 = ch + seed1 + seed2 + (seed2 << 5) + 3;
    }

    return seed1;
}

std::size_t CTempStringHasher::operator()(const CTempString key) const
{
    using boost::hash_value;
    using boost::hash_combine;
    std::size_t seed = 0;
    hash_combine(seed, (size_t)BLZ_HashString(key.m_str, 0, key.m_len, false));
    hash_combine(seed, (size_t)BLZ_HashString(key.m_str, 1, key.m_len, false));
    hash_combine(seed, (size_t)BLZ_HashString(key.m_str, 2, key.m_len, false));
    return seed;
}

bool CTempStringComparer::operator()(const CTempString &key1, const CTempString &key2) const
{
    if(!key1.m_str || !key2.m_str || key1.m_len != key2.m_len)
        return false;
    return (!wcsncmp(key1.m_str, key2.m_str, key1.m_len)) ? true : false;
}

CStringMgr *m_StringMgr = NULL;

CStringMgr::CStringMgr(QObject *parent) : QObject(parent)
{
    m_StringMgr = this;
    InitializeCriticalSection(&m_Lock);
    BLZ_InitCryptTable();
}

CStringMgr::~CStringMgr()
{
    DeleteCriticalSection(&m_Lock);
}

void CStringMgr::Lock()
{
    EnterCriticalSection(&m_Lock);
}

void CStringMgr::Unlock()
{
    LeaveCriticalSection(&m_Lock);
}

CUniqueString CStringMgr::GetString(LPCWSTR str)
{
    CUniqueString s;

    Lock();

    CTempString temp(str);
    CUniqueStringMap::iterator itor = m_StringMap.find(temp);

    if(itor != m_StringMap.end())
    {
        s = itor->second;
    }
    else
    {
        s = CUniqueString(str);
        CTempString k(s.m_str);
        m_StringMap[k] = s;
    }

    Unlock();
    return s;
}

CUniqueString CStringMgr::GetString(LPCWSTR str, size_t len)
{
    CUniqueString s;

    Lock();

    CTempString temp(str, len);
    CUniqueStringMap::iterator itor = m_StringMap.find(temp);

    if(itor != m_StringMap.end())
    {
        s = itor->second;
    }
    else
    {
        s = CUniqueString(str, len);
        CTempString k(s.m_str, len);
        m_StringMap[k] = s;
    }

    Unlock();
    return s;
}
