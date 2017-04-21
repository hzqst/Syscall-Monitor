#ifndef DRIVERLOADER_H
#define DRIVERLOADER_H

#pragma once
#include <Windows.h>

class CDriverLoader
{
public:
    CDriverLoader()
    {
        m_pSysPath[0] = 0;
        m_pServiceName[0] = 0;
        m_pDisplayName[0] = 0;
        m_szErrorInfo[0] = 0;
        m_hDriver = INVALID_HANDLE_VALUE;
        m_hClientPort = INVALID_HANDLE_VALUE;
    }
public:
    DWORD m_ErrorCode;
    TCHAR m_szErrorInfo[512];
    TCHAR m_pSysPath[512];
    TCHAR m_pServiceName[64];
    TCHAR m_pDisplayName[64];
    HANDLE m_hDriver;
    HANDLE m_hClientPort;
public:
    BOOL CreateKeys(void);
    void RemoveKeys(void);
    BOOL Install(LPCTSTR pSysPath, LPCTSTR pServiceName, LPCTSTR pDisplayName);
    BOOL Uninstall(void);
    BOOL FltLoad(LPCTSTR pSysPath, LPCTSTR pServiceName, LPCTSTR pDisplayName);
    BOOL FltUnload(void);
    BOOL Open(LPCTSTR pLinkName);
    BOOL Close(void);
    BOOL IoControl(DWORD dwIoCode, PVOID InBuff, DWORD InBuffLen, PVOID OutBuff, DWORD OutBuffLen, DWORD *RealRetBytes);
    BOOL Connect(LPCTSTR szPortName, LPVOID lpContext, DWORD dwContext);
    BOOL Disconnect(void);
    BOOL Send(LPVOID lpInBuffer, DWORD dwInBufferSize, LPVOID lpOutBuffer, DWORD dwOutBufferSize, LPDWORD lpBytesReturned);
    HRESULT Read(LPVOID lpBuffer, DWORD dwBufferSize, LPOVERLAPPED ovlp);
private:
    DWORD CTL_CODE_GEN(DWORD lngFunction);
protected:
};

extern CDriverLoader m_Driver;

#endif // DRIVERLOADER_H
