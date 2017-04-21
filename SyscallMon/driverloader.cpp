#include <Windows.h>
#include <winioctl.h>
#include "driverloader.h"
#include "nt.h"

#undef NTDDI_VERSION
#define NTDDI_VERSION NTDDI_WINXPSP3
#include <fltUser.h>
#pragma comment(lib, "fltLib.lib")

#define STATUS_IMAGE_ALREADY_LOADED      ((NTSTATUS)0xC000010EL)

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

CDriverLoader m_Driver;

BOOL CDriverLoader::CreateKeys(void)
{
    NTSTATUS status;
    TCHAR keyName[512];
    HKEY hKeyService;

    wsprintf(keyName, L"System\\CurrentControlSet\\Services\\%s", m_pServiceName);
    status = RegCreateKey(HKEY_LOCAL_MACHINE, keyName, &hKeyService);
    if (status != ERROR_SUCCESS)
    {
        m_ErrorCode = GetLastError();
        wsprintf(m_szErrorInfo, L"RegCreateKey failed with %d, %d", status, m_ErrorCode);
        return FALSE;
    }

    DWORD Data = 1;
    RegSetValueEx(hKeyService, L"Type", 0, REG_DWORD, (PUCHAR)&Data, sizeof(Data));
    RegSetValueEx(hKeyService, L"ErrorControl", 0, REG_DWORD, (PUCHAR)&Data, sizeof(Data));
    RegSetValueEx(hKeyService, L"ImagePath", 0, REG_SZ, (PUCHAR)m_pSysPath, (int)(2 * wcslen(m_pSysPath)));

    Data = SERVICE_DEMAND_START;
    RegSetValueEx(hKeyService, L"Start", 0, REG_DWORD, (PUCHAR)&Data, sizeof(Data));

    HKEY hKeyInstances = NULL;
    status = RegCreateKey(hKeyService, L"Instances", &hKeyInstances);
    if (status != ERROR_SUCCESS)
    {
        m_ErrorCode = GetLastError();
        wsprintf(m_szErrorInfo, L"RegCreateKey failed with %d, %d", status, m_ErrorCode);
        return FALSE;
    }

    RegSetValueEx(hKeyInstances, L"DefaultInstance", 0, REG_SZ, (PUCHAR)m_pServiceName, (int)(2 * wcslen(m_pServiceName)));

    HKEY hKeyInst = NULL;
    status = RegCreateKey(hKeyInstances, m_pServiceName, &hKeyInst);
    if (status != ERROR_SUCCESS)
    {
        m_ErrorCode = GetLastError();
        wsprintf(m_szErrorInfo, L"RegCreateKey failed with %d, %d", status, m_ErrorCode);
        return FALSE;
    }

    TCHAR altitude[16];
    wsprintf(altitude, L"%d", 360055);
    RegSetValueEx(hKeyInst, L"Altitude", 0, REG_SZ, (PUCHAR)(LPCWSTR)altitude, (int)(2 * wcslen(altitude)));
    Data = 0;
    RegSetValueEx(hKeyInst, L"Flags", 0, REG_DWORD, (PUCHAR)&Data, sizeof(Data));

    return TRUE;
}

void CDriverLoader::RemoveKeys(void)
{
    TCHAR keyName[512];

    wsprintf(keyName, L"System\\CurrentControlSet\\Services\\%s\\Instances\\%s", m_pServiceName, m_pServiceName);
    RegDeleteKey(HKEY_LOCAL_MACHINE, keyName);

    wsprintf(keyName, L"System\\CurrentControlSet\\Services\\%s\\Instances", m_pServiceName);
    RegDeleteKey(HKEY_LOCAL_MACHINE, keyName);

    wsprintf(keyName, L"System\\CurrentControlSet\\Services\\%s\\Enum", m_pServiceName);
    RegDeleteKey(HKEY_LOCAL_MACHINE, keyName);

    wsprintf(keyName, L"System\\CurrentControlSet\\Services\\%s", m_pServiceName);
    RegDeleteKey(HKEY_LOCAL_MACHINE, keyName);
}

BOOL CDriverLoader::Install(LPCTSTR pSysPath, LPCTSTR pServiceName, LPCTSTR pDisplayName)
{
    lstrcpy(m_pSysPath, pSysPath);
    lstrcpy(m_pServiceName, pServiceName);
    lstrcpy(m_pDisplayName, pDisplayName);

    NTSTATUS status;
    TCHAR svcName[512];

    m_szErrorInfo[0] = 0;

    BOOL bSuccess = FALSE;
    do
    {
        HMODULE ntdll = GetModuleHandle(L"ntdll.dll");
        NTSTATUS(NTAPI *fnZwLoadDriver)(PUNICODE_STRING) = (NTSTATUS(NTAPI *)(PUNICODE_STRING))GetProcAddress(ntdll, "ZwLoadDriver");
        VOID(NTAPI* fnRtlInitUnicodeString)(PUNICODE_STRING, PCWSTR) = (VOID(NTAPI*)(PUNICODE_STRING, PCWSTR))GetProcAddress(ntdll, "RtlInitUnicodeString");

        if (!CreateKeys())
            break;

        UNICODE_STRING driverServiceName;
        wsprintf(svcName, L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\%s", m_pServiceName);
        fnRtlInitUnicodeString(&driverServiceName, svcName);

        status = fnZwLoadDriver(&driverServiceName);

        if (!NT_SUCCESS(status) && status != STATUS_IMAGE_ALREADY_LOADED)
        {
            m_ErrorCode = status;
            wsprintf(m_szErrorInfo, L"ZwLoadDriver failed with 0x%X", status);
            break;
        }

        bSuccess = TRUE;
    }
    while (false);

    return bSuccess;
}

BOOL CDriverLoader::Uninstall(void)
{
    NTSTATUS status;
    TCHAR svcName[512];

    m_szErrorInfo[0] = 0;

    BOOL bSuccess = FALSE;
    do
    {
        HMODULE ntdll = GetModuleHandle(L"ntdll.dll");
        NTSTATUS(NTAPI *fnZwUnloadDriver)(PUNICODE_STRING) = (NTSTATUS(NTAPI *)(PUNICODE_STRING))GetProcAddress(ntdll, "ZwUnloadDriver");
        VOID(NTAPI* fnRtlInitUnicodeString)(PUNICODE_STRING, PCWSTR) = (VOID(NTAPI*)(PUNICODE_STRING, PCWSTR))GetProcAddress(ntdll, "RtlInitUnicodeString");

        if (!CreateKeys())
            break;

        UNICODE_STRING driverServiceName;
        wsprintf(svcName, L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\%s", m_pServiceName);
        fnRtlInitUnicodeString(&driverServiceName, svcName);

        status = fnZwUnloadDriver(&driverServiceName);

        if (!NT_SUCCESS(status))
        {
            m_ErrorCode = status;
            wsprintf(m_szErrorInfo, L"ZwUnloadDriver failed with 0x%X", status);
            break;
        }

        bSuccess = TRUE;
    } while (0);

    return bSuccess;
}

BOOL CDriverLoader::FltLoad(LPCTSTR pSysPath, LPCTSTR pServiceName, LPCTSTR pDisplayName)
{
    lstrcpy(m_pSysPath, pSysPath);
    lstrcpy(m_pServiceName, pServiceName);
    lstrcpy(m_pDisplayName, pDisplayName);

    HRESULT status = S_OK;

    m_szErrorInfo[0] = 0;

    BOOL bSuccess = FALSE;
    do
    {
        if (!CreateKeys())
            break;

        status = FilterLoad(m_pServiceName);

        if (status == HRESULT_FROM_WIN32(ERROR_BAD_DRIVER))
        {
            m_ErrorCode = status;
            wsprintf(m_szErrorInfo, L"FilterLoad failed with ERROR_BAD_DRIVER");
            break;
        }
        else if (status == HRESULT_FROM_WIN32(ERROR_BAD_EXE_FORMAT))
        {
            m_ErrorCode = status;
            wsprintf(m_szErrorInfo, L"FilterLoad failed with ERROR_BAD_EXE_FORMAT");
            break;
        }
        else if (status == HRESULT_FROM_WIN32(ERROR_INVALID_IMAGE_HASH))
        {
            m_ErrorCode = status;
            wsprintf(m_szErrorInfo, L"FilterLoad failed with ERROR_INVALID_IMAGE_HASH");
            break;
        }
        else if (status == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND))
        {
            m_ErrorCode = status;
            wsprintf(m_szErrorInfo, L"FilterLoad failed with ERROR_FILE_NOT_FOUND");
            break;
        }
        else if (status != S_OK && status != HRESULT_FROM_WIN32(ERROR_SERVICE_ALREADY_RUNNING) && status != HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS))
        {
            m_ErrorCode = status;
            wsprintf(m_szErrorInfo, L"FilterLoad failed with 0x%X", status);
            break;
        }

        bSuccess = TRUE;
    } while (0);

    return bSuccess;
}

BOOL CDriverLoader::FltUnload(void)
{
    NTSTATUS status;

    m_szErrorInfo[0] = 0;

    BOOL bSuccess = FALSE;
    do
    {
        if (!CreateKeys())
            break;

        status = FilterUnload(m_pServiceName);

        if (!NT_SUCCESS(status))
        {
            m_ErrorCode = status;
            wsprintf(m_szErrorInfo, L"FilterUnload failed with 0x%X", status);
            break;
        }

        bSuccess = TRUE;
    } while (0);

    return bSuccess;
}

BOOL CDriverLoader::Close(void)
{
    if (m_hDriver == INVALID_HANDLE_VALUE)
        return TRUE;

    if (CloseHandle(m_hDriver))
    {
        m_hDriver = INVALID_HANDLE_VALUE;
        return TRUE;
    }

    m_ErrorCode = GetLastError();
    wsprintf(m_szErrorInfo, L"CloseHandle failed with %d", m_ErrorCode);
    return FALSE;
}

BOOL CDriverLoader::Open(LPCTSTR pLinkName)
{
    if (m_hDriver != INVALID_HANDLE_VALUE)
        return TRUE;
    m_hDriver = CreateFile(pLinkName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_WRITE | FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    if (m_hDriver != INVALID_HANDLE_VALUE)
        return TRUE;

    m_ErrorCode = GetLastError();
    wsprintf(m_szErrorInfo, L"CreateFile failed with %d", m_ErrorCode);
    return FALSE;
}

BOOL CDriverLoader::Connect(LPCTSTR szPortName, LPVOID lpContext, DWORD dwContext)
{
    HRESULT hResult = FilterConnectCommunicationPort(szPortName, 0, lpContext, (WORD)dwContext, NULL, &m_hClientPort);
    if (S_OK != hResult)
    {
        m_ErrorCode = hResult;
        wsprintf(m_szErrorInfo, L"FilterConnectCommunicationPort failed %X", m_ErrorCode);
        return FALSE;
    }

    return TRUE;
}

void WriteLog(LPCWSTR fmt, ...);

HRESULT CDriverLoader::Read(LPVOID lpBuffer, DWORD dwBufferSize, LPOVERLAPPED ovlp)
{
    if (m_hClientPort == INVALID_HANDLE_VALUE)
        return HRESULT_FROM_WIN32(ERROR_INVALID_HANDLE);

    return FilterGetMessage(m_hClientPort, (PFILTER_MESSAGE_HEADER)lpBuffer, dwBufferSize, ovlp);
}

BOOL CDriverLoader::Disconnect(void)
{
    if (m_hClientPort == INVALID_HANDLE_VALUE)
        return TRUE;

    if (CloseHandle(m_hClientPort))
    {
        m_hClientPort = INVALID_HANDLE_VALUE;
        return TRUE;
    }

    m_ErrorCode = GetLastError();
    wsprintf(m_szErrorInfo, L"CloseHandle failed with %d", m_ErrorCode);
    return FALSE;
}

BOOL CDriverLoader::Send(LPVOID lpInBuffer, DWORD dwInBufferSize, LPVOID lpOutBuffer, DWORD dwOutBufferSize, LPDWORD lpBytesReturned)
{
    DWORD dwByteRead = 0;

    if (m_hClientPort == INVALID_HANDLE_VALUE)
        return FALSE;

    if (S_OK == FilterSendMessage(m_hClientPort, lpInBuffer, dwInBufferSize, lpOutBuffer, dwOutBufferSize, &dwByteRead))
    {
        if (lpBytesReturned)
            *lpBytesReturned = dwByteRead;

        return TRUE;
    }
    return FALSE;
}

BOOL CDriverLoader::IoControl(DWORD dwIoCode, PVOID InBuff, DWORD InBuffLen, PVOID OutBuff, DWORD OutBuffLen, DWORD *RealRetBytes)
{
    if (m_hDriver == INVALID_HANDLE_VALUE)
        return FALSE;

    DWORD dw = 0;
    BOOL b = DeviceIoControl(m_hDriver, CTL_CODE_GEN(dwIoCode), InBuff, InBuffLen, OutBuff, OutBuffLen, &dw, NULL);
    if (RealRetBytes)
        *RealRetBytes = dw;
    if (!b)
    {
        m_ErrorCode = GetLastError();
        wsprintf(m_szErrorInfo, L"DeviceIoControl failed with %d", m_ErrorCode);
    }

    return b;
}

DWORD CDriverLoader::CTL_CODE_GEN(DWORD lngFunction)
{
    return (FILE_DEVICE_UNKNOWN << 16) | (FILE_ANY_ACCESS << 14) | (lngFunction << 2) | METHOD_BUFFERED;
}
