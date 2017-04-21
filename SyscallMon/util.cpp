#include <Windows.h>
#include <iostream>
#include <stdio.h>
#include <intrin.h>

BOOL AdjustPrivilege(LPCTSTR Privilege)
{
    BOOL bSuccess = FALSE;
    HANDLE hToken;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
    {
        TOKEN_PRIVILEGES tp;
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        if (LookupPrivilegeValue(NULL, Privilege, &tp.Privileges[0].Luid))
        {
            if (AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL))
            {
                bSuccess = TRUE;
            }
        }
        CloseHandle(hToken);
    }
    return bSuccess;
}

BOOL IsAMD64(void)
{
    static BOOL g_bAMD64 = -1;

    if (g_bAMD64 == -1)
    {
        SYSTEM_INFO si;
        GetNativeSystemInfo(&si);

        g_bAMD64 = (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) ? TRUE : FALSE;
    }
    return g_bAMD64;
}

void GetModuleFilePath(HMODULE hModule, LPWSTR szFilePath, DWORD cbSize)
{
    GetModuleFileName(hModule, szFilePath, cbSize);

    for (size_t i = wcslen(szFilePath); i >= 0; --i)
    {
        if (szFilePath[i] == TEXT('\\') || szFilePath[i] == TEXT('/'))
        {
            szFilePath[i] = 0;
            break;
        }
    }
}


BOOL NewWow64DisableWow64FsRedirection(PVOID *v)
{
    static BOOL(WINAPI *pfnWow64DisableWow64FsRedirection)(PVOID *) = (BOOL(WINAPI *)(PVOID *))GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), "Wow64DisableWow64FsRedirection");

    if (pfnWow64DisableWow64FsRedirection)
    {
        return pfnWow64DisableWow64FsRedirection(v);
    }

    return FALSE;
}

BOOL NewWow64RevertWow64FsRedirection(PVOID v)
{
    static BOOL(WINAPI *pfnWow64RevertWow64FsRedirection)(PVOID) = (BOOL(WINAPI *)(PVOID))GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), "Wow64RevertWow64FsRedirection");

    if (pfnWow64RevertWow64FsRedirection)
    {
        return pfnWow64RevertWow64FsRedirection(v);
    }

    return FALSE;
}

LPCTSTR ExtractFileName(LPCTSTR szPath)
{
    SIZE_T len = wcslen(szPath);
    if (len < 2)
        return szPath;

    for (size_t i = len - 2; i >= 0; --i)
    {
        if (szPath[i] == L'\\' || szPath[i] == L'/')
            return &szPath[i + 1];
    }
    return szPath;
}

__time64_t FileTimeToUnixTime(FILETIME *ft)
{
    ULARGE_INTEGER ull;

    ull.LowPart = ft->dwLowDateTime;
    ull.HighPart = ft->dwHighDateTime;

    return ull.QuadPart / 10000000ULL - 11644473600ULL;
}

/// See: Feature Information Returned in the ECX Register
union CpuFeaturesEcx {
  ULONG32 all;
  struct {
    ULONG32 sse3 : 1;       //!< [0] Streaming SIMD Extensions 3 (SSE3)
    ULONG32 pclmulqdq : 1;  //!< [1] PCLMULQDQ
    ULONG32 dtes64 : 1;     //!< [2] 64-bit DS Area
    ULONG32 monitor : 1;    //!< [3] MONITOR/WAIT
    ULONG32 ds_cpl : 1;     //!< [4] CPL qualified Debug Store
    ULONG32 vmx : 1;        //!< [5] Virtual Machine Technology
    ULONG32 smx : 1;        //!< [6] Safer Mode Extensions
    ULONG32 est : 1;        //!< [7] Enhanced Intel Speedstep Technology
    ULONG32 tm2 : 1;        //!< [8] Thermal monitor 2
    ULONG32 ssse3 : 1;      //!< [9] Supplemental Streaming SIMD Extensions 3
    ULONG32 cid : 1;        //!< [10] L1 context ID
    ULONG32 sdbg : 1;       //!< [11] IA32_DEBUG_INTERFACE MSR
    ULONG32 fma : 1;        //!< [12] FMA extensions using YMM state
    ULONG32 cx16 : 1;       //!< [13] CMPXCHG16B
    ULONG32 xtpr : 1;       //!< [14] xTPR Update Control
    ULONG32 pdcm : 1;       //!< [15] Performance/Debug capability MSR
    ULONG32 reserved : 1;   //!< [16] Reserved
    ULONG32 pcid : 1;       //!< [17] Process-context identifiers
    ULONG32 dca : 1;        //!< [18] prefetch from a memory mapped device
    ULONG32 sse4_1 : 1;     //!< [19] SSE4.1
    ULONG32 sse4_2 : 1;     //!< [20] SSE4.2
    ULONG32 x2_apic : 1;    //!< [21] x2APIC feature
    ULONG32 movbe : 1;      //!< [22] MOVBE instruction
    ULONG32 popcnt : 1;     //!< [23] POPCNT instruction
    ULONG32 reserved3 : 1;  //!< [24] one-shot operation using a TSC deadline
    ULONG32 aes : 1;        //!< [25] AESNI instruction
    ULONG32 xsave : 1;      //!< [26] XSAVE/XRSTOR feature
    ULONG32 osxsave : 1;    //!< [27] enable XSETBV/XGETBV instructions
    ULONG32 avx : 1;        //!< [28] AVX instruction extensions
    ULONG32 f16c : 1;       //!< [29] 16-bit floating-point conversion
    ULONG32 rdrand : 1;     //!< [30] RDRAND instruction
    ULONG32 not_used : 1;   //!< [31] Always 0 (a.k.a. HypervisorPresent)
  } fields;
};
static_assert(sizeof(CpuFeaturesEcx) == 4, "Size check");

/// See: ARCHITECTURAL MSRS
union Ia32FeatureControlMsr {
  unsigned __int64 all;
  struct {
    unsigned lock : 1;                  //!< [0]
    unsigned enable_smx : 1;            //!< [1]
    unsigned enable_vmxon : 1;          //!< [2]
    unsigned reserved1 : 5;             //!< [3:7]
    unsigned enable_local_senter : 7;   //!< [8:14]
    unsigned enable_global_senter : 1;  //!< [15]
    unsigned reserved2 : 16;            //!<
    unsigned reserved3 : 32;            //!< [16:63]
  } fields;
};
static_assert(sizeof(Ia32FeatureControlMsr) == 8, "Size check");

#define kIa32FeatureControl 0x03A

BOOL IsVmxAvailable()
{
  // See: DISCOVERING SUPPORT FOR VMX
  // If CPUID.1:ECX.VMX[bit 5]=1, then VMX operation is supported.
  int cpu_info[4] = {};
  __cpuid(cpu_info, 1);
  const CpuFeaturesEcx cpu_features = {static_cast<ULONG_PTR>(cpu_info[2])};
  if (!cpu_features.fields.vmx) {
    return FALSE;
  }

  return TRUE;
}

/*void WriteLog(LPCWSTR fmt, ...)
{
    WCHAR buffer[4096];
    va_list argptr;
    int cnt;
    va_start(argptr, fmt);
    cnt = wvsprintf(buffer, fmt, argptr);
    va_end(argptr);

    FILE *fp = NULL;

    _wfopen_s(&fp, L"SyscallMonLog.txt", L"a+");
    if (fp)
    {
        _wsetlocale(LC_ALL, L"chs");
        fwprintf(fp, L"%s", buffer);
        fclose(fp);
    }
}*/
