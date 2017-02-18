#include <Windows.h>
#include "ps.h"
#include "nt.h"

#pragma comment(lib,"ntdll.lib")

#pragma warning (disable: 4311)
#pragma warning (disable: 4302)

EXTERN_C NTSTATUS NTAPI NtQuerySystemInformation(
    IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
    OUT PVOID SystemInformation,
    IN SIZE_T Length,
    OUT PSIZE_T ResultLength
);

ULONG EnumProcesses(fnEnumProcessProc fnEnumProc)
{
	ULONG cbBuffer = 0;
	LPVOID pBuffer = NULL;
    ULONG nCount = 0;

	while (1)
	{
		cbBuffer += 0x20000;
		pBuffer = VirtualAlloc(NULL, cbBuffer, MEM_COMMIT, PAGE_READWRITE);

		if (pBuffer == NULL)
		{
			return 0;
		}

        NTSTATUS Status = NtQuerySystemInformation(SystemProcessInformation, pBuffer, cbBuffer, NULL);

		if (NT_SUCCESS(Status))
		{
			break;
		}

		VirtualFree(pBuffer, 0, MEM_RELEASE);

		if (Status != STATUS_INFO_LENGTH_MISMATCH)
		{
			return 0;
		}
	}

	if (pBuffer == NULL)
		return 0;

	PSYSTEM_PROCESS_INFORMATION pInfo = (PSYSTEM_PROCESS_INFORMATION)pBuffer;

	while (pInfo)
	{
        fnEnumProc((ULONG)pInfo->UniqueProcessId);
        nCount ++;

		if (pInfo->NextEntryOffset == 0)
			break;

		pInfo = (PSYSTEM_PROCESS_INFORMATION)(((PUCHAR)pInfo) + pInfo->NextEntryOffset);
	}

	VirtualFree(pBuffer, 0, MEM_RELEASE);
	return nCount;
}

BOOL EnumSystemModules(fnEnumSysModuleProc fnEnumProc)
{
    ULONG cbBuffer = 0;
    LPVOID pBuffer = NULL;
    BOOL bSuccess = FALSE;
    WCHAR szImagePath[MAX_PATH];

    while (1)
    {
        cbBuffer += 0x20000;
        pBuffer = VirtualAlloc(NULL, cbBuffer, MEM_COMMIT, PAGE_READWRITE);

        if (pBuffer == NULL)
        {
            return FALSE;
        }

        NTSTATUS Status = NtQuerySystemInformation(SystemModuleInformation, pBuffer, cbBuffer, NULL);

        if (NT_SUCCESS(Status))
        {
            break;
        }

        VirtualFree(pBuffer, 0, MEM_RELEASE);

        if (Status != STATUS_INFO_LENGTH_MISMATCH)
        {
            return FALSE;
        }
    }

    if (pBuffer == NULL)
        return FALSE;

    PSYSTEM_MODULE_INFORMATION pInfo = (PSYSTEM_MODULE_INFORMATION)pBuffer;
    for (size_t i = 0; i < pInfo->Count; ++i)
    {
        int num = MultiByteToWideChar(CP_ACP, 0, pInfo->Module[i].ImageName, (int)strlen(pInfo->Module[i].ImageName), szImagePath, MAX_PATH - 1);
        if (num > 0)
        {
            szImagePath[num] = 0;
            fnEnumProc((ULONG64)pInfo->Module[i].Base, pInfo->Module[i].Size, szImagePath, pInfo->Module[i].LoadOrderIndex);
            bSuccess = TRUE;
        }
    }

    VirtualFree(pBuffer, 0, MEM_RELEASE);
    return bSuccess;
}
