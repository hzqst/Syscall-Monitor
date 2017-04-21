#include <ntifs.h>
#define NTSTRSAFE_NO_CB_FUNCTIONS
#include <Ntstrsafe.h>
#include "NativeEnums.h"
#include "NativeStructs.h"
#include "PEStructs.h"
#include "main.h"
#include "..\HyperPlatform\ia32_type.h"
#include "..\HyperPlatform\util.h"
#include "..\..\Shared\Protocol.h"

EXTERN_C{

#ifndef AMD64

extern PSYSTEM_SERVICE_DESCRIPTOR_TABLE KeServiceDescriptorTable;

#endif

NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass, 
	OUT PVOID SystemInformation, 
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength OPTIONAL);

NTSYSAPI NTSTATUS NTAPI ZwQueryInformationProcess(
	IN  HANDLE ProcessHandle,
	IN  PROCESSINFOCLASS ProcessInformationClass,
	OUT PVOID ProcessInformation,
	IN  ULONG ProcessInformationLength,
	IN  PULONG ReturnLength
);

NTSYSAPI PIMAGE_NT_HEADERS NTAPI RtlImageNtHeader(PVOID Base);

ULONG GetNativeFunctionIndex(const char *lpFunctionName);
VOID GetNativeFunctionIndexEx(PDYNAMIC_DATA pData);
PVOID GetKernelBase(OUT PULONG pSize);
PSYSTEM_SERVICE_DESCRIPTOR_TABLE GetSSDTBase(void);
NTSTATUS InitDynamicData(IN OUT PDYNAMIC_DATA pData);
VOID LoadSymbolFile(IN OUT PDYNAMIC_DATA pData);

#pragma alloc_text(PAGE, GetKernelBase)
#pragma alloc_text(PAGE, GetSSDTBase)
#pragma alloc_text(INIT, GetNativeFunctionIndexEx)
#pragma alloc_text(INIT, InitDynamicData)
#pragma alloc_text(INIT, LoadSymbolFile)

DYNAMIC_DATA dynData;
PVOID g_KernelBase = NULL;
ULONG g_KernelSize = 0;
PVOID g_ThisModuleBase = NULL;
ULONG g_ThisModuleSize = 0;

PSYSTEM_SERVICE_DESCRIPTOR_TABLE g_SSDT = NULL;

BOOLEAN IsPE64Bit(PVOID ImageBase)
{
	BOOLEAN Is64Bit = FALSE;
	__try
	{
		PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)ImageBase;
		PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((PUCHAR)ImageBase + dosHeader->e_lfanew);
		Is64Bit = (ntHeader->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) ? TRUE : FALSE;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
	}
	return Is64Bit;
}

ULONG GetImageSize(PVOID ImageBase)
{
	ULONG ImageSize = 0;
	__try
	{
		PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)ImageBase;
		PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((PUCHAR)ImageBase + dosHeader->e_lfanew);
		if (ntHeader->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64 &&
			ntHeader->FileHeader.SizeOfOptionalHeader >= sizeof(IMAGE_OPTIONAL_HEADER64))
		{
			PIMAGE_NT_HEADERS64 ntHeader64 = (PIMAGE_NT_HEADERS64)((PUCHAR)ImageBase + dosHeader->e_lfanew);
			ImageSize = ntHeader64->OptionalHeader.SizeOfImage;
		}
		else if (ntHeader->FileHeader.Machine == IMAGE_FILE_MACHINE_I386 && 
			ntHeader->FileHeader.SizeOfOptionalHeader >= sizeof(IMAGE_OPTIONAL_HEADER32))
		{
			PIMAGE_NT_HEADERS32 ntHeader32 = (PIMAGE_NT_HEADERS32)((PUCHAR)ImageBase + dosHeader->e_lfanew);
			ImageSize = ntHeader32->OptionalHeader.SizeOfImage;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
	}
	return ImageSize;
}

#if 0
ULONG GetNativeFunctionIndex(const char *lpFunctionName)
{
	HANDLE hSection, hFile;
	PIMAGE_DOS_HEADER dosHeader;
	PIMAGE_NT_HEADERS32 ntHeader;
	IMAGE_EXPORT_DIRECTORY* pExportTable;
	ULONG* arrayOfFunctionAddresses;
	ULONG* arrayOfFunctionNames;
	USHORT* arrayOfFunctionOrdinals;
	ULONG x;
	PUCHAR functionAddress = NULL;
	char* functionName = NULL;
	PVOID BaseAddress = NULL;
	SIZE_T Size = 0;
	OBJECT_ATTRIBUTES oa;
	IO_STATUS_BLOCK iosb;
	NTSTATUS status;
	ULONG uIndex = 0;
	UNICODE_STRING pDllName;

#ifdef AMD64
	RtlInitUnicodeString(&pDllName, L"\\SystemRoot\\SysWOW64\\ntdll.dll");
#else
	RtlInitUnicodeString(&pDllName, L"\\SystemRoot\\System32\\ntdll.dll");
#endif

	InitializeObjectAttributes(&oa, &pDllName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
	status = ZwOpenFile(&hFile, FILE_GENERIC_READ | SYNCHRONIZE, &oa, &iosb, FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT);

	if (NT_SUCCESS(status))
	{
		oa.ObjectName = 0;
		status = ZwCreateSection(&hSection, SECTION_ALL_ACCESS, &oa, 0, PAGE_READONLY, 0x01000000, hFile);
		if (NT_SUCCESS(status))
		{
			BaseAddress = NULL;

			status = ZwMapViewOfSection(hSection, NtCurrentProcess(), &BaseAddress, 0, 0, 0, &Size, ViewShare, MEM_TOP_DOWN, PAGE_READONLY);
			if (NT_SUCCESS(status))
			{
				dosHeader = (PIMAGE_DOS_HEADER)BaseAddress;
				ntHeader = (PIMAGE_NT_HEADERS32)((PUCHAR)BaseAddress + dosHeader->e_lfanew);

				pExportTable = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)BaseAddress + ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

				arrayOfFunctionAddresses = (ULONG*)((PUCHAR)BaseAddress + pExportTable->AddressOfFunctions);
				arrayOfFunctionNames = (ULONG*)((PUCHAR)BaseAddress + pExportTable->AddressOfNames);
				arrayOfFunctionOrdinals = (USHORT*)((PUCHAR)BaseAddress + pExportTable->AddressOfNameOrdinals);

				for (x = 0; x < pExportTable->NumberOfFunctions; x++)
				{
					functionName = (char*)((unsigned char*)BaseAddress + arrayOfFunctionNames[x]);
					functionAddress = ((unsigned char*)BaseAddress + arrayOfFunctionAddresses[arrayOfFunctionOrdinals[x]]);
					if (!_stricmp(functionName, lpFunctionName))
					{
						uIndex = *(USHORT *)(functionAddress + 1);
						break;
					}
				}

				ZwUnmapViewOfSection(NtCurrentProcess(), BaseAddress);
			}

			ZwClose(hSection);
		}
		ZwClose(hFile);
	}

	return uIndex;
}
#endif

VOID GetNativeFunctionIndexEx(PDYNAMIC_DATA pData)
{
	HANDLE hSection, hFile;
	PIMAGE_DOS_HEADER dosHeader;
	PIMAGE_NT_HEADERS32 ntHeader;
	IMAGE_EXPORT_DIRECTORY* pExportTable;
	ULONG* arrayOfFunctionAddresses;
	ULONG* arrayOfFunctionNames;
	USHORT* arrayOfFunctionOrdinals;
	ULONG x;
	PUCHAR functionAddress = NULL;
	char* functionName = NULL;
	PVOID BaseAddress = NULL;
	SIZE_T Size = 0;
	OBJECT_ATTRIBUTES oa;
	IO_STATUS_BLOCK iosb;
	NTSTATUS status;
	UNICODE_STRING pDllName;

#ifdef AMD64
	RtlInitUnicodeString(&pDllName, L"\\SystemRoot\\SysWOW64\\ntdll.dll");
#else
	RtlInitUnicodeString(&pDllName, L"\\SystemRoot\\System32\\ntdll.dll");
#endif

	InitializeObjectAttributes(&oa, &pDllName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
	status = ZwOpenFile(&hFile, FILE_GENERIC_READ | SYNCHRONIZE, &oa, &iosb, FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT);

	if (NT_SUCCESS(status))
	{
		oa.ObjectName = 0;
		status = ZwCreateSection(&hSection, SECTION_ALL_ACCESS, &oa, 0, PAGE_READONLY, 0x01000000, hFile);
		if (NT_SUCCESS(status))
		{
			BaseAddress = NULL;

			status = ZwMapViewOfSection(hSection, NtCurrentProcess(), &BaseAddress, 0, 0, 0, &Size, ViewShare, MEM_TOP_DOWN, PAGE_READONLY);
			if (NT_SUCCESS(status))
			{
				//BaseAddress is an user-mode address
				__try
				{
					dosHeader = (PIMAGE_DOS_HEADER)BaseAddress;
					ntHeader = (PIMAGE_NT_HEADERS32)((PUCHAR)BaseAddress + dosHeader->e_lfanew);

					pExportTable = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)BaseAddress + ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

					arrayOfFunctionAddresses = (ULONG*)((PUCHAR)BaseAddress + pExportTable->AddressOfFunctions);
					arrayOfFunctionNames = (ULONG*)((PUCHAR)BaseAddress + pExportTable->AddressOfNames);
					arrayOfFunctionOrdinals = (USHORT*)((PUCHAR)BaseAddress + pExportTable->AddressOfNameOrdinals);

					for (x = 0; x < pExportTable->NumberOfNames; x++)
					{
						functionName = (char*)((unsigned char*)BaseAddress + arrayOfFunctionNames[x]);
						functionAddress = ((unsigned char*)BaseAddress + arrayOfFunctionAddresses[arrayOfFunctionOrdinals[x]]);

						if (!_stricmp(functionName, "NtLoadDriver"))
						{
							pData->NtLoadDrvIndex = *(USHORT *)(functionAddress + 1);
						}
						else if (!_stricmp(functionName, "NtOpenProcess"))
						{
							pData->NtOpenProcIndex = *(USHORT *)(functionAddress + 1);
						}
						else if (!_stricmp(functionName, "NtOpenThread"))
						{
							pData->NtOpenThrdIndex = *(USHORT *)(functionAddress + 1);
						}
						else if (!_stricmp(functionName, "NtTerminateProcess"))
						{
							pData->NtTerminateIndex = *(USHORT *)(functionAddress + 1);
						}
						else if (!_stricmp(functionName, "NtTerminateThread"))
						{
							pData->NtTermThrdIndex = *(USHORT *)(functionAddress + 1);
						}
						else if (!_stricmp(functionName, "NtQueryVirtualMemory"))
						{
							pData->NtQueryIndex = *(USHORT *)(functionAddress + 1);
						}
						else if (!_stricmp(functionName, "NtProtectVirtualMemory"))
						{
							pData->NtProtectIndex = *(USHORT *)(functionAddress + 1);
						}
						else if (!_stricmp(functionName, "NtReadVirtualMemory"))
						{
							pData->NtReadIndex = *(USHORT *)(functionAddress + 1);
						}
						else if (!_stricmp(functionName, "NtWriteVirtualMemory"))
						{
							pData->NtWriteIndex = *(USHORT *)(functionAddress + 1);
						}
						else if (!_stricmp(functionName, "NtAllocateVirtualMemory"))
						{
							pData->NtAllocIndex = *(USHORT *)(functionAddress + 1);
						}
						else if (!_stricmp(functionName, "NtCreateMutant"))
						{
							pData->NtCreateMutantIndex = *(USHORT *)(functionAddress + 1);
						}
						else if (!_stricmp(functionName, "NtOpenMutant"))
						{
							pData->NtOpenMutantIndex = *(USHORT *)(functionAddress + 1);
						}
						else if (!_stricmp(functionName, "NtCreateDirectoryObject"))
						{
							pData->NtCreateDirObjIndex = *(USHORT *)(functionAddress + 1);
						}
						else if (!_stricmp(functionName, "NtOpenDirectoryObject"))
						{
							pData->NtOpenDirObjIndex = *(USHORT *)(functionAddress + 1);
						}
						else if (!_stricmp(functionName, "NtQueryDirectoryObject"))
						{
							pData->NtQueryDirObjIndex = *(USHORT *)(functionAddress + 1);
						}
					}
				}
				__except (EXCEPTION_EXECUTE_HANDLER) {
					status = GetExceptionCode();
				}

				ZwUnmapViewOfSection(NtCurrentProcess(), BaseAddress);
			}

			ZwClose(hSection);
		}
		ZwClose(hFile);
	}
}

/// <summary>
/// Get ntoskrnl base address
/// </summary>
/// <param name="pSize">Size of module</param>
/// <returns>Found address, NULL if not found</returns>
PVOID GetKernelBase(OUT PULONG pSize)
{
	NTSTATUS status = STATUS_SUCCESS;
	ULONG bytes = 0;
	PRTL_PROCESS_MODULES pMods = NULL;
	PVOID checkPtr = NULL;
	UNICODE_STRING routineName;
	ULONG i;

	// Already found
	if (g_KernelBase != NULL)
	{
		if (pSize)
			*pSize = g_KernelSize;
		return g_KernelBase;
	}

	RtlUnicodeStringInit(&routineName, L"NtOpenFile");

	checkPtr = MmGetSystemRoutineAddress(&routineName);
	if (checkPtr == NULL)
		return NULL;

	// Protect from UserMode AV
	status = ZwQuerySystemInformation(SystemModuleInformation, 0, bytes, &bytes);
	if (bytes == 0)
	{
		return NULL;
	}

	pMods = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, bytes, 'TXSB');
	RtlZeroMemory(pMods, bytes);

	status = ZwQuerySystemInformation(SystemModuleInformation, pMods, bytes, &bytes);

	if (NT_SUCCESS(status))
	{
		PRTL_PROCESS_MODULE_INFORMATION pMod = pMods->Modules;

		for (i = 0; i < pMods->NumberOfModules; i++)
		{
			// System routine is inside module
			if (checkPtr >= pMod[i].ImageBase &&
				checkPtr < (PVOID)((PUCHAR)pMod[i].ImageBase + pMod[i].ImageSize))
			{
				g_KernelBase = pMod[i].ImageBase;
				g_KernelSize = pMod[i].ImageSize;
				if (pSize)
					*pSize = g_KernelSize;
				break;
			}
		}
	}

	if (pMods)
		ExFreePoolWithTag(pMods, 'TXSB');

	return g_KernelBase;
}

/// <summary>
/// Search for pattern
/// </summary>
/// <param name="pattern">Pattern to search for</param>
/// <param name="wildcard">Used wildcard</param>
/// <param name="len">Pattern length</param>
/// <param name="base">Base address for searching</param>
/// <param name="size">Address range to search in</param>
/// <param name="ppFound">Found location</param>
/// <returns>Status code</returns>
NTSTATUS BBSearchPattern(IN PCUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, IN const VOID* base, IN ULONG_PTR size, OUT PVOID* ppFound)
{
	ULONG_PTR i, j;
	if (ppFound == NULL || pattern == NULL || base == NULL)
		return STATUS_INVALID_PARAMETER;

	for (i = 0; i < size - len; i++)
	{
		BOOLEAN found = TRUE;
		for (j = 0; j < len; j++)
		{
			if (pattern[j] != wildcard && pattern[j] != ((PCUCHAR)base)[i + j])
			{
				found = FALSE;
				break;
			}
		}

		if (found != FALSE)
		{
			*ppFound = (PUCHAR)base + i;
			return STATUS_SUCCESS;
		}
	}

	return STATUS_NOT_FOUND;
}

PSYSTEM_SERVICE_DESCRIPTOR_TABLE GetSSDTBase(void)
{
#ifdef AMD64
	PIMAGE_NT_HEADERS pHdr;
	PIMAGE_SECTION_HEADER pFirstSec;
	PIMAGE_SECTION_HEADER pSec;
	PUCHAR ntosBase;

	ntosBase = (PUCHAR)GetKernelBase(NULL);

	// Already found
	if (g_SSDT != NULL)
		return g_SSDT;

	if (!ntosBase)
		return NULL;

	pHdr = RtlImageNtHeader(ntosBase);
	pFirstSec = (PIMAGE_SECTION_HEADER)(pHdr + 1);
	for (pSec = pFirstSec; pSec < pFirstSec + pHdr->FileHeader.NumberOfSections; pSec++)
	{
		// Non-paged, non-discardable, readable sections
		// Probably still not fool-proof enough...
		if (pSec->Characteristics & IMAGE_SCN_MEM_NOT_PAGED &&
			pSec->Characteristics & IMAGE_SCN_MEM_EXECUTE &&
			!(pSec->Characteristics & IMAGE_SCN_MEM_DISCARDABLE) &&
			(*(PULONG)pSec->Name != 'TINI') &&
			(*(PULONG)pSec->Name != 'EGAP'))
		{
			PVOID pFound = NULL;

			// KiSystemServiceRepeat pattern
			UCHAR pattern[] = "\x4c\x8d\x15\xcc\xcc\xcc\xcc\x4c\x8d\x1d\xcc\xcc\xcc\xcc\xf7";
			NTSTATUS status = BBSearchPattern(pattern, 0xCC, sizeof(pattern) - 1, ntosBase + pSec->VirtualAddress, pSec->Misc.VirtualSize, &pFound);
			if (NT_SUCCESS(status))
			{
				g_SSDT = (PSYSTEM_SERVICE_DESCRIPTOR_TABLE)((PUCHAR)pFound + *(PULONG)((PUCHAR)pFound + 3) + 7);
				//DPRINT( "BlackBone: %s: KeSystemServiceDescriptorTable = 0x%p\n", __FUNCTION__, g_SSDT );
				return g_SSDT;
			}
		}
	}
	return NULL;
#else
	return KeServiceDescriptorTable;
#endif
}


/// <summary>
/// Gets the SSDT entry address by index.
/// </summary>
/// <param name="index">Service index</param>
/// <returns>Found service address, NULL if not found</returns>
PVOID GetSSDTEntry(IN ULONG index)
{
	PSYSTEM_SERVICE_DESCRIPTOR_TABLE pSSDT = GetSSDTBase();
	if (!pSSDT)
		return NULL;

	// Index range check
	if (index > pSSDT->NumberOfServices)
		return NULL;

#ifdef AMD64
	return (PUCHAR)pSSDT->ServiceTableBase + (((PLONG)pSSDT->ServiceTableBase)[index] >> 4);
#else
	return (PVOID)pSSDT->ServiceTableBase[index];
#endif
}

PVOID MiFindExportedRoutine2(
	PVOID DllBase,
	PIMAGE_EXPORT_DIRECTORY ExportDirectory,
	ULONG ExportSize,
	BOOLEAN ByName,
	PCHAR RoutineName,
	ULONG Ordinal
)
{
	USHORT OrdinalNumber;
	PULONG NameTableBase;
	PUSHORT NameOrdinalTableBase;
	PULONG AddressTableBase;
	PULONG Addr;
	LONG High;
	LONG Low;
	LONG Middle;
	LONG Result;
	PVOID FunctionAddress;
	if (ExportDirectory == NULL || ExportSize == 0)
	{
		return NULL;
	}
	NameTableBase = (PULONG)((PCHAR)DllBase + (ULONG)ExportDirectory->AddressOfNames);
	NameOrdinalTableBase = (PUSHORT)((PCHAR)DllBase + (ULONG)ExportDirectory->AddressOfNameOrdinals);
	AddressTableBase = (PULONG)((PCHAR)DllBase + (ULONG)ExportDirectory->AddressOfFunctions);
	if (!ByName)
	{
		return (PVOID)AddressTableBase[Ordinal];
	}
	Low = 0;
	Middle = 0;
	High = ExportDirectory->NumberOfNames - 1;
	while (High >= Low)
	{
		Middle = (Low + High) >> 1;
		Result = strcmp(RoutineName,
			(PCHAR)DllBase + NameTableBase[Middle]);
		if (Result < 0)
		{
			High = Middle - 1;
		}
		else if (Result > 0)
		{
			Low = Middle + 1;
		}
		else
		{
			break;
		}
	}
	if (High < Low)
	{
		return NULL;
	}
	OrdinalNumber = NameOrdinalTableBase[Middle];
	if ((ULONG)OrdinalNumber >= ExportDirectory->NumberOfFunctions)
	{
		return NULL;
	}
	Addr = (PULONG)((PCHAR)DllBase + (ULONG)ExportDirectory->AddressOfFunctions);
	FunctionAddress = (PVOID)((PCHAR)DllBase + Addr[OrdinalNumber]);
	if ((ULONG_PTR)FunctionAddress > (ULONG_PTR)ExportDirectory &&
		(ULONG_PTR)FunctionAddress < ((ULONG_PTR)ExportDirectory + ExportSize))
	{
		FunctionAddress = NULL;
	}
	return FunctionAddress;
}

#ifdef AMD64

PVOID NativeGetProcAddress(PVOID uModBase, CHAR *cSearchFnName)
{
	IMAGE_DOS_HEADER *doshdr;
	IMAGE_OPTIONAL_HEADER64 *opthdr;
	IMAGE_EXPORT_DIRECTORY *pExportTable;
	ULONG size;
	PVOID uFnAddr = NULL;
	//
	doshdr = (IMAGE_DOS_HEADER *)uModBase;
	if (NULL == doshdr)
	{
		goto __exit;
	}
	opthdr = (IMAGE_OPTIONAL_HEADER64 *)((PUCHAR)uModBase + doshdr->e_lfanew + sizeof(ULONG) + sizeof(IMAGE_FILE_HEADER));
	if (NULL == opthdr)
	{
		goto __exit;
	}
	pExportTable = (IMAGE_EXPORT_DIRECTORY *)((PUCHAR)uModBase + opthdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	if (NULL == pExportTable)
	{
		goto __exit;
	}
	size = opthdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	uFnAddr = MiFindExportedRoutine2(uModBase, pExportTable, size, TRUE, cSearchFnName, 0);
__exit:
	return uFnAddr;
}

#else

PVOID NativeGetProcAddress(PVOID uModBase, CHAR *cSearchFnName)
{
	IMAGE_DOS_HEADER *doshdr;
	IMAGE_OPTIONAL_HEADER32 *opthdr;
	IMAGE_EXPORT_DIRECTORY *pExportTable;
	ULONG size;
	PVOID uFnAddr = NULL;
	//
	doshdr = (IMAGE_DOS_HEADER *)uModBase;
	if (NULL == doshdr)
	{
		goto __exit;
	}
	opthdr = (IMAGE_OPTIONAL_HEADER32 *)((PUCHAR)uModBase + doshdr->e_lfanew + sizeof(ULONG) + sizeof(IMAGE_FILE_HEADER));
	if (NULL == opthdr)
	{
		goto __exit;
	}
	pExportTable = (IMAGE_EXPORT_DIRECTORY *)((PUCHAR)uModBase + opthdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	if (NULL == pExportTable)
	{
		goto __exit;
	}
	size = opthdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	uFnAddr = MiFindExportedRoutine2(uModBase, pExportTable, size, TRUE, cSearchFnName, 0);
__exit:
	return uFnAddr;
}

#endif

NTSTATUS FindSystemImage(PVOID *ImageBase, SIZE_T *ImageSize, LPCSTR szImageName)
{
	NTSTATUS status;
	ULONG bytes = 0;
	PRTL_PROCESS_MODULES pMods = NULL;
	SIZE_T i;

	// Protect from UserMode AV
	status = ZwQuerySystemInformation(SystemModuleInformation, 0, bytes, &bytes);
	if (bytes == 0)
		return status;

	pMods = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(PagedPool, bytes, 'TXSB');
	RtlZeroMemory(pMods, bytes);

	status = ZwQuerySystemInformation(SystemModuleInformation, pMods, bytes, &bytes);

	if (NT_SUCCESS(status))
	{
		status = STATUS_NOT_FOUND;

		PRTL_PROCESS_MODULE_INFORMATION pMod = pMods->Modules;

		for (i = 0; i < pMods->NumberOfModules; i++)
		{
			// System routine is inside module
			if (!_stricmp((PCHAR)pMod[i].FullPathName, szImageName))
			{
				if (ImageBase)
					*ImageBase = pMod[i].ImageBase;
				if (ImageSize)
					*ImageSize = pMod[i].ImageSize;

				status = STATUS_SUCCESS;
				break;
			}
		}
	}

	if (pMods)
		ExFreePoolWithTag(pMods, 'TXSB');

	return status;
}

NTSTATUS GetThisModuleInfo(VOID)
{
	NTSTATUS status = STATUS_SUCCESS;
	ULONG bytes = 0;
	PRTL_PROCESS_MODULES pMods = NULL;
	PVOID checkPtr = NULL;
	ULONG i;

	checkPtr = GetThisModuleInfo;

	// Protect from UserMode AV
	status = ZwQuerySystemInformation(SystemModuleInformation, 0, bytes, &bytes);
	if (bytes == 0)
		return status;

	pMods = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(PagedPool, bytes, 'TXSB');
	RtlZeroMemory(pMods, bytes);

	status = ZwQuerySystemInformation(SystemModuleInformation, pMods, bytes, &bytes);

	if (NT_SUCCESS(status))
	{
		PRTL_PROCESS_MODULE_INFORMATION pMod = pMods->Modules;

		status = STATUS_UNSUCCESSFUL;

		for (i = 0; i < pMods->NumberOfModules; i++)
		{
			// This routine is inside module
			if (checkPtr >= pMod[i].ImageBase &&
				checkPtr < (PVOID)((PUCHAR)pMod[i].ImageBase + pMod[i].ImageSize))
			{
				g_ThisModuleBase = pMod[i].ImageBase;
				g_ThisModuleSize = pMod[i].ImageSize;

				status = STATUS_SUCCESS;
				break;
			}
		}
	}

	if (pMods)
		ExFreePoolWithTag(pMods, 'TXSB');

	return status;
}

VOID GetKiSystemServiceCall(PDYNAMIC_DATA pData)
{
	PVOID pFoundPattern = NULL;

#ifdef _WIN64
	PVOID KiSystemCall64 = (PVOID)UtilReadMsr64(Msr::kIa32Lstar);

	//0F 85 ?? ?? 00 00                                   jnz     ???
	//41 FF D2                                            call    r10
	UCHAR KiSystemCall64Pattern[] = "\x0F\x85\xCC\xCC\x00\x00\x41\xFF\xD2";
	if (NT_SUCCESS(BBSearchPattern(KiSystemCall64Pattern, 0xCC, sizeof(KiSystemCall64Pattern) - 1, KiSystemCall64, 0x500, &pFoundPattern)))
	{
		pData->pfnKiCallSystemService = ((PUCHAR)pFoundPattern + 6);
	}
	//41 FF D2                                           call    r10
	//48 89 45 B0                                        mov[rbp - 50h], rax
	UCHAR KiSystemCall64PatternPerf[] = "\x41\xFF\xD2\x48\x89\x45\xB0";
	if (NT_SUCCESS(BBSearchPattern(KiSystemCall64PatternPerf, 0xCC, sizeof(KiSystemCall64PatternPerf) - 1, KiSystemCall64, 0x500, &pFoundPattern)))
	{
		pData->pfnKiCallSystemServicePerf = pFoundPattern;
	}
#else

#endif
}

NTSTATUS InitDynamicData(IN OUT PDYNAMIC_DATA pData)
{
	NTSTATUS status = STATUS_SUCCESS;
	RTL_OSVERSIONINFOEXW verInfo = { 0 };
	PVOID fnExGetPreviousMode = NULL;
	PVOID pFoundPattern = NULL;
	UCHAR PreviousModePattern[] = "\x00\x00\xC3";

	RtlZeroMemory(pData, sizeof(DYNAMIC_DATA));

	verInfo.dwOSVersionInfoSize = sizeof(verInfo);
	status = RtlGetVersion((PRTL_OSVERSIONINFOW)&verInfo);

	if (status == STATUS_SUCCESS)
	{
		ULONG ver_short = (verInfo.dwMajorVersion << 8) | (verInfo.dwMinorVersion << 4) | verInfo.wServicePackMajor;

		pData->OsVer = (WinVer)ver_short;

		GetNativeFunctionIndexEx(pData);

		GetThisModuleInfo();

		PVOID NtBase = GetKernelBase(NULL);
		if (NtBase != NULL)
		{
			pData->pfnNtQuerySystemInformation = NativeGetProcAddress(NtBase, "NtQuerySystemInformation");
			pData->pfnNtOpenProcess = GetSSDTEntry(pData->NtOpenProcIndex);
			pData->pfnNtOpenThread = GetSSDTEntry(pData->NtOpenThrdIndex);
			pData->pfnNtTerminateProcess = GetSSDTEntry(pData->NtTerminateIndex);
			pData->pfnNtTerminatThread = GetSSDTEntry(pData->NtTermThrdIndex);
			pData->pfnNtReadVirtualMemory = GetSSDTEntry(pData->NtReadIndex);
			pData->pfnNtWriteVirtualMemory = GetSSDTEntry(pData->NtWriteIndex);
			pData->pfnNtAllocateVirtualMemory = GetSSDTEntry(pData->NtAllocIndex);
			pData->pfnNtQueryVirtualMemory = GetSSDTEntry(pData->NtQueryIndex);
			pData->pfnNtProtectVirtualMemory = GetSSDTEntry(pData->NtProtectIndex);
			pData->pfnNtLoadDriver = GetSSDTEntry(pData->NtLoadDrvIndex);
			pData->pfnNtCreateMutant = GetSSDTEntry(pData->NtCreateMutantIndex);
			pData->pfnNtOpenMutant = GetSSDTEntry(pData->NtOpenMutantIndex);
			pData->pfnNtCreateDirectoryObject = GetSSDTEntry(pData->NtCreateDirObjIndex);
			pData->pfnNtOpenDirectoryObject = GetSSDTEntry(pData->NtOpenDirObjIndex);
			pData->pfnNtQueryDirectoryObject = GetSSDTEntry(pData->NtQueryDirObjIndex);

			fnExGetPreviousMode = NativeGetProcAddress(NtBase, "ExGetPreviousMode");

			if (fnExGetPreviousMode && NT_SUCCESS(BBSearchPattern(PreviousModePattern, 0xCC, sizeof(PreviousModePattern) - 1, fnExGetPreviousMode, 32, &pFoundPattern)))
			{
				pData->PrevMode = *(DWORD *)((PUCHAR)pFoundPattern - 2);
			}
		}

		LoadSymbolFile(pData);
		//GetKiSystemServiceCall(pData);
	}

	return status;
}

VOID LoadSymbolFile(IN OUT PDYNAMIC_DATA pData)
{
	HANDLE hFile;
	OBJECT_ATTRIBUTES oa;
	IO_STATUS_BLOCK iosb;
	FILE_STANDARD_INFORMATION fsi;
	NTSTATUS status;
	symbol_file_data data = { 0 };

	UNICODE_STRING FileName;
	RtlInitUnicodeString(&FileName, L"\\SystemRoot\\SyscallMonSymbol.dat");

	InitializeObjectAttributes(&oa, &FileName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
	status = ZwOpenFile(&hFile, GENERIC_READ | SYNCHRONIZE | DELETE, &oa, &iosb, FILE_SHARE_READ | FILE_SHARE_DELETE, FILE_SYNCHRONOUS_IO_NONALERT);
	if (NT_SUCCESS(status))
	{
		status = ZwQueryInformationFile(hFile, &iosb, &fsi, sizeof(fsi), FileStandardInformation);
		if (fsi.EndOfFile.QuadPart >= sizeof(symbol_file_data))
		{
			LARGE_INTEGER ByteOffset = { 0 };			
			status = ZwReadFile(hFile, NULL, NULL, NULL, &iosb, &data, sizeof(symbol_file_data), &ByteOffset, NULL);
			if (NT_SUCCESS(status))
			{
				if (data.txsb == 'TXSB' && data.ver == SYMBOL_FILE_VERSION)
				{
					status = STATUS_SUCCESS;
				}
				else
				{
					status = STATUS_UNSUCCESSFUL;
				}
			}
		}
		else
		{
			status = STATUS_UNSUCCESSFUL;
		}

		FILE_DISPOSITION_INFORMATION info;
		info.DeleteFile = TRUE;
		ZwSetInformationFile(hFile, &iosb, &info, sizeof(info), FileDispositionInformation);

		ZwClose(hFile);
	}

	if (NT_SUCCESS(status))
	{
		pData->EnableVmx = data.EnableVmx;

		PVOID Win32kBase = NULL;
		if (pData->OsVer >= WINVER_10)
			FindSystemImage(&Win32kBase, NULL, "\\SystemRoot\\System32\\win32kfull.sys");
		else
			FindSystemImage(&Win32kBase, NULL, "\\SystemRoot\\System32\\win32k.sys");

		if (Win32kBase)
		{
			if (data.NtUserSetWindowsHookExOffset)
				pData->pfnNtUserSetWindowsHookEx = (PUCHAR)Win32kBase + data.NtUserSetWindowsHookExOffset;

			if (data.NtUserSetWindowsHookAWOffset)
				pData->pfnNtUserSetWindowsHookAW = (PUCHAR)Win32kBase + data.NtUserSetWindowsHookAWOffset;

			if (data.NtUserFindWindowExOffset)
				pData->pfnNtUserFindWindowEx = (PUCHAR)Win32kBase + data.NtUserFindWindowExOffset;

			if (data.NtUserInternalGetWindowTextOffset)
				pData->pfnNtUserInternalGetWindowText = (PUCHAR)Win32kBase + data.NtUserInternalGetWindowTextOffset;

			if (data.NtUserGetClassNameOffset)
				pData->pfnNtUserGetClassName = (PUCHAR)Win32kBase + data.NtUserGetClassNameOffset;
		}
	}
}

HANDLE GetCsrssProcessId(VOID)
{
	static HANDLE CsrssPID = NULL;
	ULONG bytes = 0;
	PVOID pBuf = NULL;
	UNICODE_STRING ustrCsrss;

	if (CsrssPID)
		return CsrssPID;

	RtlInitUnicodeString(&ustrCsrss, L"csrss.exe");
	
	NTSTATUS status = ZwQuerySystemInformation(SystemProcessInformation, 0, bytes, &bytes);
	if (bytes == 0)
		return NULL;

	pBuf = ExAllocatePoolWithTag(PagedPool, bytes, 'TXSB');
	RtlZeroMemory(pBuf, bytes);

	status = ZwQuerySystemInformation(SystemProcessInformation, pBuf, bytes, &bytes);
	if (NT_SUCCESS(status))
	{
		PSYSTEM_PROCESS_INFORMATION_EX pInfo = (PSYSTEM_PROCESS_INFORMATION_EX)pBuf;

		while (pInfo)
		{
			if (0 == RtlCompareUnicodeString(&pInfo->ImageName, &ustrCsrss, TRUE))
			{
				PROCESS_SESSION_INFORMATION psi = {0};
				ULONG BreakOnTermination = 0;//out
				CLIENT_ID ClientId;
				ClientId.UniqueProcess = pInfo->UniqueProcessId;
				ClientId.UniqueThread = NULL;
				OBJECT_ATTRIBUTES oa;
				InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, 0, 0);
				HANDLE ProcessHandle = NULL;
				if (NT_SUCCESS(ZwOpenProcess(&ProcessHandle, PROCESS_QUERY_INFORMATION, &oa, &ClientId)))
				{
					ZwQueryInformationProcess(ProcessHandle, ProcessBreakOnTermination, &BreakOnTermination, sizeof(BreakOnTermination), NULL);
					ZwQueryInformationProcess(ProcessHandle, ProcessSessionInformation, &psi, sizeof(psi), NULL);
					ZwClose(ProcessHandle);
				}

				if (psi.SessionId != 0 && BreakOnTermination != 0)
				{
					CsrssPID = pInfo->UniqueProcessId;
				}
			}

			if (pInfo->NextEntryOffset == 0)
				break;

			pInfo = (PSYSTEM_PROCESS_INFORMATION_EX)(((PUCHAR)pInfo) + pInfo->NextEntryOffset);
		}
	}

	ExFreePoolWithTag(pBuf, 'TXSB');

	return CsrssPID;
}

}//EXTERN C