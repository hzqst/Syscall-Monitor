#include <ntifs.h>
#define NTSTRSAFE_NO_CB_FUNCTIONS
#include <ntstrsafe.h>
#include "NativeEnums.h"
#include "NativeStructs.h"
#include "../HyperPlatform/kernel_stl.h"
#include "main.h"

NTSTATUS NtFileNameToDosFileName(IN PUNICODE_STRING NtFileName, OUT PUNICODE_STRING DosFileName);
NTSTATUS GetFileDosName(IN PFILE_OBJECT pFileObject, OUT PUNICODE_STRING ustrDosName);

EXTERN_C{

NTKERNELAPI PVOID NTAPI PsGetProcessPeb(PEPROCESS Process);
#ifdef AMD64
NTKERNELAPI PVOID NTAPI PsGetProcessWow64Process(PEPROCESS Process);
#endif

#define MEM_IMAGE 0x1000000 

#define MemorySectionName 2

NTKERNELAPI PVOID PsGetProcessSectionBaseAddress(PEPROCESS Process);

NTKERNELAPI NTSTATUS NTAPI ZwQueryInformationProcess(
	_In_      HANDLE           ProcessHandle,
	_In_      PROCESSINFOCLASS ProcessInformationClass,
	_Out_     PVOID            ProcessInformation,
	_In_      ULONG            ProcessInformationLength,
	_Out_opt_ PULONG           ReturnLength
);

NTSTATUS NTAPI NewZwQueryVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, MEMORY_INFORMATION_CLASS_EX MemoryInformationClass, PVOID MemoryInformation, SIZE_T MemoryInformationLength, PSIZE_T ReturnLength);

BOOLEAN IsProcessIdEqual(HANDLE ProcessId1, HANDLE ProcessId2)
{
	return ((SIZE_T)ProcessId1 / 4 == (SIZE_T)ProcessId2 / 4) ? TRUE : FALSE;
}

NTSTATUS GetCurrentProcessCurDirectory(PUNICODE_STRING CurDirectory)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PVOID Peb;
#ifdef _WIN64
	//Wow64
	Peb = PsGetProcessWow64Process(PsGetCurrentProcess());
	if (Peb)
	{
		__try
		{
			PPEB32 pPeb32 = (PPEB32)Peb;
			PRTL_USER_PROCESS_PARAMETERS32 Param = (PRTL_USER_PROCESS_PARAMETERS32)pPeb32->ProcessParameters;

			UNICODE_STRING ustrCurDirectory;
			ustrCurDirectory.Buffer = (PWCH)Param->CurrentDirectoryPath.Buffer;
			ustrCurDirectory.Length = (USHORT)Param->CurrentDirectoryPath.Length;
			ustrCurDirectory.MaximumLength = (USHORT)Param->CurrentDirectoryPath.MaximumLength;

			ProbeForRead(ustrCurDirectory.Buffer, ustrCurDirectory.Length, sizeof(WCHAR));

			RtlCopyUnicodeString(CurDirectory, &ustrCurDirectory);

			status = STATUS_SUCCESS;
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			status = GetExceptionCode();
		}
		return status;
	}
#endif
	//Native
	Peb = PsGetProcessPeb(PsGetCurrentProcess());
	__try
	{
		PPEB pPebNative = (PPEB)Peb;
		PRTL_USER_PROCESS_PARAMETERS Param = (PRTL_USER_PROCESS_PARAMETERS)pPebNative->ProcessParameters;

		UNICODE_STRING ustrCurDirectory;
		ustrCurDirectory.Buffer = (PWCH)Param->CurrentDirectoryPath.Buffer;
		ustrCurDirectory.Length = (USHORT)Param->CurrentDirectoryPath.Length;
		ustrCurDirectory.MaximumLength = (USHORT)Param->CurrentDirectoryPath.MaximumLength;

		ProbeForRead(ustrCurDirectory.Buffer, ustrCurDirectory.Length, sizeof(WCHAR));

		RtlCopyUnicodeString(CurDirectory, &ustrCurDirectory);

		status = STATUS_SUCCESS;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		status = GetExceptionCode();
	}
	return status;
}

NTSTATUS GetCurrentProcessCommandLine(PUNICODE_STRING Commandline)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PVOID Peb;
#ifdef _WIN64
	//Wow64
	Peb = PsGetProcessWow64Process(PsGetCurrentProcess());
	if (Peb)
	{
		__try
		{
			PPEB32 pPeb32 = (PPEB32)Peb;
			PRTL_USER_PROCESS_PARAMETERS32 Param = (PRTL_USER_PROCESS_PARAMETERS32)pPeb32->ProcessParameters;

			UNICODE_STRING ustrCommandLine;
			ustrCommandLine.Buffer = (PWCH)Param->CommandLine.Buffer;
			ustrCommandLine.Length = (USHORT)Param->CommandLine.Length;
			ustrCommandLine.MaximumLength = (USHORT)Param->CommandLine.MaximumLength;

			ProbeForRead(ustrCommandLine.Buffer, ustrCommandLine.Length, 1);

			RtlCopyUnicodeString(Commandline, &ustrCommandLine);

			status = STATUS_SUCCESS;
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			status = GetExceptionCode();
		}
		return status;
	}
#endif
	//Native
	Peb = PsGetProcessPeb(PsGetCurrentProcess());
	__try
	{
		PPEB pPebNative = (PPEB)Peb;
		PRTL_USER_PROCESS_PARAMETERS Param = (PRTL_USER_PROCESS_PARAMETERS)pPebNative->ProcessParameters;

		UNICODE_STRING ustrCommandLine;
		ustrCommandLine.Buffer = (PWCH)Param->CommandLine.Buffer;
		ustrCommandLine.Length = (USHORT)Param->CommandLine.Length;
		ustrCommandLine.MaximumLength = (USHORT)Param->CommandLine.MaximumLength;

		ProbeForRead(ustrCommandLine.Buffer, ustrCommandLine.Length, 1);

		RtlCopyUnicodeString(Commandline, &ustrCommandLine);

		status = STATUS_SUCCESS;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		status = GetExceptionCode();
	}
	return status;
}

NTSTATUS GetCurrentProcessPath(PUNICODE_STRING ProcessName)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	
	PVOID ImageBase = PsGetProcessSectionBaseAddress(PsGetCurrentProcess());
	PVOID SectionName = ExAllocatePoolWithTag(NonPagedPool, ProcessName->MaximumLength + sizeof(MEMORY_SECTION_NAME), 'TXSB');
	if (!SectionName)
		return status;

	if (ImageBase)
	{
		//PIRP lastIrp = IoGetTopLevelIrp();
		//IoSetTopLevelIrp(SYSCALLMON_TOLLEVEL_IRP);

		MEMORY_BASIC_INFORMATION BasicInfo;
		status = NewZwQueryVirtualMemory(NtCurrentProcess(), ImageBase, MemoryBasicInformationEx, &BasicInfo, sizeof(BasicInfo), NULL);
		if (NT_SUCCESS(status) && BasicInfo.Type == MEM_IMAGE)
		{
			status = NewZwQueryVirtualMemory(NtCurrentProcess(), ImageBase, MemoryMappedFilenameInformation, SectionName, ProcessName->MaximumLength + sizeof(MEMORY_SECTION_NAME), NULL);
			if (NT_SUCCESS(status))
			{
				PUNICODE_STRING pSectionFileName = &((PMEMORY_SECTION_NAME)SectionName)->SectionFileName;

				if (!NT_SUCCESS(NtFileNameToDosFileName(pSectionFileName, ProcessName))) {
					RtlCopyUnicodeString(ProcessName, pSectionFileName);
				}

				status = STATUS_SUCCESS;
			}
		}

		//IoSetTopLevelIrp(lastIrp);
	}

	ExFreePoolWithTag(SectionName, 'TXSB');
	return status;
}

NTSTATUS GetCurDirectoryByPID(HANDLE ProcessId, PUNICODE_STRING CurDirectory)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	if ((SIZE_T)ProcessId > 4)
	{
		if (IsProcessIdEqual(ProcessId, PsGetCurrentProcessId()))
		{
			status = GetCurrentProcessCurDirectory(CurDirectory);
		}
		else
		{
			PEPROCESS Process = NULL;
			if (NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &Process)))
			{
				KAPC_STATE KApc;
				KeStackAttachProcess((PRKPROCESS)Process, &KApc);
				status = GetCurrentProcessCurDirectory(CurDirectory);
				KeUnstackDetachProcess(&KApc);
				ObDereferenceObject(Process);
			}
		}
	}
	return status;
}

NTSTATUS GetCommandLineByPID(HANDLE ProcessId, PUNICODE_STRING CommandLine)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	if ((SIZE_T)ProcessId > 4)
	{
		if (IsProcessIdEqual(ProcessId, PsGetCurrentProcessId()))
		{
			status = GetCurrentProcessCommandLine(CommandLine);
		}
		else
		{
			PEPROCESS Process = NULL;
			if (NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &Process)))
			{
				KAPC_STATE KApc;
				KeStackAttachProcess((PRKPROCESS)Process, &KApc);
				status = GetCurrentProcessCommandLine(CommandLine);
				KeUnstackDetachProcess(&KApc);
				ObDereferenceObject(Process);
			}
		}
	}
	return status;
}

NTSTATUS GetProcessPathByPID(HANDLE ProcessId, PUNICODE_STRING ProcessName)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	if ((SIZE_T)ProcessId <= 4)
	{
		ProcessName->Length = 0;
		RtlAppendUnicodeToString(ProcessName, L"System");
		status = STATUS_SUCCESS;
	}
	else if (IsProcessIdEqual(ProcessId, PsGetCurrentProcessId()))
	{
		status = GetCurrentProcessPath(ProcessName);
	}
	else
	{
		PEPROCESS Process = NULL;
		if (NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &Process)))
		{
			KAPC_STATE KApc;
			KeStackAttachProcess((PRKPROCESS)Process, &KApc);
			status = GetCurrentProcessPath(ProcessName);
			KeUnstackDetachProcess(&KApc);
			ObDereferenceObject(Process);
		}
	}
	return status;
}

NTSTATUS GetCurrentImageBase(IN PVOID BaseAddress, OUT PVOID *ImageBase)
{
	MEMORY_BASIC_INFORMATION BasicInfo;
	NTSTATUS status = NewZwQueryVirtualMemory(NtCurrentProcess(), BaseAddress, MemoryBasicInformationEx, &BasicInfo, sizeof(BasicInfo), NULL);
	if (NT_SUCCESS(status) && BasicInfo.Type == MEM_IMAGE)
	{
		*ImageBase = BasicInfo.AllocationBase;
		return STATUS_SUCCESS;
	}
	return status;
}

NTSTATUS GetImageBaseByAddress(IN HANDLE ProcessId, IN PVOID BaseAddress, OUT PVOID *ImageBase)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	if (IsProcessIdEqual(ProcessId, PsGetCurrentProcessId()))
	{
		status = GetCurrentImageBase(BaseAddress, ImageBase);
	}
	else
	{
		PEPROCESS Process = NULL;
		if (NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &Process)))
		{
			KAPC_STATE KApc;
			KeStackAttachProcess((PRKPROCESS)Process, &KApc);
			status = GetCurrentImageBase(BaseAddress, ImageBase);
			KeUnstackDetachProcess(&KApc);
			ObDereferenceObject(Process);
		}
	}

	return status;
}

NTSTATUS GetCurrentImagePath(PVOID ImageBase, PUNICODE_STRING ImagePath)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PVOID SectionName = ExAllocatePoolWithTag(NonPagedPool, ImagePath->MaximumLength + sizeof(MEMORY_SECTION_NAME), 'TXSB');
	if (!SectionName)
		return status;

	if (ImageBase)
	{
		//PIRP lastIrp = IoGetTopLevelIrp();
		//IoSetTopLevelIrp(SYSCALLMON_TOLLEVEL_IRP);

		MEMORY_BASIC_INFORMATION BasicInfo;
		status = NewZwQueryVirtualMemory(NtCurrentProcess(), ImageBase, MemoryBasicInformationEx, &BasicInfo, sizeof(BasicInfo), NULL);
		if (NT_SUCCESS(status) && BasicInfo.Type == MEM_IMAGE)
		{
			status = NewZwQueryVirtualMemory(NtCurrentProcess(), ImageBase, MemoryMappedFilenameInformation, SectionName, ImagePath->MaximumLength + sizeof(MEMORY_SECTION_NAME), NULL);
			if (NT_SUCCESS(status))
			{
				PUNICODE_STRING pSectionFileName = &((PMEMORY_SECTION_NAME)SectionName)->SectionFileName;

				if (!NT_SUCCESS(NtFileNameToDosFileName(pSectionFileName, ImagePath))) {
					RtlCopyUnicodeString(ImagePath, pSectionFileName);
				}

				status = STATUS_SUCCESS;
			}
		}

		//IoSetTopLevelIrp(lastIrp);
	}

	ExFreePoolWithTag(SectionName, 'TXSB');
	return status;
}

NTSTATUS GetImagePathByAddress(HANDLE ProcessId, PVOID ImageBase, PUNICODE_STRING ImagePath)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	if (IsProcessIdEqual(ProcessId, PsGetCurrentProcessId()))
	{
		status = GetCurrentImagePath(ImageBase, ImagePath);
	}
	else
	{
		PEPROCESS Process = NULL;
		if (NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &Process)))
		{
			KAPC_STATE KApc;
			KeStackAttachProcess((PRKPROCESS)Process, &KApc);
			status = GetCurrentImagePath(ImageBase, ImagePath);
			KeUnstackDetachProcess(&KApc);
			ObDereferenceObject(Process);
		}
	}

	return status;
}

NTSTATUS GetProcessIdByHandle(__in HANDLE ProcessHandle, __out PHANDLE ProcessId)
{
	PROCESS_BASIC_INFORMATION pbi;
	
	NTSTATUS st = ZwQueryInformationProcess(ProcessHandle, ProcessBasicInformation, &pbi, sizeof(pbi), NULL);
	if (NT_SUCCESS(st))
	{
		*ProcessId = (HANDLE)pbi.UniqueProcessId;
		return STATUS_SUCCESS;
	}
	return st;
}

}