#include <fltKernel.h>

#define NTSTRSAFE_NO_CB_FUNCTIONS
#include <ntstrsafe.h>
#include "../HyperPlatform/kernel_stl.h"
#include "../HyperPlatform/performance.h"
#include "../../Shared/Protocol.h"
#include "NativeEnums.h"
#include "main.h"

extern CProcList *m_IgnoreProcList;
extern CFileList *m_IgnoreFileList;
extern CEventList *m_EventList;
extern DYNAMIC_DATA dynData;

EXTERN_C {

extern PVOID g_ThisModuleBase;
extern ULONG g_ThisModuleSize;

NTSTATUS GetProcessPathByPID(HANDLE ProcessId, PUNICODE_STRING ProcessName);
NTSTATUS GetCommandLineByPID(HANDLE ProcessId, PUNICODE_STRING CommandLine);
NTSTATUS GetCurDirectoryByPID(HANDLE ProcessId, PUNICODE_STRING CurDirectory);

NTSTATUS GetImageBaseByAddress(IN HANDLE ProcessId, IN PVOID BaseAddress, OUT PVOID *ImageBase);
NTSTATUS GetImagePathByAddress(HANDLE ProcessId, PVOID ImageBase, PUNICODE_STRING ImagePath);

ULONG GetImageSize(PVOID ImageBase);
BOOLEAN IsPE64Bit(PVOID ImageBase);

NTKERNELAPI HANDLE PsGetProcessInheritedFromUniqueProcessId(__in PEPROCESS Process);

#ifdef _WIN64
NTKERNELAPI PVOID NTAPI PsGetProcessWow64Process(PEPROCESS Process);
#endif

NTKERNELAPI NTSTATUS NTAPI ZwQueryInformationProcess(
	_In_      HANDLE           ProcessHandle,
	_In_      PROCESSINFOCLASS ProcessInformationClass,
	_Out_     PVOID            ProcessInformation,
	_In_      ULONG            ProcessInformationLength,
	_Out_opt_ PULONG           ReturnLength
);

NTSTATUS NTAPI NewZwQueryVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, MEMORY_INFORMATION_CLASS_EX MemoryInformationClass, PVOID MemoryInformation, SIZE_T MemoryInformationLength, PSIZE_T ReturnLength);

}

LONG FsMessageExceptionFilter(_In_ PEXCEPTION_POINTERS ExceptionPointer, _In_ BOOLEAN AccessingUserBuffer)
{
	NTSTATUS Status = ExceptionPointer->ExceptionRecord->ExceptionCode;

	if (!FsRtlIsNtstatusExpected(Status) && !AccessingUserBuffer) {
		return EXCEPTION_CONTINUE_SEARCH;
	}

	return EXCEPTION_EXECUTE_HANDLER;
}

NTSTATUS CL_Nop(IN PVOID InputBuffer OPTIONAL, IN ULONG InputBufferLength, OUT PVOID OutputBuffer OPTIONAL, IN ULONG OutputBufferLength, OUT PULONG ReturnOutputBufferLength)
{
	*ReturnOutputBufferLength = 0;

	return STATUS_SUCCESS;
}

NTSTATUS CL_SetCaptureEnable(IN PVOID InputBuffer OPTIONAL, IN ULONG InputBufferLength, OUT PVOID OutputBuffer OPTIONAL, IN ULONG OutputBufferLength, OUT PULONG ReturnOutputBufferLength)
{
	NTSTATUS status = STATUS_INVALID_PARAMETER;
	cls_set_capture_enable_data *data = NULL;

	*ReturnOutputBufferLength = 0;

	__try
	{
		if (InputBuffer == NULL || InputBufferLength < sizeof(cls_set_capture_enable_data))
			return status;

		data = (cls_set_capture_enable_data *)InputBuffer;

		ProbeForRead(data, sizeof(cls_set_capture_enable_data), 1);

		if (m_EventList)
		{
			if (data->Enable)
				InterlockedExchange(&m_EventList->m_EnableCapture, 1);
			else
				InterlockedExchange(&m_EventList->m_EnableCapture, 0);
		}

		status = STATUS_SUCCESS;
	}
	__except (FsMessageExceptionFilter(GetExceptionInformation(), TRUE)) {
		status = GetExceptionCode();
	}

	return status;
}

NTSTATUS CL_GetSystemTime(IN PVOID InputBuffer OPTIONAL, IN ULONG InputBufferLength, OUT PVOID OutputBuffer OPTIONAL, IN ULONG OutputBufferLength, OUT PULONG ReturnOutputBufferLength)
{
	NTSTATUS status = STATUS_INVALID_PARAMETER;

	*ReturnOutputBufferLength = 0;

	__try
	{
		if (OutputBuffer == NULL || OutputBufferLength < sizeof(ULONG))
			return status;

		*(ULONG64 *)OutputBuffer = PerfGetSystemTime();
		*ReturnOutputBufferLength = sizeof(ULONG64);
		status = STATUS_SUCCESS;
	}
	__except (FsMessageExceptionFilter(GetExceptionInformation(), TRUE)) {
		status = GetExceptionCode();
	}

	return status;
}

NTSTATUS CL_GetImageBaseInfo(IN PVOID InputBuffer OPTIONAL, IN ULONG InputBufferLength, OUT PVOID OutputBuffer OPTIONAL, IN ULONG OutputBufferLength, OUT PULONG ReturnOutputBufferLength)
{
	NTSTATUS status = STATUS_INVALID_PARAMETER;
	cls_get_image_data *data = NULL;
	cls_get_image_baseinfo_data *out = NULL;
	HANDLE ProcessId = NULL;
	PVOID BaseAddress = NULL;
	PVOID ImageBase = NULL;
	ULONG ImageSize = 0;
	BOOLEAN Is64Bit = FALSE;

	*ReturnOutputBufferLength = 0;

	__try
	{
		if (InputBufferLength < sizeof(cls_get_image_data))
			return status;
		data = (cls_get_image_data *)InputBuffer;
		ProbeForRead(data, sizeof(cls_get_image_data), 1);

		ProcessId = (HANDLE)data->ProcessId;
		BaseAddress = (PVOID)data->BaseAddress;

		if (OutputBuffer == NULL || OutputBufferLength == 0)
			return status;

		ProbeForWrite(OutputBuffer, sizeof(cls_get_image_baseinfo_data), 1);

	}
	__except (FsMessageExceptionFilter(GetExceptionInformation(), TRUE)) {
		return GetExceptionCode();
	}
	
	status = GetImageBaseByAddress(ProcessId, BaseAddress, &ImageBase);
	if (NT_SUCCESS(status))
	{
		PEPROCESS Process = NULL;
		if (NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &Process)))
		{
			KAPC_STATE kApc;
			KeStackAttachProcess(Process, &kApc);
			ImageSize = GetImageSize(ImageBase);
#ifdef _WIN64
			Is64Bit = IsPE64Bit(ImageBase);
#endif
			KeUnstackDetachProcess(&kApc);
			ObDereferenceObject(Process);
		}
		if (ImageSize > 0)
		{
			__try
			{
				out = (cls_get_image_baseinfo_data *)OutputBuffer;
				out->ImageBase = (ULONG64)ImageBase;
				out->ImageSize = ImageSize;
				out->Is64Bit = Is64Bit;
				*ReturnOutputBufferLength = sizeof(cls_get_image_baseinfo_data);
				status = STATUS_SUCCESS;
			}
			__except (FsMessageExceptionFilter(GetExceptionInformation(), TRUE)) {
				status = GetExceptionCode();
			}
		}
	}

	return status;
}

NTSTATUS CL_GetImagePath(IN PVOID InputBuffer OPTIONAL, IN ULONG InputBufferLength, OUT PVOID OutputBuffer OPTIONAL, IN ULONG OutputBufferLength, OUT PULONG ReturnOutputBufferLength)
{
	NTSTATUS status = STATUS_INVALID_PARAMETER;
	cls_get_image_data *data = NULL;
	PVOID NewOutBuffer = NULL;
	UNICODE_STRING ImageName = { 0 };

	*ReturnOutputBufferLength = 0;

	__try
	{
		if (InputBufferLength < sizeof(cls_get_image_data))
			return status;
		data = (cls_get_image_data *)InputBuffer;
		ProbeForRead(data, sizeof(cls_get_image_data), 1);

		if (OutputBuffer == NULL || OutputBufferLength == 0)
			return status;

		NewOutBuffer = ExAllocatePoolWithTag(PagedPool, OutputBufferLength, 'TXSB');
		if (!NewOutBuffer)
			return STATUS_INSUFFICIENT_RESOURCES;
		ImageName.Length = 0;
		ImageName.MaximumLength = OutputBufferLength;
		ImageName.Buffer = (PWCH)NewOutBuffer;
	}
	__except (FsMessageExceptionFilter(GetExceptionInformation(), TRUE)) {
		return GetExceptionCode();
	}

	status = GetImagePathByAddress((HANDLE)data->ProcessId, (PVOID)data->BaseAddress, &ImageName);
	if (NT_SUCCESS(status))
	{
		__try
		{
			memcpy(OutputBuffer, NewOutBuffer, ImageName.Length);//exception?
			*ReturnOutputBufferLength = ImageName.Length;
			status = STATUS_SUCCESS;
		}
		__except (FsMessageExceptionFilter(GetExceptionInformation(), TRUE)) {
			status = GetExceptionCode();
		}
	}

	if (NewOutBuffer)
		ExFreePool(NewOutBuffer);

	return status;
}

NTSTATUS CL_GetProcessPath(IN PVOID InputBuffer OPTIONAL, IN ULONG InputBufferLength, OUT PVOID OutputBuffer OPTIONAL, IN ULONG OutputBufferLength, OUT PULONG ReturnOutputBufferLength)
{
	NTSTATUS status = STATUS_INVALID_PARAMETER;
	cls_pid_data *data = NULL;
	PVOID NewOutBuffer = NULL;
	UNICODE_STRING ProcessName = { 0 };

	*ReturnOutputBufferLength = 0;

	__try
	{
		if (InputBufferLength < sizeof(cls_pid_data))
			return status;
		data = (cls_pid_data *)InputBuffer;
		ProbeForRead(data, sizeof(cls_pid_data), 1);

		if (OutputBuffer == NULL || OutputBufferLength == 0)
			return status;
		NewOutBuffer = ExAllocatePoolWithTag(PagedPool, OutputBufferLength, 'TXSB');
		if (!NewOutBuffer)
			return STATUS_INSUFFICIENT_RESOURCES;
		ProcessName.Length = 0;
		ProcessName.MaximumLength = OutputBufferLength;
		ProcessName.Buffer = (PWCH)NewOutBuffer;
	}
	__except (FsMessageExceptionFilter(GetExceptionInformation(), TRUE)) {
		return GetExceptionCode();
	}

	status = GetProcessPathByPID((HANDLE)data->ProcessId, &ProcessName);
	if (NT_SUCCESS(status))
	{
		__try
		{
			memcpy(OutputBuffer, NewOutBuffer, ProcessName.Length);//exception?
			*ReturnOutputBufferLength = ProcessName.Length;
			status = STATUS_SUCCESS;
		}
		__except (FsMessageExceptionFilter(GetExceptionInformation(), TRUE)) {
			status = GetExceptionCode();
		}
	}

	if (NewOutBuffer)
		ExFreePool(NewOutBuffer);

	return status;
}

NTSTATUS CL_GetProcessCmdLine(IN PVOID InputBuffer OPTIONAL, IN ULONG InputBufferLength, OUT PVOID OutputBuffer OPTIONAL, IN ULONG OutputBufferLength, OUT PULONG ReturnOutputBufferLength)
{
	NTSTATUS status = STATUS_INVALID_PARAMETER;
	cls_pid_data *data = NULL;
	PVOID NewOutBuffer = NULL;
	UNICODE_STRING CommandLine = { 0 };

	*ReturnOutputBufferLength = 0;

	__try
	{
		if (InputBufferLength < sizeof(cls_pid_data))
			return status;
		data = (cls_pid_data *)InputBuffer;
		ProbeForRead(data, sizeof(cls_pid_data), 1);

		if (OutputBuffer == NULL || OutputBufferLength == 0)
			return status;
		NewOutBuffer = ExAllocatePoolWithTag(PagedPool, OutputBufferLength, 'TXSB');
		if (!NewOutBuffer)
			return STATUS_INSUFFICIENT_RESOURCES;
		CommandLine.Length = 0;
		CommandLine.MaximumLength = OutputBufferLength;
		CommandLine.Buffer = (PWCH)NewOutBuffer;
	}
	__except (FsMessageExceptionFilter(GetExceptionInformation(), TRUE)) {
		return GetExceptionCode();
	}

	status = GetCommandLineByPID((HANDLE)data->ProcessId, &CommandLine);
	if (NT_SUCCESS(status))
	{
		__try
		{
			memcpy(OutputBuffer, NewOutBuffer, CommandLine.Length);//exception?
			*ReturnOutputBufferLength = CommandLine.Length;
			status = STATUS_SUCCESS;
		}
		__except (FsMessageExceptionFilter(GetExceptionInformation(), TRUE)) {
			status = GetExceptionCode();
		}
	}

	if (NewOutBuffer)
		ExFreePool(NewOutBuffer);

	return status;
}

NTSTATUS CL_GetProcessCurDir(IN PVOID InputBuffer OPTIONAL, IN ULONG InputBufferLength, OUT PVOID OutputBuffer OPTIONAL, IN ULONG OutputBufferLength, OUT PULONG ReturnOutputBufferLength)
{
	NTSTATUS status = STATUS_INVALID_PARAMETER;
	cls_pid_data *data = NULL;
	PVOID NewOutBuffer = NULL;
	UNICODE_STRING CurDir = { 0 };

	*ReturnOutputBufferLength = 0;

	__try
	{
		if (InputBufferLength < sizeof(cls_pid_data))
			return status;
		data = (cls_pid_data *)InputBuffer;
		ProbeForRead(data, sizeof(cls_pid_data), 1);

		if (OutputBuffer == NULL || OutputBufferLength == 0)
			return status;
		NewOutBuffer = ExAllocatePoolWithTag(PagedPool, OutputBufferLength, 'TXSB');
		if (!NewOutBuffer)
			return STATUS_INSUFFICIENT_RESOURCES;
		CurDir.Length = 0;
		CurDir.MaximumLength = OutputBufferLength;
		CurDir.Buffer = (PWCH)NewOutBuffer;
	}
	__except (FsMessageExceptionFilter(GetExceptionInformation(), TRUE)) {
		return GetExceptionCode();
	}

	status = GetCurDirectoryByPID((HANDLE)data->ProcessId, &CurDir);
	if (NT_SUCCESS(status))
	{
		__try
		{
			memcpy(OutputBuffer, NewOutBuffer, CurDir.Length);//exception?
			*ReturnOutputBufferLength = CurDir.Length;
			status = STATUS_SUCCESS;
		}
		__except (FsMessageExceptionFilter(GetExceptionInformation(), TRUE)) {
			status = GetExceptionCode();
		}
	}

	if (NewOutBuffer)
		ExFreePool(NewOutBuffer);

	return status;
}

NTSTATUS CL_GetProcessBaseInfo(IN PVOID InputBuffer OPTIONAL, IN ULONG InputBufferLength, OUT PVOID OutputBuffer OPTIONAL, IN ULONG OutputBufferLength, OUT PULONG ReturnOutputBufferLength)
{
	NTSTATUS status = STATUS_INVALID_PARAMETER;
	cls_pid_data *data = NULL;
	HANDLE ProcessId = NULL;
	PEPROCESS Process = NULL;

	cls_get_process_baseinfo_data *out = NULL;

	*ReturnOutputBufferLength = 0;

	__try
	{
		if (InputBufferLength < sizeof(cls_pid_data))
			return status;
		data = (cls_pid_data *)InputBuffer;
		ProbeForRead(data, sizeof(cls_pid_data), 1);

		ProcessId = (HANDLE)data->ProcessId;

		if (OutputBuffer == NULL || OutputBufferLength < sizeof(cls_get_process_baseinfo_data))
			return status;

		ProbeForWrite(OutputBuffer, sizeof(cls_get_process_baseinfo_data), 1);
	}
	__except (FsMessageExceptionFilter(GetExceptionInformation(), TRUE)) {
		return GetExceptionCode();
	}

	status = PsLookupProcessByProcessId(ProcessId, &Process);
	if (NT_SUCCESS(status))
	{
		__try
		{
			out = (cls_get_process_baseinfo_data *)OutputBuffer;

			out->ParentProcessId = (ULONG)PsGetProcessInheritedFromUniqueProcessId(Process);
			out->CreateTime = PsGetProcessCreateTimeQuadPart(Process);
			out->SessionId = 0;

			//Get SessionId
			HANDLE ProcessHandle = NULL;
			CLIENT_ID ClientId;
			ClientId.UniqueProcess = ProcessId;
			ClientId.UniqueThread = NULL;
			OBJECT_ATTRIBUTES oa;
			InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, 0, 0);
			if (NT_SUCCESS(ZwOpenProcess(&ProcessHandle, PROCESS_QUERY_INFORMATION, &oa, &ClientId)))
			{
				PROCESS_SESSION_INFORMATION psi;
				if (NT_SUCCESS(ZwQueryInformationProcess(ProcessHandle, ProcessSessionInformation, &psi, sizeof(psi), NULL)))
				{
					out->SessionId = psi.SessionId;
				}
				ZwClose(ProcessHandle);
			}
#ifdef _WIN64
			out->Is64Bit = (PsGetProcessWow64Process(Process) == NULL) ? TRUE : FALSE;
#else
			out->Is64Bit = FALSE;
#endif

			*ReturnOutputBufferLength = sizeof(cls_get_process_baseinfo_data);
			status = STATUS_SUCCESS;
		}
		__except (FsMessageExceptionFilter(GetExceptionInformation(), TRUE)) {
			status = GetExceptionCode();
		}

		ObDereferenceObject(Process);
	}

	return status;
}

FltClientMessage_Parse_t m_ClientMessageProtocols[] = {
	{ cls_nop, CL_Nop },
	{ cls_set_capture_enable, CL_SetCaptureEnable },
	{ cls_get_system_time, CL_GetSystemTime },
	{ cls_get_image_path, CL_GetImagePath },
	{ cls_get_image_baseinfo, CL_GetImageBaseInfo },
	{ cls_get_process_path, CL_GetProcessPath },
	{ cls_get_process_cmdline, CL_GetProcessCmdLine },
	{ cls_get_process_curdir, CL_GetProcessCurDir },
	{ cls_get_process_baseinfo, CL_GetProcessBaseInfo },
};

EXTERN_C{

NTSTATUS FLTAPI FsMessageNotifyCallback(
	IN PVOID PortCookie,
	IN PVOID InputBuffer OPTIONAL,
	IN ULONG InputBufferLength,
	OUT PVOID OutputBuffer OPTIONAL,
	IN ULONG OutputBufferLength,
	OUT PULONG ReturnOutputBufferLength)
{
	PAGED_CODE();

	UNREFERENCED_PARAMETER(PortCookie);

	//打印用户发来的信息
	if (InputBuffer != NULL && InputBufferLength >= 1)
	{
		__try {
			ProbeForRead(InputBuffer, 1, 1);
		}__except (FsMessageExceptionFilter(GetExceptionInformation(), TRUE)) {
			return GetExceptionCode();
		}

		UCHAR ProtocolIdx = *(PUCHAR)InputBuffer;
		if (ProtocolIdx < _ARRAYSIZE(m_ClientMessageProtocols))
		{
			return m_ClientMessageProtocols[ProtocolIdx].fnParse(InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength, ReturnOutputBufferLength);
		}
	}

	return STATUS_SUCCESS;
}

ULONG GetCallStacks(_In_ ULONG MaxCallers, _Out_ PVOID *Callers, _Out_opt_ ULONG *pKernelCallerCount, _Out_opt_ ULONG *pUserCallerCount)
{
	ULONG KernelCallerCount = RtlWalkFrameChain(Callers, MaxCallers, 0);
	ULONG i = 0;
	while (i < KernelCallerCount)
	{
		if ((PUCHAR)Callers[i] >= (PUCHAR)g_ThisModuleBase && (PUCHAR)Callers[i] < (PUCHAR)g_ThisModuleBase + g_ThisModuleSize)
			Callers[i] = 0;
		++i;
	}

	ULONG UserCallerCount = RtlWalkFrameChain(&Callers[KernelCallerCount], MaxCallers - KernelCallerCount, 1);

	if(pKernelCallerCount)
		*pKernelCallerCount = KernelCallerCount;
	if(pUserCallerCount)
		*pUserCallerCount = UserCallerCount;
	return UserCallerCount + KernelCallerCount;
}

BOOLEAN IsFsCallbackIgnored(VOID)
{
	PVOID Callers[64];
	ULONG KernelCallerCount = RtlWalkFrameChain(Callers, 64, 0);
	for (ULONG i = 0; i < KernelCallerCount; ++i)
	{
		if (Callers[i] >= NewZwQueryVirtualMemory && Callers[i] < (PUCHAR)NewZwQueryVirtualMemory + 0x100)
			return FALSE;
	}
	return TRUE;
}

PVOID CreateCallStackEvent(ULONG64 EventId)
{
	ULONG KernelCallerCount, UserCallerCount;
	PVOID Callers[64];
	ULONG CallerCount = GetCallStacks(64, Callers, &KernelCallerCount, &UserCallerCount);

	if (CallerCount)
	{
		ULONG size = sizeof(svc_callstack_data) + sizeof(ULONG64) * CallerCount;
		svc_callstack_data *data = (svc_callstack_data *)ExAllocatePoolWithTag(PagedPool, size, 'TXSB');
		if (data)
		{
			RtlZeroMemory(data, size);
			data->protocol = svc_callstack;
			data->size = size;
			data->eventId = EventId;
			data->time = 0;
			data->KernelCallerCount = KernelCallerCount;
			data->UserCallerCount = UserCallerCount;
			for (ULONG i = 0; i < CallerCount; ++i)
				data->Callers[i] = (ULONG64)Callers[i];

			return data;
		}
	}
	return NULL;
}

}