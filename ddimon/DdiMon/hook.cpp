// Copyright (c) 2015-2016, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

/// @file
/// Implements DdiMon functions.

#include "ddi_mon.h"
#include <ntimage.h>
#define NTSTRSAFE_NO_CB_FUNCTIONS
#include <ntstrsafe.h>
#include "../HyperPlatform/common.h"
#include "../HyperPlatform/log.h"
#include "../HyperPlatform/util.h"
#include "../HyperPlatform/ept.h"
#include "../HyperPlatform/kernel_stl.h"
#include "../HyperPlatform/performance.h"
#include "../HyperPlatform/asm.h"
#include "shadow_hook.h"
#include "main.h"
#include "NativeEnums.h"
#include "NativeStructs.h"
#include "../../Shared/Protocol.h"

extern CProcList *m_IgnoreProcList;
extern CFileList *m_IgnoreFileList;
extern CEventList *m_EventList;
extern HANDLE m_SyscallMonPID;

extern PFLT_FILTER m_pFilterHandle;
extern PFLT_PORT m_pClientPort;

EXTERN_C
{

extern DYNAMIC_DATA dynData;

extern POBJECT_TYPE *PsProcessType;

extern PVOID g_ThisModuleBase;

NTSTATUS GetProcessIdByHandle(__in HANDLE ProcessHandle, __out PHANDLE ProcessId);

HANDLE GetCsrssProcessId(VOID);

PVOID CreateCallStackEvent(ULONG64 EventId);

ULONG_PTR m_CsrssCR3 = NULL;

NTKERNELAPI PCHAR NTAPI PsGetProcessImageFileName(PEPROCESS Process);

volatile LONG m_HookLock;

}

//NtQuerySystemInformation

NTSTATUS NTAPI NewNtQuerySystemInformation(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength);

static ShadowHookTarget m_NtQuerySystemInformationHookTarget =
{
	NewNtQuerySystemInformation,
	nullptr,
};

NTSTATUS NTAPI NewNtQuerySystemInformation(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength)
{
	InterlockedIncrement(&m_HookLock);

	const auto original = (NTSTATUS(NTAPI*)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG))m_NtQuerySystemInformationHookTarget.original_call;
	
	const auto status = original(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);

	svc_nt_query_systeminfo_data *data = NULL;

	if (m_EventList->IsCapturing())
	{
		if (NT_SUCCESS(status) && ExGetPreviousMode() == UserMode)
		{
			//Hide me from user-mode program
#if 0
			__try
			{
				if (SystemInformationClass == SystemProcessInformation){
					PSYSTEM_PROCESS_INFORMATION_EX next = (PSYSTEM_PROCESS_INFORMATION_EX)SystemInformation;
					while (next->NextEntryOffset) {
						PSYSTEM_PROCESS_INFORMATION_EX curr = next;
						next = (PSYSTEM_PROCESS_INFORMATION_EX)((PUCHAR)curr + curr->NextEntryOffset);
						if (next->UniqueProcessId == m_SyscallMonPID) {
							if (next->NextEntryOffset) {
								curr->NextEntryOffset += next->NextEntryOffset;
							} else {
								curr->NextEntryOffset = 0;
							}
							next = curr;
						}
					}
				}
				else if (SystemInformationClass == SystemModuleInformation) {
					PRTL_PROCESS_MODULES mods = (PRTL_PROCESS_MODULES)SystemInformation;
					for (ULONG i = 0; i < mods->NumberOfModules; ++i) {
						if (mods->Modules[i].ImageBase == g_ThisModuleBase)
						{
							memcpy(&mods->Modules[i], &mods->Modules[i + 1], sizeof(RTL_PROCESS_MODULE_INFORMATION) * (mods->NumberOfModules - i - 1));
							--mods->NumberOfModules;
							for (ULONG j = i; j < mods->NumberOfModules; ++j)
								--mods->Modules[i].LoadOrderIndex;

							break;
						}
					}
				}
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
			}
#endif

			ULONG64 EventId = m_EventList->GetEventId();
			if (EventId)
			{
				data = (svc_nt_query_systeminfo_data *)
					ExAllocatePoolWithTag(PagedPool, sizeof(svc_nt_query_systeminfo_data), 'TXSB');
				if (data)
				{
					RtlZeroMemory(data, sizeof(svc_nt_query_systeminfo_data));
					data->protocol = svc_nt_query_systeminfo;
					data->size = sizeof(svc_nt_query_systeminfo_data);
					data->time = PerfGetSystemTime();
					data->eventId = EventId;
					data->ProcessId = (ULONG)PsGetCurrentProcessId();
					data->ThreadId = (ULONG)PsGetCurrentThreadId();
					data->QueryClass = (ULONG)SystemInformationClass;

					m_EventList->Lock();
					m_EventList->SendEvent(data);
					m_EventList->SendEvent(CreateCallStackEvent(EventId));
					m_EventList->Unlock();
					m_EventList->NotifyEvent();
				}
			}
		}
	}

	InterlockedDecrement(&m_HookLock);

	return status;
}

//NtOpenProcess

NTSTATUS NTAPI NewNtOpenProcess(
	_Out_    PHANDLE            ProcessHandle,
	_In_     ACCESS_MASK        DesiredAccess,
	_In_     POBJECT_ATTRIBUTES ObjectAttributes,
	_In_opt_ PCLIENT_ID         ClientId
);

static ShadowHookTarget m_NtOpenProcessHookTarget =
{
	NewNtOpenProcess,
	nullptr,
};

NTSTATUS NTAPI NewNtOpenProcess(
	_Out_    PHANDLE            ProcessHandle,
	_In_     ACCESS_MASK        DesiredAccess,
	_In_     POBJECT_ATTRIBUTES ObjectAttributes,
	_In_opt_ PCLIENT_ID         ClientId
)
{
	InterlockedIncrement(&m_HookLock);

	svc_nt_open_process_data *data = NULL;
	ULONG64 EventId = 0;
	BOOLEAN ValidProcessId = FALSE;
	CLIENT_ID CapturedCid = {0};

	const auto original = (NTSTATUS(NTAPI *)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID))m_NtOpenProcessHookTarget.original_call;

	if (m_EventList->IsCapturing())
	{
		__try
		{
			if (ARGUMENT_PRESENT(ClientId) && ExGetPreviousMode() == UserMode)
			{
				ProbeForRead(ClientId, sizeof(CLIENT_ID), sizeof(ULONG));
				CapturedCid = *ClientId;
				ValidProcessId = TRUE;
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
		}
		if (ValidProcessId)
		{
			EventId = m_EventList->GetEventId();
			if (EventId)
			{
				data = (svc_nt_open_process_data *)
					ExAllocatePoolWithTag(PagedPool, sizeof(svc_nt_open_process_data), 'TXSB');

				if (data)
				{
					RtlZeroMemory(data, sizeof(svc_nt_open_process_data));
					data->protocol = svc_nt_open_process;
					data->size = sizeof(svc_nt_open_process_data);
					data->time = PerfGetSystemTime();
					data->eventId = EventId;
					data->ProcessId = (ULONG)PsGetCurrentProcessId();
					data->ThreadId = (ULONG)PsGetCurrentThreadId();
					data->TargetProcessId = (ULONG)CapturedCid.UniqueProcess;
					data->DesiredAccess = (ULONG)DesiredAccess;
				}
			}
		}
	}

	NTSTATUS status = STATUS_SUCCESS;
	
	if (ValidProcessId)
	{
		PEPROCESS ProcessObj = NULL;
		if (NT_SUCCESS(PsLookupProcessByProcessId(CapturedCid.UniqueProcess, &ProcessObj))) 
		{
			if (!_stricmp(PsGetProcessImageFileName(ProcessObj), "Xubei.exe")) {
				PEPROCESS CurrentProcessObj = NULL;
				if (NT_SUCCESS(PsLookupProcessByProcessId(PsGetCurrentProcessId(), &CurrentProcessObj)))
				{
					if (!_stricmp(PsGetProcessImageFileName(CurrentProcessObj), "crossfire.exe"))
						status = STATUS_ACCESS_DENIED;

					ObfDereferenceObject(CurrentProcessObj);
				}
			}
			ObfDereferenceObject(ProcessObj);
		}
	}

	if(status == STATUS_SUCCESS)
		status = original(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);

	if (data) {
		data->ResultStatus = (ULONG)status;

		m_EventList->Lock();
		m_EventList->SendEvent(data);
		m_EventList->SendEvent(CreateCallStackEvent(EventId));
		m_EventList->Unlock();
		m_EventList->NotifyEvent();
	}

	InterlockedDecrement(&m_HookLock);

	return status;
}

//NtOpenThread

NTSTATUS NTAPI NewNtOpenThread(
	__out PHANDLE ThreadHandle,
	__in ACCESS_MASK DesiredAccess,
	__in POBJECT_ATTRIBUTES ObjectAttributes,
	__in_opt PCLIENT_ID ClientId
);

static ShadowHookTarget m_NtOpenThreadHookTarget =
{
	NewNtOpenThread,
	nullptr,
};

NTSTATUS NTAPI NewNtOpenThread(
	__out PHANDLE ThreadHandle,
	__in ACCESS_MASK DesiredAccess,
	__in POBJECT_ATTRIBUTES ObjectAttributes,
	__in_opt PCLIENT_ID ClientId
)
{
	InterlockedIncrement(&m_HookLock);

	BOOLEAN ValidThreadId = FALSE;
	CLIENT_ID CapturedCid = { 0 };

	const auto original = (NTSTATUS(NTAPI *)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID))m_NtOpenThreadHookTarget.original_call;

	NTSTATUS status = original(ThreadHandle, DesiredAccess, ObjectAttributes, ClientId);

	if (m_EventList->IsCapturing())
	{
		__try
		{
			if (ARGUMENT_PRESENT(ClientId) && ExGetPreviousMode() == UserMode)
			{
				ProbeForRead(ClientId, sizeof(CLIENT_ID), sizeof(ULONG));
				CapturedCid = *ClientId;
				ValidThreadId = TRUE;

				PETHREAD Thread = NULL;
				if (NT_SUCCESS(PsLookupThreadByThreadId(CapturedCid.UniqueThread, &Thread)))
				{
					CapturedCid.UniqueProcess = PsGetThreadProcessId(Thread);
					ObDereferenceObject(Thread);
				}
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
		}
		if (ValidThreadId)
		{
			ULONG64 EventId = m_EventList->GetEventId();
			if (EventId)
			{
				svc_nt_open_thread_data *data = (svc_nt_open_thread_data *)
					ExAllocatePoolWithTag(PagedPool, sizeof(svc_nt_open_thread_data), 'TXSB');

				if (data)
				{
					RtlZeroMemory(data, sizeof(svc_nt_open_thread_data));
					data->protocol = svc_nt_open_thread;
					data->size = sizeof(svc_nt_open_thread_data);
					data->time = PerfGetSystemTime();
					data->eventId = EventId;
					data->ProcessId = (ULONG)PsGetCurrentProcessId();
					data->ThreadId = (ULONG)PsGetCurrentThreadId();
					data->TargetProcessId = (ULONG)CapturedCid.UniqueProcess;
					data->TargetThreadId = (ULONG)CapturedCid.UniqueThread;
					data->DesiredAccess = (ULONG)DesiredAccess;
					data->ResultStatus = (ULONG)status;

					m_EventList->Lock();
					m_EventList->SendEvent(data);
					m_EventList->SendEvent(CreateCallStackEvent(EventId));
					m_EventList->Unlock();
					m_EventList->NotifyEvent();
				}
			}
		}
	}

	InterlockedDecrement(&m_HookLock);

	return status;
}

//NtTerminateProcess

NTSTATUS NTAPI NewNtTerminateProcess(
	_In_opt_ HANDLE ProcessHandle,
	_In_ NTSTATUS ExitStatus
);

static ShadowHookTarget m_NtTerminateProcessHookTarget =
{
	NewNtTerminateProcess,
	nullptr,
};

NTSTATUS NTAPI NewNtTerminateProcess(
	_In_opt_ HANDLE ProcessHandle,
	_In_ NTSTATUS ExitStatus
)
{
	InterlockedIncrement(&m_HookLock);

	ULONG64 EventId = 0;
	HANDLE ProcessId = NULL;
	BOOLEAN bValid = FALSE;

	if (ARGUMENT_PRESENT(ProcessHandle) && !ObIsKernelHandle(ProcessHandle) && ExGetPreviousMode() == UserMode)
	{
		if (NT_SUCCESS(GetProcessIdByHandle(ProcessHandle, &ProcessId)) && PsGetCurrentProcessId() != ProcessId)
		{
			bValid = TRUE;
		}
	}

	const auto original = (NTSTATUS(NTAPI *)(HANDLE, NTSTATUS))m_NtTerminateProcessHookTarget.original_call;
	
	svc_nt_terminate_process_data *data = NULL;

	if (bValid && m_EventList->IsCapturing())
	{
		EventId = m_EventList->GetEventId();
		if (EventId)
		{
			data = (svc_nt_terminate_process_data *)
				ExAllocatePoolWithTag(PagedPool, sizeof(svc_nt_terminate_process_data), 'TXSB');

			if (data)
			{
				RtlZeroMemory(data, sizeof(svc_nt_terminate_process_data));
				data->protocol = svc_nt_terminate_process;
				data->size = sizeof(svc_nt_terminate_process_data);
				data->time = PerfGetSystemTime();
				data->eventId = EventId;
				data->ProcessId = (ULONG)PsGetCurrentProcessId();
				data->ThreadId = (ULONG)PsGetCurrentThreadId();
				data->TargetProcessId = (ULONG)ProcessId;
				data->ResultStatus = (ULONG)STATUS_SUCCESS;
			}
		}
	}

	NTSTATUS status;
	//if (bValid && ProcessId == m_SyscallMonPID)
	//	status = STATUS_ACCESS_DENIED;
	//else
		status = original(ProcessHandle, ExitStatus);

	if (data)
	{
		data->ResultStatus = (ULONG)status;

		m_EventList->Lock();
		m_EventList->SendEvent(data);
		m_EventList->SendEvent(CreateCallStackEvent(EventId));
		m_EventList->Unlock();
		m_EventList->NotifyEvent();
	}

	InterlockedDecrement(&m_HookLock);

	return status;
}

//NtAllocateVirtualMemory

NTSTATUS NTAPI NewNtAllocateVirtualMemory(
	_In_ HANDLE ProcessHandle,
	_Inout_ PVOID *BaseAddress,
	_In_ ULONG_PTR ZeroBits,
	_Inout_ PSIZE_T RegionSize,
	_In_ ULONG AllocationType,
	_In_ ULONG Protect
);

static ShadowHookTarget m_NtAllocateVirtualMemoryHookTarget =
{
	NewNtAllocateVirtualMemory,
	nullptr,
};

NTSTATUS NTAPI NewNtAllocateVirtualMemory(
	_In_ HANDLE ProcessHandle,
	_Inout_ PVOID *BaseAddress,
	_In_ ULONG_PTR ZeroBits,
	_Inout_ PSIZE_T RegionSize,
	_In_ ULONG AllocationType,
	_In_ ULONG Protect
)
{
	InterlockedIncrement(&m_HookLock);

	PVOID OldBaseAddress = NULL;
	PVOID NewBaseAddress = NULL;
	SIZE_T OldRegionSize = 0;
	SIZE_T NewRegionSize = 0;
	HANDLE ProcessId = NULL;
	BOOLEAN bValid = FALSE;
	
	KPROCESSOR_MODE mode = ExGetPreviousMode();

	if (ARGUMENT_PRESENT(ProcessHandle) && !ObIsKernelHandle(ProcessHandle) && mode == UserMode)
	{
		if (NT_SUCCESS(GetProcessIdByHandle(ProcessHandle, &ProcessId)) && ProcessId != PsGetCurrentProcessId())
		{
			bValid = TRUE;
		}
	}

	if (bValid)
	{
		__try
		{
			ProbeForWrite(BaseAddress, sizeof(PVOID), sizeof(ULONG));
			ProbeForWrite(RegionSize, sizeof(SIZE_T), sizeof(ULONG));

			OldBaseAddress = *BaseAddress;
			OldRegionSize = *RegionSize;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
		}
	}

	const auto original = (NTSTATUS(NTAPI *)(HANDLE, PVOID *, ULONG_PTR, PSIZE_T, ULONG, ULONG))m_NtAllocateVirtualMemoryHookTarget.original_call;

	NTSTATUS status;
	//if (bValid && ProcessId == m_SyscallMonPID && PsGetCurrentProcessId() != ProcessId)
	//	status = STATUS_ACCESS_DENIED;
	//else
		status = original(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);

	if (bValid)
	{
		__try
		{
			ProbeForWrite(BaseAddress, sizeof(PVOID), sizeof(ULONG));
			ProbeForWrite(RegionSize, sizeof(SIZE_T), sizeof(ULONG));

			NewBaseAddress = *BaseAddress;
			NewRegionSize = *RegionSize;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
		}
	}

	svc_nt_alloc_virtual_mem_data *data = NULL;

	if (bValid && m_EventList->IsCapturing())
	{
		PEPROCESS Process = NULL;
		if (NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &Process)))
		{
			ULONG64 EventId = m_EventList->GetEventId();
			if (EventId)
			{
				data = (svc_nt_alloc_virtual_mem_data *)
					ExAllocatePoolWithTag(PagedPool, sizeof(svc_nt_alloc_virtual_mem_data), 'TXSB');

				if (data)
				{
					RtlZeroMemory(data, sizeof(svc_nt_alloc_virtual_mem_data));
					data->protocol = svc_nt_alloc_virtual_mem;
					data->size = sizeof(svc_nt_alloc_virtual_mem_data);
					data->time = PerfGetSystemTime();
					data->eventId = EventId;
					data->ProcessId = (ULONG)PsGetCurrentProcessId();
					data->ThreadId = (ULONG)PsGetCurrentThreadId();
					data->TargetProcessId = (ULONG)ProcessId;
					data->OldBaseAddress = (ULONG64)OldBaseAddress;
					data->OldRegionSize = (ULONG64)OldRegionSize;
					data->NewBaseAddress = (ULONG64)NewBaseAddress;
					data->NewRegionSize = (ULONG64)NewRegionSize;
					data->AllocationType = AllocationType;
					data->Protect = Protect;
					data->ResultStatus = (ULONG)status;

					m_EventList->Lock();
					m_EventList->SendEvent(data);
					m_EventList->SendEvent(CreateCallStackEvent(EventId));
					m_EventList->Unlock();
					m_EventList->NotifyEvent();
				}
			}
			ObDereferenceObject(Process);
		}
	}

	InterlockedDecrement(&m_HookLock);

	return status;
}

//NtReadVirtualMemory

NTSTATUS NTAPI NewNtReadVirtualMemory(
	__in HANDLE ProcessHandle,
	__in_opt PVOID BaseAddress,
	__out_bcount(BufferSize) PVOID Buffer,
	__in SIZE_T BufferSize,
	__out_opt PSIZE_T NumberOfBytesRead
);

static ShadowHookTarget m_NtReadVirtualMemoryHookTarget =
{
	NewNtReadVirtualMemory,
	nullptr,
};

NTSTATUS NTAPI NewNtReadVirtualMemory(
	__in HANDLE ProcessHandle,
	__in_opt PVOID BaseAddress,
	__out_bcount(BufferSize) PVOID Buffer,
	__in SIZE_T BufferSize,
	__out_opt PSIZE_T NumberOfBytesRead
)
{
	InterlockedIncrement(&m_HookLock);

	const auto original = (NTSTATUS(NTAPI *)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T))m_NtReadVirtualMemoryHookTarget.original_call;

	NTSTATUS status = original(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesRead);
	
	svc_nt_readwrite_virtual_mem_data *data = NULL;

	if (m_EventList->IsCapturing())
	{
		if (ARGUMENT_PRESENT(ProcessHandle) && !ObIsKernelHandle(ProcessHandle) && ExGetPreviousMode() == UserMode)
		{
			HANDLE ProcessId = NULL;
			if (NT_SUCCESS(GetProcessIdByHandle(ProcessHandle, &ProcessId)) && ProcessId != PsGetCurrentProcessId())
			{
				PEPROCESS Process = NULL;
				if (NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &Process)))
				{
					ULONG64 EventId = m_EventList->GetEventId();
					if (EventId)
					{
						data = (svc_nt_readwrite_virtual_mem_data *)
							ExAllocatePoolWithTag(PagedPool, sizeof(svc_nt_readwrite_virtual_mem_data), 'TXSB');

						if (data)
						{
							RtlZeroMemory(data, sizeof(svc_nt_readwrite_virtual_mem_data));
							data->protocol = svc_nt_readwrite_virtual_mem;
							data->size = sizeof(svc_nt_readwrite_virtual_mem_data);
							data->time = PerfGetSystemTime();
							data->eventId = EventId;
							data->ProcessId = (ULONG)PsGetCurrentProcessId();
							data->ThreadId = (ULONG)PsGetCurrentThreadId();
							data->TargetProcessId = (ULONG)ProcessId;
							data->BaseAddress = (ULONG64)BaseAddress;
							data->BufferSize = (ULONG64)BufferSize;
							data->ResultStatus = (ULONG)status;

							m_EventList->Lock();
							m_EventList->SendEvent(data);
							m_EventList->SendEvent(CreateCallStackEvent(EventId));
							m_EventList->Unlock();
							m_EventList->NotifyEvent();
						}
					}
					ObDereferenceObject(Process);
				}				
			}
		}
	}

	InterlockedDecrement(&m_HookLock);

	return status;
}

//NtWriteVirtualMemory

NTSTATUS NTAPI NewNtWriteVirtualMemory(
	__in HANDLE ProcessHandle,
	__in_opt PVOID BaseAddress,
	__out_bcount(BufferSize) PVOID Buffer,
	__in SIZE_T BufferSize,
	__out_opt PSIZE_T NumberOfBytesRead
);

static ShadowHookTarget m_NtWriteVirtualMemoryHookTarget =
{
	NewNtWriteVirtualMemory,
	nullptr,
};

NTSTATUS NTAPI NewNtWriteVirtualMemory(
	__in HANDLE ProcessHandle,
	__in_opt PVOID BaseAddress,
	__in_bcount(BufferSize) PVOID Buffer,
	__in SIZE_T BufferSize,
	__out_opt PSIZE_T NumberOfBytesWritten
)
{
	InterlockedIncrement(&m_HookLock);

	HANDLE ProcessId = NULL;
	BOOLEAN bValid = FALSE;

	KPROCESSOR_MODE mode = ExGetPreviousMode();

	if (ARGUMENT_PRESENT(ProcessHandle) && !ObIsKernelHandle(ProcessHandle) && mode == UserMode)
	{
		if (NT_SUCCESS(GetProcessIdByHandle(ProcessHandle, &ProcessId)) && ProcessId != PsGetCurrentProcessId())
		{
			bValid = TRUE;
		}
	}

	const auto original = (NTSTATUS(NTAPI *)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T))m_NtWriteVirtualMemoryHookTarget.original_call;

	NTSTATUS status;
	
	//if (bValid && ProcessId == m_SyscallMonPID && PsGetCurrentProcessId() != ProcessId)
	//	status = STATUS_ACCESS_DENIED;
	//else
		status = original(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesWritten);

	svc_nt_readwrite_virtual_mem_data *data = NULL;

	if (bValid && m_EventList->IsCapturing())
	{
		PEPROCESS Process = NULL;
		if (NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &Process)))
		{
			ULONG64 EventId = m_EventList->GetEventId();
			if (EventId)
			{
				data = (svc_nt_readwrite_virtual_mem_data *)
					ExAllocatePoolWithTag(PagedPool, sizeof(svc_nt_readwrite_virtual_mem_data), 'TXSB');

				if (data)
				{
					RtlZeroMemory(data, sizeof(svc_nt_readwrite_virtual_mem_data));
					data->protocol = svc_nt_readwrite_virtual_mem;
					data->size = sizeof(svc_nt_readwrite_virtual_mem_data);
					data->time = PerfGetSystemTime();
					data->eventId = EventId;
					data->ProcessId = (ULONG)PsGetCurrentProcessId();
					data->ThreadId = (ULONG)PsGetCurrentThreadId();
					data->TargetProcessId = (ULONG)ProcessId;
					data->BaseAddress = (ULONG64)BaseAddress;
					data->BufferSize = (ULONG64)BufferSize;
					data->ResultStatus = (ULONG)status;

					m_EventList->Lock();
					m_EventList->SendEvent(data);
					m_EventList->SendEvent(CreateCallStackEvent(EventId));
					m_EventList->Unlock();
					m_EventList->NotifyEvent();
				}
			}
			ObDereferenceObject(Process);
		}
	}

	InterlockedDecrement(&m_HookLock);

	return status;
}

//NtProtectVirtualMemory

NTSTATUS NTAPI NewNtProtectVirtualMemory(
	__in HANDLE ProcessHandle,
	__inout PVOID *BaseAddress,
	__inout PSIZE_T RegionSize,
	__in ULONG NewProtect,
	__out PULONG OldProtect
);

static ShadowHookTarget m_NtProtectVirtualMemoryHookTarget =
{
	NewNtProtectVirtualMemory,
	nullptr,
};

NTSTATUS NTAPI NewNtProtectVirtualMemory(
	__in HANDLE ProcessHandle,
	__inout PVOID *BaseAddress,
	__inout PSIZE_T RegionSize,
	__in ULONG NewProtect,
	__out PULONG OldProtect
)
{
	InterlockedIncrement(&m_HookLock);

	PVOID OldBaseAddress = NULL;
	PVOID NewBaseAddress = NULL;
	SIZE_T OldRegionSize = 0;
	SIZE_T NewRegionSize = 0;
	ULONG MyOldProtect = 0;
	HANDLE ProcessId = NULL;
	BOOLEAN bValid = FALSE;

	KPROCESSOR_MODE mode = ExGetPreviousMode();

	if (ARGUMENT_PRESENT(ProcessHandle) && !ObIsKernelHandle(ProcessHandle) && mode == UserMode)
	{
		if (NT_SUCCESS(GetProcessIdByHandle(ProcessHandle, &ProcessId)) && ProcessId != PsGetCurrentProcessId())
		{
			bValid = TRUE;
		}
	}

	if (bValid)
	{
		__try
		{
			ProbeForWrite(BaseAddress, sizeof(PVOID), sizeof(ULONG));
			ProbeForWrite(RegionSize, sizeof(SIZE_T), sizeof(ULONG));

			OldBaseAddress = *BaseAddress;
			OldRegionSize = *RegionSize;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
		}
	}

	const auto original = (NTSTATUS(NTAPI *)(HANDLE, PVOID *, PSIZE_T, ULONG, PULONG))m_NtProtectVirtualMemoryHookTarget.original_call;

	NTSTATUS status;
	
	//if (bValid && ProcessId == m_SyscallMonPID && PsGetCurrentProcessId() != ProcessId)
	//	status = STATUS_ACCESS_DENIED;
	//else
		status = original(ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect);

	if (bValid)
	{
		__try
		{
			ProbeForWrite(BaseAddress, sizeof(PVOID), sizeof(ULONG));
			ProbeForWrite(RegionSize, sizeof(SIZE_T), sizeof(ULONG));

			NewBaseAddress = *BaseAddress;
			NewRegionSize = *RegionSize;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
		}

		__try
		{
			ProbeForWrite(OldProtect, sizeof(ULONG), sizeof(ULONG));
			MyOldProtect = *OldProtect;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
		}
	}

	svc_nt_protect_virtual_mem_data *data = NULL;

	if (bValid && m_EventList->IsCapturing())
	{
		PEPROCESS Process = NULL;
		if (NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &Process)))
		{
			ULONG64 EventId = m_EventList->GetEventId();
			if (EventId)
			{
				data = (svc_nt_protect_virtual_mem_data *)
					ExAllocatePoolWithTag(PagedPool, sizeof(svc_nt_protect_virtual_mem_data), 'TXSB');

				if (data)
				{
					RtlZeroMemory(data, sizeof(svc_nt_protect_virtual_mem_data));
					data->protocol = svc_nt_protect_virtual_mem;
					data->size = sizeof(svc_nt_protect_virtual_mem_data);
					data->time = PerfGetSystemTime();
					data->eventId = EventId;
					data->ProcessId = (ULONG)PsGetCurrentProcessId();
					data->ThreadId = (ULONG)PsGetCurrentThreadId();
					data->TargetProcessId = (ULONG)ProcessId;
					data->OldBaseAddress = (ULONG64)OldBaseAddress;
					data->OldRegionSize = (ULONG64)OldRegionSize;
					data->NewBaseAddress = (ULONG64)NewBaseAddress;
					data->NewRegionSize = (ULONG64)NewRegionSize;
					data->OldProtect = MyOldProtect;
					data->NewProtect = NewProtect;
					data->ResultStatus = (ULONG)status;

					m_EventList->Lock();
					m_EventList->SendEvent(data);
					m_EventList->SendEvent(CreateCallStackEvent(EventId));
					m_EventList->Unlock();
					m_EventList->NotifyEvent();
				}
			}
			ObDereferenceObject(Process);
		}
	}

	InterlockedDecrement(&m_HookLock);

	return status;
}

//NtQueryVirtualMemory

NTSTATUS
NewNtQueryVirtualMemory(
	__in HANDLE ProcessHandle,
	__in PVOID BaseAddress,
	__in MEMORY_INFORMATION_CLASS_EX MemoryInformationClass,
	__out_bcount(MemoryInformationLength) PVOID MemoryInformation,
	__in SIZE_T MemoryInformationLength,
	__out_opt PSIZE_T ReturnLength
);

static ShadowHookTarget m_NtQueryVirtualMemoryHookTarget =
{
	NewNtQueryVirtualMemory,
	nullptr,
};

NTSTATUS
NewNtQueryVirtualMemory(
	__in HANDLE ProcessHandle,
	__in PVOID BaseAddress,
	__in MEMORY_INFORMATION_CLASS_EX MemoryInformationClass,
	__out_bcount(MemoryInformationLength) PVOID MemoryInformation,
	__in SIZE_T MemoryInformationLength,
	__out_opt PSIZE_T ReturnLength
)
{
	InterlockedIncrement(&m_HookLock);

	const auto original = (NTSTATUS(NTAPI *)(HANDLE, PVOID, MEMORY_INFORMATION_CLASS_EX, PVOID, SIZE_T, PSIZE_T))m_NtQueryVirtualMemoryHookTarget.original_call;

	NTSTATUS status = original(ProcessHandle, BaseAddress, MemoryInformationClass, MemoryInformation, MemoryInformationLength, ReturnLength);

	svc_nt_query_virtual_mem_data *data = NULL;

	if (m_EventList->IsCapturing())
	{
		if (NT_SUCCESS(status) && ARGUMENT_PRESENT(ProcessHandle) && !ObIsKernelHandle(ProcessHandle) && ExGetPreviousMode() == UserMode)
		{
			HANDLE ProcessId = NULL;
			if (NT_SUCCESS(GetProcessIdByHandle(ProcessHandle, &ProcessId)) && ProcessId != PsGetCurrentProcessId())
			{
				PEPROCESS Process = NULL;
				if (NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &Process)))
				{
					ULONG64 EventId = m_EventList->GetEventId();
					if (EventId)
					{
						data = (svc_nt_query_virtual_mem_data *)
							ExAllocatePoolWithTag(PagedPool, sizeof(svc_nt_query_virtual_mem_data), 'TXSB');

						if (data)
						{
							RtlZeroMemory(data, sizeof(svc_nt_query_virtual_mem_data));
							data->protocol = svc_nt_query_virtual_mem;
							data->size = sizeof(svc_nt_query_virtual_mem_data);
							data->time = PerfGetSystemTime();
							data->eventId = EventId;
							data->ProcessId = (ULONG)PsGetCurrentProcessId();
							data->ThreadId = (ULONG)PsGetCurrentThreadId();
							data->TargetProcessId = (ULONG)ProcessId;
							data->BaseAddress = (ULONG64)BaseAddress;
							data->QueryClass = (ULONG)MemoryInformationClass;
							__try
							{
								if (MemoryInformationClass == MemoryBasicInformationEx)
								{
									PMEMORY_BASIC_INFORMATION pmbi = (PMEMORY_BASIC_INFORMATION)MemoryInformation;
									data->mbi.AllocationBase = (ULONG64)pmbi->AllocationBase;
									data->mbi.BaseAddress = (ULONG64)pmbi->BaseAddress;
									data->mbi.RegionSize = (ULONG64)pmbi->RegionSize;
									data->mbi.AllocationProtect = pmbi->AllocationProtect;
									data->mbi.Protect = pmbi->Protect;
									data->mbi.State = pmbi->State;
									data->mbi.Type = pmbi->Type;
								}
								else if (MemoryInformationClass == MemoryMappedFilenameInformation)
								{
									PMEMORY_SECTION_NAME pSectionName = (PMEMORY_SECTION_NAME)MemoryInformation;
									UNICODE_STRING ustrSectionName;
									RtlInitEmptyUnicodeString(&ustrSectionName, data->MappedFileName, sizeof(data->MappedFileName) - sizeof(WCHAR));
									RtlCopyUnicodeString(&ustrSectionName, &pSectionName->SectionFileName);
								}
							}
							__except (EXCEPTION_EXECUTE_HANDLER) {
							}
							data->ResultStatus = (ULONG)status;

							m_EventList->Lock();
							m_EventList->SendEvent(data);
							m_EventList->SendEvent(CreateCallStackEvent(EventId));
							m_EventList->Unlock();
							m_EventList->NotifyEvent();
						}
					}
					ObDereferenceObject(Process);
				}
			}
		}
	}

	InterlockedDecrement(&m_HookLock);

	return status;
}

//NtLoadDriver

NTSTATUS NTAPI NewNtLoadDriver(PUNICODE_STRING RegisterPath);

static ShadowHookTarget m_NtLoadDriverHookTarget =
{
	NewNtLoadDriver,
	nullptr,
};

NTSTATUS NTAPI NewNtLoadDriver(PUNICODE_STRING DriverServiceName)
{
	InterlockedIncrement(&m_HookLock);

	const auto original = (NTSTATUS(NTAPI*)(PUNICODE_STRING))m_NtLoadDriverHookTarget.original_call;

	svc_nt_load_driver_data *data = NULL;
	ULONG64 EventId = 0;

	if (m_EventList->IsCapturing())
	{
		__try
		{
			UNICODE_STRING NewServiceName;
			ProbeForRead(DriverServiceName, sizeof(UNICODE_STRING), sizeof(ULONG));
			ProbeForRead(DriverServiceName->Buffer, DriverServiceName->Length, sizeof(WCHAR));

			EventId = m_EventList->GetEventId();
			if (EventId)
			{
				data = (svc_nt_load_driver_data *)
					ExAllocatePoolWithTag(PagedPool, sizeof(svc_nt_load_driver_data), 'TXSB');
				if (data)
				{
					RtlZeroMemory(data, sizeof(svc_nt_load_driver_data));
					data->protocol = svc_nt_load_driver;
					data->size = sizeof(svc_nt_load_driver_data);
					data->time = PerfGetSystemTime();
					data->eventId = EventId;
					data->ProcessId = (ULONG)PsGetCurrentProcessId();
					data->ThreadId = (ULONG)PsGetCurrentThreadId();
					data->ResultStatus = STATUS_SUCCESS;
					RtlInitEmptyUnicodeString(&NewServiceName, data->RegisterPath, sizeof(data->RegisterPath) - sizeof(WCHAR));
					RtlCopyUnicodeString(&NewServiceName, DriverServiceName);

					//Read ImagePath...
					HANDLE keyHandle = NULL;
					OBJECT_ATTRIBUTES oa;
					InitializeObjectAttributes(&oa, &NewServiceName,
						OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
						0, 0);
					if (NT_SUCCESS(ZwOpenKey(&keyHandle, KEY_READ, &oa)))
					{
						KEY_VALUE_PARTIAL_INFORMATION info = { 0 };
						ULONG ulValueSize = 0;
						UNICODE_STRING valueName;
						RtlInitUnicodeString(&valueName, L"ImagePath");
						if (ZwQueryValueKey(keyHandle, &valueName, KeyValuePartialInformation, &info, sizeof(info), &ulValueSize) && ulValueSize > 0 && (info.Type == REG_SZ || info.Type == REG_EXPAND_SZ))
						{
							PKEY_VALUE_PARTIAL_INFORMATION infoBuffer = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, ulValueSize, 'TXSB');
							if (infoBuffer != NULL)
							{
								if (NT_SUCCESS(ZwQueryValueKey(keyHandle, &valueName, KeyValuePartialInformation,
									infoBuffer, ulValueSize, &ulValueSize)))
								{
									UNICODE_STRING ustrSrcValue, ustrDstValue;
									ustrSrcValue.Buffer = (PWCH)infoBuffer->Data;
									ustrSrcValue.Length = ulValueSize;
									ustrSrcValue.MaximumLength = ulValueSize;
									RtlInitEmptyUnicodeString(&ustrDstValue, data->ImagePath, sizeof(data->ImagePath) - sizeof(WCHAR));
									RtlCopyUnicodeString(&ustrDstValue, &ustrSrcValue);
								}
								ExFreePoolWithTag(infoBuffer, 'TXSB');
							}
						}

						ZwClose(keyHandle);
					}//ZwOpenKey
				}//data
			}//eventid
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			if (data != NULL)
			{
				ExFreePoolWithTag(data, 'TXSB');
				data = NULL;
			}
		}
	}
	//const auto status = STATUS_ACCESS_DENIED;
	const auto status = original(DriverServiceName);

	if (data)
	{
		data->ResultStatus = status;

		m_EventList->Lock();
		m_EventList->SendEvent(data);
		m_EventList->SendEvent(CreateCallStackEvent(EventId));
		m_EventList->Unlock();
		m_EventList->NotifyEvent();
	}

	InterlockedDecrement(&m_HookLock);

	return status;
}

//NtCreateMutant

NTSTATUS NTAPI NewNtCreateMutant(
	__out PHANDLE MutantHandle,
	__in ACCESS_MASK DesiredAccess,
	__in_opt POBJECT_ATTRIBUTES ObjectAttributes,
	__in BOOLEAN InitialOwner
);

static ShadowHookTarget m_NtCreateMutantHookTarget =
{
	NewNtCreateMutant,
	nullptr,
};

NTSTATUS NTAPI NewNtCreateMutant(
	__out PHANDLE MutantHandle,
	__in ACCESS_MASK DesiredAccess,
	__in_opt POBJECT_ATTRIBUTES ObjectAttributes,
	__in BOOLEAN InitialOwner
)
{
	InterlockedIncrement(&m_HookLock);

	const auto original = (NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, BOOLEAN))
		m_NtCreateMutantHookTarget.original_call;

	const auto status = original(MutantHandle, DesiredAccess, ObjectAttributes, InitialOwner);

	svc_nt_createopen_mutant_data *data = NULL;
	ULONG64 EventId = 0;

	if (m_EventList->IsCapturing())
	{
		__try
		{
			if (ObjectAttributes && ObjectAttributes->ObjectName)
			{
				UNICODE_STRING ObjectName;
				ProbeForRead(ObjectAttributes->ObjectName, sizeof(UNICODE_STRING), sizeof(ULONG));
				ProbeForRead(ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length, sizeof(WCHAR));

				EventId = m_EventList->GetEventId();
				if (EventId)
				{
					data = (svc_nt_createopen_mutant_data *)
						ExAllocatePoolWithTag(PagedPool, sizeof(svc_nt_createopen_mutant_data), 'TXSB');
					if (data)
					{
						RtlZeroMemory(data, sizeof(svc_nt_createopen_mutant_data));
						data->protocol = svc_nt_createopen_mutant;
						data->size = sizeof(svc_nt_createopen_mutant_data);
						data->time = PerfGetSystemTime();
						data->eventId = EventId;
						data->ProcessId = (ULONG)PsGetCurrentProcessId();
						data->ThreadId = (ULONG)PsGetCurrentThreadId();
						data->ResultStatus = status;
						data->IsOpen = FALSE;
						data->InitialOwner = InitialOwner;
						data->DesiredAccess = (ULONG)DesiredAccess;
						RtlInitEmptyUnicodeString(&ObjectName, data->MutexName, sizeof(data->MutexName) - sizeof(WCHAR));
						RtlCopyUnicodeString(&ObjectName, ObjectAttributes->ObjectName);
					}//data
				}//eventid
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			if (data != NULL)
			{
				ExFreePoolWithTag(data, 'TXSB');
				data = NULL;
			}
		}
	}

	if (data)
	{
		m_EventList->Lock();
		m_EventList->SendEvent(data);
		m_EventList->SendEvent(CreateCallStackEvent(EventId));
		m_EventList->Unlock();
		m_EventList->NotifyEvent();
	}

	InterlockedDecrement(&m_HookLock);

	return status;
}

//NtOpenMutant

NTSTATUS NTAPI NewNtOpenMutant(
	__out PHANDLE MutantHandle,
	__in ACCESS_MASK DesiredAccess,
	__in POBJECT_ATTRIBUTES ObjectAttributes
);

static ShadowHookTarget m_NtOpenMutantHookTarget =
{
	NewNtOpenMutant,
	nullptr,
};

NTSTATUS NTAPI NewNtOpenMutant(
	__out PHANDLE MutantHandle,
	__in ACCESS_MASK DesiredAccess,
	__in POBJECT_ATTRIBUTES ObjectAttributes
)
{
	InterlockedIncrement(&m_HookLock);

	const auto original = (NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES))
		m_NtOpenMutantHookTarget.original_call;

	const auto status = original(MutantHandle, DesiredAccess, ObjectAttributes);

	svc_nt_createopen_mutant_data *data = NULL;
	ULONG64 EventId = 0;

	if (m_EventList->IsCapturing())
	{
		__try
		{
			if (ObjectAttributes && ObjectAttributes->ObjectName)
			{
				UNICODE_STRING ObjectName;
				ProbeForRead(ObjectAttributes->ObjectName, sizeof(UNICODE_STRING), sizeof(ULONG));
				ProbeForRead(ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length, sizeof(WCHAR));

				EventId = m_EventList->GetEventId();
				if (EventId)
				{
					data = (svc_nt_createopen_mutant_data *)
						ExAllocatePoolWithTag(PagedPool, sizeof(svc_nt_createopen_mutant_data), 'TXSB');
					if (data)
					{
						RtlZeroMemory(data, sizeof(svc_nt_createopen_mutant_data));
						data->protocol = svc_nt_createopen_mutant;
						data->size = sizeof(svc_nt_createopen_mutant_data);
						data->time = PerfGetSystemTime();
						data->eventId = EventId;
						data->ProcessId = (ULONG)PsGetCurrentProcessId();
						data->ThreadId = (ULONG)PsGetCurrentThreadId();
						data->ResultStatus = status;
						data->IsOpen = TRUE;
						data->InitialOwner = FALSE;
						data->DesiredAccess = (ULONG)DesiredAccess;
						RtlInitEmptyUnicodeString(&ObjectName, data->MutexName, sizeof(data->MutexName) - sizeof(WCHAR));
						RtlCopyUnicodeString(&ObjectName, ObjectAttributes->ObjectName);
					}//data
				}//eventid
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			if (data != NULL)
			{
				ExFreePoolWithTag(data, 'TXSB');
				data = NULL;
			}
		}
	}

	if (data)
	{
		m_EventList->Lock();
		m_EventList->SendEvent(data);
		m_EventList->SendEvent(CreateCallStackEvent(EventId));
		m_EventList->Unlock();
		m_EventList->NotifyEvent();
	}

	InterlockedDecrement(&m_HookLock);

	return status;
}

//NtCreateDirectoryObject

NTSTATUS NTAPI NewNtCreateDirectoryObject(
	__out PHANDLE DirectoryHandle,
	__in ACCESS_MASK DesiredAccess,
	__in POBJECT_ATTRIBUTES ObjectAttributes
);

static ShadowHookTarget m_NtCreateDirectoryObjectHookTarget =
{
	NewNtCreateDirectoryObject,
	nullptr,
};

NTSTATUS NTAPI NewNtCreateDirectoryObject(
	__out PHANDLE DirectoryHandle,
	__in ACCESS_MASK DesiredAccess,
	__in POBJECT_ATTRIBUTES ObjectAttributes
)
{
	InterlockedIncrement(&m_HookLock);

	const auto original = (NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES))
		m_NtCreateDirectoryObjectHookTarget.original_call;

	const auto status = original(DirectoryHandle, DesiredAccess, ObjectAttributes);

	svc_nt_createopen_dirobj_data *data = NULL;
	ULONG64 EventId = 0;

	if (m_EventList->IsCapturing())
	{
		__try
		{
			if (ObjectAttributes && ObjectAttributes->ObjectName)
			{
				UNICODE_STRING ObjectName;
				ProbeForRead(ObjectAttributes->ObjectName, sizeof(UNICODE_STRING), sizeof(ULONG));
				ProbeForRead(ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length, sizeof(WCHAR));

				EventId = m_EventList->GetEventId();
				if (EventId)
				{
					data = (svc_nt_createopen_dirobj_data *)
						ExAllocatePoolWithTag(PagedPool, sizeof(svc_nt_createopen_dirobj_data), 'TXSB');
					if (data)
					{
						RtlZeroMemory(data, sizeof(svc_nt_createopen_dirobj_data));
						data->protocol = svc_nt_createopen_dirobj;
						data->size = sizeof(svc_nt_createopen_dirobj_data);
						data->time = PerfGetSystemTime();
						data->eventId = EventId;
						data->ProcessId = (ULONG)PsGetCurrentProcessId();
						data->ThreadId = (ULONG)PsGetCurrentThreadId();
						data->ResultStatus = status;
						data->IsOpen = FALSE;
						data->DesiredAccess = (ULONG)DesiredAccess;
						RtlInitEmptyUnicodeString(&ObjectName, data->ObjectName, sizeof(data->ObjectName) - sizeof(WCHAR));
						RtlCopyUnicodeString(&ObjectName, ObjectAttributes->ObjectName);
					}//data
				}//eventid
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			if (data != NULL)
			{
				ExFreePoolWithTag(data, 'TXSB');
				data = NULL;
			}
		}
	}

	if (data)
	{
		m_EventList->Lock();
		m_EventList->SendEvent(data);
		m_EventList->SendEvent(CreateCallStackEvent(EventId));
		m_EventList->Unlock();
		m_EventList->NotifyEvent();
	}

	InterlockedDecrement(&m_HookLock);

	return status;
}

//NtOpenDirectoryObject

NTSTATUS NTAPI NewNtOpenDirectoryObject(
	__out PHANDLE DirectoryHandle,
	__in ACCESS_MASK DesiredAccess,
	__in POBJECT_ATTRIBUTES ObjectAttributes
);

static ShadowHookTarget m_NtOpenDirectoryObjectHookTarget =
{
	NewNtOpenDirectoryObject,
	nullptr,
};

NTSTATUS NTAPI NewNtOpenDirectoryObject(
	__out PHANDLE DirectoryHandle,
	__in ACCESS_MASK DesiredAccess,
	__in POBJECT_ATTRIBUTES ObjectAttributes
)
{
	InterlockedIncrement(&m_HookLock);

	const auto original = (NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES))
		m_NtOpenDirectoryObjectHookTarget.original_call;

	const auto status = original(DirectoryHandle, DesiredAccess, ObjectAttributes);

	svc_nt_createopen_dirobj_data *data = NULL;
	ULONG64 EventId = 0;

	if (m_EventList->IsCapturing())
	{
		__try
		{
			if (ObjectAttributes && ObjectAttributes->ObjectName)
			{
				UNICODE_STRING ObjectName;
				ProbeForRead(ObjectAttributes->ObjectName, sizeof(UNICODE_STRING), sizeof(ULONG));
				ProbeForRead(ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length, sizeof(WCHAR));

				EventId = m_EventList->GetEventId();
				if (EventId)
				{
					data = (svc_nt_createopen_dirobj_data *)
						ExAllocatePoolWithTag(PagedPool, sizeof(svc_nt_createopen_dirobj_data), 'TXSB');
					if (data)
					{
						RtlZeroMemory(data, sizeof(svc_nt_createopen_dirobj_data));
						data->protocol = svc_nt_createopen_dirobj;
						data->size = sizeof(svc_nt_createopen_dirobj_data);
						data->time = PerfGetSystemTime();
						data->eventId = EventId;
						data->ProcessId = (ULONG)PsGetCurrentProcessId();
						data->ThreadId = (ULONG)PsGetCurrentThreadId();
						data->ResultStatus = status;
						data->IsOpen = TRUE;
						data->DesiredAccess = (ULONG)DesiredAccess;
						RtlInitEmptyUnicodeString(&ObjectName, data->ObjectName, sizeof(data->ObjectName) - sizeof(WCHAR));
						RtlCopyUnicodeString(&ObjectName, ObjectAttributes->ObjectName);
					}//data
				}//eventid
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			if (data != NULL)
			{
				ExFreePoolWithTag(data, 'TXSB');
				data = NULL;
			}
		}
	}

	if (data)
	{
		m_EventList->Lock();
		m_EventList->SendEvent(data);
		m_EventList->SendEvent(CreateCallStackEvent(EventId));
		m_EventList->Unlock();
		m_EventList->NotifyEvent();
	}

	InterlockedDecrement(&m_HookLock);

	return status;
}

//NtQueryDirectoryObject

NTSTATUS NTAPI NewNtQueryDirectoryObject(
	__in HANDLE DirectoryHandle,
	__out_bcount_opt(Length) PVOID Buffer,
	__in ULONG Length,
	__in BOOLEAN ReturnSingleEntry,
	__in BOOLEAN RestartScan,
	__inout PULONG Context,
	__out_opt PULONG ReturnLength
);

static ShadowHookTarget m_NtQueryDirectoryObjectHookTarget =
{
	NewNtQueryDirectoryObject,
	nullptr,
};

NTSTATUS NTAPI NewNtQueryDirectoryObject(
	__in HANDLE DirectoryHandle,
	__out_bcount_opt(Length) PVOID Buffer,
	__in ULONG Length,
	__in BOOLEAN ReturnSingleEntry,
	__in BOOLEAN RestartScan,
	__inout PULONG Context,
	__out_opt PULONG ReturnLength
)
{
	InterlockedIncrement(&m_HookLock);

	const auto original = (NTSTATUS(NTAPI*)(HANDLE, PVOID, ULONG, BOOLEAN, BOOLEAN, PULONG, PULONG))
		m_NtQueryDirectoryObjectHookTarget.original_call;

	const auto status = original(DirectoryHandle, Buffer, Length, ReturnSingleEntry, RestartScan, Context, ReturnLength);

	svc_nt_query_dirobj_data *data = NULL;
	ULONG64 EventId = 0;

	if (m_EventList->IsCapturing())
	{
		__try
		{
			POBJECT_NAME_INFORMATION pObjectName = NULL;
			PVOID DirectoryObject = NULL;
			NTSTATUS st = ObReferenceObjectByHandle(DirectoryHandle, DIRECTORY_QUERY,
				NULL, ExGetPreviousMode(), &DirectoryObject, NULL);
			if (NT_SUCCESS(st))
			{
				ULONG returnedLength = 0;				
				st = ObQueryNameString(DirectoryObject, pObjectName, 0, &returnedLength);
				if (st == STATUS_INFO_LENGTH_MISMATCH)
				{
					pObjectName = (POBJECT_NAME_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, returnedLength, 'TXSB');
					st = ObQueryNameString(DirectoryObject, pObjectName, returnedLength, &returnedLength);
					if (NT_SUCCESS(st))
					{
						EventId = m_EventList->GetEventId();
						if (EventId)
						{
							data = (svc_nt_query_dirobj_data *)
								ExAllocatePoolWithTag(PagedPool, sizeof(svc_nt_query_dirobj_data), 'TXSB');
							if (data)
							{
								RtlZeroMemory(data, sizeof(svc_nt_query_dirobj_data));
								data->protocol = svc_nt_query_dirobj;
								data->size = sizeof(svc_nt_query_dirobj_data);
								data->time = PerfGetSystemTime();
								data->eventId = EventId;
								data->ProcessId = (ULONG)PsGetCurrentProcessId();
								data->ThreadId = (ULONG)PsGetCurrentThreadId();
								data->ResultStatus = status;
								UNICODE_STRING ObjectName;
								RtlInitEmptyUnicodeString(&ObjectName, data->ObjectName, sizeof(data->ObjectName) - sizeof(WCHAR));
								RtlCopyUnicodeString(&ObjectName, &pObjectName->Name);
							}//data
						}//eventid
						if(pObjectName)
							ExFreePoolWithTag(pObjectName, 'TXSB');
					}//obquery
				}
				ObDereferenceObject(DirectoryObject);
			}			
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			if (data != NULL)
			{
				ExFreePoolWithTag(data, 'TXSB');
				data = NULL;
			}
		}
	}

	if (data)
	{
		m_EventList->Lock();
		m_EventList->SendEvent(data);
		m_EventList->SendEvent(CreateCallStackEvent(EventId));
		m_EventList->Unlock();
		m_EventList->NotifyEvent();
	}

	InterlockedDecrement(&m_HookLock);

	return status;
}

//Set Windows Hook

PVOID MakeSetWindowsHookEvent(ULONG64 EventId, ULONG HookThreadId, int HookType, PVOID HookProc, UCHAR chFlags, PVOID hMod, PUNICODE_STRING pustrMod)
{
	svc_nt_setwindowshook_data *data = (svc_nt_setwindowshook_data *)
		ExAllocatePoolWithTag(PagedPool, sizeof(svc_nt_setwindowshook_data), 'TXSB');

	if (data)
	{
		RtlZeroMemory(data, sizeof(svc_nt_setwindowshook_data));

		data->protocol = svc_nt_setwindowshook;
		data->size = sizeof(svc_nt_setwindowshook_data);
		data->time = PerfGetSystemTime();
		data->eventId = EventId;
		data->ProcessId = (ULONG)PsGetCurrentProcessId();
		data->ThreadId = (ULONG)PsGetCurrentThreadId();
		data->HookThreadId = HookThreadId;
		data->HookType = HookType;
		data->HookProc = (ULONG64)HookProc;
		data->Flags = chFlags;
		data->Module = (ULONG64)hMod;
		
		if (ARGUMENT_PRESENT(pustrMod))
		{
			UNICODE_STRING ustrModName;
			RtlInitEmptyUnicodeString(&ustrModName, data->ModuleName, sizeof(data->ModuleName) - sizeof(WCHAR));
			__try
			{
				ProbeForRead(pustrMod, sizeof(UNICODE_STRING), sizeof(ULONG));
				ProbeForRead(pustrMod->Buffer, pustrMod->Length, sizeof(WCHAR));

				RtlCopyUnicodeString(&ustrModName, pustrMod);
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
			}
		}
	}

	return data;
}

PVOID NTAPI NewNtUserSetWindowsHookEx(
	HANDLE hmod,
	PUNICODE_STRING pstrLib,
	DWORD ThreadId,
	int nFilterType,
	PVOID pfnFilterProc,
	BOOLEAN chFlags);

static ShadowHookTarget m_NtUserSetWindowsHookExHookTarget =
{
	NewNtUserSetWindowsHookEx,
	nullptr,
};

PVOID NTAPI NewNtUserSetWindowsHookEx(
	HANDLE hmod,
	PUNICODE_STRING pstrLib,
	DWORD ThreadId,
	int nFilterType,
	PVOID pfnFilterProc,
	UCHAR chFlags)
{
	InterlockedIncrement(&m_HookLock);

	const auto original = (PVOID(NTAPI *)(HANDLE, PUNICODE_STRING, DWORD, int, PVOID, UCHAR))m_NtUserSetWindowsHookExHookTarget.original_call;

	const auto result = original(hmod, pstrLib, ThreadId, nFilterType, pfnFilterProc, chFlags);

	if (m_EventList->IsCapturing())
	{
		ULONG64 EventId = m_EventList->GetEventId();
		if (EventId)
		{
			svc_nt_setwindowshook_data *data = (svc_nt_setwindowshook_data *)
				MakeSetWindowsHookEvent(EventId, ThreadId,
					nFilterType, pfnFilterProc, chFlags, hmod, pstrLib);
			if (data)
			{
				data->ResultHHook = (ULONG)result;

				m_EventList->Lock();
				m_EventList->SendEvent(data);
				m_EventList->SendEvent(CreateCallStackEvent(EventId));
				m_EventList->Unlock();
				m_EventList->NotifyEvent();
			}
		}
	}

	InterlockedDecrement(&m_HookLock);

	return result;
}

PVOID NTAPI NewNtUserSetWindowsHookAW(
	IN int nFilterType,
	IN PVOID pfnFilterProc,
	IN UCHAR chFlags);

static ShadowHookTarget m_NtUserSetWindowsHookAWHookTarget =
{
	NewNtUserSetWindowsHookAW,
	nullptr,
};

PVOID NTAPI NewNtUserSetWindowsHookAW(
	IN int nFilterType,
	IN PVOID pfnFilterProc,
	IN UCHAR chFlags)
{
	InterlockedIncrement(&m_HookLock);

	const auto original = (PVOID(NTAPI *)(int, PVOID, UCHAR))m_NtUserSetWindowsHookAWHookTarget.original_call;

	const auto result = original(nFilterType, pfnFilterProc, chFlags);

	if (m_EventList->IsCapturing())
	{
		ULONG64 EventId = m_EventList->GetEventId();
		if (EventId)
		{
			svc_nt_setwindowshook_data *data = (svc_nt_setwindowshook_data *)
				MakeSetWindowsHookEvent(EventId, (ULONG)PsGetCurrentThreadId(), 
					nFilterType, pfnFilterProc, chFlags, NULL, NULL);
			if (data)
			{
				data->ResultHHook = (ULONG)result;

				m_EventList->Lock();
				m_EventList->SendEvent(data);
				m_EventList->SendEvent(CreateCallStackEvent(EventId));
				m_EventList->Unlock();
				m_EventList->NotifyEvent();
			}
		}
	}

	InterlockedDecrement(&m_HookLock);

	return result;
}

//NtUserFindWindowEx

PVOID NTAPI NewNtUserFindWindowEx(
	IN PVOID hwndParent,
	IN PVOID hwndChild,
	IN PUNICODE_STRING pstrClassName OPTIONAL,
	IN PUNICODE_STRING pstrWindowName OPTIONAL,
	IN DWORD dwType);

static ShadowHookTarget m_NtUserFindWindowExHookTarget =
{
	NewNtUserFindWindowEx,
	nullptr,
};

PVOID NTAPI NewNtUserFindWindowEx(
	IN PVOID hwndParent,
	IN PVOID hwndChild,
	IN PUNICODE_STRING pstrClassName OPTIONAL,
	IN PUNICODE_STRING pstrWindowName OPTIONAL,
	IN DWORD dwType)
{
	InterlockedIncrement(&m_HookLock);

	const auto original = (PVOID(NTAPI *)(PVOID, PVOID, PUNICODE_STRING, PUNICODE_STRING, DWORD))m_NtUserFindWindowExHookTarget.original_call;

	const auto result = original(hwndParent, hwndChild, pstrClassName, pstrWindowName, dwType);

	if (m_EventList->IsCapturing())
	{
		ULONG64 EventId = m_EventList->GetEventId();
		if (EventId)
		{
			svc_nt_findwindow_data *data = (svc_nt_findwindow_data *)
				ExAllocatePoolWithTag(PagedPool, sizeof(svc_nt_findwindow_data), 'TXSB');

			if (data)
			{
				RtlZeroMemory(data, sizeof(svc_nt_findwindow_data));

				data->protocol = svc_nt_findwindow;
				data->size = sizeof(svc_nt_findwindow_data);
				data->time = PerfGetSystemTime();
				data->eventId = EventId;
				data->ProcessId = (ULONG)PsGetCurrentProcessId();
				data->ThreadId = (ULONG)PsGetCurrentThreadId();
				data->HwndParent = (ULONG)hwndParent;
				data->HwndChild = (ULONG)hwndChild;

				if (ARGUMENT_PRESENT(pstrClassName))
				{
					UNICODE_STRING ustrClass;
					RtlInitEmptyUnicodeString(&ustrClass, data->ClassName, sizeof(data->ClassName) - sizeof(WCHAR));
					__try
					{
						ProbeForRead(pstrClassName, sizeof(UNICODE_STRING), sizeof(ULONG));
						ProbeForRead(pstrClassName->Buffer, pstrClassName->Length, sizeof(WCHAR));

						RtlCopyUnicodeString(&ustrClass, pstrClassName);
					}
					__except (EXCEPTION_EXECUTE_HANDLER)
					{
					}
				}

				if (ARGUMENT_PRESENT(pstrWindowName))
				{
					UNICODE_STRING ustrWindow;
					RtlInitEmptyUnicodeString(&ustrWindow, data->WindowName, sizeof(data->WindowName) - sizeof(WCHAR));
					__try
					{
						ProbeForRead(pstrWindowName, sizeof(UNICODE_STRING), sizeof(ULONG));
						ProbeForRead(pstrWindowName->Buffer, pstrWindowName->Length, sizeof(WCHAR));

						RtlCopyUnicodeString(&ustrWindow, pstrWindowName);
					}
					__except (EXCEPTION_EXECUTE_HANDLER)
					{
					}
				}

				data->ResultHwnd = (ULONG)result;

				m_EventList->Lock();
				m_EventList->SendEvent(data);
				m_EventList->SendEvent(CreateCallStackEvent(EventId));
				m_EventList->Unlock();
				m_EventList->NotifyEvent();
			}
		}
	}

	InterlockedDecrement(&m_HookLock);

	return result;
}

int NTAPI NewNtUserInternalGetWindowText(
	IN PVOID hwnd,
	OUT LPWSTR lpString,
	IN int nMaxCount);

static ShadowHookTarget m_NtUserInternalGetWindowTextHookTarget =
{
	NewNtUserInternalGetWindowText,
	nullptr,
};

int NTAPI NewNtUserInternalGetWindowText(
	IN PVOID hwnd,
	OUT LPWSTR lpString,
	IN int nMaxCount)
{
	InterlockedIncrement(&m_HookLock);

	const auto original = (int(NTAPI *)(PVOID, LPWSTR, int))m_NtUserInternalGetWindowTextHookTarget.original_call;

	const auto result = original(hwnd, lpString, nMaxCount);

	if (m_EventList->IsCapturing())
	{
		ULONG64 EventId = m_EventList->GetEventId();
		if (EventId)
		{
			svc_nt_getwindowtext_data *data = (svc_nt_getwindowtext_data *)
				ExAllocatePoolWithTag(PagedPool, sizeof(svc_nt_getwindowtext_data), 'TXSB');

			if (data)
			{
				RtlZeroMemory(data, sizeof(svc_nt_getwindowtext_data));

				data->protocol = svc_nt_getwindowtext;
				data->size = sizeof(svc_nt_getwindowtext_data);
				data->time = PerfGetSystemTime();
				data->eventId = EventId;
				data->ProcessId = (ULONG)PsGetCurrentProcessId();
				data->ThreadId = (ULONG)PsGetCurrentThreadId();
				data->Hwnd = (ULONG)hwnd;
				data->MaxCount = (ULONG)nMaxCount;

				if (result)
				{
					__try
					{
						ULONG nMaxCopy = min(sizeof(data->WindowName) - sizeof(WCHAR), result * sizeof(WCHAR));
						ProbeForRead(lpString, nMaxCopy, 1);
						memcpy(data->WindowName, lpString, nMaxCopy);
					}
					__except (EXCEPTION_EXECUTE_HANDLER)
					{
					}
				}

				data->ResultCount = (ULONG)result;

				m_EventList->Lock();
				m_EventList->SendEvent(data);
				m_EventList->SendEvent(CreateCallStackEvent(EventId));
				m_EventList->Unlock();
				m_EventList->NotifyEvent();
			}
		}
	}

	InterlockedDecrement(&m_HookLock);

	return result;
}

//NtUserGetClassName

int NTAPI NewNtUserGetClassName(
	IN PVOID hwnd,
	IN int bReal,
	IN OUT PUNICODE_STRING pstrClassName);

static ShadowHookTarget m_NtUserGetClassNameHookTarget =
{
	NewNtUserGetClassName,
	nullptr,
};

int NTAPI NewNtUserGetClassName(
	IN PVOID hwnd,
	IN int bReal,
	IN OUT PUNICODE_STRING pstrClassName)
{
	InterlockedIncrement(&m_HookLock);

	const auto original = (int(NTAPI *)(PVOID, int, PUNICODE_STRING))m_NtUserGetClassNameHookTarget.original_call;

	const auto result = original(hwnd, bReal, pstrClassName);

	if (m_EventList->IsCapturing())
	{
		ULONG64 EventId = m_EventList->GetEventId();
		if (EventId)
		{
			svc_nt_getwindowclass_data *data = (svc_nt_getwindowclass_data *)
				ExAllocatePoolWithTag(PagedPool, sizeof(svc_nt_getwindowclass_data), 'TXSB');

			if (data)
			{
				RtlZeroMemory(data, sizeof(svc_nt_getwindowclass_data));

				data->protocol = svc_nt_getwindowclass;
				data->size = sizeof(svc_nt_getwindowclass_data);
				data->time = PerfGetSystemTime();
				data->eventId = EventId;
				data->ProcessId = (ULONG)PsGetCurrentProcessId();
				data->ThreadId = (ULONG)PsGetCurrentThreadId();
				data->Hwnd = (ULONG)hwnd;
				
				if (result && pstrClassName)
				{
					__try
					{
						data->MaxCount = pstrClassName->MaximumLength / sizeof(WCHAR);
						ULONG nMaxCopy = min(sizeof(data->WindowClass) - sizeof(WCHAR), result * sizeof(WCHAR));
						ProbeForRead(pstrClassName->Buffer, nMaxCopy, 1);
						memcpy(data->WindowClass, pstrClassName->Buffer, nMaxCopy);
					}
					__except (EXCEPTION_EXECUTE_HANDLER)
					{
					}
				}

				data->ResultCount = (ULONG)result;

				m_EventList->Lock();
				m_EventList->SendEvent(data);
				m_EventList->SendEvent(CreateCallStackEvent(EventId));
				m_EventList->Unlock();
				m_EventList->NotifyEvent();
			}
		}
	}

	InterlockedDecrement(&m_HookLock);

	return result;
}

//free

#define FREE_SHADOWHOOK(a)if(m_##a##HookTarget.original_call != nullptr)\
	ExFreePoolWithTag(m_##a##HookTarget.original_call, kHyperPlatformCommonPoolTag);

VOID FreeShadowHooks(VOID)
{
		FREE_SHADOWHOOK(NtQuerySystemInformation)
		FREE_SHADOWHOOK(NtOpenProcess)
		FREE_SHADOWHOOK(NtOpenThread)
		FREE_SHADOWHOOK(NtTerminateProcess)
		FREE_SHADOWHOOK(NtAllocateVirtualMemory)
		FREE_SHADOWHOOK(NtReadVirtualMemory)
		FREE_SHADOWHOOK(NtWriteVirtualMemory)
		FREE_SHADOWHOOK(NtProtectVirtualMemory)
		FREE_SHADOWHOOK(NtQueryVirtualMemory)
		FREE_SHADOWHOOK(NtLoadDriver)
		FREE_SHADOWHOOK(NtCreateMutant)
		FREE_SHADOWHOOK(NtOpenMutant)
		FREE_SHADOWHOOK(NtCreateDirectoryObject)
		FREE_SHADOWHOOK(NtOpenDirectoryObject)
		FREE_SHADOWHOOK(NtQueryDirectoryObject)
		FREE_SHADOWHOOK(NtUserSetWindowsHookEx)
		FREE_SHADOWHOOK(NtUserSetWindowsHookAW)
		FREE_SHADOWHOOK(NtUserFindWindowEx)
		FREE_SHADOWHOOK(NtUserInternalGetWindowText)
		FREE_SHADOWHOOK(NtUserGetClassName)
}

#define INSTALL_SHADOWHOOK(a) if (dynData.pfn##a)\
	{\
		if (!ShInstallHook(shared_sh_data, dynData.pfn##a, &m_##a##HookTarget))\
			break;\
	}

NTSTATUS ShadowHookInitialization(SharedShadowHookData* shared_sh_data) 
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	//for win32k hook
	PEPROCESS Process = NULL;
	KAPC_STATE kApc;

	InterlockedExchange(&m_HookLock, 0);

	HANDLE ProcessId = GetCsrssProcessId();

	if (ProcessId)
		PsLookupProcessByProcessId(ProcessId, &Process);

	if (Process != NULL){
		KeStackAttachProcess(Process, &kApc);
		m_CsrssCR3 = __readcr3();
	}

	do
	{
			INSTALL_SHADOWHOOK(NtQuerySystemInformation)
			INSTALL_SHADOWHOOK(NtOpenProcess)
			INSTALL_SHADOWHOOK(NtOpenThread)
			INSTALL_SHADOWHOOK(NtTerminateProcess)
			INSTALL_SHADOWHOOK(NtAllocateVirtualMemory)
			INSTALL_SHADOWHOOK(NtReadVirtualMemory)
			INSTALL_SHADOWHOOK(NtWriteVirtualMemory)
			INSTALL_SHADOWHOOK(NtProtectVirtualMemory)
			INSTALL_SHADOWHOOK(NtQueryVirtualMemory)
			INSTALL_SHADOWHOOK(NtLoadDriver)
			INSTALL_SHADOWHOOK(NtCreateMutant)
			INSTALL_SHADOWHOOK(NtOpenMutant)
			INSTALL_SHADOWHOOK(NtCreateDirectoryObject)
			INSTALL_SHADOWHOOK(NtOpenDirectoryObject)
			INSTALL_SHADOWHOOK(NtQueryDirectoryObject)
			INSTALL_SHADOWHOOK(NtUserSetWindowsHookEx)
			INSTALL_SHADOWHOOK(NtUserSetWindowsHookAW)
			INSTALL_SHADOWHOOK(NtUserFindWindowEx)
			INSTALL_SHADOWHOOK(NtUserInternalGetWindowText)
			INSTALL_SHADOWHOOK(NtUserGetClassName)
		status = STATUS_SUCCESS;
	} while (0);

	//for win32k hook
	if (Process != NULL)
	{
		KeUnstackDetachProcess(&kApc);
		ObDereferenceObject(Process);
	}

	if(!NT_SUCCESS(status))
	{
		FreeShadowHooks();
		return status;
	}

	status = ShEnableHooks();
	if (!NT_SUCCESS(status))
	{
		FreeShadowHooks();
		return status;
	}

	return STATUS_SUCCESS;
}

VOID ShadowHookTermination(VOID)
{
	PAGED_CODE();

	ShDisableHooks();
	while (InterlockedCompareExchange(&m_HookLock, 0, 0) > 0) {
		InterlockedDecrement(&m_HookLock);
		UtilSleep(100);	
	}
	FreeShadowHooks();
}