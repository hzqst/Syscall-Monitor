#include <ntifs.h>
#define NTSTRSAFE_NO_CB_FUNCTIONS
#include <ntstrsafe.h>
#include "../HyperPlatform/kernel_stl.h"
#include "../HyperPlatform/performance.h"
#include "../../Shared/Protocol.h"
#include "NativeEnums.h"
#include "NativeStructs.h"
#include "main.h"

extern CProcList *m_IgnoreProcList;
extern CFileList *m_IgnoreFileList;
extern CEventList *m_EventList;

extern PFLT_FILTER m_pFilterHandle;
extern PFLT_PORT m_pClientPort;

NTSTATUS NtFileNameToDosFileName(IN PUNICODE_STRING NtFileName, OUT PUNICODE_STRING DosFileName);
NTSTATUS GetFileDosName(IN PFILE_OBJECT pFileObject, OUT PUNICODE_STRING ustrDosName);

EXTERN_C{

	_IRQL_requires_max_(PASSIVE_LEVEL) bool VmpIsHyperPlatformInstalled();

extern DYNAMIC_DATA dynData;

NTSTATUS GetProcessPathByPID(HANDLE ProcessId, PUNICODE_STRING ProcessName);
NTSTATUS GetCommandLineByPID(HANDLE ProcessId, PUNICODE_STRING CommandLine);
NTSTATUS GetCurDirectoryByPID(HANDLE ProcessId, PUNICODE_STRING CurDirectory);
NTSTATUS GetImagePathByAddress(HANDLE ProcessId, PVOID ImageBase, PUNICODE_STRING ImagePath);

PVOID CreateCallStackEvent(ULONG64 EventId);

typedef NTSTATUS(*fnObRegisterCallbacks)(POB_CALLBACK_REGISTRATION, PVOID *);
typedef VOID(*fnObUnRegisterCallbacks)(PVOID);
typedef USHORT(*fnObGetFilterVersion)(VOID);

fnObRegisterCallbacks m_pfnObRegisterCallbacks = NULL;
fnObUnRegisterCallbacks m_pfnObUnRegisterCallbacks = NULL;
fnObGetFilterVersion m_pfnObGetFilterVersion = NULL;

PVOID m_ProcessObCallbackHandle = NULL;
PVOID m_ThreadObCallbackHandle = NULL;

_IRQL_requires_max_(PASSIVE_LEVEL) VOID PsInitialization(PDRIVER_OBJECT pDriverObject);
_IRQL_requires_max_(PASSIVE_LEVEL) VOID PsTermination(VOID);

#if defined(ALLOC_PRAGMA)
#pragma alloc_text(INIT, PsInitialization)
#pragma alloc_text(PAGE, PsTermination)
#endif

#ifdef _WIN64

NTKERNELAPI PVOID NTAPI PsGetProcessWow64Process(PEPROCESS Process);

#endif

NTKERNELAPI PCHAR NTAPI PsGetProcessImageFileName(PEPROCESS Process);

NTSTATUS NTAPI NewZwTerminateThread(_In_opt_ HANDLE ThreadHandle, _In_ NTSTATUS ExitStatus);

NTKERNELAPI NTSTATUS NTAPI ZwOpenThread(
	__out PHANDLE ThreadHandle,
	__in ACCESS_MASK DesiredAccess,
	__in POBJECT_ATTRIBUTES ObjectAttributes,
	__in_opt PCLIENT_ID ClientId
);

NTKERNELAPI NTSTATUS NTAPI ZwQueryInformationThread(
	__in HANDLE ThreadHandle,
	__in THREADINFOCLASS ThreadInformationClass,
	__out_bcount(ThreadInformationLength) PVOID ThreadInformation,
	__in ULONG ThreadInformationLength,
	__out_opt PULONG ReturnLength
);

NTKERNELAPI NTSTATUS NTAPI ZwQuerySystemInformation(
	__in SYSTEM_INFORMATION_CLASS SystemInformationClass,
	__out_bcount_opt(SystemInformationLength) PVOID SystemInformation,
	__in ULONG SystemInformationLength,
	__out_opt PULONG ReturnLength
);

NTKERNELAPI NTSTATUS NTAPI ZwQueryInformationProcess(
	_In_      HANDLE           ProcessHandle,
	_In_      PROCESSINFOCLASS ProcessInformationClass,
	_Out_     PVOID            ProcessInformation,
	_In_      ULONG            ProcessInformationLength,
	_Out_opt_ PULONG           ReturnLength
);

PVOID MakePsCreateProcessEvent(ULONG64 EventId, HANDLE ParentId, HANDLE ProcessId, BOOLEAN Create)
{
	svc_ps_create_process_data *data = (svc_ps_create_process_data *)
		ExAllocatePoolWithTag(PagedPool, sizeof(svc_ps_create_process_data), 'TXSB');

	if (data)
	{
		RtlZeroMemory(data, sizeof(svc_ps_create_process_data));
		data->protocol = svc_ps_create_process;
		data->size = sizeof(svc_ps_create_process_data);
		data->time = PerfGetSystemTime();
		data->eventId = EventId;
		data->Create = Create;
		data->ProcessId = (ULONG)ProcessId;
		data->ThreadId = (ULONG)PsGetCurrentThreadId();
		data->ParentProcessId = (ULONG)ParentId;

		UNICODE_STRING ProcessName;
		RtlInitEmptyUnicodeString(&ProcessName, data->ImagePath, sizeof(data->ImagePath) - sizeof(WCHAR));
		UNICODE_STRING CommandLine;
		RtlInitEmptyUnicodeString(&CommandLine, data->CommandLine, sizeof(data->CommandLine) - sizeof(WCHAR));
		UNICODE_STRING CurDirectory;
		RtlInitEmptyUnicodeString(&CurDirectory, data->CurDirectory, sizeof(data->CurDirectory) - sizeof(WCHAR));
		GetProcessPathByPID(ProcessId, &ProcessName);
		GetCommandLineByPID(ProcessId, &CommandLine);
		GetCurDirectoryByPID(ProcessId, &CurDirectory);

		PEPROCESS Process = NULL;
		if (NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &Process)))
		{
			data->CreateTime = PsGetProcessCreateTimeQuadPart(Process);
			data->SessionId = 0;

			//Get SessionId
			CLIENT_ID ClientId;
			ClientId.UniqueProcess = ProcessId;
			ClientId.UniqueThread = NULL;
			OBJECT_ATTRIBUTES oa;
			InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, 0, 0);
			HANDLE ProcessHandle = NULL;
			if (NT_SUCCESS(ZwOpenProcess(&ProcessHandle, PROCESS_QUERY_INFORMATION, &oa, &ClientId)))
			{
				PROCESS_SESSION_INFORMATION psi;
				if (NT_SUCCESS(ZwQueryInformationProcess(ProcessHandle, ProcessSessionInformation, &psi, sizeof(psi), NULL)))
				{
					data->SessionId = psi.SessionId;
				}
				ZwClose(ProcessHandle);
			}

#ifdef _WIN64
			data->Is64Bit = (PsGetProcessWow64Process(Process) == NULL) ? TRUE : FALSE;
#else
			data->Is64Bit = FALSE;
#endif
			ObDereferenceObject(Process);
		}
	}

	return data;
}

VOID CreateProcessNotifyRoutine(HANDLE ParentId, HANDLE ProcessId, BOOLEAN Create)
{
	if (m_EventList->IsCapturing())
	{
		ULONG64 EventId = m_EventList->GetEventId();

		svc_ps_create_process_data *data = (svc_ps_create_process_data *)
			MakePsCreateProcessEvent(EventId, ParentId, ProcessId, Create);

		if (data)
		{
			m_EventList->Lock();
			m_EventList->SendEvent(data);
			m_EventList->SendEvent(CreateCallStackEvent(EventId));
			m_EventList->Unlock();
			m_EventList->NotifyEvent();
		}
	}
}

VOID CreateThreadNotifyCallback(_In_ HANDLE  ProcessId, _In_ HANDLE  ThreadId, _In_ BOOLEAN Create)
{
	if (m_EventList->IsCapturing())
	{
		ULONG64 EventId = m_EventList->GetEventId();
		if (EventId)
		{
			svc_ps_create_thread_data *data = (svc_ps_create_thread_data *)
				ExAllocatePoolWithTag(PagedPool, sizeof(svc_ps_create_thread_data), 'TXSB');

			if (data)
			{
				RtlZeroMemory(data, sizeof(svc_ps_create_thread_data));
				data->protocol = svc_ps_create_thread;
				data->size = sizeof(svc_ps_create_thread_data);
				data->time = PerfGetSystemTime();
				data->eventId = EventId;
				data->Create = Create;
				data->ProcessId = (ULONG)ProcessId;
				data->ThreadId = (ULONG)ThreadId;
				data->CurProcessId = (ULONG)PsGetCurrentProcessId();
				data->CurThreadId = (ULONG)PsGetCurrentThreadId();

				PETHREAD Thread = NULL;
				if (Create && NT_SUCCESS(PsLookupThreadByThreadId(ThreadId, &Thread)))
				{
					CLIENT_ID ClientId;
					ClientId.UniqueProcess = NULL;
					ClientId.UniqueThread = ThreadId;

					OBJECT_ATTRIBUTES oa;
					InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, 0, 0);
					HANDLE ThreadHandle = NULL;
					if (NT_SUCCESS(ZwOpenThread(&ThreadHandle, PROCESS_QUERY_INFORMATION, &oa, &ClientId)))
					{
						PVOID StartAddress;
						if (NT_SUCCESS(ZwQueryInformationThread(ThreadHandle, ThreadQuerySetWin32StartAddress, &StartAddress, sizeof(StartAddress), NULL)))
						{
							data->ThreadStartAddress = (ULONG64)StartAddress;
						}
						ULONG BreakOnTermination;
						if (NT_SUCCESS(ZwQueryInformationThread(ThreadHandle, ThreadBreakOnTermination, &BreakOnTermination, sizeof(BreakOnTermination), NULL)))
						{
							data->ThreadFlags.Fields.BreakOnTermination = BreakOnTermination ? 1 : 0;
						}
						ZwClose(ThreadHandle);
					}

					data->ThreadFlags.Fields.SystemThread = PsIsSystemThread(Thread);
					
					ObDereferenceObject(Thread);
				}

				m_EventList->Lock();
				m_EventList->SendEvent(data);
				m_EventList->SendEvent(CreateCallStackEvent(EventId));
				m_EventList->Unlock();
				m_EventList->NotifyEvent();

				/*if (data->ThreadStartAddress & 0xFFFF == 0x233b) {
					PEPROCESS Process = NULL;
					if (NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &Process))) {
						if (!_stricmp(PsGetProcessImageFileName(Process), "MapleStory2.exe")) {
							CLIENT_ID cid;
							cid.UniqueProcess = NULL;
							cid.UniqueThread = ThreadId;
							OBJECT_ATTRIBUTES oa;
							HANDLE ThreadHandle;
							InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, 0, 0);
							if (NT_SUCCESS(ZwOpenThread(&ThreadHandle, THREAD_ALL_ACCESS, &oa, &cid))) {
								NewZwTerminateThread(ThreadHandle, 0);
								ZwClose(ThreadHandle);
							}
						}
						ObDereferenceObject(Process);
					}
				}*/
			}//data
		}//eventid
	}
}

PVOID MakeLoadImageEvent(ULONG64 EventId, HANDLE ProcessId, PVOID ImageBase, ULONG ImageSize)
{
	svc_ps_load_image_data *data = (svc_ps_load_image_data *)
		ExAllocatePoolWithTag(PagedPool, sizeof(svc_ps_load_image_data), 'TXSB');

	if (data)
	{
		RtlZeroMemory(data, sizeof(svc_ps_load_image_data));

		data->protocol = svc_ps_load_image;
		data->size = sizeof(svc_ps_load_image_data);
		data->time = PerfGetSystemTime();
		data->eventId = EventId;
		data->ProcessId = (ULONG)ProcessId;		
		data->ThreadId = (ULONG)PsGetCurrentThreadId();
		data->ImageBase = (ULONG64)ImageBase;
		data->ImageSize = ImageSize;
	}

	return data;
}

VOID EnumSystemModules(VOID)
{
	ULONG cbBuffer = 0;
	PVOID pBuffer = NULL;
	ANSI_STRING strModulePath;
	UNICODE_STRING ustrModulePath;
	UNICODE_STRING ustrDriverPath;
	UNICODE_STRING ImageFileName;

	RtlInitUnicodeString(&ustrDriverPath, L"\\SystemRoot\\System32\\Drivers\\");

	while (1)
	{
		cbBuffer += 0x1000;
		pBuffer = ExAllocatePoolWithTag(PagedPool, cbBuffer, 'TXSB');

		if (pBuffer == NULL)
			return;

		NTSTATUS Status = ZwQuerySystemInformation(SystemModuleInformation, pBuffer, cbBuffer, NULL);

		if (NT_SUCCESS(Status))
			break;

		ExFreePoolWithTag(pBuffer, 'TXSB');

		if (Status != STATUS_INFO_LENGTH_MISMATCH)
			return;
	}

	if (pBuffer == NULL)
		return;

	PRTL_PROCESS_MODULES pInfo = (PRTL_PROCESS_MODULES)pBuffer;
	for (ULONG i = 0; i < pInfo->NumberOfModules; ++i)
	{
		PRTL_PROCESS_MODULE_INFORMATION pEntry = &pInfo->Modules[i];
		if ((ULONG64)pEntry->ImageBase < MmUserProbeAddress)
			continue;
		strModulePath.Buffer = (PCHAR)pEntry->FullPathName;
		strModulePath.Length = strlen((const char *)pEntry->FullPathName);
		strModulePath.MaximumLength = strModulePath.Length;
		if (NT_SUCCESS(RtlAnsiStringToUnicodeString(&ustrModulePath, &strModulePath, TRUE)))
		{
			svc_ps_load_image_data *data = (svc_ps_load_image_data *)
				MakeLoadImageEvent(0, (HANDLE)4, pEntry->ImageBase, (ULONG)pEntry->ImageSize);
			if (data)
			{
				RtlInitEmptyUnicodeString(&ImageFileName, data->ImagePath, sizeof(data->ImagePath) - sizeof(WCHAR));

				if (ustrModulePath.Buffer[0] != L'\\')
				{
					RtlCopyUnicodeString(&ImageFileName, &ustrDriverPath);
					RtlAppendUnicodeStringToString(&ImageFileName, &ustrModulePath);
				}
				else
				{
					RtlCopyUnicodeString(&ImageFileName, &ustrModulePath);
				}

				m_EventList->SendEvent(data);
			}
			RtlFreeUnicodeString(&ustrModulePath);
		}
	}

	ExFreePoolWithTag(pBuffer, 'TXSB');
}

VOID LoadImageNotifyCallback(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO pImageInfo)
{
	LARGE_INTEGER time = { 0 };

	if (m_EventList->IsCapturing())
	{
		ULONG64 EventId = m_EventList->GetEventId();
		if (EventId)
		{
			svc_ps_load_image_data *data = (svc_ps_load_image_data *)
				MakeLoadImageEvent(EventId, ProcessId, pImageInfo->ImageBase, (ULONG)pImageInfo->ImageSize);
			if (data)
			{
				if (pImageInfo->SystemModeImage)
					data->ProcessId = 4;

				UNICODE_STRING ImageFileName;
				RtlInitEmptyUnicodeString(&ImageFileName, data->ImagePath, sizeof(data->ImagePath) - sizeof(WCHAR));

				if (pImageInfo->ExtendedInfoPresent)
				{
					PIMAGE_INFO_EX pImageInfoEx = CONTAINING_RECORD(pImageInfo, IMAGE_INFO_EX, ImageInfo);

					if (!NT_SUCCESS(GetFileDosName(pImageInfoEx->FileObject, &ImageFileName)))
					{
						if (ARGUMENT_PRESENT(FullImageName))
							RtlCopyUnicodeString(&ImageFileName, FullImageName);
					}
				}
				else
				{
					if (ARGUMENT_PRESENT(FullImageName))
						RtlCopyUnicodeString(&ImageFileName, FullImageName);
				}

				m_EventList->Lock();
				m_EventList->SendEvent(data);
				m_EventList->SendEvent(CreateCallStackEvent(EventId));
				m_EventList->Unlock();
				m_EventList->NotifyEvent();
			}//data
		}//eventid
	}
}

OB_PREOP_CALLBACK_STATUS ProcessObCallback(PVOID RegistrationContext, POB_POST_OPERATION_INFORMATION pOperationInformation)
{
	UNREFERENCED_PARAMETER(RegistrationContext);

	if (pOperationInformation->KernelHandle)
		return OB_PREOP_SUCCESS;

	if (m_EventList->IsCapturing() && pOperationInformation->Object != NULL)
	{
		ULONG64 EventId = m_EventList->GetEventId();
		if (EventId)
		{
			svc_nt_open_process_data *data = (svc_nt_open_process_data *)
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
				data->TargetProcessId = (ULONG)PsGetProcessId((PEPROCESS)pOperationInformation->Object);
				data->DesiredAccess = (ULONG)pOperationInformation->Parameters->CreateHandleInformation.GrantedAccess;
				data->ResultStatus = (ULONG)pOperationInformation->ReturnStatus;

				m_EventList->Lock();
				m_EventList->SendEvent(data);
				m_EventList->SendEvent(CreateCallStackEvent(EventId));
				m_EventList->Unlock();
				m_EventList->NotifyEvent();
			}
		}
	}

	return OB_PREOP_SUCCESS;
}

OB_PREOP_CALLBACK_STATUS ThreadObCallback(PVOID RegistrationContext, POB_POST_OPERATION_INFORMATION pOperationInformation)
{
	UNREFERENCED_PARAMETER(RegistrationContext);

	if (pOperationInformation->KernelHandle)
		return OB_PREOP_SUCCESS;

	if (m_EventList->IsCapturing() && pOperationInformation->Object != NULL)
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
				data->TargetProcessId = (ULONG)PsGetThreadProcessId((PETHREAD)pOperationInformation->Object);
				data->TargetThreadId = (ULONG)PsGetThreadId((PETHREAD)pOperationInformation->Object);
				data->DesiredAccess = (ULONG)pOperationInformation->Parameters->CreateHandleInformation.GrantedAccess;
				data->ResultStatus = (ULONG)pOperationInformation->ReturnStatus;

				m_EventList->Lock();
				m_EventList->SendEvent(data);
				m_EventList->SendEvent(CreateCallStackEvent(EventId));
				m_EventList->Unlock();
				m_EventList->NotifyEvent();
			}
		}
	}

	return OB_PREOP_SUCCESS;
}

NTSTATUS SetProcessObCallback(VOID)
{
	OB_CALLBACK_REGISTRATION obReg;
	OB_OPERATION_REGISTRATION opReg;
	NTSTATUS status;
	int AltitudeIndex;
	WCHAR szAltitude[16] = { 0 };

	memset(&obReg, 0, sizeof(obReg));
	obReg.Version = m_pfnObGetFilterVersion();
	obReg.OperationRegistrationCount = 1;
	obReg.RegistrationContext = NULL;

	obReg.Altitude.Length = 0;
	obReg.Altitude.Buffer = szAltitude;
	obReg.Altitude.MaximumLength = sizeof(szAltitude);

	memset(&opReg, 0, sizeof(opReg));
	opReg.ObjectType = PsProcessType;
	opReg.Operations = OB_OPERATION_HANDLE_CREATE;
	opReg.PostOperation = (POB_POST_OPERATION_CALLBACK)&ProcessObCallback;
	obReg.OperationRegistration = &opReg;

	AltitudeIndex = 321000;
	do
	{
		RtlUnicodeStringPrintf(&obReg.Altitude, L"%d", AltitudeIndex++);
		status = m_pfnObRegisterCallbacks(&obReg, &m_ProcessObCallbackHandle);
	} while (STATUS_FLT_INSTANCE_ALTITUDE_COLLISION == status);

	return status;
}

NTSTATUS SetThreadObCallback(VOID)
{
	OB_CALLBACK_REGISTRATION obReg;
	OB_OPERATION_REGISTRATION opReg;
	NTSTATUS status;
	int AltitudeIndex;
	WCHAR szAltitude[16] = { 0 };

	memset(&obReg, 0, sizeof(obReg));
	obReg.Version = m_pfnObGetFilterVersion();
	obReg.OperationRegistrationCount = 1;
	obReg.RegistrationContext = NULL;

	obReg.Altitude.Length = 0;
	obReg.Altitude.Buffer = szAltitude;
	obReg.Altitude.MaximumLength = sizeof(szAltitude);

	memset(&opReg, 0, sizeof(opReg));
	opReg.ObjectType = PsThreadType;
	opReg.Operations = OB_OPERATION_HANDLE_CREATE;
	opReg.PostOperation = (POB_POST_OPERATION_CALLBACK)&ThreadObCallback;
	obReg.OperationRegistration = &opReg;

	AltitudeIndex = 321000;
	do
	{
		RtlUnicodeStringPrintf(&obReg.Altitude, L"%d", AltitudeIndex++);
		status = m_pfnObRegisterCallbacks(&obReg, &m_ThreadObCallbackHandle);
	} while (STATUS_FLT_INSTANCE_ALTITUDE_COLLISION == status);

	return status;
}

VOID PsInitialization(PDRIVER_OBJECT pDriverObject)
{
	if (!VmpIsHyperPlatformInstalled()) {	
		UNICODE_STRING routineName;
		RtlInitUnicodeString(&routineName, L"ObRegisterCallbacks");
		m_pfnObRegisterCallbacks = (fnObRegisterCallbacks)MmGetSystemRoutineAddress(&routineName);

		RtlInitUnicodeString(&routineName, L"ObUnRegisterCallbacks");
		m_pfnObUnRegisterCallbacks = (fnObUnRegisterCallbacks)MmGetSystemRoutineAddress(&routineName);

		RtlInitUnicodeString(&routineName, L"ObGetFilterVersion");
		m_pfnObGetFilterVersion = (fnObGetFilterVersion)MmGetSystemRoutineAddress(&routineName);

		if (dynData.OsVer >= WINVER_VISTA)
		{
			auto ldr = (PLDR_DATA_TABLE_ENTRY)pDriverObject->DriverSection;
			ldr->Flags |= 0x20;
		}

		if (m_pfnObRegisterCallbacks && m_pfnObGetFilterVersion) {
			SetProcessObCallback();
			SetThreadObCallback();
		}
	}

	PsSetLoadImageNotifyRoutine(LoadImageNotifyCallback);
	PsSetCreateProcessNotifyRoutine(CreateProcessNotifyRoutine, FALSE);
	PsSetCreateThreadNotifyRoutine(CreateThreadNotifyCallback);
}

VOID PsTermination(VOID)
{
	PAGED_CODE();
	if (m_pfnObUnRegisterCallbacks) {
		if(m_ProcessObCallbackHandle != NULL)
			m_pfnObUnRegisterCallbacks(m_ProcessObCallbackHandle);
		if(m_ThreadObCallbackHandle != NULL)
			m_pfnObUnRegisterCallbacks(m_ThreadObCallbackHandle);
	}

	PsRemoveCreateThreadNotifyRoutine(CreateThreadNotifyCallback);
	PsSetCreateProcessNotifyRoutine(CreateProcessNotifyRoutine, TRUE);
	PsRemoveLoadImageNotifyRoutine(LoadImageNotifyCallback);
}

}