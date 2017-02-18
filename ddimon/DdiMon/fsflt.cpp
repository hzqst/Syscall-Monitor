#include <fltKernel.h>

#define NTSTRSAFE_NO_CB_FUNCTIONS
#include <ntstrsafe.h>
#include "../HyperPlatform/common.h"
#include "../HyperPlatform/kernel_stl.h"
#include "../HyperPlatform/performance.h"
#include "../../Shared/Protocol.h"
#include <set>
#include <vector>

#include "main.h"

PFLT_FILTER m_pFilterHandle = NULL;
PFLT_PORT 	m_pServerPort = NULL;
PFLT_PORT 	m_pClientPort = NULL;
HANDLE m_SyscallMonPID = NULL;

extern CProcList *m_IgnoreProcList;
extern CFileList *m_IgnoreFileList;
extern CEventList *m_EventList;

NTSTATUS NtFileNameToDosFileName(IN PUNICODE_STRING NtFileName, OUT PUNICODE_STRING DosFileName);
NTSTATUS GetDeviceDosName(IN PDEVICE_OBJECT pDeviceObject, OUT PUNICODE_STRING ustrDosName);
NTSTATUS GetFileDosName(IN PFILE_OBJECT pFileObject, OUT PUNICODE_STRING ustrDosName);
NTSTATUS GetDeviceDosNameUnsafe(IN PDEVICE_OBJECT pDeviceObject, OUT PUNICODE_STRING ustrDosName);

EXTERN_C
{

VOID EnumSystemModules(VOID);
VOID SendCallStackEvent(ULONG64 EventId);
PVOID CreateCallStackEvent(ULONG64 EventId);
BOOLEAN IsFsCallbackIgnored(VOID);

NTSTATUS DriverEntryFilter(__in PDRIVER_OBJECT DriverObject, __in PUNICODE_STRING RegistryPath);
NTSTATUS FLTAPI FsUnload(__in FLT_FILTER_UNLOAD_FLAGS Flags);
VOID InitDynVers(VOID);
VOID FreeDynVers(VOID);

#if defined(ALLOC_PRAGMA)
#pragma alloc_text(INIT, DriverEntryFilter)
#pragma alloc_text(INIT, InitDynVers)
#pragma alloc_text(PAGE, FsUnload)
#pragma alloc_text(PAGE, FreeDynVers)
#endif

typedef struct
{
	UNICODE_STRING NtFilePath;
	UNICODE_STRING DosFilePath;
}flt_file_context_t;

typedef struct
{
	PVOID data;
	PVOID callstack;
}flt_data_context_t;

NTSTATUS FLTAPI FsMessageNotifyCallback(
	IN PVOID PortCookie,
	IN PVOID InputBuffer OPTIONAL,
	IN ULONG InputBufferLength,
	OUT PVOID OutputBuffer OPTIONAL,
	IN ULONG OutputBufferLength,
	OUT PULONG ReturnOutputBufferLength);

VOID MessageSenderThread(IN PVOID pContext)
{
	UNREFERENCED_PARAMETER(pContext);

	while (!m_EventList->m_Stop)
	{
		svc_nop_data *msg = NULL;

		if (NT_SUCCESS(KeWaitForSingleObject(&m_EventList->m_MsgEvent, Executive, KernelMode, FALSE, NULL)))
		{
			m_EventList->Lock();
			if (!m_EventList->m_List.empty())
			{
				msg = (svc_nop_data *)m_EventList->m_List.front();
				m_EventList->m_List.pop_front();

				if (!m_EventList->m_List.empty())
					KeSetEvent(&m_EventList->m_MsgEvent, IO_NO_INCREMENT, FALSE);
			}
			m_EventList->Unlock();

			if (msg)
			{
				if (m_pClientPort != NULL)
					FltSendMessage(m_pFilterHandle, &m_pClientPort, msg, msg->size, NULL, NULL, NULL);

				ExFreePoolWithTag(msg, 'TXSB');
			}
		}
	}

	PsTerminateSystemThread(STATUS_SUCCESS);
}

NTSTATUS FLTAPI FsConnectNotifyCallback(IN PFLT_PORT ClientPort, IN PVOID ServerPortCookie, IN PVOID ConnectionContext, IN ULONG SizeOfContext, OUT PVOID * ConnectionPortCookie)
{
	PAGED_CODE();

	UNREFERENCED_PARAMETER(ServerPortCookie);
	UNREFERENCED_PARAMETER(ConnectionContext);
	UNREFERENCED_PARAMETER(SizeOfContext);
	UNREFERENCED_PARAMETER(ConnectionPortCookie);

	if (SizeOfContext == sizeof(conn_context_data))
	{
		conn_context_data *data = (conn_context_data *)ConnectionContext;
		if (data->txsb == 'TXSB' && data->ver == 1)
		{
			m_pClientPort = ClientPort;
			m_SyscallMonPID = PsGetCurrentProcessId();

			m_EventList->FreeAll();
			EnumSystemModules();

			return STATUS_SUCCESS;
		}
	}

	return STATUS_OBJECT_NAME_NOT_FOUND;
}

VOID FLTAPI FsDisconnectNotifyCallback(_In_opt_ PVOID ConnectionCookie)
{
	PAGED_CODE();

	UNREFERENCED_PARAMETER(ConnectionCookie);

	FltCloseClientPort(m_pFilterHandle, &m_pClientPort);
	m_pClientPort = NULL;
	m_SyscallMonPID = NULL;
}

NTSTATUS FLTAPI FsUnload(__in FLT_FILTER_UNLOAD_FLAGS Flags)
{
	UNREFERENCED_PARAMETER(Flags);
	PAGED_CODE();

	HYPERPLATFORM_COMMON_DBG_BREAK();

	InterlockedExchange(&m_EventList->m_Stop, 1);	
	KeSetEvent(&m_EventList->m_MsgEvent, IO_NO_INCREMENT, FALSE);
	if(m_EventList->m_hMsgThread != NULL)
		ZwWaitForSingleObject(m_EventList->m_hMsgThread, FALSE, NULL);
	m_EventList->m_hMsgThread = NULL;

	if (NULL != m_pServerPort) {
		FltCloseCommunicationPort(m_pServerPort);
		m_pServerPort = NULL;
	}
	if (NULL != m_pClientPort) {
		FltCloseClientPort(m_pFilterHandle, &m_pClientPort);
		m_pClientPort = NULL;
	}
	FltUnregisterFilter(m_pFilterHandle);
	m_pFilterHandle = NULL;
	return STATUS_SUCCESS;
};

NTSTATUS FsGetCachedFileName(
	_In_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Out_opt_ PUNICODE_STRING pustrDosFileName
)
{
	PFILE_OBJECT pFileObject = Data->Iopb->TargetFileObject;
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	//Make sure we have a stream context attached to FileObject
	PFLT_CONTEXT pContext = NULL;
	if (NT_SUCCESS(FltGetStreamContext(FltObjects->Instance, pFileObject, &pContext)))
	{
		flt_file_context_t *ctx = (flt_file_context_t *)pContext;

		if (ARGUMENT_PRESENT(pustrDosFileName))
			RtlCopyUnicodeString(pustrDosFileName, &ctx->DosFilePath);

		FltReleaseContext(pContext);

		status = STATUS_SUCCESS;
	}
	else
	{
		ULONG FullLength = 0;
		PFLT_FILE_NAME_INFORMATION pNameInfo = NULL;
		UNICODE_STRING ustrVolumeName = { 0 };
		PUNICODE_STRING pustrVolumeName = NULL;
		PUNICODE_STRING pustrVolumelessName = NULL;

		if (NT_SUCCESS(FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP, &pNameInfo)))
		{
			FullLength = pNameInfo->Name.Length;
		}
		else if (NT_SUCCESS(FltGetFileNameInformation(Data, FLT_FILE_NAME_OPENED | FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP, &pNameInfo)))
		{
			FullLength = pNameInfo->Name.Length;
		}
		else
		{
			ULONG bufNeed = 0;
			if (STATUS_BUFFER_TOO_SMALL == FltGetVolumeName(FltObjects->Volume, NULL, &bufNeed)) {
				ustrVolumeName.Buffer = (PWCH)ExAllocatePoolWithTag(PagedPool, bufNeed, 'TXSB');
				ustrVolumeName.Length = 0;
				ustrVolumeName.MaximumLength = (USHORT)bufNeed;
				if (NT_SUCCESS(FltGetVolumeName(FltObjects->Volume, &ustrVolumeName, NULL))) {
					pustrVolumeName = &ustrVolumeName;
					pustrVolumelessName = &pFileObject->FileName;
					FullLength = pustrVolumeName->Length + pustrVolumelessName->Length;
				}
			}
		}

		if (FullLength > 0 && NT_SUCCESS(FltAllocateContext(m_pFilterHandle, FLT_STREAM_CONTEXT, sizeof(flt_file_context_t), PagedPool, &pContext)))
		{
			flt_file_context_t *ctx = (flt_file_context_t *)pContext;
			ctx->NtFilePath.Buffer = (PWCH)ExAllocatePoolWithTag(PagedPool, FullLength, 'TXSB');
			ctx->NtFilePath.Length = 0;
			ctx->NtFilePath.MaximumLength = (USHORT)FullLength;

			ctx->DosFilePath.Buffer = (PWCH)ExAllocatePoolWithTag(PagedPool, FullLength, 'TXSB');
			ctx->DosFilePath.Length = 0;
			ctx->DosFilePath.MaximumLength = (USHORT)FullLength;

			//full name
			if (pNameInfo) {
				RtlCopyUnicodeString(&ctx->NtFilePath, &pNameInfo->Name);
			} else if (pustrVolumeName && pustrVolumelessName){
				RtlCopyUnicodeString(&ctx->NtFilePath, pustrVolumeName);
				RtlAppendUnicodeStringToString(&ctx->NtFilePath, pustrVolumelessName);
			}

			//Query file system for the device's dos name
			//PIRP lastIRP = IoGetTopLevelIrp();
			//IoSetTopLevelIrp(SYSCALLMON_TOLLEVEL_IRP);
			if (NT_SUCCESS(GetDeviceDosNameUnsafe(pFileObject->DeviceObject, &ctx->DosFilePath)) && ctx->DosFilePath.Length != 0) {
				//concat the name with device dos name
				if (pNameInfo && pNameInfo->Name.Length > pNameInfo->Volume.Length)	{
					UNICODE_STRING ustrVolumelessName;
					ustrVolumelessName.Length = pNameInfo->Name.Length - pNameInfo->Volume.Length;
					ustrVolumelessName.MaximumLength = ustrVolumelessName.Length;
					ustrVolumelessName.Buffer = pNameInfo->Name.Buffer + (pNameInfo->Volume.Length / sizeof(WCHAR));
					RtlAppendUnicodeStringToString(&ctx->DosFilePath, &ustrVolumelessName);
				} else if(pustrVolumelessName) {
					RtlAppendUnicodeStringToString(&ctx->DosFilePath, pustrVolumelessName);
				}
			}
			//IoSetTopLevelIrp(lastIRP);

			if (ARGUMENT_PRESENT(pustrDosFileName))
				RtlCopyUnicodeString(pustrDosFileName, &ctx->DosFilePath);

			//Save name in context
			FltSetStreamContext(FltObjects->Instance, pFileObject, FLT_SET_CONTEXT_REPLACE_IF_EXISTS, pContext, NULL);

			//Dereference the context
			FltReleaseContext(pContext);

			status = STATUS_SUCCESS;
		}

		//Free all
		if (pNameInfo)
			FltReleaseFileNameInformation(pNameInfo);
		if (ustrVolumeName.Buffer)
			ExFreePoolWithTag(ustrVolumeName.Buffer, 'TXSB');
	}

	return status;
}

FLT_PREOP_CALLBACK_STATUS FLTAPI FsPreCallback(
	__inout PFLT_CALLBACK_DATA Data,
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__deref_out_opt PVOID *CompletionContext
)
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);

	PAGED_CODE();

	FLT_PREOP_CALLBACK_STATUS result = FLT_PREOP_SUCCESS_NO_CALLBACK;
	PFILE_OBJECT pFileObject = Data->Iopb->TargetFileObject;
	UNICODE_STRING ustrFilePath = { 0 };

	if (!pFileObject || FsRtlIsPagingFile(pFileObject))
		return result;

	//if(IsFsCallbackIgnored())
	//	return result;

	ULONG64 EventId = 0;

	flt_data_context_t *dataCtx = NULL;

	if (m_EventList->IsCapturing())
	{
		ULONG ProcessId = FltGetRequestorProcessId(Data);

		//if (ProcessId == (ULONG)m_SyscallMonPID || ProcessId == 4)
		//	return result;

		dataCtx = (flt_data_context_t *)
			ExAllocatePoolWithTag(NonPagedPool, sizeof(flt_data_context_t), 'TXSB');
		RtlZeroMemory(dataCtx, sizeof(flt_data_context_t));

		if (Data->Iopb->MajorFunction == IRP_MJ_CREATE)
		{
			EventId = m_EventList->GetEventId();
			if (EventId)
			{
				svc_fs_create_file_data *data = (svc_fs_create_file_data *)
					ExAllocatePoolWithTag(PagedPool, sizeof(svc_fs_create_file_data), 'TXSB');

				if (data)
				{
					RtlZeroMemory(data, sizeof(svc_fs_create_file_data));

					RtlInitEmptyUnicodeString(&ustrFilePath, data->FilePath, sizeof(data->FilePath) - sizeof(WCHAR));

					data->protocol = svc_fs_create_file;
					data->size = sizeof(svc_fs_create_file_data);
					data->time = PerfGetSystemTime();
					data->eventId = EventId;
					data->ProcessId = ProcessId;
					data->ThreadId = (ULONG)PsGetCurrentThreadId();
					data->DesiredAccess = Data->Iopb->Parameters.Create.ShareAccess;
					data->Disposition = (Data->Iopb->Parameters.Create.Options >> 24) & 0x000000ff;
					data->Options = Data->Iopb->Parameters.Create.Options & 0x00ffffff;
					data->DesiredAccess = (Data->Iopb->Parameters.Create.SecurityContext) ? Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess : 0;
					data->ShareAccess = Data->Iopb->Parameters.Create.ShareAccess;
					data->Attributes = Data->Iopb->Parameters.Create.FileAttributes;

					data->ResultStatus = STATUS_SUCCESS;//Modify later

					dataCtx->data = data;
					*CompletionContext = dataCtx;
					result = FLT_PREOP_SUCCESS_WITH_CALLBACK;
				}
			}
		}
		else if (Data->Iopb->MajorFunction == IRP_MJ_CLEANUP)
		{
			EventId = m_EventList->GetEventId();
			if (EventId)
			{
				svc_fs_close_file_data *data = (svc_fs_close_file_data *)
					ExAllocatePoolWithTag(PagedPool, sizeof(svc_fs_close_file_data), 'TXSB');

				if (data)
				{
					RtlZeroMemory(data, sizeof(svc_fs_close_file_data));

					RtlInitEmptyUnicodeString(&ustrFilePath, data->FilePath, sizeof(data->FilePath) - sizeof(WCHAR));

					data->protocol = svc_fs_close_file;
					data->size = sizeof(svc_fs_close_file_data);
					data->time = PerfGetSystemTime();
					data->eventId = EventId;
					data->ProcessId = ProcessId;
					data->ThreadId = (ULONG)PsGetCurrentThreadId();

					data->ResultStatus = STATUS_SUCCESS;

					dataCtx->data = data;
					*CompletionContext = dataCtx;
					result = FLT_PREOP_SUCCESS_WITH_CALLBACK;
				}
			}
		}
		else if (Data->Iopb->MajorFunction == IRP_MJ_READ)
		{
			EventId = m_EventList->GetEventId();
			if (EventId)
			{
				svc_fs_readwrite_file_data *data = (svc_fs_readwrite_file_data *)
					ExAllocatePoolWithTag(PagedPool, sizeof(svc_fs_readwrite_file_data), 'TXSB');

				if (data)
				{
					RtlZeroMemory(data, sizeof(svc_fs_readwrite_file_data));

					RtlInitEmptyUnicodeString(&ustrFilePath, data->FilePath, sizeof(data->FilePath) - sizeof(WCHAR));

					data->protocol = svc_fs_readwrite_file;
					data->size = sizeof(svc_fs_readwrite_file_data);
					data->time = PerfGetSystemTime();
					data->eventId = EventId;
					data->ProcessId = ProcessId;
					data->ThreadId = (ULONG)PsGetCurrentThreadId();
					data->IsWrite = FALSE;
					data->Length = Data->Iopb->Parameters.Read.Length;
					data->ByteOffset = Data->Iopb->Parameters.Read.ByteOffset.QuadPart;
					data->ResultStatus = STATUS_SUCCESS;//Modify later

					dataCtx->data = data;
					*CompletionContext = dataCtx;
					result = FLT_PREOP_SUCCESS_WITH_CALLBACK;
				}
			}
		}
		else if (Data->Iopb->MajorFunction == IRP_MJ_WRITE)
		{
			EventId = m_EventList->GetEventId();
			if (EventId)
			{
				svc_fs_readwrite_file_data *data = (svc_fs_readwrite_file_data *)
					ExAllocatePoolWithTag(PagedPool, sizeof(svc_fs_readwrite_file_data), 'TXSB');

				if (data)
				{
					RtlZeroMemory(data, sizeof(svc_fs_readwrite_file_data));

					RtlInitEmptyUnicodeString(&ustrFilePath, data->FilePath, sizeof(data->FilePath) - sizeof(WCHAR));

					data->protocol = svc_fs_readwrite_file;
					data->size = sizeof(svc_fs_readwrite_file_data);
					data->time = PerfGetSystemTime();
					data->eventId = EventId;
					data->ProcessId = ProcessId;
					data->ThreadId = (ULONG)PsGetCurrentThreadId();
					data->IsWrite = TRUE;
					data->Length = Data->Iopb->Parameters.Write.Length;
					data->ByteOffset = Data->Iopb->Parameters.Write.ByteOffset.QuadPart;
					data->ResultStatus = STATUS_SUCCESS;//Modify later

					dataCtx->data = data;
					*CompletionContext = dataCtx;
					result = FLT_PREOP_SUCCESS_WITH_CALLBACK;
				}
			}
		}
		else if (Data->Iopb->MajorFunction == IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION)
		{
			EventId = m_EventList->GetEventId();
			if (EventId)
			{
				svc_fs_createfilemapping_data *data = (svc_fs_createfilemapping_data *)
					ExAllocatePoolWithTag(PagedPool, sizeof(svc_fs_createfilemapping_data), 'TXSB');

				if (data)
				{
					RtlZeroMemory(data, sizeof(svc_fs_createfilemapping_data));

					RtlInitEmptyUnicodeString(&ustrFilePath, data->FilePath, sizeof(data->FilePath) - sizeof(WCHAR));

					data->protocol = svc_fs_createfilemapping;
					data->size = sizeof(svc_fs_createfilemapping_data);
					data->time = PerfGetSystemTime();
					data->eventId = EventId;
					data->ProcessId = ProcessId;
					data->ThreadId = (ULONG)PsGetCurrentThreadId();
					data->SyncType = Data->Iopb->Parameters.AcquireForSectionSynchronization.SyncType;
					data->PageProtection = Data->Iopb->Parameters.AcquireForSectionSynchronization.PageProtection;
					data->ResultStatus = STATUS_SUCCESS;//Modify later

					dataCtx->data = data;
					*CompletionContext = dataCtx;
					result = FLT_PREOP_SUCCESS_WITH_CALLBACK;
				}
			}
		}
		//Need filename

		if (ustrFilePath.Buffer != NULL)
		{
			FsGetCachedFileName(Data, FltObjects, &ustrFilePath);
		}
	}

	if (dataCtx && dataCtx->data)
	{
		dataCtx->callstack = CreateCallStackEvent(EventId);
	}

	return result;
}

typedef struct
{
	flt_data_context_t *dataCtx;
	NTSTATUS ResultStatus;
}FsPostCallbackSafeContext_t;

VOID FsPostCallbackSafeRoutine(
	_In_ PFLT_GENERIC_WORKITEM FltWorkItem,
	_In_ PVOID FltObject,
	_In_opt_ PVOID Context
)
{
	UNREFERENCED_PARAMETER(FltObject);

	FsPostCallbackSafeContext_t *routineCtx = (FsPostCallbackSafeContext_t *)Context;
	flt_data_context_t *dataCtx = routineCtx->dataCtx;
	svc_nop_data *header = (svc_nop_data *)dataCtx->data;

	if (header->protocol == svc_fs_create_file)
	{
		svc_fs_create_file_data *data = (svc_fs_create_file_data *)dataCtx->data;
		data->ResultStatus = routineCtx->ResultStatus;
	}
	else if (header->protocol == svc_fs_close_file)
	{
		svc_fs_close_file_data *data = (svc_fs_close_file_data *)dataCtx->data;
		data->ResultStatus = routineCtx->ResultStatus;
	}
	else if (header->protocol == svc_fs_readwrite_file)
	{
		svc_fs_readwrite_file_data *data = (svc_fs_readwrite_file_data *)dataCtx->data;
		data->ResultStatus = routineCtx->ResultStatus;
	}
	else if (header->protocol == svc_fs_createfilemapping)
	{
		svc_fs_createfilemapping_data *data = (svc_fs_createfilemapping_data *)dataCtx->data;
		data->ResultStatus = routineCtx->ResultStatus;
	}
	m_EventList->Lock();
	m_EventList->SendEvent(dataCtx->data);
	m_EventList->SendEvent(dataCtx->callstack);
	m_EventList->Unlock();
	m_EventList->NotifyEvent();

	ExFreePoolWithTag(dataCtx, 'TXSB');
	ExFreePoolWithTag(routineCtx, 'TXSB');

	FltFreeGenericWorkItem(FltWorkItem);
}

FLT_POSTOP_CALLBACK_STATUS FLTAPI FsPostCallback(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
) {
	UNREFERENCED_PARAMETER(FltObjects);

	FLT_POSTOP_CALLBACK_STATUS result = FLT_POSTOP_FINISHED_PROCESSING;
	flt_data_context_t *dataCtx = (flt_data_context_t *)CompletionContext;

	if (FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING))
	{
		if (dataCtx->callstack != NULL)
			ExFreePoolWithTag(dataCtx->callstack, 'TXSB');
		if (dataCtx->data != NULL)
			ExFreePoolWithTag(dataCtx->data, 'TXSB');
		if (dataCtx != NULL)
			ExFreePoolWithTag(dataCtx, 'TXSB');

		return result;
	}

	BOOLEAN bSuccess = FALSE;
	PFLT_GENERIC_WORKITEM pWorkItem = NULL;
	FsPostCallbackSafeContext_t *routineCtx = NULL;

	if (CompletionContext != NULL)
	{
		pWorkItem = FltAllocateGenericWorkItem();
		if (pWorkItem)
		{
			routineCtx = (FsPostCallbackSafeContext_t *)ExAllocatePoolWithTag(NonPagedPool, sizeof(FsPostCallbackSafeContext_t), 'TXSB');
			if (routineCtx)
			{
				routineCtx->dataCtx = (flt_data_context_t *)dataCtx;
				routineCtx->ResultStatus = Data->IoStatus.Status;

				if (NT_SUCCESS(FltQueueGenericWorkItem(pWorkItem, FltObjects->Instance,
					(PFLT_GENERIC_WORKITEM_ROUTINE)FsPostCallbackSafeRoutine, DelayedWorkQueue, routineCtx)))
				{
					bSuccess = TRUE;
				}
			}
		}
	}

	if (!bSuccess)
	{
		if (dataCtx->callstack != NULL)
			ExFreePoolWithTag(dataCtx->callstack, 'TXSB');
		if (dataCtx->data != NULL)
			ExFreePoolWithTag(dataCtx->data, 'TXSB');
		if (dataCtx != NULL)
			ExFreePoolWithTag(dataCtx, 'TXSB');
		if (routineCtx != NULL)
			ExFreePoolWithTag(routineCtx, 'TXSB');
		if (pWorkItem != NULL)
			FltFreeGenericWorkItem(pWorkItem);
	}

	return result;
}

FLT_PREOP_CALLBACK_STATUS FLTAPI FsPreQueryInformation(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID *CompletionContext
)
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	PAGED_CODE();

	FLT_PREOP_CALLBACK_STATUS result = FLT_PREOP_SUCCESS_NO_CALLBACK;

	PFILE_OBJECT pFileObject = Data->Iopb->TargetFileObject;

	if (!pFileObject || FsRtlIsPagingFile(pFileObject))
		return result;

	//if (IsFsCallbackIgnored())
	//	return result;

	ULONG64 EventId = 0;
	flt_data_context_t *dataCtx = NULL;
	UNICODE_STRING ustrFilePath = { 0 };

	if (m_EventList->IsCapturing())
	{
		EventId = m_EventList->GetEventId();
		if (EventId)
		{
			ULONG ExtraNameLength = 0;

			if (Data->Iopb->Parameters.QueryFileInformation.FileInformationClass == FileNameInformation)
			{
				ExtraNameLength = Data->Iopb->Parameters.QueryFileInformation.Length - sizeof(FILE_NAME_INFORMATION);
			}
			else if (Data->Iopb->Parameters.QueryFileInformation.FileInformationClass == FileAllInformation)
			{
				ExtraNameLength = Data->Iopb->Parameters.QueryFileInformation.Length - sizeof(FILE_ALL_INFORMATION);
			}

			dataCtx = (flt_data_context_t *)
				ExAllocatePoolWithTag(NonPagedPool, sizeof(flt_data_context_t), 'TXSB');
			
			if (dataCtx)
			{
				RtlZeroMemory(dataCtx, sizeof(flt_data_context_t));

				svc_fs_queryfileinformation_data *data = (svc_fs_queryfileinformation_data *)
					ExAllocatePoolWithTag(PagedPool, sizeof(svc_fs_queryfileinformation_data) + ExtraNameLength, 'TXSB');

				if (data)
				{
					RtlZeroMemory(data, sizeof(svc_fs_queryfileinformation_data));

					RtlInitEmptyUnicodeString(&ustrFilePath, data->FilePath, sizeof(data->FilePath) - sizeof(WCHAR));

					data->protocol = svc_fs_queryfileinformation;
					data->size = sizeof(svc_fs_queryfileinformation_data) + ExtraNameLength;
					data->time = PerfGetSystemTime();
					data->eventId = EventId;
					data->ProcessId = FltGetRequestorProcessId(Data);
					data->ThreadId = (ULONG)PsGetCurrentThreadId();
					data->QueryClass = (ULONG)Data->Iopb->Parameters.QueryFileInformation.FileInformationClass;
					data->ResultStatus = STATUS_SUCCESS;//Modify later

					dataCtx->data = data;
					*CompletionContext = dataCtx;
					result = FLT_PREOP_SYNCHRONIZE;
				}
			}
		}
	}

	if (dataCtx)
	{
		//Need filename

		if (ustrFilePath.Buffer != NULL)
		{
			FsGetCachedFileName(Data, FltObjects, &ustrFilePath);
		}

		dataCtx->callstack = CreateCallStackEvent(EventId);
	}

	return result;
}

FLT_POSTOP_CALLBACK_STATUS FLTAPI FsPostQueryInformation(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
)
{
	UNREFERENCED_PARAMETER(FltObjects);

	FLT_POSTOP_CALLBACK_STATUS result = FLT_POSTOP_FINISHED_PROCESSING;

	flt_data_context_t *dataCtx = (flt_data_context_t *)CompletionContext;

	if (FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING))
	{
		if (dataCtx->callstack != NULL)
			ExFreePoolWithTag(dataCtx->callstack, 'TXSB');
		if (dataCtx->data != NULL)
			ExFreePoolWithTag(dataCtx->data, 'TXSB');
		if (dataCtx != NULL)
			ExFreePoolWithTag(dataCtx, 'TXSB');

		return result;
	}

	if (dataCtx)
	{
		svc_fs_queryfileinformation_data *data = (svc_fs_queryfileinformation_data *)dataCtx->data;
		data->ResultStatus = Data->IoStatus.Status;

		if (NT_SUCCESS(Data->IoStatus.Status) || Data->IoStatus.Status == STATUS_BUFFER_OVERFLOW)
		{
			__try
			{
				if (Data->Iopb->Parameters.QueryFileInformation.FileInformationClass == FileAllInformation)
				{
					PFILE_ALL_INFORMATION pAllInfo = (PFILE_ALL_INFORMATION)Data->Iopb->Parameters.QueryFileInformation.InfoBuffer;
					RtlCopyMemory(&data->AllInfo, pAllInfo, sizeof(FILE_ALL_INFORMATION));
					ULONG MaxCopy = min((ULONG)((PUCHAR)data + data->size - (PUCHAR)data->AllInfo.NameInformation.FileName), pAllInfo->NameInformation.FileNameLength);
					RtlCopyMemory(data->AllInfo.NameInformation.FileName, pAllInfo->NameInformation.FileName, MaxCopy);
				}
				else if (Data->Iopb->Parameters.QueryFileInformation.FileInformationClass == FileNameInformation)
				{
					PFILE_NAME_INFORMATION pNameInfo = (PFILE_NAME_INFORMATION)Data->Iopb->Parameters.QueryFileInformation.InfoBuffer;
					RtlCopyMemory(&data->AllInfo.NameInformation, pNameInfo, sizeof(FILE_NAME_INFORMATION));
					ULONG MaxCopy = min((ULONG)((PUCHAR)data + data->size - (PUCHAR)data->AllInfo.NameInformation.FileName), pNameInfo->FileNameLength);
					RtlCopyMemory(data->AllInfo.NameInformation.FileName, pNameInfo->FileName, MaxCopy);
				}
				else if (Data->Iopb->Parameters.QueryFileInformation.FileInformationClass == FileBasicInformation)
				{
					PFILE_BASIC_INFORMATION pBasicInfo = (PFILE_BASIC_INFORMATION)Data->Iopb->Parameters.QueryFileInformation.InfoBuffer;
					RtlCopyMemory(&data->AllInfo.BasicInformation, pBasicInfo, sizeof(FILE_BASIC_INFORMATION));
				}
				else if (Data->Iopb->Parameters.QueryFileInformation.FileInformationClass == FileStandardInformation)
				{
					PFILE_STANDARD_INFORMATION pStandardInfo = (PFILE_STANDARD_INFORMATION)Data->Iopb->Parameters.QueryFileInformation.InfoBuffer;
					RtlCopyMemory(&data->AllInfo.StandardInformation, pStandardInfo, sizeof(FILE_STANDARD_INFORMATION));
				}
				else if (Data->Iopb->Parameters.QueryFileInformation.FileInformationClass == FileInternalInformation)
				{
					PFILE_INTERNAL_INFORMATION pInternalInfo = (PFILE_INTERNAL_INFORMATION)Data->Iopb->Parameters.QueryFileInformation.InfoBuffer;
					RtlCopyMemory(&data->AllInfo.InternalInformation, pInternalInfo, sizeof(FILE_INTERNAL_INFORMATION));
				}
				else if (Data->Iopb->Parameters.QueryFileInformation.FileInformationClass == FileEaInformation)
				{
					PFILE_EA_INFORMATION pEaInfo = (PFILE_EA_INFORMATION)Data->Iopb->Parameters.QueryFileInformation.InfoBuffer;
					RtlCopyMemory(&data->AllInfo.EaInformation, pEaInfo, sizeof(FILE_EA_INFORMATION));
				}
				else if (Data->Iopb->Parameters.QueryFileInformation.FileInformationClass == FileAccessInformation)
				{
					PFILE_ACCESS_INFORMATION pAccessInfo = (PFILE_ACCESS_INFORMATION)Data->Iopb->Parameters.QueryFileInformation.InfoBuffer;
					RtlCopyMemory(&data->AllInfo.AccessInformation, pAccessInfo, sizeof(FILE_ACCESS_INFORMATION));
				}
				else if (Data->Iopb->Parameters.QueryFileInformation.FileInformationClass == FilePositionInformation)
				{
					PFILE_POSITION_INFORMATION pPositionInfo = (PFILE_POSITION_INFORMATION)Data->Iopb->Parameters.QueryFileInformation.InfoBuffer;
					RtlCopyMemory(&data->AllInfo.PositionInformation, pPositionInfo, sizeof(FILE_POSITION_INFORMATION));
				}
				else if (Data->Iopb->Parameters.QueryFileInformation.FileInformationClass == FileModeInformation)
				{
					PFILE_MODE_INFORMATION pModeInfo = (PFILE_MODE_INFORMATION)Data->Iopb->Parameters.QueryFileInformation.InfoBuffer;
					RtlCopyMemory(&data->AllInfo.ModeInformation, pModeInfo, sizeof(FILE_MODE_INFORMATION));
				}
				else if (Data->Iopb->Parameters.QueryFileInformation.FileInformationClass == FileAlignmentInformation)
				{
					PFILE_ALIGNMENT_INFORMATION pAlignmentInfo = (PFILE_ALIGNMENT_INFORMATION)Data->Iopb->Parameters.QueryFileInformation.InfoBuffer;
					RtlCopyMemory(&data->AllInfo.AlignmentInformation, pAlignmentInfo, sizeof(FILE_ALIGNMENT_INFORMATION));
				}
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
			}
		}

		m_EventList->Lock();
		if (dataCtx->data)
			m_EventList->SendEvent(dataCtx->data);
		if (dataCtx->callstack)
			m_EventList->SendEvent(dataCtx->callstack);
		m_EventList->Unlock();
		m_EventList->NotifyEvent();
		
		ExFreePoolWithTag(dataCtx, 'TXSB');
	}

	return result;
}

const FLT_OPERATION_REGISTRATION Callbacks[] =
{
	//CreateFile
	{
		IRP_MJ_CREATE,
		FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO,
		FsPreCallback,
		FsPostCallback
	},
	//CloseHandle
	{
		IRP_MJ_CLEANUP,
		FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO,
		FsPreCallback,
		FsPostCallback
	},
	//ReadFile
	{
		IRP_MJ_READ,
		FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO,
		FsPreCallback,
		FsPostCallback
	},
	//WriteFile
	{
		IRP_MJ_WRITE,
		FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO,
		FsPreCallback,
		FsPostCallback
	},
	//CreateFileMapping
	{
		IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION,
		FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO,
		FsPreCallback,
		FsPostCallback
	},
	//QueryInformationFile
	{
		IRP_MJ_QUERY_INFORMATION,
		FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO,
		FsPreQueryInformation,
		FsPostQueryInformation
	},
	/*{
		IRP_MJ_DIRECTORY_CONTROL,
		0,
		FsPreCallback,
		FsPostCallback
	},*/
	{
		IRP_MJ_OPERATION_END
	}
};

VOID FLTAPI FsFileContextCleanup(
	_In_ PFLT_CONTEXT Context,
	_In_ FLT_CONTEXT_TYPE ContextType)
{
	UNREFERENCED_PARAMETER(ContextType);

	flt_file_context_t *ctx = (flt_file_context_t *)Context;
	ctx->NtFilePath.Length = 0;
	ctx->NtFilePath.MaximumLength = 0;
	if (ctx->NtFilePath.Buffer != NULL)
	{
		ExFreePoolWithTag(ctx->NtFilePath.Buffer, 'TXSB');
		ctx->NtFilePath.Buffer = NULL;
	}

	ctx->DosFilePath.Length = 0;
	ctx->DosFilePath.MaximumLength = 0;
	if (ctx->DosFilePath.Buffer != NULL)
	{
		ExFreePoolWithTag(ctx->DosFilePath.Buffer, 'TXSB');
		ctx->DosFilePath.Buffer = NULL;
	}
}

const FLT_CONTEXT_REGISTRATION ContextRegistration[] = {

	{ FLT_STREAM_CONTEXT,
	0,
	FsFileContextCleanup,
	sizeof(flt_file_context_t),
	'TXSB' },

	{ FLT_CONTEXT_END }
};

const FLT_REGISTRATION FilterRegistration =
{
	sizeof(FLT_REGISTRATION),         //  Size
	FLT_REGISTRATION_VERSION,           //  Version
	0,                                  //  Flags
	ContextRegistration,                               //  Context
	Callbacks,                          //  Operation callbacks
	FsUnload,                           //  MiniFilterUnload
	NULL,								//  InstanceSetup
	NULL,								//  InstanceQueryTeardown
	NULL,								//  InstanceTeardownStart
	NULL,								//  InstanceTeardownComplete
	NULL,                               //  GenerateFileName
	NULL,                               //  GenerateDestinationFileName
	NULL                                //  NormalizeNameComponent
};

NTSTATUS DriverEntryFilter(__in PDRIVER_OBJECT DriverObject, __in PUNICODE_STRING RegistryPath)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PSECURITY_DESCRIPTOR sd;
	OBJECT_ATTRIBUTES oa;
	UNICODE_STRING ustrName;

	UNREFERENCED_PARAMETER(RegistryPath);
	__try
	{
		status = FltRegisterFilter(DriverObject, &FilterRegistration, &m_pFilterHandle);
		if (!NT_SUCCESS(status))
			__leave;

		status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
		if (!NT_SUCCESS(status))
			__leave;

		RtlInitUnicodeString(&ustrName, L"\\SyscallMonPort");
		InitializeObjectAttributes(&oa, &ustrName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, sd);
		status = FltCreateCommunicationPort(m_pFilterHandle, &m_pServerPort, &oa, NULL, FsConnectNotifyCallback, FsDisconnectNotifyCallback, FsMessageNotifyCallback, 1);
		FltFreeSecurityDescriptor(sd);

		status = FltStartFiltering(m_pFilterHandle);
		if (!NT_SUCCESS(status))
			__leave;

		PsCreateSystemThread(&m_EventList->m_hMsgThread, THREAD_ALL_ACCESS, NULL, NULL, NULL, MessageSenderThread, NULL);
	}
	__finally
	{
		if (!NT_SUCCESS(status))
		{
			if (NULL != m_pServerPort) {
				FltCloseCommunicationPort(m_pServerPort);
				m_pServerPort = NULL;
			}
			if (NULL != m_pFilterHandle) {
				FltUnregisterFilter(m_pFilterHandle);
				m_pFilterHandle = NULL;
			}
		}
	}
	return status;
}

VOID InitDynVers(VOID)
{
	m_IgnoreProcList = new CProcList();
	m_IgnoreFileList = new CFileList();
	m_EventList = new CEventList();
}

VOID FreeDynVers(VOID)
{
	delete m_IgnoreProcList;
	m_IgnoreProcList = NULL;

	delete m_IgnoreFileList;
	m_IgnoreFileList = NULL;

	delete m_EventList;
	m_EventList = NULL;
}

}//EXTERN C