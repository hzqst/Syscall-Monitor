#include <fltKernel.h>

#define NTSTRSAFE_NO_CB_FUNCTIONS
#include <ntstrsafe.h>
#include "../HyperPlatform/kernel_stl.h"
#include "../HyperPlatform/performance.h"
#include "main.h"
#include "../../Shared/Protocol.h"

extern CEventList *m_EventList;

EXTERN_C
{

VOID CmInitialization(PDRIVER_OBJECT pDriverObject);
VOID CmTermination(VOID);

#if defined(ALLOC_PRAGMA)
#pragma alloc_text(INIT, CmInitialization)
#pragma alloc_text(PAGE, CmTermination)
#endif

LARGE_INTEGER m_CmCookie = {0};

PVOID CreateCallStackEvent(ULONG64 EventId);
HANDLE GetCsrssProcessId(VOID);

NTKERNELAPI NTSTATUS NTAPI RtlFormatCurrentUserKeyPath(_Out_ PUNICODE_STRING CurrentUserKeyPath);

NTSTATUS (*m_pfnGetRegistryObjectName)(_In_ PVOID Object, _In_ ULONG ReservedLength, _Out_ PUNICODE_STRING FullPath) = NULL;
NTSTATUS (*m_pfnCmCallbackGetKeyObjectID)(_In_ PLARGE_INTEGER Cookie, _In_ PVOID Object, _Out_opt_ PULONG_PTR ObjectID, _Outptr_opt_ PCUNICODE_STRING *ObjectName) = NULL;

NTSTATUS GetRegistryObjectNameVista(_In_ PVOID Object, _In_ ULONG ReservedLength, _Out_ PUNICODE_STRING KeyPath)
{
	PCUNICODE_STRING pKeyName = NULL;

	NTSTATUS status = m_pfnCmCallbackGetKeyObjectID(&m_CmCookie, Object, NULL, &pKeyName);

	if (NT_SUCCESS(status) && pKeyName)
	{
		KeyPath->MaximumLength = pKeyName->Length + ReservedLength;
		KeyPath->Length = 0;
		KeyPath->Buffer = (PWCH)ExAllocatePoolWithTag(PagedPool, KeyPath->MaximumLength, 'TXSB');

		if (KeyPath->Buffer)
		{
			RtlCopyUnicodeString(KeyPath, pKeyName);
			status = STATUS_SUCCESS;
		}
		else
		{
			status = STATUS_INSUFFICIENT_RESOURCES;
		}
	}

	return status;
}

NTSTATUS GetRegistryObjectNameXP(_In_ PVOID Object, _In_ ULONG ReservedLength, _Out_ PUNICODE_STRING KeyPath)
{
	ULONG returnedLength = 0;
	POBJECT_NAME_INFORMATION pObjectName = NULL;
	NTSTATUS status = ObQueryNameString(Object, pObjectName, 0, &returnedLength);
	if (status == STATUS_INFO_LENGTH_MISMATCH)
	{
		pObjectName = (POBJECT_NAME_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, returnedLength, 'TXSB');
		status = ObQueryNameString(Object, pObjectName, returnedLength, &returnedLength);
		if (NT_SUCCESS(status))
		{
			KeyPath->MaximumLength = returnedLength + ReservedLength;
			KeyPath->Length = 0;
			KeyPath->Buffer = (PWCH)ExAllocatePoolWithTag(PagedPool, KeyPath->MaximumLength, 'TXSB');
			if (KeyPath->Buffer)
			{
				RtlCopyUnicodeString(KeyPath, &pObjectName->Name);
				status = STATUS_SUCCESS;
			}
			else
			{
				status = STATUS_INSUFFICIENT_RESOURCES;
			}
		}
		ExFreePoolWithTag(pObjectName, 'TXSB');
	}
	return status;
}

//The FullPath is callee allocate, and should be freed by caller with ExFreePool
NTSTATUS GetRegistryObjectFullName(_In_ PVOID RootObject, _In_opt_ PUNICODE_STRING CompleteName, _Out_ PUNICODE_STRING FullPath)
{
	//Absolute path
	if (CompleteName && CompleteName->Length >= 1 && CompleteName->Buffer[0] == '\\')
	{
		FullPath->MaximumLength = CompleteName->Length;
		FullPath->Length = 0;
		FullPath->Buffer = (PWCH)ExAllocatePoolWithTag(PagedPool, FullPath->MaximumLength, 'TXSB');
		if (FullPath->Buffer)
		{
			RtlCopyUnicodeString(FullPath, CompleteName);
			return STATUS_SUCCESS;
		}
		else
		{
			return STATUS_INSUFFICIENT_RESOURCES;
		}
	}

	//Reserve space for L"\\"
	NTSTATUS st = m_pfnGetRegistryObjectName(RootObject, (CompleteName) ? CompleteName->Length + 2 : 0, FullPath);
	if (!NT_SUCCESS(st))
		return st;

	if (CompleteName) 
	{
		RtlAppendUnicodeToString(FullPath, L"\\");
		RtlAppendUnicodeStringToString(FullPath, CompleteName);
	}

	return STATUS_SUCCESS;
}

NTSTATUS NormalizeRegistryPath(_In_ PUNICODE_STRING FullPath, _Out_ PUNICODE_STRING NormalizedPath)
{
	UNICODE_STRING Prefix, Append;
	NTSTATUS st = STATUS_UNSUCCESSFUL;

	do
	{
		RtlInitUnicodeString(&Prefix, L"\\REGISTRY\\MACHINE\\SOFTWARE\\CLASSES");
		if (RtlPrefixUnicodeString(&Prefix, FullPath, TRUE))
		{
			Append.Buffer = (PWCH)((PUCHAR)FullPath->Buffer + Prefix.Length);
			Append.Length = FullPath->Length - Prefix.Length;
			Append.MaximumLength = Append.Length;

			RtlUnicodeStringCopyString(NormalizedPath, L"\\HKCR");
			RtlAppendUnicodeStringToString(NormalizedPath, &Append);
			st = STATUS_SUCCESS;
			break;
		}

		RtlInitUnicodeString(&Prefix, L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Hardware Profiles\\Current");
		if (RtlPrefixUnicodeString(&Prefix, FullPath, TRUE))
		{
			Append.Buffer = (PWCH)((PUCHAR)FullPath->Buffer + Prefix.Length);
			Append.Length = FullPath->Length - Prefix.Length;
			Append.MaximumLength = Append.Length;

			RtlUnicodeStringCopyString(NormalizedPath, L"\\HKCC");
			RtlAppendUnicodeStringToString(NormalizedPath, &Append);
			st = STATUS_SUCCESS;
			break;
		}

		UNICODE_STRING ustrHKCU;

		if (NT_SUCCESS(RtlFormatCurrentUserKeyPath(&ustrHKCU)))
		{
			if (RtlPrefixUnicodeString(&ustrHKCU, FullPath, TRUE))
			{
				Append.Buffer = (PWCH)((PUCHAR)FullPath->Buffer + ustrHKCU.Length);
				Append.Length = FullPath->Length - ustrHKCU.Length;
				Append.MaximumLength = Append.Length;

				NT_ASSERT(Append.Length >= 0);

				RtlInitUnicodeString(&Prefix, L"_CLASSES");
				if (RtlPrefixUnicodeString(&Prefix, &Append, TRUE))
				{
					Append.Buffer = (PWCH)((PUCHAR)FullPath->Buffer + ustrHKCU.Length + Prefix.Length);
					Append.Length = FullPath->Length - ustrHKCU.Length - Prefix.Length;
					Append.MaximumLength = Append.Length;

					NT_ASSERT(Append.Length >= 0);

					RtlUnicodeStringCopyString(NormalizedPath, L"\\HKCU\\Software\\Classes");
					RtlAppendUnicodeStringToString(NormalizedPath, &Append);
				}
				else
				{
					RtlUnicodeStringCopyString(NormalizedPath, L"\\HKCU");
					RtlAppendUnicodeStringToString(NormalizedPath, &Append);
				}
				st = STATUS_SUCCESS;
			}
			RtlFreeUnicodeString(&ustrHKCU);
			if(st == STATUS_SUCCESS)
				break;
		}

		RtlInitUnicodeString(&Prefix, L"\\REGISTRY\\MACHINE");
		if (RtlPrefixUnicodeString(&Prefix, FullPath, TRUE))
		{
			Append.Buffer = (PWCH)((PUCHAR)FullPath->Buffer + Prefix.Length);
			Append.Length = FullPath->Length - Prefix.Length;
			Append.MaximumLength = Append.Length;

			RtlUnicodeStringCopyString(NormalizedPath, L"\\HKLM");
			RtlAppendUnicodeStringToString(NormalizedPath, &Append);
			st = STATUS_SUCCESS;
			break;
		}

		RtlInitUnicodeString(&Prefix, L"\\REGISTRY\\USER");
		if (RtlPrefixUnicodeString(&Prefix, FullPath, TRUE))
		{
			Append.Buffer = (PWCH)((PUCHAR)FullPath->Buffer + Prefix.Length);
			Append.Length = FullPath->Length - Prefix.Length;
			Append.MaximumLength = Append.Length;

			RtlUnicodeStringCopyString(NormalizedPath, L"\\HKU");
			RtlAppendUnicodeStringToString(NormalizedPath, &Append);
			st = STATUS_SUCCESS;
			break;
		}
	} while (0);

	return st;
}

NTSTATUS RegPostCreateOpenKeyEx(_In_ const PREG_POST_OPERATION_INFORMATION Information, BOOLEAN bIsOpen)
{
	svc_reg_createopenkey_data *data = (svc_reg_createopenkey_data *)
		ExAllocatePoolWithTag(PagedPool, sizeof(svc_reg_createopenkey_data), 'TXSB');

	if (data)
	{
		ULONG64 EventId = m_EventList->GetEventId();

		RtlZeroMemory(data, sizeof(svc_reg_createopenkey_data));
		data->protocol = svc_reg_createopenkey;
		data->size = sizeof(svc_reg_createopenkey_data);
		data->time = PerfGetSystemTime();
		data->eventId = EventId;
		data->ResultStatus = Information->Status;
		data->ProcessId = (ULONG)PsGetCurrentProcessId();
		data->ThreadId = (ULONG)PsGetCurrentThreadId();
		data->IsOpen = bIsOpen;

		const auto pCreateInformation = (PREG_CREATE_KEY_INFORMATION)Information->PreInformation;
		data->CreateOptions = pCreateInformation->CreateOptions;
		data->DesiredAccess = pCreateInformation->DesiredAccess;
		data->Disposition = (pCreateInformation->Disposition) ? *pCreateInformation->Disposition : 0;

		UNICODE_STRING ustrKeyNameTemp, ustrKeyName;
		NTSTATUS stGetName;
		if (Information->Status == STATUS_SUCCESS)
			stGetName = GetRegistryObjectFullName(Information->Object, NULL, &ustrKeyNameTemp);
		else
			stGetName = GetRegistryObjectFullName(pCreateInformation->RootObject, pCreateInformation->CompleteName, &ustrKeyNameTemp);
		
		if (NT_SUCCESS(stGetName))
		{
			RtlInitEmptyUnicodeString(&ustrKeyName, data->KeyPath, sizeof(data->KeyPath) - sizeof(WCHAR));
			NormalizeRegistryPath(&ustrKeyNameTemp, &ustrKeyName);

			ExFreePoolWithTag(ustrKeyNameTemp.Buffer, 'TXSB');
		}

		m_EventList->Lock();
		m_EventList->SendEvent(data);
		m_EventList->SendEvent(CreateCallStackEvent(EventId));
		m_EventList->Unlock();
		m_EventList->NotifyEvent();
	}

	return STATUS_SUCCESS;
}

NTSTATUS RegPostSetValueKey(_In_ const PREG_POST_OPERATION_INFORMATION Information)
{
	const auto pSetValueInformation = (PREG_SET_VALUE_KEY_INFORMATION)Information->PreInformation;
	ULONG MaxCopySize = min(pSetValueInformation->DataSize, 128);

	svc_reg_setvaluekey_data *data = (svc_reg_setvaluekey_data *)
		ExAllocatePoolWithTag(PagedPool, sizeof(svc_reg_setvaluekey_data) + MaxCopySize, 'TXSB');

	if (data)
	{
		ULONG64 EventId = m_EventList->GetEventId();

		RtlZeroMemory(data, sizeof(svc_reg_setvaluekey_data) + MaxCopySize);
		data->protocol = svc_reg_setvaluekey;
		data->size = sizeof(svc_reg_setvaluekey_data) + MaxCopySize;
		data->time = PerfGetSystemTime();
		data->eventId = EventId;
		data->ResultStatus = Information->Status;
		data->ProcessId = (ULONG)PsGetCurrentProcessId();
		data->ThreadId = (ULONG)PsGetCurrentThreadId();

		data->DataType = pSetValueInformation->Type;
		data->DataSize = pSetValueInformation->DataSize;
		data->CopySize = MaxCopySize;		
		if (MaxCopySize && pSetValueInformation->Data)
		{
			__try {
				memcpy(data->CopyData, pSetValueInformation->Data, MaxCopySize);
			} __except (EXCEPTION_EXECUTE_HANDLER) {

			}
		}
		UNICODE_STRING ustrKeyNameTemp, ustrKeyName;

		RtlInitEmptyUnicodeString(&ustrKeyName, data->ValueName, sizeof(data->ValueName) - sizeof(WCHAR));
		
		if (pSetValueInformation->ValueName)
		{
			__try {
				RtlCopyUnicodeString(&ustrKeyName, pSetValueInformation->ValueName);
			} __except (EXCEPTION_EXECUTE_HANDLER) {

			}
		}

		NTSTATUS stGetName = GetRegistryObjectFullName(Information->Object, NULL, &ustrKeyNameTemp);

		if (NT_SUCCESS(stGetName))
		{
			RtlInitEmptyUnicodeString(&ustrKeyName, data->KeyPath, sizeof(data->KeyPath) - sizeof(WCHAR));
			NormalizeRegistryPath(&ustrKeyNameTemp, &ustrKeyName);

			ExFreePoolWithTag(ustrKeyNameTemp.Buffer, 'TXSB');
		}

		m_EventList->Lock();
		m_EventList->SendEvent(data);
		m_EventList->SendEvent(CreateCallStackEvent(EventId));
		m_EventList->Unlock();
		m_EventList->NotifyEvent();
	}

	return STATUS_SUCCESS;
}

NTSTATUS RegPostQueryValueKey(_In_ const PREG_POST_OPERATION_INFORMATION Information)
{
	const auto pQueryValueInformation = (PREG_QUERY_VALUE_KEY_INFORMATION)Information->PreInformation;
	ULONG MaxCopySize = 0;
	__try {
		if (pQueryValueInformation->ResultLength)
			MaxCopySize = *pQueryValueInformation->ResultLength;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {

	}
	if (MaxCopySize > pQueryValueInformation->Length)
		MaxCopySize = pQueryValueInformation->Length;
	if (MaxCopySize > 128)
		MaxCopySize = 128;

	svc_reg_queryvaluekey_data *data = (svc_reg_queryvaluekey_data *)
		ExAllocatePoolWithTag(PagedPool, sizeof(svc_reg_queryvaluekey_data) + MaxCopySize, 'TXSB');

	if (data)
	{
		ULONG64 EventId = m_EventList->GetEventId();

		RtlZeroMemory(data, sizeof(svc_reg_queryvaluekey_data) + MaxCopySize);
		data->protocol = svc_reg_queryvaluekey;
		data->size = sizeof(svc_reg_queryvaluekey_data) + MaxCopySize;
		data->time = PerfGetSystemTime();
		data->eventId = EventId;
		data->ResultStatus = Information->Status;
		data->ProcessId = (ULONG)PsGetCurrentProcessId();
		data->ThreadId = (ULONG)PsGetCurrentThreadId();

		data->QueryClass = pQueryValueInformation->KeyValueInformationClass;
		data->QueryLength = pQueryValueInformation->Length;

		UNICODE_STRING ustrKeyNameTemp, ustrKeyName;

		if (Information->Status == STATUS_SUCCESS || Information->Status == STATUS_BUFFER_OVERFLOW || Information->Status == STATUS_BUFFER_TOO_SMALL)
		{
			data->DataSize = (pQueryValueInformation->ResultLength) ? *pQueryValueInformation->ResultLength : 0;
			data->CopySize = MaxCopySize;
			if (MaxCopySize && pQueryValueInformation->KeyValueInformation)
			{
				__try {
					memcpy(data->CopyData, pQueryValueInformation->KeyValueInformation, MaxCopySize);
				}
				__except (EXCEPTION_EXECUTE_HANDLER) {

				}
			}
			
			RtlInitEmptyUnicodeString(&ustrKeyName, data->ValueName, sizeof(data->ValueName) - sizeof(WCHAR));

			if (pQueryValueInformation->ValueName)
			{
				__try {
					RtlCopyUnicodeString(&ustrKeyName, pQueryValueInformation->ValueName);
				}
				__except (EXCEPTION_EXECUTE_HANDLER) {

				}
			}
		}

		NTSTATUS stGetName = GetRegistryObjectFullName(Information->Object, NULL, &ustrKeyNameTemp);

		if (NT_SUCCESS(stGetName))
		{
			RtlInitEmptyUnicodeString(&ustrKeyName, data->KeyPath, sizeof(data->KeyPath) - sizeof(WCHAR));
			NormalizeRegistryPath(&ustrKeyNameTemp, &ustrKeyName);

			ExFreePoolWithTag(ustrKeyNameTemp.Buffer, 'TXSB');
		}

		m_EventList->Lock();
		m_EventList->SendEvent(data);
		m_EventList->SendEvent(CreateCallStackEvent(EventId));
		m_EventList->Unlock();
		m_EventList->NotifyEvent();
	}

	return STATUS_SUCCESS;
}

NTSTATUS RegPostQueryKey(_In_ const PREG_POST_OPERATION_INFORMATION Information)
{
	const auto pQueryKeyInformation = (PREG_QUERY_KEY_INFORMATION)Information->PreInformation;
	ULONG MaxCopySize = 0;
	__try {
		if (pQueryKeyInformation->ResultLength)
			MaxCopySize = *pQueryKeyInformation->ResultLength;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {

	}
	if (MaxCopySize > pQueryKeyInformation->Length)
		MaxCopySize = pQueryKeyInformation->Length;

	if (MaxCopySize > 128)
		MaxCopySize = 128;

	svc_reg_querykey_data *data = (svc_reg_querykey_data *)
		ExAllocatePoolWithTag(PagedPool, sizeof(svc_reg_querykey_data) + MaxCopySize, 'TXSB');

	if (data)
	{
		ULONG64 EventId = m_EventList->GetEventId();

		RtlZeroMemory(data, sizeof(svc_reg_querykey_data) + MaxCopySize);
		data->protocol = svc_reg_querykey;
		data->size = sizeof(svc_reg_querykey_data) + MaxCopySize;
		data->time = PerfGetSystemTime();
		data->eventId = EventId;
		data->ResultStatus = Information->Status;
		data->ProcessId = (ULONG)PsGetCurrentProcessId();
		data->ThreadId = (ULONG)PsGetCurrentThreadId();

		data->QueryClass = pQueryKeyInformation->KeyInformationClass;
		data->QueryLength = pQueryKeyInformation->Length;

		if (Information->Status == STATUS_SUCCESS || Information->Status == STATUS_BUFFER_OVERFLOW || Information->Status == STATUS_BUFFER_TOO_SMALL)
		{
			data->DataSize = (pQueryKeyInformation->ResultLength) ? *pQueryKeyInformation->ResultLength : 0;
			data->CopySize = MaxCopySize;
			if (MaxCopySize && pQueryKeyInformation->KeyInformation)
			{
				__try {
					memcpy(data->CopyData, pQueryKeyInformation->KeyInformation, MaxCopySize);
				}
				__except (EXCEPTION_EXECUTE_HANDLER) {

				}
			}
		}

		UNICODE_STRING ustrKeyNameTemp, ustrKeyName;
		NTSTATUS stGetName = GetRegistryObjectFullName(Information->Object, NULL, &ustrKeyNameTemp);

		if (NT_SUCCESS(stGetName))
		{
			RtlInitEmptyUnicodeString(&ustrKeyName, data->KeyPath, sizeof(data->KeyPath) - sizeof(WCHAR));
			NormalizeRegistryPath(&ustrKeyNameTemp, &ustrKeyName);

			ExFreePoolWithTag(ustrKeyNameTemp.Buffer, 'TXSB');
		}

		m_EventList->Lock();
		m_EventList->SendEvent(data);
		m_EventList->SendEvent(CreateCallStackEvent(EventId));
		m_EventList->Unlock();
		m_EventList->NotifyEvent();
	}
	return STATUS_SUCCESS;
}

NTSTATUS RegistryCallbackRoutine(
	_In_     PVOID CallbackContext,
	_In_opt_ PVOID Argument1,
	_In_opt_ PVOID Argument2
) {
	UNREFERENCED_PARAMETER(CallbackContext);

	if (m_EventList->IsCapturing())
	{
		REG_NOTIFY_CLASS index = (REG_NOTIFY_CLASS)(ULONG)Argument1;

		switch (index) 
		{
		case RegNtPostCreateKeyEx:
			return RegPostCreateOpenKeyEx((PREG_POST_OPERATION_INFORMATION)Argument2, FALSE);
		case RegNtPostOpenKeyEx:
			return RegPostCreateOpenKeyEx((PREG_POST_OPERATION_INFORMATION)Argument2, TRUE);
		case RegNtPostSetValueKey:
			return RegPostSetValueKey((PREG_POST_OPERATION_INFORMATION)Argument2);
		case RegNtPostQueryValueKey:
			return RegPostQueryValueKey((PREG_POST_OPERATION_INFORMATION)Argument2);
		case RegNtPostQueryKey:
			return RegPostQueryKey((PREG_POST_OPERATION_INFORMATION)Argument2);
		}
	}

	return STATUS_SUCCESS;
}

VOID CmInitialization(PDRIVER_OBJECT pDriverObject)
{
	UNICODE_STRING ustrRoutine;
	RtlInitUnicodeString(&ustrRoutine, L"CmRegisterCallbackEx");
	const auto pfnCmRegisterCallbackEx =
		(NTSTATUS(*)(PEX_CALLBACK_FUNCTION, PCUNICODE_STRING, PVOID, PVOID, PLARGE_INTEGER, PVOID))MmGetSystemRoutineAddress(&ustrRoutine);

	if (pfnCmRegisterCallbackEx != NULL)
	{
		UNICODE_STRING Altitude;
		RtlInitUnicodeString(&Altitude, L"49999");
		pfnCmRegisterCallbackEx(RegistryCallbackRoutine, &Altitude, pDriverObject, NULL, &m_CmCookie, NULL);
	}
	else
	{
		CmRegisterCallback(RegistryCallbackRoutine, NULL, &m_CmCookie);
	}

	RtlInitUnicodeString(&ustrRoutine, L"CmCallbackGetKeyObjectID");
	m_pfnCmCallbackGetKeyObjectID = (NTSTATUS(*)(PLARGE_INTEGER, PVOID, PULONG_PTR, PCUNICODE_STRING *))
		MmGetSystemRoutineAddress(&ustrRoutine);

	if (m_pfnCmCallbackGetKeyObjectID != NULL)
		m_pfnGetRegistryObjectName = GetRegistryObjectNameVista;
	else
		m_pfnGetRegistryObjectName = GetRegistryObjectNameXP;
}

VOID CmTermination(VOID)
{
	PAGED_CODE();

	CmUnRegisterCallback(m_CmCookie);
}

}