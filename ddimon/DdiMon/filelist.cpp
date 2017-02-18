#include <fltKernel.h>

#define NTSTRSAFE_NO_CB_FUNCTIONS
#include <ntstrsafe.h>
#include "../HyperPlatform/kernel_stl.h"
#include "main.h"

CFileList *m_IgnoreFileList = NULL;

NTSTATUS DosFilenameToNtFilename(IN PUNICODE_STRING DosFilename, OUT PUNICODE_STRING NtFilename, OUT PUNICODE_STRING VolumeName);

CFileList::CFileList()
{
	ExInitializeResourceLite(&m_Lock);
}

CFileList::~CFileList()
{
	FreeAll();

	ExDeleteResourceLite(&m_Lock);
}

NTSTATUS CFileList::AddFile(PUNICODE_STRING DosFileName)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;;
	UNICODE_STRING NtFileName, VolumeName;

	ExAcquireResourceExclusiveLite(&m_Lock, TRUE);

	if (!FindDosFileUnsafe(DosFileName, TRUE))
	{
		File_t p;
		memset(&p, 0, sizeof(File_t));

		status = DosFilenameToNtFilename(DosFileName, &NtFileName, &VolumeName);
		if (NT_SUCCESS(status))
		{
			p.DosFileName.Buffer = (PWCH)ExAllocatePoolWithTag(PagedPool, DosFileName->Length, 'TXSB');
			p.DosFileName.Length = 0;
			p.DosFileName.MaximumLength = DosFileName->Length;
			RtlCopyUnicodeString(&p.DosFileName, DosFileName);

			p.NtFileName.Buffer = NtFileName.Buffer;
			p.NtFileName.Length = NtFileName.Length;
			p.NtFileName.MaximumLength = NtFileName.MaximumLength;

			if (VolumeName.Length > 0 && VolumeName.Length < p.NtFileName.Length)
			{
				p.VolumelessFileName.Buffer = (PWCH)((PUCHAR)p.NtFileName.Buffer + VolumeName.Length);
				p.VolumelessFileName.Length = p.NtFileName.Length - VolumeName.Length;
				p.VolumelessFileName.MaximumLength = p.VolumelessFileName.Length;
			}

			m_List.push_back(p);			
		}
	}
	else
	{
		status = STATUS_OBJECT_NAME_EXISTS;;
	}
	ExReleaseResourceLite(&m_Lock);

	return status;
}

BOOLEAN CFileList::FindDosFileUnsafe(PUNICODE_STRING DosFileName, BOOLEAN CaseInSensitive)
{
	for (size_t i = 0; i < m_List.size(); ++i)
	{
		if (0 == RtlCompareUnicodeString(&m_List[i].DosFileName, DosFileName, CaseInSensitive))
		{
			return TRUE;
		}
	}
	return FALSE;
}

BOOLEAN CFileList::FindNtFileUnsafe(PUNICODE_STRING NtFileName, BOOLEAN CaseInSensitive)
{
	for (size_t i = 0; i < m_List.size(); ++i)
	{
		if (0 == RtlCompareUnicodeString(&m_List[i].NtFileName, NtFileName, CaseInSensitive))
		{
			return TRUE;
		}
	}
	return FALSE;
}

BOOLEAN CFileList::FindDosFile(PUNICODE_STRING DosFileName, BOOLEAN CaseInSensitive)
{
	ExAcquireResourceSharedLite(&m_Lock, TRUE);
	BOOLEAN bFound = FindDosFileUnsafe(DosFileName, CaseInSensitive);
	ExReleaseResourceLite(&m_Lock);
	return bFound;
}

BOOLEAN CFileList::FindNtFile(PUNICODE_STRING NtFileName, BOOLEAN CaseInSensitive)
{
	ExAcquireResourceSharedLite(&m_Lock, TRUE);
	BOOLEAN bFound = FindNtFileUnsafe(NtFileName, CaseInSensitive);
	ExReleaseResourceLite(&m_Lock);
	return bFound;
}

void CFileList::FreeAll(void)
{
	ExAcquireResourceExclusiveLite(&m_Lock, TRUE);
	m_List.clear();
	ExReleaseResourceLite(&m_Lock);
}

NTSTATUS QuerySymbolicLink(IN PUNICODE_STRING SymbolicLinkName, OUT PUNICODE_STRING LinkTarget)
{
	OBJECT_ATTRIBUTES oa;
	NTSTATUS status;
	HANDLE handle;

	InitializeObjectAttributes(&oa, SymbolicLinkName,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		0, 0);

	status = ZwOpenSymbolicLinkObject(&handle, GENERIC_READ, &oa);
	if (!NT_SUCCESS(status))
		return status;

	LinkTarget->MaximumLength = 200 * sizeof(WCHAR);
	LinkTarget->Length = 0;
	LinkTarget->Buffer = (PWCH)ExAllocatePoolWithTag(NonPagedPool, LinkTarget->MaximumLength, 'TXSB');
	if (!LinkTarget->Buffer)
	{
		ZwClose(handle);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	RtlZeroMemory(LinkTarget->Buffer, LinkTarget->MaximumLength);

	status = ZwQuerySymbolicLinkObject(handle, LinkTarget, NULL);
	ZwClose(handle);

	if (!NT_SUCCESS(status))
	{
		ExFreePoolWithTag(LinkTarget->Buffer, 'TXSB');
	}

	return status;
}
// \\\\hostname\\xxx.yyy --> \\Device\\Mup\\hostname\\xxx.yyy
// c:\\xxx.yyy -> \\Device\\HarddiskVolume0\\xxx.yyy
NTSTATUS DosFilenameToNtFilename(IN PUNICODE_STRING DosFilename, OUT PUNICODE_STRING NtFilename, OUT PUNICODE_STRING VolumeName)
{
	UNICODE_STRING DeviceName;
	UNICODE_STRING FilePath;
	NTSTATUS status;

	if (DosFilename->Length < 2 * sizeof(WCHAR))
		return STATUS_UNSUCCESSFUL;

	//Network device
	if (DosFilename->Buffer[0] == L'\\' && DosFilename->Buffer[1] == L'\\')
	{
		DeviceName.Length = sizeof(L"\\Device\\Mup\\") - sizeof(WCHAR);
		DeviceName.MaximumLength = DeviceName.Length;
		DeviceName.Buffer = (PWCH)ExAllocatePool(NonPagedPool, DeviceName.Length);
		memcpy(DeviceName.Buffer, L"\\Device\\Mup\\", DeviceName.Length);
	}
	else
	{
		UNICODE_STRING SymbolinkName;
		WCHAR Buffer[7] = L"\\??\\C:";

		Buffer[4] = DosFilename->Buffer[0];

		SymbolinkName.Buffer = Buffer;
		SymbolinkName.Length = 6 * sizeof(WCHAR);
		SymbolinkName.MaximumLength = 6 * sizeof(WCHAR);

		status = QuerySymbolicLink(&SymbolinkName, &DeviceName);

		if (!NT_SUCCESS(status))
			return status;
	}

	FilePath.Buffer = &DosFilename->Buffer[2];
	FilePath.Length = DosFilename->Length - 2 * sizeof(WCHAR);
	FilePath.MaximumLength = FilePath.Length;

	NtFilename->Length = 0;
	NtFilename->MaximumLength = DeviceName.Length + FilePath.Length;
	NtFilename->Buffer = (PWCH)ExAllocatePoolWithTag(NonPagedPool, NtFilename->MaximumLength, 'TXSB');

	if (!NtFilename->Buffer)
		return STATUS_INSUFFICIENT_RESOURCES;

	RtlCopyUnicodeString(NtFilename, &DeviceName);
	RtlAppendUnicodeStringToString(NtFilename, &FilePath);

	VolumeName->Buffer = NtFilename->Buffer;
	VolumeName->Length = DeviceName.Length;
	VolumeName->MaximumLength = DeviceName.Length;

	ExFreePool(DeviceName.Buffer);

	return STATUS_SUCCESS;
}


// \\Device\\HarddiskVolume1  --> C:
// \\Device\\HarddiskVolume2  --> D:
// \\Device\\VirtualDiskXClient\\VDXCLN1 --> Z:

NTSTATUS RtlDeviceNameToDosName(
	IN PUNICODE_STRING NtFileName,
	OUT PUNICODE_STRING DeviceName,//Buffer must be from NtFileName
	OUT PUNICODE_STRING DosName//Buffer must be caller-allocated
)
{

	NTSTATUS                status;
	WCHAR                   c = L'\0';
	WCHAR                   driveLetter[8] = { 0 };
	UNICODE_STRING          ustrPrefix = { 0 };
	UNICODE_STRING          driveLetterName = { 0 };
	UNICODE_STRING          linkTarget = { 0 };
	BOOLEAN					bFound = FALSE;

	RtlInitUnicodeString(&ustrPrefix, L"\\Device\\Mup\\");
	if (RtlPrefixUnicodeString(&ustrPrefix, NtFileName, TRUE))
	{
		RtlUnicodeStringCopyString(DeviceName, L"\\Device\\Mup\\");
		DosName->Length = 2;
		DosName->Buffer[0] = L'\\';
		return STATUS_SUCCESS;
	}

	for (c = L'A'; c <= L'Z'; c++)
	{
		RtlInitEmptyUnicodeString(&driveLetterName, driveLetter, sizeof(driveLetter));
		RtlUnicodeStringCopyString(&driveLetterName, L"\\??\\C:");
		driveLetter[4] = c;

		status = QuerySymbolicLink(&driveLetterName, &linkTarget);
		if (!NT_SUCCESS(status))
			continue;

		if (RtlPrefixUnicodeString(&linkTarget, NtFileName, TRUE))
		{
			DeviceName->Buffer = NtFileName->Buffer;
			DeviceName->Length = linkTarget.Length;
			DeviceName->MaximumLength = linkTarget.Length;
			bFound = TRUE;

			ExFreePoolWithTag(linkTarget.Buffer, 'TXSB');
			break;
		}

		ExFreePoolWithTag(linkTarget.Buffer, 'TXSB');
	}

	if (bFound)
	{
		DosName->Length = 4;
		DosName->Buffer[0] = c;
		DosName->Buffer[1] = L':';

		return STATUS_SUCCESS;
	}

	return STATUS_OBJECT_NAME_NOT_FOUND;
}

//PASSIVE_LEVEL
//\\Device\\HarddiskVolume1\\Windows\\hi.txt --> C:\\Windows\\hi.txt  <
//\\Device\\HarddiskVolume1  -->  C:
//\\Device\\Mup\\host\\123.tzt --> \\\\host\\123.txt
//\\Device\\Mup --> \\

NTSTATUS NtFileNameToDosFileName(IN PUNICODE_STRING NtFileName, OUT PUNICODE_STRING DosFileName)
{
	NTSTATUS st;

	UNICODE_STRING      ustrTemp;
	UNICODE_STRING      ustrDeviceName = {0};
	UNICODE_STRING		ustrDosDeviceName = { 0 };
	WCHAR				szDosDeviceNameBuf[6] = {0};

	RtlInitUnicodeString(&ustrTemp, L"\\Device\\");

	if (NtFileName->Length < ustrTemp.Length || !RtlPrefixUnicodeString(&ustrTemp, NtFileName, TRUE))
		return STATUS_OBJECT_NAME_INVALID;

	RtlInitEmptyUnicodeString(&ustrDosDeviceName, szDosDeviceNameBuf, sizeof(szDosDeviceNameBuf));

	st = RtlDeviceNameToDosName(NtFileName, &ustrDeviceName, &ustrDosDeviceName);
	if (!NT_SUCCESS(st))
		return st;

	ustrTemp.Buffer = (PWCH)((PUCHAR)NtFileName->Buffer + ustrDeviceName.Length);
	ustrTemp.Length = NtFileName->Length - ustrDeviceName.Length;
	ustrTemp.MaximumLength = ustrTemp.Length;

	//Dos文件名不会比NT文件名大
	if (!DosFileName->Buffer)
		return STATUS_INSUFFICIENT_RESOURCES;

	RtlCopyUnicodeString(DosFileName, &ustrDosDeviceName);
	if (ustrTemp.Length)
		RtlAppendUnicodeStringToString(DosFileName, &ustrTemp);

	return STATUS_SUCCESS;
}

NTSTATUS NtFileNameToDosFileNameEx(IN PUNICODE_STRING ustrDeviceName, OUT PUNICODE_STRING ustrDosName)
{
	NTSTATUS status;
	HANDLE hFile;
	OBJECT_ATTRIBUTES oa;
	IO_STATUS_BLOCK sb;

	InitializeObjectAttributes(&oa, ustrDeviceName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	status = ZwOpenFile(&hFile, FILE_READ_ATTRIBUTES | SYNCHRONIZE, &oa, &sb, FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT);

	if (NT_SUCCESS(status))
	{
		PFILE_OBJECT FileObject;
		status = ObReferenceObjectByHandle(hFile, FILE_READ_ATTRIBUTES, *IoFileObjectType, KernelMode, (PVOID*)&FileObject, NULL);
		if (NT_SUCCESS(status))
		{
			POBJECT_NAME_INFORMATION lpName;
			status = IoQueryFileDosDeviceName(FileObject, &lpName);
			if (NT_SUCCESS(status))
			{
				RtlCopyUnicodeString(ustrDosName, &lpName->Name);
				ExFreePool(lpName);
				status = STATUS_SUCCESS;
			}
			ObDereferenceObject(FileObject);
		}
		ZwClose(hFile);
	}

	return status;
}

typedef struct
{
	PFILE_OBJECT FileObject;
	POBJECT_NAME_INFORMATION pFileName;
	PKEVENT NotifyEvent;
	NTSTATUS Status;
}QueryFileName_t;

VOID QueryFileDosNameRoutine(QueryFileName_t *Parameter)
{
	POBJECT_NAME_INFORMATION pFileName = NULL;

	Parameter->Status = IoQueryFileDosDeviceName(Parameter->FileObject, &pFileName);
	if (NT_SUCCESS(Parameter->Status))
	{
		Parameter->pFileName = pFileName;
	}
	KeSetEvent(Parameter->NotifyEvent, 0, FALSE);
}

//PASSIVE_LEVEL
NTSTATUS GetFileDosName(IN PFILE_OBJECT pFileObject, OUT PUNICODE_STRING ustrDosName)
{
	KEVENT QueryEvent;
	WORK_QUEUE_ITEM QueryWorkItem;
	QueryFileName_t QueryParam = { 0 };

	QueryParam.FileObject = pFileObject;
	QueryParam.NotifyEvent = &QueryEvent;
	QueryParam.Status = STATUS_UNSUCCESSFUL;

	KeInitializeEvent(&QueryEvent, NotificationEvent, FALSE);
	ExInitializeWorkItem(&QueryWorkItem, (PWORKER_THREAD_ROUTINE)QueryFileDosNameRoutine, &QueryParam);
	ExQueueWorkItem(&QueryWorkItem, DelayedWorkQueue);
	KeWaitForSingleObject(&QueryEvent, Executive, KernelMode, FALSE, 0);

	if (NT_SUCCESS(QueryParam.Status))
		RtlCopyUnicodeString(ustrDosName, &QueryParam.pFileName->Name);
	if (QueryParam.pFileName != NULL)
		ExFreePool(QueryParam.pFileName);

	return QueryParam.Status;
}

typedef struct
{
	PDEVICE_OBJECT DeviceObject;
	UNICODE_STRING DosName;
	PKEVENT NotifyEvent;
	NTSTATUS Status;
}QueryVolumeDosName_t;

VOID QueryVolumeDosNameRoutine(QueryVolumeDosName_t *Parameter)
{
	Parameter->Status = IoVolumeDeviceToDosName(Parameter->DeviceObject, &Parameter->DosName);
	KeSetEvent(Parameter->NotifyEvent, 0, FALSE);
}

//PASSIVE_LEVEL
NTSTATUS GetDeviceDosName(IN PDEVICE_OBJECT pDeviceObject, OUT PUNICODE_STRING ustrDosName)
{
	KEVENT QueryEvent;
	WORK_QUEUE_ITEM QueryWorkItem;
	QueryVolumeDosName_t QueryParam = { 0 };

	QueryParam.DeviceObject = pDeviceObject;
	QueryParam.NotifyEvent = &QueryEvent;
	QueryParam.Status = STATUS_UNSUCCESSFUL;

	KeInitializeEvent(&QueryEvent, NotificationEvent, FALSE);
	ExInitializeWorkItem(&QueryWorkItem, (PWORKER_THREAD_ROUTINE)QueryVolumeDosNameRoutine, &QueryParam);
	ExQueueWorkItem(&QueryWorkItem, DelayedWorkQueue);
	KeWaitForSingleObject(&QueryEvent, Executive, KernelMode, FALSE, 0);

	if (NT_SUCCESS(QueryParam.Status))
		RtlCopyUnicodeString(ustrDosName, &QueryParam.DosName);
	if (QueryParam.DosName.Buffer != NULL)
		ExFreePoolWithTag(QueryParam.DosName.Buffer, 'TXSB');

	return QueryParam.Status;
}

//PASSIVE_LEVEL only
NTSTATUS GetDeviceDosNameUnsafe(IN PDEVICE_OBJECT pDeviceObject, OUT PUNICODE_STRING ustrDosName)
{
	UNICODE_STRING ustrOut = {0};
	
	NTSTATUS st = IoVolumeDeviceToDosName(pDeviceObject, &ustrOut);

	if (NT_SUCCESS(st))
		RtlCopyUnicodeString(ustrDosName, &ustrOut);

	if (ustrOut.Buffer)
		ExFreePool(ustrOut.Buffer);

	return st;
}