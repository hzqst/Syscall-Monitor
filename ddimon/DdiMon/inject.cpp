#include <ntifs.h>
#include <Ntstrsafe.h>
#include "NativeEnums.h"
#include "NativeStructs.h"
#include "PEStructs.h"
#include "main.h"

#pragma warning(disable : 4311)
#pragma warning(disable : 4302)

EXTERN_C{

UNICODE_STRING m_GlobalInject = { 0 };
#ifdef AMD64
UNICODE_STRING m_GlobalInject64 = { 0 };
#endif

extern DYNAMIC_DATA dynData;

typedef NTSTATUS(*fnNtProtectVirtualMemory)(HANDLE ProcessHandle, PVOID* BaseAddress, SIZE_T* NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection);
typedef NTSTATUS(*fnNtWriteVirtualMemory)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG BufferLength, PULONG ReturnLength);
typedef NTSTATUS(*fnNtReadVirtualMemory)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG BufferLength, PULONG ReturnLength);
typedef NTSTATUS(*fnNtQueryVirtualMemory)(HANDLE ProcessHandle, PVOID BaseAddress, MEMORY_INFORMATION_CLASS_EX MemoryInformationClass, PVOID MemoryInformation, SIZE_T MemoryInformationLength, PSIZE_T ReturnLength);
typedef NTSTATUS(*fnNtCreateThreadEx)(OUT PHANDLE hThread, IN ACCESS_MASK DesiredAccess, IN PVOID ObjectAttributes, IN HANDLE ProcessHandle, IN PVOID lpStartAddress, IN PVOID lpParameter, IN ULONG Flags, IN SIZE_T StackZeroBits, IN SIZE_T SizeOfStackCommit, IN SIZE_T SizeOfStackReserve, OUT PVOID lpBytesBuffer);

NTKERNELAPI PVOID NTAPI PsGetProcessPeb(PEPROCESS Process);
#ifdef AMD64
NTKERNELAPI PVOID NTAPI PsGetProcessWow64Process(PEPROCESS Process);
#endif

typedef struct _INJECT_BUFFER
{
	UCHAR code[0x200];
	UCHAR original_code[8];
	PVOID hook_func;
	union
	{
		UNICODE_STRING path;
		UNICODE_STRING32 path32;
	};

	wchar_t buffer[488];
	PVOID module;
} INJECT_BUFFER, *PINJECT_BUFFER;

PVOID GetSSDTEntry(IN ULONG index);

static PVOID PsNtDllBase = NULL;
static PVOID fnLdrLoadDll = NULL;
static PVOID fnProtectVirtualMemory = NULL;
static PVOID fnHookFunc = NULL;

#ifdef AMD64
static PVOID PsNtDllBase64 = NULL;
static PVOID fnLdrLoadDll64 = NULL;
static PVOID fnProtectVirtualMemory64 = NULL;
static PVOID fnHookFunc64 = NULL;
#endif

PINJECT_BUFFER GetInlineHookCode(IN HANDLE hProcess, IN PUNICODE_STRING pDllPath);
PINJECT_BUFFER GetInlineHookCode64(IN HANDLE hProcess, IN PUNICODE_STRING pDllPath);
PVOID GetModuleExport(IN PVOID pBase, IN PCCHAR name_ord);

#pragma alloc_text(PAGE, GetInlineHookCode)
#pragma alloc_text(PAGE, GetInlineHookCode64)
#pragma alloc_text(PAGE, GetModuleExport)

NTSTATUS NTAPI NewZwQueryVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, MEMORY_INFORMATION_CLASS_EX MemoryInformationClass, PVOID MemoryInformation, SIZE_T MemoryInformationLength, PSIZE_T ReturnLength)
{
	NTSTATUS status = STATUS_SUCCESS;
	fnNtQueryVirtualMemory pfnNtQueryVirtualMemory;

	if (dynData.NtQueryIndex == 0)
		return STATUS_NOT_FOUND;

	pfnNtQueryVirtualMemory = (fnNtQueryVirtualMemory)(ULONG_PTR)GetSSDTEntry(dynData.NtQueryIndex);
	if (pfnNtQueryVirtualMemory)
	{
		PUCHAR pPrevMode = (PUCHAR)PsGetCurrentThread() + dynData.PrevMode;
		UCHAR prevMode = *pPrevMode;
		*pPrevMode = KernelMode;

		status = pfnNtQueryVirtualMemory(ProcessHandle, BaseAddress, MemoryInformationClass, MemoryInformation, MemoryInformationLength, ReturnLength);

		*pPrevMode = prevMode;
	}
	else
		status = STATUS_NOT_FOUND;

	return status;
}

NTSTATUS NTAPI NewNtReadVirtualMemory(IN HANDLE ProcessHandle, IN PVOID BaseAddress, IN PVOID Buffer, IN ULONG BufferLength, OUT PULONG ReturnLength OPTIONAL)
{
	NTSTATUS status = STATUS_SUCCESS;
	fnNtReadVirtualMemory pfnNtReadVirtualMemory;

	if (dynData.NtReadIndex == 0)
		return STATUS_NOT_FOUND;

	pfnNtReadVirtualMemory = (fnNtReadVirtualMemory)(ULONG_PTR)GetSSDTEntry(dynData.NtReadIndex);
	if (pfnNtReadVirtualMemory)
	{
		PUCHAR pPrevMode = (PUCHAR)PsGetCurrentThread() + dynData.PrevMode;
		UCHAR prevMode = *pPrevMode;
		*pPrevMode = KernelMode;

		status = pfnNtReadVirtualMemory(ProcessHandle, BaseAddress, Buffer, BufferLength, ReturnLength);

		*pPrevMode = prevMode;
	}
	else
		status = STATUS_NOT_FOUND;

	return status;
}

NTSTATUS NTAPI NewNtWriteVirtualMemory(IN HANDLE ProcessHandle, IN PVOID BaseAddress, IN PVOID Buffer, IN ULONG BufferLength, OUT PULONG ReturnLength OPTIONAL)
{
	NTSTATUS status = STATUS_SUCCESS;
	fnNtWriteVirtualMemory pfnNtWriteVirtualMemory;

	if (dynData.NtWriteIndex == 0)
		return STATUS_NOT_FOUND;

	pfnNtWriteVirtualMemory = (fnNtWriteVirtualMemory)(ULONG_PTR)GetSSDTEntry(dynData.NtWriteIndex);
	if (pfnNtWriteVirtualMemory)
	{
		PUCHAR pPrevMode = (PUCHAR)PsGetCurrentThread() + dynData.PrevMode;
		UCHAR prevMode = *pPrevMode;
		*pPrevMode = KernelMode;

		status = pfnNtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, BufferLength, ReturnLength);

		*pPrevMode = prevMode;
	}
	else
		status = STATUS_NOT_FOUND;

	return status;
}

NTSTATUS NTAPI NewNtProtectVirtualMemory(IN HANDLE ProcessHandle, IN PVOID* BaseAddress, IN SIZE_T* NumberOfBytesToProtect, IN ULONG NewAccessProtection, OUT PULONG OldAccessProtection)
{
	NTSTATUS status = STATUS_SUCCESS;
	fnNtProtectVirtualMemory pfnNtProtectVirtualMemory;

	if (dynData.NtProtectIndex == 0)
		return STATUS_NOT_FOUND;

	pfnNtProtectVirtualMemory = (fnNtProtectVirtualMemory)(ULONG_PTR)GetSSDTEntry(dynData.NtProtectIndex);
	if (pfnNtProtectVirtualMemory)
	{
		PUCHAR pPrevMode = (PUCHAR)PsGetCurrentThread() + dynData.PrevMode;
		UCHAR prevMode = *pPrevMode;
		*pPrevMode = KernelMode;

		status = pfnNtProtectVirtualMemory(ProcessHandle, BaseAddress, NumberOfBytesToProtect, NewAccessProtection, OldAccessProtection);

		*pPrevMode = prevMode;
	}
	else
		status = STATUS_NOT_FOUND;

	return status;
}
/*
PVOID AllocateInjectMemory(IN HANDLE ProcessHandle, IN PVOID DesiredAddress, IN SIZE_T DesiredSize)
{
	MEMORY_BASIC_INFORMATION mbi;
	SIZE_T AllocateSize = DesiredSize;

	if ((ULONG_PTR)DesiredAddress >= 0x70000000 && (ULONG_PTR)DesiredAddress < 0x80000000)
		DesiredAddress = (PVOID)0x70000000;

	while (1)
	{
		if (!NT_SUCCESS(NewZwQueryVirtualMemory(ProcessHandle, DesiredAddress, MemoryBasicInformationEx, &mbi, sizeof(mbi), NULL)))
			return NULL;

		if (DesiredAddress != mbi.AllocationBase)
		{
			DesiredAddress = mbi.AllocationBase;
		}
		else
		{
			DesiredAddress = (PVOID)((ULONG_PTR)mbi.AllocationBase - 0x10000);
		}

		if (mbi.State == MEM_FREE)
		{
			if (NT_SUCCESS(ZwAllocateVirtualMemory(ProcessHandle, &mbi.BaseAddress, 0, &AllocateSize, MEM_RESERVE, PAGE_EXECUTE_READWRITE)))
			{
				if (NT_SUCCESS(ZwAllocateVirtualMemory(ProcessHandle, &mbi.BaseAddress, 0, &AllocateSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE)))
				{
					return mbi.BaseAddress;
				}
			}
		}
	}
	return NULL;
}

const UCHAR HookCode[] =
{
	0x55,									// push        ebp
	0x8B, 0xEC,								// mov         ebp,esp
	0x83, 0xEC, 0x0C,						// sub         esp,0Ch
	0xA1, 0, 0, 0, 0,						// mov         eax,dword ptr[fnHookFunc] //offset +7
	0x89, 0x45, 0xF4,						// mov         dword ptr[ebp-0Ch],eax
	0x8D, 0x45, 0xFC,						// lea         eax,[ebp - 4]
	0x50,									// push        eax
	0x6A, 0x40,								// push        40h
	0x8D, 0x45, 0xF8,						// lea         eax,[ebp - 8]
	0xC7, 0x45, 0xF8, 5, 0, 0, 0,			// mov         dword ptr[ebp - 8],5
	0x50,									// push        eax
	0x8D, 0x45, 0xF4,						// lea         eax,[ebp - 0Ch]
	0x50,									// push        eax
	0x6A, 0xFF,								// push        0FFFFFFFFh
	0xE8, 0, 0, 0, 0,						// call        NtProtectVirtualMemory //offset +38
	0x8B, 0x0D, 0, 0, 0, 0,					// mov         ecx,dword ptr ds : [fnHookFunc] //offset + 44
	0xA1, 0, 0, 0, 0,						// mov         eax,dword ptr ds : [fnOriCode] //offset + 49
	0x89, 0x01,								// mov         dword ptr[ecx],eax
	0xA0, 0, 0, 0, 0,						// mov         al,byte ptr ds : [fnOriCode+4] //offset +56
	0x88, 0x41, 0x04,						// mov         byte ptr[ecx + 4],al
	0x8D, 0x45, 0xFC,						// lea         eax,[ebp-4]
	0x50,									// push        eax
	0xFF, 0x75, 0xFC,						// push        dword ptr[ebp-4]
	0x8D, 0x45, 0xF8,						// lea         eax,[ebp - 8]
	0x50,									// push        eax
	0x8D, 0x45, 0xF4,						// lea         eax,[ebp - 0Ch]
	0x50,									// push        eax
	0x6A, 0xFF,								// push        0FFFFFFFFh
	0xE8, 0, 0, 0, 0,                       // call        NtProtectVirtualMemory //offset +81
	0x68, 0, 0, 0, 0,                       // push        ModuleHandle           //offset +86
	0x68, 0, 0, 0, 0,                       // push        ModuleFileName         //offset +91
	0x6A, 0,                                // push        0  
	0x6A, 0,                                // push        0
	0xE8, 0, 0, 0, 0,                       // call        LdrLoadDll              //offset +100
	0x8B, 0xE5,								// mov         esp,ebp
	0x5D,									// pop         ebp
	0xE9, 0, 0, 0, 0,						// jmp								   //offset+108
	0xCC,									// padding
};

PINJECT_BUFFER GetInlineHookCode(IN HANDLE ProcessHandle, IN PUNICODE_STRING pDllPath)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PINJECT_BUFFER pBuffer = NULL;
	INJECT_BUFFER Buffer = { 0 };

	//Try to allocate before ntdll.dll
	pBuffer = (PINJECT_BUFFER)AllocateInjectMemory(ProcessHandle, (PVOID)PsNtDllBase, PAGE_SIZE);
	if (pBuffer != NULL)
	{
		status = NewNtReadVirtualMemory(ProcessHandle, fnHookFunc, Buffer.original_code, sizeof(Buffer.original_code), NULL);
		if (NT_SUCCESS(status))
		{
			// Fill data
			Buffer.path32.Length = min(pDllPath->Length, sizeof(Buffer.buffer));
			Buffer.path32.MaximumLength = min(pDllPath->MaximumLength, sizeof(Buffer.buffer));
			Buffer.path32.Buffer = (ULONG)pBuffer->buffer;
			Buffer.hook_func = fnHookFunc;
			memcpy(Buffer.buffer, pDllPath->Buffer, Buffer.path32.Length);
			memcpy(Buffer.code, HookCode, sizeof(HookCode));

			// Fill code
			*(DWORD*)((PUCHAR)Buffer.code + 7) = (DWORD)&pBuffer->hook_func;
			*(DWORD*)((PUCHAR)Buffer.code + 38) = (DWORD)((DWORD)fnProtectVirtualMemory - ((DWORD)pBuffer + 42));
			*(DWORD*)((PUCHAR)Buffer.code + 44) = (DWORD)&pBuffer->hook_func;
			*(DWORD*)((PUCHAR)Buffer.code + 49) = (DWORD)pBuffer->original_code;
			*(DWORD*)((PUCHAR)Buffer.code + 56) = (DWORD)pBuffer->original_code + 4;
			*(DWORD*)((PUCHAR)Buffer.code + 81) = (DWORD)((DWORD)fnProtectVirtualMemory - ((DWORD)pBuffer + 85));
			*(DWORD*)((PUCHAR)Buffer.code + 86) = (DWORD)&pBuffer->module;
			*(DWORD*)((PUCHAR)Buffer.code + 91) = (DWORD)&pBuffer->path32;
			*(DWORD*)((PUCHAR)Buffer.code + 100) = (DWORD)((DWORD)fnLdrLoadDll - ((DWORD)pBuffer + 104));
			*(DWORD*)((PUCHAR)Buffer.code + 108) = (DWORD)((DWORD)fnHookFunc - ((DWORD)pBuffer + 112));

			// Copy all
			NewNtWriteVirtualMemory(ProcessHandle, pBuffer, &Buffer, sizeof(Buffer), NULL);

			return pBuffer;
		}
		else
		{
			DbgPrint("%s: Failed to read original code %X\n", __FUNCTION__, status);
		}
	}
	else
	{
		DbgPrint("%s: Failed to allocate memory\n", __FUNCTION__);
	}

	return NULL;
}

#ifdef AMD64

const UCHAR HookCode64[] = {
	0x50, 							// push       rax
	0x51, 							// push       rcx
	0x52, 							// push       rdx
	0x41, 0x50, 					// push       r8
	0x41, 0x51, 					// push       r9
	0x41, 0x53, 					// push       r11
	0x48, 0x83, 0xEC, 0x38,			// sub         rsp,38h
	0x48, 0x8B, 0x05, 0, 0, 0, 0,	// mov         rax,qword ptr [fnHookPort]	offset+16
	0x4C, 0x8D, 0x44, 0x24, 0x48,   // lea         r8,[rsp + 48h]
	0x48, 0x89, 0x44, 0x24, 0x50,	// mov         qword ptr [rsp+50h],rax  
	0x48, 0x8D, 0x54, 0x24, 0x50,   // lea         rdx,[rsp + 50h]
	0x48, 0x8D, 0x44, 0x24, 0x40,   // lea         rax,[rsp + 40h]
	0x48, 0xC7, 0x44, 0x24, 0x48,   // mov         qword ptr[rsp + 48h],5
	5, 0, 0, 0,
	0x41, 0xB9, 0x40, 0, 0, 0,		// mov         r9d,40h
	0x48, 0x89, 0x44, 0x24, 0x20,	// mov         qword ptr[rsp + 20h],rax
	0x48, 0x83, 0xC9, 0xFF,			// or          rcx, 0FFFFFFFFFFFFFFFFh
	0xE8, 0, 0, 0, 0,				// call		   fnProtectVirtualMemory		 offset +65
	0x8B, 0x05, 0, 0, 0, 0,			// mov         eax,dword ptr[fnOriCode]		offset+71
	0x4C, 0x8D, 0x44, 0x24, 0x48,   // lea         r8,[rsp + 48h]
	0x48, 0x8B, 0x15, 0, 0, 0, 0,	// mov         rdx,qword ptr[fnHookPort]	 offset+83
	0x48, 0x83, 0xC9, 0xFF,			// or          rcx, 0FFFFFFFFFFFFFFFFh
	0x89, 0x02,						// mov         dword ptr[rdx],eax
	0x0F, 0xB6, 0x05, 0, 0, 0, 0,	// movzx       eax,byte ptr[fnOriCode+4]	offset+96
	0x88, 0x42, 0x04,	            // mov         byte ptr[rdx + 4],al
	0x48, 0x8D, 0x44, 0x24, 0x40,   // lea         rax,[rsp + 40h]
	0x44, 0x8B, 0x4C, 0x24, 0x40,   // mov         r9d,dword ptr[rsp + 40h]
	0x48, 0x8D, 0x54, 0x24, 0x50,	// lea         rdx,[rsp + 50h]
	0x48, 0x89, 0x44, 0x24, 0x20,	// mov         qword ptr [rsp+20h],rax
	0xE8, 0, 0, 0, 0,				// call        fnProtectVirtualMemory		offset +124
	0x4C, 0x8D, 0x0D, 0, 0, 0, 0,	// lea         r9,qword ptr [pModuleHandle]  offset+131
	0x33, 0xD2,						// xor         edx,edx
	0x4C, 0x8D, 0x05, 0, 0, 0, 0,	// lea         r8,qword ptr [pModuleName]	 offset+140			
	0x33, 0xC9,						// xor         ecx,ecx
	0xE8, 0, 0, 0, 0,				// call        fnLdrLoadDll					 offset +147
	0x48, 0x83, 0xC4, 0x38,			// add         rsp,38h
	0x41, 0x5B, 					// pop        r11
	0x41, 0x59, 					// pop        r9
	0x41, 0x58, 					// pop        r8
	0x5A, 							// pop        rdx
	0x59, 							// pop        rcx
	0x58, 							// pop        rax
	0xE9, 0, 0, 0, 0, 				// jmp        OriFunc offset+165
	0xCC,							// padding
};

PINJECT_BUFFER GetInlineHookCode64(IN HANDLE ProcessHandle, IN PUNICODE_STRING pDllPath)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PINJECT_BUFFER pBuffer = NULL;
	INJECT_BUFFER Buffer = { 0 };

	//Try to allocate before ntdll.dll
	pBuffer = (PINJECT_BUFFER)AllocateInjectMemory(ProcessHandle, (PVOID)PsNtDllBase64, PAGE_SIZE);
	if (pBuffer != NULL)
	{
		status = NewNtReadVirtualMemory(ProcessHandle, fnHookFunc64, Buffer.original_code, sizeof(Buffer.original_code), NULL);
		if (NT_SUCCESS(status))
		{
			// Fill data
			Buffer.path.Length = min(pDllPath->Length, sizeof(Buffer.buffer));
			Buffer.path.MaximumLength = min(pDllPath->MaximumLength, sizeof(Buffer.buffer));
			Buffer.path.Buffer = (PWCH)pBuffer->buffer;
			Buffer.hook_func = fnHookFunc64;
			memcpy(Buffer.buffer, pDllPath->Buffer, Buffer.path.Length);
			memcpy(Buffer.code, HookCode64, sizeof(HookCode64));

			// Fill code
			*(ULONG*)((PUCHAR)Buffer.code + 16) = (ULONG)((ULONGLONG)&pBuffer->hook_func - ((ULONGLONG)pBuffer + 20));
			*(ULONG*)((PUCHAR)Buffer.code + 65) = (ULONG)((ULONGLONG)fnProtectVirtualMemory64 - ((ULONGLONG)pBuffer + 69));
			*(ULONG*)((PUCHAR)Buffer.code + 71) = (ULONG)((ULONGLONG)pBuffer->original_code - ((ULONGLONG)pBuffer + 75));
			*(ULONG*)((PUCHAR)Buffer.code + 83) = (ULONG)((ULONGLONG)&pBuffer->hook_func - ((ULONGLONG)pBuffer + 87));
			*(ULONG*)((PUCHAR)Buffer.code + 96) = (ULONG)((ULONGLONG)(pBuffer->original_code + 4) - ((ULONGLONG)pBuffer + 100));
			*(ULONG*)((PUCHAR)Buffer.code + 124) = (ULONG)((ULONGLONG)fnProtectVirtualMemory64 - ((ULONGLONG)pBuffer + 128));
			*(ULONG*)((PUCHAR)Buffer.code + 131) = (ULONG)((ULONGLONG)&pBuffer->module - ((ULONGLONG)pBuffer + 135));
			*(ULONG*)((PUCHAR)Buffer.code + 140) = (ULONG)((ULONGLONG)&pBuffer->path - ((ULONGLONG)pBuffer + 144));
			*(ULONG*)((PUCHAR)Buffer.code + 147) = (ULONG)((ULONGLONG)fnLdrLoadDll64 - ((ULONGLONG)pBuffer + 151));
			*(ULONG*)((PUCHAR)Buffer.code + 165) = (ULONG)((ULONGLONG)fnHookFunc64 - ((ULONGLONG)pBuffer + 169));

			//Write all
			NewNtWriteVirtualMemory(ProcessHandle, pBuffer, &Buffer, sizeof(Buffer), NULL);

			return pBuffer;
		}
		else
		{
			DbgPrint("%s: Failed to read original code %X\n", __FUNCTION__, status);
		}
	}
	else
	{
		DbgPrint("%s: Failed to allocate memory\n", __FUNCTION__);
	}
	return NULL;
}

#endif

PVOID GetModuleExport(IN PVOID pBase, IN PCCHAR name_ord)
{
	PIMAGE_DOS_HEADER pDosHdr = (PIMAGE_DOS_HEADER)pBase;
	PIMAGE_NT_HEADERS32 pNtHdr32 = NULL;
	PIMAGE_NT_HEADERS64 pNtHdr64 = NULL;
	PIMAGE_EXPORT_DIRECTORY pExport = NULL;
	ULONG expSize = 0;
	ULONG_PTR pAddress = 0;
	PUSHORT pAddressOfOrds;
	PULONG  pAddressOfNames;
	PULONG  pAddressOfFuncs;
	ULONG i;

	ASSERT(pBase != NULL);
	if (pBase == NULL)
		return NULL;

	/// Not a PE file
	if (pDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
		return NULL;

	pNtHdr32 = (PIMAGE_NT_HEADERS32)((PUCHAR)pBase + pDosHdr->e_lfanew);
	pNtHdr64 = (PIMAGE_NT_HEADERS64)((PUCHAR)pBase + pDosHdr->e_lfanew);

	// Not a PE file
	if (pNtHdr32->Signature != IMAGE_NT_SIGNATURE)
		return NULL;

	// 64 bit image
	if (pNtHdr32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	{
		pExport = (PIMAGE_EXPORT_DIRECTORY)(pNtHdr64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + (ULONG_PTR)pBase);
		expSize = pNtHdr64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	}
	// 32 bit image
	else
	{
		pExport = (PIMAGE_EXPORT_DIRECTORY)(pNtHdr32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + (ULONG_PTR)pBase);
		expSize = pNtHdr32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	}

	pAddressOfOrds = (PUSHORT)(pExport->AddressOfNameOrdinals + (ULONG_PTR)pBase);
	pAddressOfNames = (PULONG)(pExport->AddressOfNames + (ULONG_PTR)pBase);
	pAddressOfFuncs = (PULONG)(pExport->AddressOfFunctions + (ULONG_PTR)pBase);

	for (i = 0; i < pExport->NumberOfFunctions; ++i)
	{
		USHORT OrdIndex = 0xFFFF;
		PCHAR  pName = NULL;

		// Find by index
		if ((ULONG_PTR)name_ord <= 0xFFFF)
		{
			OrdIndex = (USHORT)i;
		}
		// Find by name
		else if ((ULONG_PTR)name_ord > 0xFFFF && i < pExport->NumberOfNames)
		{
			pName = (PCHAR)(pAddressOfNames[i] + (ULONG_PTR)pBase);
			OrdIndex = pAddressOfOrds[i];
		}
		// Weird params
		else
			return NULL;

		if (((ULONG_PTR)name_ord <= 0xFFFF && (USHORT)((ULONG_PTR)name_ord) == OrdIndex + pExport->Base) ||
			((ULONG_PTR)name_ord > 0xFFFF && strcmp(pName, name_ord) == 0))
		{
			pAddress = pAddressOfFuncs[OrdIndex] + (ULONG_PTR)pBase;

			// Check forwarded export
			if (pAddress >= (ULONG_PTR)pExport && pAddress <= (ULONG_PTR)pExport + expSize)
			{
				return NULL;
			}

			break;
		}
	}

	return (PVOID)pAddress;
}

NTSTATUS InjectByHook(HANDLE ProcessId, PVOID ImageBase, PUNICODE_STRING pDllPath)
{
	ULONG ReturnLength;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PEPROCESS Process = NULL;
	HANDLE ProcessHandle = NULL;

	if (!PsNtDllBase)
		PsNtDllBase = ImageBase;

	status = PsLookupProcessByProcessId((HANDLE)ProcessId, &Process);
	if (NT_SUCCESS(status))
	{
		status = ObOpenObjectByPointer(Process, OBJ_KERNEL_HANDLE, NULL, PROCESS_ALL_ACCESS, NULL, KernelMode, &ProcessHandle);
		if (NT_SUCCESS(status))
		{
			status = STATUS_UNSUCCESSFUL;

			if (!fnLdrLoadDll || !fnHookFunc || !fnProtectVirtualMemory)
			{
				KAPC_STATE kApc;
				KeStackAttachProcess(Process, &kApc);
				fnProtectVirtualMemory = GetModuleExport(ImageBase, "ZwProtectVirtualMemory");
				fnLdrLoadDll = GetModuleExport(ImageBase, "LdrLoadDll");
				fnHookFunc = GetModuleExport(ImageBase, "ZwTestAlert");
				KeUnstackDetachProcess(&kApc);
			}

			if (fnLdrLoadDll && fnHookFunc && fnProtectVirtualMemory)
			{
				PINJECT_BUFFER pBuffer = GetInlineHookCode(ProcessHandle, pDllPath);
				if (pBuffer)
				{
					UCHAR trampo[] = { 0xE9, 0, 0, 0, 0 };
					ULONG OldProtect = 0;
					PVOID ProtectAddress = fnHookFunc;
					SIZE_T ProtectSize = sizeof(trampo);

					*(DWORD *)(trampo + 1) = (DWORD)((DWORD)pBuffer->code - ((DWORD)fnHookFunc + 5));

					status = NewNtProtectVirtualMemory(ProcessHandle, &ProtectAddress, &ProtectSize, PAGE_EXECUTE_READWRITE, &OldProtect);
					if (NT_SUCCESS(status))
					{
						NewNtWriteVirtualMemory(ProcessHandle, fnHookFunc, trampo, sizeof(trampo), &ReturnLength);
						NewNtProtectVirtualMemory(ProcessHandle, &ProtectAddress, &ProtectSize, OldProtect, &OldProtect);
					}
				}
			}

			ZwClose(ProcessHandle);
		}

		ObDereferenceObject(Process);
	}

	return status;
}

#ifdef AMD64

NTSTATUS InjectByHook64(HANDLE ProcessId, PVOID ImageBase, PUNICODE_STRING pDllPath)
{
	ULONG ReturnLength;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PEPROCESS Process = NULL;
	HANDLE ProcessHandle = NULL;

	if (!PsNtDllBase64)
		PsNtDllBase64 = ImageBase;

	status = PsLookupProcessByProcessId((HANDLE)ProcessId, &Process);
	if (NT_SUCCESS(status))
	{
		//Do not inject WOW64 process
		status = STATUS_UNSUCCESSFUL;
		if (PsGetProcessWow64Process(Process) == NULL)
		{
			status = ObOpenObjectByPointer(Process, OBJ_KERNEL_HANDLE, NULL, PROCESS_ALL_ACCESS, NULL, KernelMode, &ProcessHandle);
			if (NT_SUCCESS(status))
			{
				KAPC_STATE kApc;

				if (!fnLdrLoadDll64 || !fnHookFunc64 || !fnProtectVirtualMemory64)
				{
					KeStackAttachProcess(Process, &kApc);
					fnProtectVirtualMemory64 = GetModuleExport(ImageBase, "ZwProtectVirtualMemory");
					fnLdrLoadDll64 = GetModuleExport(ImageBase, "LdrLoadDll");
					fnHookFunc64 = GetModuleExport(ImageBase, "ZwTestAlert");
					KeUnstackDetachProcess(&kApc);
				}

				status = STATUS_UNSUCCESSFUL;

				if (fnLdrLoadDll64 && fnHookFunc64 && fnProtectVirtualMemory64)
				{
					PINJECT_BUFFER pBuffer = GetInlineHookCode64(ProcessHandle, pDllPath);
					if (pBuffer)
					{
						UCHAR trampo[] = { 0xE9, 0, 0, 0, 0 };
						ULONG OldProtect = 0;
						PVOID ProtectAddress = fnHookFunc64;
						SIZE_T ProtectSize = sizeof(trampo);

						*(DWORD *)(trampo + 1) = (DWORD)((ULONG_PTR)pBuffer->code - ((ULONG_PTR)fnHookFunc64 + 5));

						status = NewNtProtectVirtualMemory(ProcessHandle, &ProtectAddress, &ProtectSize, PAGE_EXECUTE_READWRITE, &OldProtect);
						if (NT_SUCCESS(status))
						{
							NewNtWriteVirtualMemory(ProcessHandle, fnHookFunc64, trampo, sizeof(trampo), &ReturnLength);
							NewNtProtectVirtualMemory(ProcessHandle, &ProtectAddress, &ProtectSize, OldProtect, &OldProtect);
						}
					}
				}

				ZwClose(ProcessHandle);
			}
		}
		ObDereferenceObject(Process);
	}

	return status;
}

#endif

BOOLEAN ReadKernelMemory(PVOID pDestination, PVOID pSourceAddress, SIZE_T SizeOfCopy)
{
	PMDL pMdl = NULL;
	PVOID pSafeAddress = NULL;
	pMdl = IoAllocateMdl(pSourceAddress, (ULONG)SizeOfCopy, FALSE, FALSE, NULL);
	if (!pMdl) return FALSE;
	__try
	{
		MmProbeAndLockPages(pMdl, KernelMode, IoReadAccess);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		IoFreeMdl(pMdl);
		return FALSE;
	}
	pSafeAddress = MmGetSystemAddressForMdlSafe(pMdl, NormalPagePriority);
	if (!pSafeAddress) return FALSE;
	RtlCopyMemory(pDestination, pSafeAddress, SizeOfCopy);
	MmUnlockPages(pMdl);
	IoFreeMdl(pMdl);
	return TRUE;
}

BOOLEAN WriteKernelMemory(PVOID pDestination, PVOID pSourceAddress, SIZE_T SizeOfCopy)
{
	PMDL pMdl = NULL;
	PVOID pSafeAddress = NULL;
	pMdl = IoAllocateMdl(pDestination, (ULONG)SizeOfCopy, FALSE, FALSE, NULL);
	if (!pMdl) return FALSE;
	__try
	{
		MmProbeAndLockPages(pMdl, KernelMode, IoReadAccess);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		IoFreeMdl(pMdl);
		return FALSE;
	}
	pSafeAddress = MmGetSystemAddressForMdlSafe(pMdl, NormalPagePriority);
	if (!pSafeAddress) return FALSE;
	RtlCopyMemory(pSafeAddress, pSourceAddress, SizeOfCopy);
	MmUnlockPages(pMdl);
	IoFreeMdl(pMdl);
	return TRUE;
}
*/

}//EXTERN C