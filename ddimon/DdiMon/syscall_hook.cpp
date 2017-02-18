// Copyright (c) 2015-2016, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

/// @file
/// Implements syscall hook functions.

#include "syscall_hook.h"

#include <ntimage.h>
#define NTSTRSAFE_NO_CB_FUNCTIONS
#include <ntstrsafe.h>
#include "../HyperPlatform/common.h"
#include "../HyperPlatform/log.h"
#include "../HyperPlatform/util.h"
#include "../HyperPlatform/ept.h"
#include "../HyperPlatform/kernel_stl.h"
#include "../HyperPlatform/asm.h"

#define MAX_SYSCALL_INDEX  0x1000

EXTERN_C
{

CHAR HookEnabled[MAX_SYSCALL_INDEX] = { 0 };
CHAR ArgTble[MAX_SYSCALL_INDEX] = { 0 };
PVOID HookTable[MAX_SYSCALL_INDEX] = { 0 };

#ifdef _WIN64
PVOID KiSystemCall64Ptr = NULL;
#else
PVOID KiFastCallEntry = NULL;
#endif

// Enables syscall hook for all processors
_Use_decl_annotations_ NTSTATUS SyscallHookEnable() {
	PAGED_CODE();

#ifdef _WIN64
	if (KiSystemCall64Ptr == NULL)
	{
		KiSystemCall64Ptr = (PVOID)UtilReadMsr64(Msr::kIa32Lstar);
	}
	return UtilForEachProcessor(
		[](void* context) {
		UNREFERENCED_PARAMETER(context);
		return UtilVmCall(HypercallNumber::kHookSyscall, context);
	},
		nullptr);
#else
	if (KiFastCallEntry == NULL)
	{
		KiFastCallEntry = (PVOID)UtilReadMsr(Msr::kIa32SysenterEip);
	}
	return UtilForEachProcessor(
		[](void* context) {
		UNREFERENCED_PARAMETER(context);
		return UtilVmCall(HypercallNumber::kHookSyscall, context);
	},
		nullptr);
#endif
}

// Disables syscall hook for all processors
_Use_decl_annotations_ NTSTATUS SyscallHookDisable() {
	PAGED_CODE();

	return UtilForEachProcessor(
		[](void* context) {
		UNREFERENCED_PARAMETER(context);
		return UtilVmCall(HypercallNumber::kUnhookSyscall, nullptr);
	},
		nullptr);
}

/// <summary>
/// Hook specific SSDT entry
/// </summary>
/// <param name="index">SSDT index</param>
/// <param name="hookPtr">Hook address</param>
/// <param name="argCount">Number of function arguments</param>
/// <returns>Status code</returns>
_Use_decl_annotations_ NTSTATUS SyscallHookSSDT(IN ULONG index, IN PVOID hookPtr, IN CHAR argCount)
{
	NTSTATUS status = STATUS_SUCCESS;
	if (index > MAX_SYSCALL_INDEX || hookPtr == NULL)
		return STATUS_INVALID_PARAMETER;

	KIRQL irql = KeGetCurrentIrql();
	if (irql < DISPATCH_LEVEL)
		irql = KeRaiseIrqlToDpcLevel();
#ifdef _WIN64
	InterlockedExchange64((PLONG64)&HookTable[index], (LONG64)hookPtr);
#else
	InterlockedExchange((PLONG)&HookTable[index], (LONG)hookPtr);
#endif
	InterlockedExchange8(&ArgTble[index], argCount);
	InterlockedExchange8(&HookEnabled[index], TRUE);

	if (KeGetCurrentIrql() > irql)
		KeLowerIrql(irql);

	return status;
}

}