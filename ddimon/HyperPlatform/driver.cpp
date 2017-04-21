// Copyright (c) 2015-2016, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

/// @file
/// Implements an entry point of the driver.

#ifndef POOL_NX_OPTIN
#define POOL_NX_OPTIN 1
#endif
#include "driver.h"
#include "common.h"
#include "log.h"
#include "powercallback.h"
#include "util.h"
#include "vm.h"
#include "performance.h"
#include "main.h"

EXTERN_C {

extern DYNAMIC_DATA dynData;

////////////////////////////////////////////////////////////////////////////////
//
// macro utilities
//

////////////////////////////////////////////////////////////////////////////////
//
// constants and macros
//

////////////////////////////////////////////////////////////////////////////////
//
// types
//

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

//Termination
static DRIVER_UNLOAD DriverpDriverUnload;
VOID FreeDynVers(VOID);
VOID CmTermination(VOID);
VOID PsTermination(VOID);

//Initialization
DRIVER_INITIALIZE DriverEntry;
bool DriverpIsSuppoetedOS();
NTSTATUS DriverEntryFilter(__in PDRIVER_OBJECT DriverObject, __in PUNICODE_STRING RegistryPath);
NTSTATUS InitDynamicData(IN OUT PDYNAMIC_DATA pData);
VOID CmInitialization(PDRIVER_OBJECT pDriverObject);
VOID PsInitialization(PDRIVER_OBJECT pDriverObject);
VOID InitDynVers(VOID);

#if defined(ALLOC_PRAGMA)
#pragma alloc_text(PAGE, DriverpDriverUnload)
#pragma alloc_text(PAGE, FreeDynVers)
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(INIT, DriverpIsSuppoetedOS)
#pragma alloc_text(INIT, InitDynVers)
#pragma alloc_text(INIT, DriverEntryFilter)
#endif

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

// A driver entry point
_Use_decl_annotations_ NTSTATUS DriverEntry(PDRIVER_OBJECT driver_object,
                                            PUNICODE_STRING registry_path) {
  UNREFERENCED_PARAMETER(registry_path);
  PAGED_CODE();

  static const wchar_t kLogFilePath[] = L"\\SystemRoot\\HyperPlatform.log";
  static const auto kLogLevel =
      (IsReleaseBuild()) ? kLogPutLevelInfo | kLogOptDisableFunctionName
                         : kLogPutLevelDebug | kLogOptDisableFunctionName;

  auto status = STATUS_UNSUCCESSFUL;
  driver_object->DriverUnload = DriverpDriverUnload;
  HYPERPLATFORM_COMMON_DBG_BREAK();

  // Request NX Non-Paged Pool when available
  ExInitializeDriverRuntime(DrvRtPoolNxOptIn);

  InitDynamicData(&dynData);
  InitDynVers();

  // Initialize log functions
  bool need_reinitialization = false;
  status = LogInitialization(kLogLevel, kLogFilePath);
  if (status == STATUS_REINITIALIZATION_NEEDED) {
    need_reinitialization = true;
  } else if (!NT_SUCCESS(status)) {
    return status;
  }

  // Test if the system is supported
  if (!DriverpIsSuppoetedOS()) {
    LogTermination();
	FreeDynVers();
    return STATUS_CANCELLED;
  }

  // Initialize perf functions
  status = PerfInitialization();
  if (!NT_SUCCESS(status)) {
    LogTermination();
	FreeDynVers();
    return status;
  }

  // Initialize utility functions
  status = UtilInitialization(driver_object);
  if (!NT_SUCCESS(status)) {
    PerfTermination();
    LogTermination();
	FreeDynVers();
    return status;
  }

  // Initialize power callback
  status = PowerCallbackInitialization();
  if (!NT_SUCCESS(status)) {
    UtilTermination();
    PerfTermination();
    LogTermination();
	FreeDynVers();
    return status;
  }

  // Virtualize all processors

  if (dynData.EnableVmx) 
  {
	  status = VmInitialization();
	  if (!NT_SUCCESS(status)) {
		  PowerCallbackTermination();
		  UtilTermination();
		  PerfTermination();
		  LogTermination();
		  FreeDynVers();
		  return status;
	  }
  }

  // Register re-initialization for the log functions if needed
  if (need_reinitialization) {
    LogRegisterReinitialization(driver_object);
  }

  CmInitialization(driver_object);
  PsInitialization(driver_object);

  DriverEntryFilter(driver_object, registry_path);
 
  HYPERPLATFORM_LOG_INFO("The VMM has been installed.");
  return status;
}

// Unload handler
_Use_decl_annotations_ static void DriverpDriverUnload(
    PDRIVER_OBJECT driver_object) {
  UNREFERENCED_PARAMETER(driver_object);
  PAGED_CODE();

  HYPERPLATFORM_COMMON_DBG_BREAK();

  PsTermination();
  CmTermination();

  VmTermination();

  PowerCallbackTermination();
  UtilTermination();
  PerfTermination();
  LogTermination();
  FreeDynVers();
}

// Test if the system is one of supported OS versions
_Use_decl_annotations_ bool DriverpIsSuppoetedOS() {
  PAGED_CODE();

  RTL_OSVERSIONINFOW os_version = {};
  auto status = RtlGetVersion(&os_version);
  if (!NT_SUCCESS(status)) {
    return false;
  }
  if (os_version.dwMajorVersion != 6 && os_version.dwMajorVersion != 10) {
    return false;
  }
  // 4-gigabyte tuning (4GT) should not be enabled
  if (!IsX64() &&
      reinterpret_cast<ULONG_PTR>(MmSystemRangeStart) != 0x80000000) {
    return false;
  }
  return true;
}

}  // extern "C"
