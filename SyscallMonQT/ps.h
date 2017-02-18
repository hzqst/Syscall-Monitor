#pragma once
#include <Windows.h>
#include "ps.h"

#include <boost/bind.hpp>
#include <boost/function.hpp>

typedef boost::function<void(ULONG)> fnEnumProcessProc;
typedef boost::function<void(ULONG64, ULONG, LPCWSTR, int)> fnEnumSysModuleProc;

ULONG EnumProcesses(fnEnumProcessProc fnEnumProc);
BOOL EnumSystemModules(fnEnumSysModuleProc fnEnumProc);
