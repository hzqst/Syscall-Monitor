#include <fltKernel.h>

#include "../HyperPlatform/kernel_stl.h"
#include "main.h"

CProcList *m_IgnoreProcList = NULL;

CProcList::CProcList()
{
	ExInitializeResourceLite(&m_Lock);
}

CProcList::~CProcList()
{
	FreeAll();

	ExDeleteResourceLite(&m_Lock);
}

void CProcList::AddProcess(HANDLE ProcessId)
{
	ExAcquireResourceExclusiveLite(&m_Lock, TRUE);

	m_List.insert(ProcessId);

	ExReleaseResourceLite(&m_Lock);
}

BOOLEAN CProcList::Find(HANDLE ProcessId)
{
	ExAcquireResourceSharedLite(&m_Lock, TRUE);

	BOOLEAN bFind = (m_List.find(ProcessId) != m_List.end());

	ExReleaseResourceLite(&m_Lock);

	return bFind;
}

void CProcList::RemoveProcess(HANDLE ProcessId)
{
	ExAcquireResourceExclusiveLite(&m_Lock, TRUE);

	m_List.erase(ProcessId);

	ExReleaseResourceLite(&m_Lock);
}

void CProcList::FreeAll(void)
{
	ExAcquireResourceExclusiveLite(&m_Lock, TRUE);

	m_List.clear();

	ExReleaseResourceLite(&m_Lock);
}