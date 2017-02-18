#include <fltKernel.h>

#include "../HyperPlatform/kernel_stl.h"
#include "main.h"

CEventList *m_EventList = NULL;

extern PFLT_PORT 	m_pClientPort;

CEventList::CEventList()
{
	ExInitializeFastMutex(&m_MsgLock);
	KeInitializeEvent(&m_MsgEvent, SynchronizationEvent, FALSE);
	m_Stop = 0; 
	m_hMsgThread = NULL;
	m_EventCount = 0;
	m_EnableCapture = 0;
}

CEventList::~CEventList()
{
	FreeAll();
}

bool CEventList::IsCapturing(void)
{
	if (m_pClientPort != NULL && m_EnableCapture != 0 && !m_Stop)
		return true;

	return false;
}

ULONG64 CEventList::GetEventId(void)
{
	ULONG64 EventId = 0;

	Lock();
	if (m_List.size() < 1000)
	{
		EventId = m_EventCount;
		++m_EventCount;
		if (EventId > 0xFFFFFFFFFF64)
			EventId = 1;
	}
	Unlock();

	return EventId;
}

void CEventList::SendEvent(PVOID pEvent)
{
	m_List.push_back(pEvent);
}

void CEventList::NotifyEvent(void)
{
	KeSetEvent(&m_MsgEvent, IO_NO_INCREMENT, FALSE);
}

void CEventList::FreeAll(void)
{
	Lock();

	InterlockedExchange(&m_EnableCapture, 0);

	m_EventCount = 0;

	for (std::list<PVOID>::iterator itor = m_List.begin(); itor != m_List.end(); ++itor)
	{
		ExFreePoolWithTag(*itor, 'TXSB');
	}

	m_List.clear();

	Unlock();
}

void CEventList::Lock(void)
{
	ExAcquireFastMutex(&m_MsgLock);
}

void CEventList::Unlock(void)
{
	ExReleaseFastMutex(&m_MsgLock);
}