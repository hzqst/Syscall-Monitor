#include <QTranslator>
#include <Windows.h>
#include <time.h>
#include "ProcessMgr.h"
#include "EventMgr.h"
#include "DriverWrapper.h"
#include "util.h"
#include "nt.h"

#define USE_DL_PREFIX
#include "dlmalloc.h"

CEventMgr *m_EventMgr = NULL;

CCallStack::CCallStack()
{
    m_ReturnAddress = NULL;
    m_UniqueModule = NULL;
}

CCallStack::CCallStack(ULONG64 ReturnAddress, CUniqueModule *um)
{
    m_ReturnAddress = ReturnAddress;
    m_UniqueModule = um;
}

ULONG CCallStack::GetClosestFunctionOffset(std::string &funcName)
{
    return m_UniqueModule->FindClosestFunction(m_ReturnAddress - m_UniqueModule->m_ImageBase, funcName);
}

//event

CUniqueEvent::CUniqueEvent(CUniqueProcess *up, ULONG ThreadId, ULONG64 KeSystemTime, ULONG64 EventId)
{
    m_UniqueProcess = up;
    m_ThreadId = ThreadId;
    m_EventId = EventId;
    m_EventTime = (KeSystemTime - m_EventMgr->m_u64KeSystemTimeStart) + m_EventMgr->m_u64UnixTimeStart;
    m_KernelCallerCount = 0;
    m_UserCallerCount = 0;
}

size_t g_total;

void* CUniqueEvent::operator new(size_t size)
{
    g_total += size;
    //OutputDebugString((LPCWSTR)QString("CRegKeyValue alloc %1 / %2 bytes\n").arg(size).arg(g_total).utf16());
    return dlmalloc(size);
}

void CUniqueEvent::operator delete(void*p)
{
    dlfree(p);
}

void CUniqueEvent::CreateCallStacks(int kernelCaller, int userCaller, ULONG64 *callers)
{
    m_CallStacks.reserve(kernelCaller + userCaller);
    for(int i = 0; i < kernelCaller; ++i) {
        ULONG64 retAddr = callers[i];
        if(NULL == retAddr)
            continue;
        m_CallStacks.emplace_back(CCallStack(retAddr, m_ProcessMgr->m_PsSystemProcess->GetModuleFromAddress(retAddr)));
        m_KernelCallerCount ++;
    }
    for(int i = 0; i < userCaller; ++i) {
        ULONG64 retAddr = callers[i + kernelCaller];
        if(NULL == retAddr)
            continue;
        m_CallStacks.emplace_back(CCallStack(retAddr, GetUniqueProcess()->GetModuleFromAddress(retAddr)));
        m_UserCallerCount ++;
    }
}

void CUniqueEvent::FixCallStacks(bool bQueryUnknownMods)
{
    for(int i = 0; i < (int)m_CallStacks.size(); ++i)
    {
        CUniqueModule *um = m_CallStacks[i].m_UniqueModule;
        if(um) continue;
        if(i < m_KernelCallerCount)
        {
            um = m_ProcessMgr->m_PsSystemProcess->GetModuleFromAddress(m_CallStacks[i].m_ReturnAddress);
            if(um)
            {
                m_CallStacks[i].m_UniqueModule = um;
                continue;
            }
        }
        else
        {
            um = GetUniqueProcess()->GetModuleFromAddress(m_CallStacks[i].m_ReturnAddress);
            if(um)
            {
                 m_CallStacks[i].m_UniqueModule = um;
                 continue;
            }
            else if(bQueryUnknownMods)
            {
                m_ModuleMgr->QueuedGetModuleInfo(GetUniqueProcess(), m_CallStacks[i].m_ReturnAddress);
                continue;
            }
        }
    }
}

QString CUniqueEvent::GetEventName(void) const
{
    return m_EventMgr->m_EventNames[GetEventType()];
}

QString CUniqueEvent::GetEventClassName(void) const
{
    return m_EventMgr->m_EventClassNames[GetEventClassify()];
}

//worker

CEventWorker::CEventWorker(QObject *parent) : QObject(parent)
{

}

void CEventWorker::OnFilterRoutine(void)
{
    m_EventMgr->FilterRoutine();
}

//mgr

CEventMgr::CEventMgr(QObject *parent) : QObject(parent)
{
    m_EventMgr = this;
    m_CaptureEnable = TRUE;
    m_DropExclude = FALSE;
    InitializeCriticalSection(&m_Lock);
    m_hReadyEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    m_EventList.reserve(100000);
}

CEventMgr::~CEventMgr()
{
    if(m_hReadyEvent != NULL)
        CloseHandle(m_hReadyEvent);

    DeleteCriticalSection(&m_Lock);
}

void CEventMgr::Initialize(void)
{
    m_EventNames[EV_ProcessCreate] = tr("ProcessCreate");
    m_EventNames[EV_ProcessDestroy] = tr("ProcessExit");
    m_EventNames[EV_CreateProcess] = tr("CreateProcess");
    m_EventNames[EV_ThreadCreate] = tr("ThreadCreate");
    m_EventNames[EV_ThreadDestroy] = tr("ThreadExit");
    m_EventNames[EV_CreateThread] = tr("CreateThread");
    m_EventNames[EV_LoadImage] = tr("LoadImage");
    m_EventNames[EV_LoadDriver] = tr("LoadDriver");
    m_EventNames[EV_EnumProcess] = tr("EnumProcesses");
    m_EventNames[EV_EnumSystemModule] = tr("EnumSystemModules");
    m_EventNames[EV_EnumSystemHandle] = tr("EnumSystemHandles");
    m_EventNames[EV_EnumSystemObject] = tr("EnumSystemObjects");
    m_EventNames[EV_OpenProcess] = tr("OpenProcess");
    m_EventNames[EV_OpenThread] = tr("OpenThread");
    m_EventNames[EV_TerminateProcess] = tr("TerminateProcess");
    m_EventNames[EV_AllocateVirtualMemory] = tr("AllocateVirtualMemory");
    m_EventNames[EV_ReadVirtualMemory] = tr("ReadVirtualMemory");
    m_EventNames[EV_WriteVirtualMemory] = tr("WriteVirtualMemory");
    m_EventNames[EV_ProtectVirtualMemory] = tr("ProtectVirtualMemory");
    m_EventNames[EV_QueryVirtualMemory] = tr("QueryVirtualMemory");
    m_EventNames[EV_CreateMutex] = tr("CreateMutex");
    m_EventNames[EV_OpenMutex] = tr("OpenMutex");
    m_EventNames[EV_CreateDirectoryObject] = tr("CreateDirectoryObject");
    m_EventNames[EV_OpenDirectoryObject] = tr("OpenDirectoryObject");
    m_EventNames[EV_QueryDirectoryObject] = tr("QueryDirectoryObject");
    m_EventNames[EV_SetWindowsHook] = tr("SetWindowsHook");
    m_EventNames[EV_FindWindow] = tr("FindWindow");
    m_EventNames[EV_GetWindowText] = tr("GetWindowText");
    m_EventNames[EV_GetWindowClass] = tr("GetWindowClass");
    m_EventNames[EV_CreateFile] = tr("CreateFile");
    m_EventNames[EV_CloseFile] = tr("CloseFile");
    m_EventNames[EV_ReadFile] = tr("ReadFile");
    m_EventNames[EV_WriteFile] = tr("WriteFile");
    m_EventNames[EV_CreateFileMapping] = tr("CreateFileMapping");
    m_EventNames[EV_QueryFileInformation] = tr("QueryFileInformation");
    m_EventNames[EV_CreateKey] = tr("RegCreateKey");
    m_EventNames[EV_OpenKey] = tr("RegOpenKey");
    m_EventNames[EV_SetValueKey] = tr("RegSetValueKey");
    m_EventNames[EV_QueryValueKey] = tr("RegQueryValueKey");
    m_EventNames[EV_QueryKey] = tr("RegQueryKey");

    m_EventClassNames[EVClass_PsNotify] = tr("PsNotify");
    m_EventClassNames[EVClass_Syscall] = tr("SystemService");
    m_EventClassNames[EVClass_FileSystem] = tr("FileSystem");
    m_EventClassNames[EVClass_Registry] = tr("Registry");

    m_FltKeyTable[FltKey_PID] = tr("PID");
    m_FltKeyTable[FltKey_ProcessName] = tr("Process Name");
    m_FltKeyTable[FltKey_ProcessPath] = tr("Image Path");
    m_FltKeyTable[FltKey_EventPath] = tr("Path");
    m_FltKeyTable[FltKey_Arch] = tr("Architecture");
    m_FltKeyTable[FltKey_SessionId] = tr("Session ID");
    m_FltKeyTable[FltKey_EventType] = tr("Behavior");
    m_FltKeyTable[FltKey_EventClass] = tr("Event Class");
    m_FltKeyTable[FltKey_BriefResult] = tr("Result");

    m_FltRelTable[FltRel_Is] = tr("=");
    m_FltRelTable[FltRel_IsNot] = tr("!=");
    m_FltRelTable[FltRel_LargerThan] = tr(">=");
    m_FltRelTable[FltRel_SmallerThan] = tr("<=");
    m_FltRelTable[FltRel_Contain] = tr("contain");
    m_FltRelTable[FltRel_NotContain] = tr("not contain");

    m_FltIncTable[0] = tr("Include");
    m_FltIncTable[1] = tr("Exclude");

    SyncKeSystemTime(GetKeSystemTime());

    CEventWorker *worker = new CEventWorker;
    worker->moveToThread(&m_workerThread);
    connect(&m_workerThread, SIGNAL(finished()), worker, SLOT(deleteLater()));
    connect(this, &CEventMgr::StartFilter, worker, &CEventWorker::OnFilterRoutine, Qt::QueuedConnection);
    m_workerThread.start();

    //Add basic filters, exclude current process and system process.
    CEventFilter *flt;

    flt = new CEventFilter_PID(GetCurrentProcessId(), FltRel_Is, false);
    flt->Reference();
    m_FilterList.push_back(flt);
    m_KeyFilterList[FltKey_PID].push_back(flt);

    flt = new CEventFilter_PID(4, FltRel_Is, false);
    flt->Reference();
    m_FilterList.push_back(flt);
    m_KeyFilterList[FltKey_PID].push_back(flt);
}

void CEventMgr::Uninitialize(void)
{
    m_workerThread.quit();
    m_workerThread.wait();

    /*for(int i = 0;i < m_FilterList.size(); ++i)
        m_FilterList[i]->Dereference();

    ClearAllEvents();*/
}

void CEventMgr::StartParsing(void)
{
    //Ready to go
    SetEvent(m_hReadyEvent);
}

void CEventMgr::AddEvent(CUniqueEvent *ev)
{
    bool bPass = DoFilter(ev);
    if(!m_DropExclude) {
        InsertEvent(ev);
        if(bPass)
            AddEventItem(ev);
    } else {
        if(bPass){
            InsertEvent(ev);
            AddEventItem(ev);
        } else {
            delete ev;
        }
    }
}

void CEventMgr::Lock(void)
{
    EnterCriticalSection(&m_Lock);
}

void CEventMgr::Unlock(void)
{
    LeaveCriticalSection(&m_Lock);
}

void CEventMgr::LoadFilters(const CFilterList &list)
{
    for(size_t i = 0;i < FltKey_Max; ++i)
        m_KeyFilterList[i].clear();

    for(size_t i = 0;i < list.size(); ++i)
    {
        m_KeyFilterList[ (int)list[i]->GetKey() ].push_back( list[i] );
        list[i]->Reference();
    }

    //Delete all filters which is not referenced anymore
    for(size_t i = 0;i < m_FilterList.size(); ++i)
        m_FilterList[i]->Dereference();

    //Copy list
    m_FilterList = list;
}

void CEventMgr::GetFilters(CFilterList &list)
{
    list = m_FilterList;
}

CUniqueEvent *CEventMgr::FindEventById(ULONG64 EventId)
{
    QEventList::reverse_iterator it = m_EventList.rbegin();
    if(it == m_EventList.rend())
        return NULL;

    CUniqueEvent *ev = (CUniqueEvent *)(*it);

    if(EventId > ev->GetEventId())
        return NULL;

    while(it != m_EventList.rend()){
        ev = (CUniqueEvent *)(*it);
        if(ev->GetEventId() == EventId && ev->GetEventType() != EV_ProcessCreate && ev->GetEventType() != EV_ThreadCreate)
            return ev;
        ++it;
    }
    return NULL;
}

void CEventMgr::ClearAllEvents(void)
{
    Lock();

    ClearAllDisplayingEvents();

    QEventList::iterator it = m_EventList.begin();
    while(it != m_EventList.end()){
        delete (*it);
        ++it;
    }
    m_EventList.clear();

    Unlock();
}

void CEventMgr::InsertEvent(CUniqueEvent *ev)
{
    //No need to sort
    m_EventList.push_back(ev);
}

void CEventMgr::SyncKeSystemTime(const ULONG64 KeSystemTime)
{
	m_u64UnixTimeStart = time(NULL) * 1000;
	m_u64KeSystemTimeStart = KeSystemTime;
}

bool CEventMgr::DoFilter(const CUniqueEvent *ev)
{
    int bAnyInclude[FltKey_Max] = { 0 };
    int bKeyPass[FltKey_Max] = { 0 };
    for (size_t i = 0; i < FltKey_Max; ++i)
    {
        CFilterList &list = m_KeyFilterList[i];
        for (size_t j = 0; j < list.size(); ++j)
        {
            bool bPass = list[j]->DoFilter(ev);
            bool bInclude = list[j]->m_Include;

            if (!bAnyInclude[i] && bInclude)
                bAnyInclude[i] = 1;

            if (bPass && !bInclude)
                return false;

            if (bPass && bInclude)
            {
                bKeyPass[i] = 1;
                break;
            }
        }
    }
    for (size_t i = 0; i < FltKey_Max; ++i)
    {
        if (bAnyInclude[i] && !bKeyPass[i])
            return false;
    }
    return true;
}

//Thread routine

void CEventMgr::FilterRoutine(void)
{
    Lock();

    QEventList *resultList = new QEventList;

    size_t total = m_EventList.size();
    size_t step = max(total / 100, 1);
    resultList->reserve((int)total);

    for(int i = 0;i < m_EventList.size(); ++i){
        const auto ev = m_EventList[i];
        if(DoFilter(ev))
            resultList->push_back(ev);
        if(i % step == 0)
            FilterUpdatePercent(i, total);
    }

    RefillEventItems(resultList);

    Unlock();
}

void CEventMgr::OnCallStack(QSharedPointer<QByteArray> data)
{
    auto param = (svc_callstack_data *)data->constData();
    auto ev = FindEventById(param->eventId);
    if(!ev)
        return;

    ev->CreateCallStacks(param->KernelCallerCount, param->UserCallerCount, param->Callers);
}

void CEventMgr::OnPsCreateProcess(QSharedPointer<QByteArray> data)
{
    auto param = (svc_ps_create_process_data *)data->constData();

    std::wstring NormalizedImagePath;
    NormalizeFilePath(param->ImagePath, NormalizedImagePath);

    CUniqueProcess *up = NULL;

    if (param->Create)
    {
        up = m_ProcessMgr->Find(param->ProcessId);
        if (!up) {

            //File operation is slow...?
            QIcon *pIcon = m_ProcessMgr->GetImageFileIcon(NormalizedImagePath);

            up = new CUniqueProcess(param->ProcessId, param->ParentProcessId,
                                    param->CreateTime, param->Is64Bit ? true : false,
                                    param->SessionId, NormalizedImagePath.c_str(),
                                    param->CommandLine, param->CurDirectory, pIcon);
            m_ProcessMgr->InsertProcess(up);
            m_ProcessMgr->FillParent(up);

            emit m_ProcessMgr->AddProcessItem(up);
        }
    } else {
        up = m_ProcessMgr->Find(param->ProcessId);
        if (up)
        {
            up->m_bAlive = false;
            emit m_ProcessMgr->KillProcessItem(up);
        }
    }

    if(!m_CaptureEnable)
        return;

    if(param->Create)
    {
        auto creator = m_ProcessMgr->Find(param->ParentProcessId);
        if(creator) {
            AddEvent(new CUniqueEvent_CreateProcess(
                         creator, param->ThreadId, up,
                         param->time, param->eventId));
            AddEvent(new CUniqueEvent_ProcessCreate(
                         up, param->ThreadId,
                         param->time, param->eventId));
        }
    } else {
        if (up)
        {
            AddEvent(new CUniqueEvent_ProcessDestroy(
                         up, param->ThreadId,
                         param->time, param->eventId));
        }
    }
}

void CEventMgr::OnPsCreateThread(QSharedPointer<QByteArray> data)
{
    if (!m_CaptureEnable)
        return;
    auto param = (svc_ps_create_thread_data *)data->constData();

    auto up = m_ProcessMgr->Find(param->ProcessId);
    if (!up)
        return;
    if(param->Create)
    {
        auto creator = m_ProcessMgr->Find(param->CurProcessId);
        if(creator)
        {
            AddEvent(new CUniqueEvent_CreateThread(
                         creator, param->CurThreadId,
                         up, param->ThreadId,
                         param->time, param->eventId));

            AddEvent(new CUniqueEvent_ThreadCreate(
                         up, param->ThreadId, creator, param->CurThreadId,
                         param->ThreadStartAddress, param->ThreadFlags,
                         param->time, param->eventId));
        }
    }
    else
    {
        AddEvent(new CUniqueEvent_ThreadDestroy(
                     up, param->ThreadId,
                     param->time, param->eventId) );
    }
}

void CEventMgr::OnPsLoadImage(QSharedPointer<QByteArray> data)
{
    if(!m_CaptureEnable)
        return;
    auto param = (svc_ps_load_image_data *)data->constData();
    auto up = m_ProcessMgr->Find(param->ProcessId);
    if (!up)
        return;
    bool bIs64Bit;
    if(param->ProcessId == 4)
        bIs64Bit = IsAMD64() ? true : false;
    else
        bIs64Bit = param->ImageBase > 0xffffffff ? true : false;

    std::wstring NormalizedImagePath;
    NormalizeFilePath(param->ImagePath, NormalizedImagePath);

    auto ui = m_ModuleMgr->GetImage( NormalizedImagePath,
                                     param->ImageSize, bIs64Bit, (param->ProcessId == 4) ? true : false);

    up->m_ModuleList.push_back(new CUniqueModule(param->ImageBase, ui));
    if(param->eventId > 0)
    {
        AddEvent(new CUniqueEvent_LoadImage(
                     up, param->ThreadId,
                     NormalizedImagePath.c_str(), param->ImageBase, param->ImageSize,
                     param->time, param->eventId));
    }
}

void CEventMgr::OnNtLoadDriver(QSharedPointer<QByteArray> data)
{
    if(!m_CaptureEnable)
        return;
    auto param = (svc_nt_load_driver_data *)data->constData();
    CUniqueProcess *up = m_ProcessMgr->Find(param->ProcessId);
    if (!up)
        return;
    AddEvent(new CUniqueEvent_LoadDriver(
                 up, param->ThreadId,
                 param->RegisterPath, param->ImagePath,
                 param->ResultStatus, param->time, param->eventId));
}

void CEventMgr::OnNtQuerySystemInfo(QSharedPointer<QByteArray> data)
{
    if(!m_CaptureEnable)
        return;
    auto param = (svc_nt_query_systeminfo_data *)data->constData();
    auto up = m_ProcessMgr->Find(param->ProcessId);
    if (!up)
        return;
    switch (param->QueryClass)
    {
    case SystemProcessInformation:
        AddEvent(new CUniqueEvent_EnumProcess(up, param->ThreadId, param->time, param->eventId));
        break;
    case SystemModuleInformation:
        AddEvent(new CUniqueEvent_EnumSystemModule(up, param->ThreadId, param->time, param->eventId));
        break;
    case SystemHandleInformation:
        AddEvent(new CUniqueEvent_EnumSystemHandle(up, param->ThreadId, param->time, param->eventId));
        break;
    case SystemObjectInformation:
        AddEvent(new CUniqueEvent_EnumSystemObject(up, param->ThreadId, param->time, param->eventId));
        break;
    }
}

void CEventMgr::OnNtOpenProcess(QSharedPointer<QByteArray> data)
{
    if(!m_CaptureEnable)
        return;
    auto param = (svc_nt_open_process_data *)data->constData();
    CUniqueProcess *up = m_ProcessMgr->Find(param->ProcessId);
    CUniqueProcess *target = m_ProcessMgr->Find(param->TargetProcessId);
    if (!up || !target)
        return;
    AddEvent(new CUniqueEvent_OpenProcess(
                 up, param->ThreadId, target,
                 param->DesiredAccess, param->ResultStatus,
                 param->time, param->eventId));
}

void CEventMgr::OnNtOpenThread(QSharedPointer<QByteArray> data)
{
    if(!m_CaptureEnable)
        return;
    auto param = (svc_nt_open_thread_data *)data->constData();
    CUniqueProcess *up = m_ProcessMgr->Find(param->ProcessId);
    CUniqueProcess *target = m_ProcessMgr->Find(param->TargetProcessId);
    if (!up || !target)
        return;
    AddEvent(new CUniqueEvent_OpenThread(
                 up, param->ThreadId, target, param->TargetThreadId,
                 param->DesiredAccess, param->ResultStatus,
                 param->time, param->eventId));
}

void CEventMgr::OnNtTerminateProcess(QSharedPointer<QByteArray> data)
{
    if(!m_CaptureEnable)
        return;
    auto param = (svc_nt_terminate_process_data *)data->constData();
    CUniqueProcess *up = m_ProcessMgr->Find(param->ProcessId);
    CUniqueProcess *target = m_ProcessMgr->Find(param->TargetProcessId);
    if (!up || !target)
        return;
    AddEvent(new CUniqueEvent_TerminateProcess(
                 up, param->ThreadId,
                 target, param->ResultStatus,
                 param->time, param->eventId));
}

void CEventMgr::OnNtAllocateVirtualMemory(QSharedPointer<QByteArray> data)
{
    if(!m_CaptureEnable)
        return;
    auto param = (svc_nt_alloc_virtual_mem_data *)data->constData();
    CUniqueProcess *up = m_ProcessMgr->Find(param->ProcessId);
    CUniqueProcess *target = m_ProcessMgr->Find(param->TargetProcessId);
    if (!up || !target)
        return;
    AddEvent(new CUniqueEvent_AllocateVirtualMemory(
                 up, param->ThreadId, target,
                 param->OldBaseAddress, param->OldRegionSize,
                 param->NewBaseAddress, param->NewRegionSize,
                 param->AllocationType, param->Protect,
                 param->ResultStatus, param->time, param->eventId));
}

void CEventMgr::OnNtReadWriteVirtualMemory(QSharedPointer<QByteArray> data)
{
    if(!m_CaptureEnable)
        return;
    auto param = (svc_nt_readwrite_virtual_mem_data *)data->constData();
    CUniqueProcess *up = m_ProcessMgr->Find(param->ProcessId);
    CUniqueProcess *target = m_ProcessMgr->Find(param->TargetProcessId);
    if (!up || !target)
        return;
    if(param->IsWrite)
        AddEvent(new CUniqueEvent_WriteVirtualMemory(
                     up, param->ThreadId, target,
                     param->BaseAddress, param->BufferSize,
                     param->ResultStatus, param->time, param->eventId));
    else
        AddEvent(new CUniqueEvent_ReadVirtualMemory(
                     up, param->ThreadId, target,
                     param->BaseAddress, param->BufferSize,
                     param->ResultStatus, param->time, param->eventId));

}

void CEventMgr::OnNtProtectVirtualMemory(QSharedPointer<QByteArray> data)
{
    if(!m_CaptureEnable)
        return;
    auto param = (svc_nt_protect_virtual_mem_data *)data->constData();
    CUniqueProcess *up = m_ProcessMgr->Find(param->ProcessId);
    CUniqueProcess *target = m_ProcessMgr->Find(param->TargetProcessId);
    if (!up || !target)
        return;
    AddEvent(new CUniqueEvent_ProtectVirtualMemory(
                 up, param->ThreadId, target,
                 param->OldBaseAddress, param->OldRegionSize,
                 param->NewBaseAddress, param->NewRegionSize,
                 param->OldProtect, param->NewProtect,
                 param->ResultStatus, param->time, param->eventId));
}

void CEventMgr::OnNtQueryVirtualMemory(QSharedPointer<QByteArray> data)
{
    if(!m_CaptureEnable)
        return;
    auto param = (svc_nt_query_virtual_mem_data *)data->constData();
    CUniqueProcess *up = m_ProcessMgr->Find(param->ProcessId);
    CUniqueProcess *target = m_ProcessMgr->Find(param->TargetProcessId);
    if (!up || !target)
        return;
    if(param->QueryClass == MemoryBasicInformationEx) {
        AddEvent(new CUniqueEvent_QueryVirtualMemory_BasicInformation(
                     up, param->ThreadId,
                     target, param->BaseAddress, &param->mbi,
                     param->ResultStatus, param->time, param->eventId));
    } else if(param->QueryClass == MemoryMappedFilenameInformation) {
        AddEvent(new CUniqueEvent_QueryVirtualMemory_MappedFileName(
                     up, param->ThreadId, target,
                     param->BaseAddress, param->MappedFileName,
                     param->ResultStatus, param->time, param->eventId));
    } else {
        AddEvent(new CUniqueEvent_QueryVirtualMemory(
                     up, param->ThreadId, target,
                     param->BaseAddress, param->QueryClass,
                     param->ResultStatus, param->time, param->eventId));
    }
}

void CEventMgr::OnNtCreateOpenMutant(QSharedPointer<QByteArray> data)
{
    if(!m_CaptureEnable)
        return;
    auto param = (svc_nt_createopen_mutant_data *)data->constData();
    CUniqueProcess *up = m_ProcessMgr->Find(param->ProcessId);
    if (!up )
        return;
    if(!param->IsOpen)
        AddEvent(new CUniqueEvent_CreateMutex(
                 up, param->ThreadId, param->MutexName,
                 param->DesiredAccess, param->InitialOwner ? true : false,
                 param->ResultStatus, param->time, param->eventId));
    else
        AddEvent(new CUniqueEvent_OpenMutex(
                 up, param->ThreadId, param->MutexName, param->DesiredAccess,
                     param->ResultStatus, param->time, param->eventId));
}

void CEventMgr::OnNtCreateOpenDirectoryObject(QSharedPointer<QByteArray> data)
{
    if(!m_CaptureEnable)
        return;
    auto param = (svc_nt_createopen_dirobj_data *)data->constData();
    CUniqueProcess *up = m_ProcessMgr->Find(param->ProcessId);
    if (!up )
        return;
    if(!param->IsOpen)
        AddEvent(new CUniqueEvent_CreateDirectoryObject(
                 up, param->ThreadId, param->ObjectName, param->DesiredAccess,
                     param->ResultStatus, param->time, param->eventId));
    else
        AddEvent(new CUniqueEvent_OpenDirectoryObject(
                 up, param->ThreadId, param->ObjectName, param->DesiredAccess,
                     param->ResultStatus, param->time, param->eventId));
}

void CEventMgr::OnNtQueryDirectoryObject(QSharedPointer<QByteArray> data)
{
    if(!m_CaptureEnable)
        return;
    auto param = (svc_nt_query_dirobj_data *)data->constData();
    CUniqueProcess *up = m_ProcessMgr->Find(param->ProcessId);
    if (!up )
        return;
    AddEvent(new CUniqueEvent_QueryDirectoryObject(
                 up, param->ThreadId, param->ObjectName,
                 param->ResultStatus, param->time, param->eventId));
}

void CEventMgr::OnNtUserSetWindowsHook(QSharedPointer<QByteArray> data)
{
    if(!m_CaptureEnable)
        return;
    auto param = (svc_nt_setwindowshook_data *)data->constData();
    CUniqueProcess *up = m_ProcessMgr->Find(param->ProcessId);
    if (!up)
        return;
    AddEvent(new CUniqueEvent_SetWindowsHook(
                 up, param->ThreadId,
                 param->HookThreadId, param->HookType,
                 param->HookProc, param->Flags,
                 param->Module, param->ModuleName,
                 param->ResultHHook, param->time, param->eventId
                 ));
}

void CEventMgr::OnNtUserFindWindow(QSharedPointer<QByteArray> data)
{
    if(!m_CaptureEnable)
        return;
    auto param = (svc_nt_findwindow_data *)data->constData();
    CUniqueProcess *up = m_ProcessMgr->Find(param->ProcessId);
    if (!up)
        return;
    AddEvent(new CUniqueEvent_FindWindow(
                 up, param->ThreadId,
                 param->HwndParent, param->HwndChild,
                 param->ClassName, param->WindowName,
                 param->ResultHwnd, param->time, param->eventId
                 ));
}

void CEventMgr::OnNtUserInternalGetWindowText(QSharedPointer<QByteArray> data)
{
    if(!m_CaptureEnable)
        return;
    auto param = (svc_nt_getwindowtext_data *)data->constData();
    CUniqueProcess *up = m_ProcessMgr->Find(param->ProcessId);
    if (!up)
        return;
    AddEvent(new CUniqueEvent_GetWindowText(
                 up, param->ThreadId,
                 param->Hwnd, param->MaxCount, param->WindowName,
                 param->ResultCount, param->time, param->eventId
                 ));
}

void CEventMgr::OnNtUserGetClassName(QSharedPointer<QByteArray> data)
{
    if(!m_CaptureEnable)
        return;
    auto param = (svc_nt_getwindowclass_data *)data->constData();
    CUniqueProcess *up = m_ProcessMgr->Find(param->ProcessId);
    if (!up)
        return;
    AddEvent(new CUniqueEvent_GetWindowClass(
                 up, param->ThreadId,
                 param->Hwnd, param->MaxCount, param->WindowClass,
                 param->ResultCount, param->time, param->eventId
                 ));
}

void CEventMgr::OnFsCreateFile(QSharedPointer<QByteArray> data)
{
    if(!m_CaptureEnable)
        return;
    auto param = (svc_fs_create_file_data *)data->constData();
    CUniqueProcess *up = m_ProcessMgr->Find(param->ProcessId);
    if (!up)
        return;
    AddEvent(new CUniqueEvent_CreateFile(
                 up, param->ThreadId, param->FilePath,
                 param->DesiredAccess, param->Disposition,
                 param->Options, param->ShareAccess,
                 param->Attributes, param->ResultStatus,
                 param->time, param->eventId));
}

void CEventMgr::OnFsCloseFile(QSharedPointer<QByteArray> data)
{
    if(!m_CaptureEnable)
        return;
    auto param = (svc_fs_close_file_data *)data->constData();
    CUniqueProcess *up = m_ProcessMgr->Find(param->ProcessId);
    if (!up)
        return;
    AddEvent(new CUniqueEvent_CloseFile(
                 up, param->ThreadId,
                 param->FilePath, param->ResultStatus,
                 param->time, param->eventId));
}

void CEventMgr::OnFsReadWriteFile(QSharedPointer<QByteArray> data)
{
    if(!m_CaptureEnable)
        return;
    auto param = (svc_fs_readwrite_file_data *)data->constData();
    CUniqueProcess *up = m_ProcessMgr->Find(param->ProcessId);
    if (!up)
        return;
    if(param->IsWrite)
        AddEvent(new CUniqueEvent_WriteFile(
                     up, param->ThreadId, param->FilePath,
                     param->Length, param->ByteOffset,
                     param->ResultStatus, param->time, param->eventId));
    else
        AddEvent(new CUniqueEvent_ReadFile(
                     up, param->ThreadId,
                     param->FilePath, param->Length, param->ByteOffset,
                     param->ResultStatus, param->time, param->eventId));
}

void CEventMgr::OnFsCreateFileMapping(QSharedPointer<QByteArray> data)
{
    if(!m_CaptureEnable)
        return;
    auto param = (svc_fs_createfilemapping_data *)data->constData();
    CUniqueProcess *up = m_ProcessMgr->Find(param->ProcessId);
    if (!up)
        return;
    AddEvent(new CUniqueEvent_CreateFileMapping(
                 up, param->ThreadId,
                 param->FilePath, param->SyncType, param->PageProtection,
                 param->ResultStatus, param->time, param->eventId));
}

void CEventMgr::OnFsQueryFileInformation(QSharedPointer<QByteArray> data)
{
    if(!m_CaptureEnable)
        return;
    auto param = (svc_fs_queryfileinformation_data *)data->constData();
    CUniqueProcess *up = m_ProcessMgr->Find(param->ProcessId);
    if (!up)
        return;
    std::wstring fileNameInfo;
    if(param->AllInfo.NameInformation.FileNameLength > 0){
        fileNameInfo = std::wstring(param->AllInfo.NameInformation.FileName, param->AllInfo.NameInformation.FileNameLength/sizeof(WCHAR));
    }

    AddEvent(new CUniqueEvent_QueryFileInformation(
                 up, param->ThreadId, param->FilePath,
                 param->QueryClass, &param->AllInfo, fileNameInfo.c_str(),
                 param->ResultStatus, param->time, param->eventId));
}

void CEventMgr::OnRgCreateOpenKey(QSharedPointer<QByteArray> data)
{
    if(!m_CaptureEnable)
        return;
    auto param = (svc_reg_createopenkey_data *)data->constData();
    CUniqueProcess *up = m_ProcessMgr->Find(param->ProcessId);
    if (!up)
        return;
    if(param->IsOpen)
        AddEvent(new CUniqueEvent_OpenKey(
                     up, param->ThreadId,
                     param->KeyPath, param->DesiredAccess,
                     param->ResultStatus, param->time, param->eventId));
    else
        AddEvent(new CUniqueEvent_CreateKey(
                     up, param->ThreadId,
                     param->KeyPath, param->DesiredAccess,
                     param->Disposition, param->CreateOptions,
                     param->ResultStatus, param->time, param->eventId));
}

void CEventMgr::OnRgSetValueKey(QSharedPointer<QByteArray> data)
{
    if(!m_CaptureEnable)
        return;
    auto param = (svc_reg_setvaluekey_data *)data->constData();
    CUniqueProcess *up = m_ProcessMgr->Find(param->ProcessId);
    if (!up)
        return;
    if( (const char *)param->CopyData + param->CopySize > (const char *)param + data->size())
        return;
    QByteArray binaryData((const char *)param->CopyData, param->CopySize);
    AddEvent(new CUniqueEvent_SetValueKey(
                 up, param->ThreadId,
                 param->KeyPath, param->ValueName, param->DataType, param->DataSize, binaryData,
                 param->ResultStatus, param->time, param->eventId));
}

void CEventMgr::OnRgQueryValueKey(QSharedPointer<QByteArray> data)
{
    if(!m_CaptureEnable)
        return;
    auto param = (svc_reg_queryvaluekey_data *)data->constData();
    CUniqueProcess *up = m_ProcessMgr->Find(param->ProcessId);
    if (!up)
        return;
    if( (const char *)param->CopyData + param->CopySize > (const char *)param + data->size())
        return;
    QByteArray binaryData((const char *)param->CopyData, param->CopySize);
    if( param->QueryClass == KeyValueBasicInformation && binaryData.size() >= offsetof(KEY_VALUE_BASIC_INFORMATION, Name)){
        AddEvent(new CUniqueEvent_QueryValueKey_BasicInformation(
                     up, param->ThreadId,
                     param->KeyPath, param->ValueName, param->QueryLength, binaryData,
                     param->ResultStatus, param->time, param->eventId));
    } else if( param->QueryClass == KeyValueFullInformation && binaryData.size() >= offsetof(KEY_VALUE_FULL_INFORMATION, Name)) {
        AddEvent(new CUniqueEvent_QueryValueKey_FullInformation(
                     up, param->ThreadId,
                     param->KeyPath, param->ValueName, param->QueryLength, binaryData,
                     param->ResultStatus, param->time, param->eventId));
    } else if( param->QueryClass == KeyValuePartialInformation && binaryData.size() >= offsetof(KEY_VALUE_PARTIAL_INFORMATION, Data)) {
        AddEvent(new CUniqueEvent_QueryValueKey_PartialInformation(
                     up, param->ThreadId,
                     param->KeyPath, param->ValueName, param->QueryLength, binaryData,
                     param->ResultStatus, param->time, param->eventId));
    } else  {
        AddEvent(new CUniqueEvent_QueryValueKey(
                     up, param->ThreadId,
                     param->KeyPath, param->ValueName, param->QueryClass, param->QueryLength, binaryData,
                     param->ResultStatus, param->time, param->eventId));
    }
}

void CEventMgr::OnRgQueryKey(QSharedPointer<QByteArray> data)
{
    if(!m_CaptureEnable)
        return;
    auto param = (svc_reg_querykey_data *)data->constData();
    CUniqueProcess *up = m_ProcessMgr->Find(param->ProcessId);
    if (!up)
        return;
    if( (const char *)param->CopyData + param->CopySize > (const char *)param + data->size())
        return;
    QByteArray binaryData((const char *)param->CopyData, param->CopySize);
    if( param->QueryClass == KeyBasicInformation && binaryData.size() >= offsetof(KEY_BASIC_INFORMATION, Name)) {
        AddEvent(new CUniqueEvent_QueryKey_BasicInformation(
                     up, param->ThreadId,
                     param->KeyPath, param->QueryLength, binaryData,
                     param->ResultStatus, param->time, param->eventId));
    } else if( param->QueryClass == KeyNodeInformation && binaryData.size() >= offsetof(KEY_NODE_INFORMATION, Name)) {
        AddEvent(new CUniqueEvent_QueryKey_NodeInformation(
                     up, param->ThreadId,
                     param->KeyPath, param->QueryLength, binaryData,
                     param->ResultStatus, param->time, param->eventId));
    } else if( param->QueryClass == KeyFullInformation && binaryData.size() >= offsetof(KEY_FULL_INFORMATION, Class)) {
        AddEvent(new CUniqueEvent_QueryKey_FullInformation(
                     up, param->ThreadId,
                     param->KeyPath, param->QueryLength, binaryData,
                     param->ResultStatus, param->time, param->eventId));
    } else if( param->QueryClass == KeyNameInformation && binaryData.size() >= offsetof(KEY_NAME_INFORMATION, Name)) {
        AddEvent(new CUniqueEvent_QueryKey_NameInformation(
                     up, param->ThreadId,
                     param->KeyPath, param->QueryLength, binaryData,
                     param->ResultStatus, param->time, param->eventId));
    } else if( param->QueryClass == KeyCachedInformation && binaryData.size() >= sizeof(KEY_CACHED_INFORMATION)) {
        AddEvent(new CUniqueEvent_QueryKey_CachedInformation(
                     up, param->ThreadId,
                     param->KeyPath, param->QueryLength, binaryData,
                     param->ResultStatus, param->time, param->eventId));
    } else if( param->QueryClass == KeyVirtualizationInformation && binaryData.size() >= sizeof(KEY_VIRTUALIZATION_INFORMATION)) {
        AddEvent(new CUniqueEvent_QueryKey_VirtualizationInformation(
                     up, param->ThreadId,
                     param->KeyPath, param->QueryLength, binaryData,
                     param->ResultStatus, param->time, param->eventId));
    } else {
        AddEvent(new CUniqueEvent_QueryKey(
                     up, param->ThreadId,
                     param->KeyPath, param->QueryClass, param->QueryLength, binaryData,
                     param->ResultStatus, param->time, param->eventId));
    }
}
