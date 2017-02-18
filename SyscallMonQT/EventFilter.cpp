#include "ProcessMgr.h"
#include "EventMgr.h"
#include "EventFilter.h"
#include "util.h"
#include "nt.h"

void CEventFilter::Reference()
{
    InterlockedIncrement(&m_RefCount);
}

void CEventFilter::Dereference()
{
    if(0 == InterlockedDecrement(&m_RefCount))
        delete this;
}

CEventFilter_Hex64::CEventFilter_Hex64(ULONG64 HexValue, filter_rel Relation, bool bInclude) : CEventFilter(Relation, bInclude)
{
    m_HexValue = HexValue;
    m_DisplayValue = QString("0x%1").arg(FormatHexString(HexValue, 16));
}

CEventFilter_PID::CEventFilter_PID(ULONG ProcessId, filter_rel Relation, bool bInclude) : CEventFilter_Number(ProcessId, Relation, bInclude)
{
}

CEventFilter_ProcessName::CEventFilter_ProcessName(QString val, filter_rel Relation, bool bInclude) : CEventFilter_String(val, Relation, bInclude)
{
}

CEventFilter_ProcessPath::CEventFilter_ProcessPath(QString val, filter_rel Relation, bool bInclude) : CEventFilter_String(val, Relation, bInclude)
{
}

CEventFilter_EventPath::CEventFilter_EventPath(QString val, filter_rel Relation, bool bInclude) : CEventFilter_String(val, Relation, bInclude)
{
}

CEventFilter_SessionId::CEventFilter_SessionId(ULONG SessionId, filter_rel Relation, bool bInclude) : CEventFilter_Number(SessionId, Relation, bInclude)
{
}

CEventFilter_Arch::CEventFilter_Arch(bool bIs64Bit, filter_rel Relation, bool bInclude) : CEventFilter_Binary(bIs64Bit, Relation, bInclude)
{
    m_DisplayValue = bIs64Bit ? "x64" : "x86";
}

CEventFilter_EventType::CEventFilter_EventType(EventType_t eventType, filter_rel Relation, bool bInclude) : CEventFilter(Relation, bInclude)
{
    m_EventType = eventType;

    m_DisplayValue = m_EventMgr->m_EventNames[eventType];
}

CEventFilter_EventClass::CEventFilter_EventClass(EventClass_t eventClass, filter_rel Relation, bool bInclude) : CEventFilter(Relation, bInclude)
{
    m_EventClass = eventClass;

    m_DisplayValue = m_EventMgr->m_EventClassNames[eventClass];
}

CEventFilter_BriefResult::CEventFilter_BriefResult(QString val, filter_rel Relation, bool bInclude) : CEventFilter_String(val, Relation, bInclude)
{
}

bool CEventFilter_PID::DoFilter(const CUniqueEvent *ev)
{
	if (m_Relation == FltRel_Is)
	{
        return ((int)ev->GetProcessId() == m_NumberValue) ? true : false;
	}
	else if (m_Relation == FltRel_IsNot)
	{
        return ((int)ev->GetProcessId() != m_NumberValue) ? true : false;
	}
	else if (m_Relation == FltRel_LargerThan)
	{
        return ((int)ev->GetProcessId() >= m_NumberValue) ? true : false;
	}
	else if (m_Relation == FltRel_SmallerThan)
	{
        return ((int)ev->GetProcessId() <= m_NumberValue) ? true : false;
	}
	//Should not go here

	return false;
}

bool CEventFilter_ProcessName::DoFilter(const CUniqueEvent *ev)
{
    QString str = ev->GetProcessName();
    if (m_Relation == FltRel_Is)
    {
        return (0 == str.compare(m_StrValue, Qt::CaseSensitivity::CaseInsensitive)) ? true : false;
    }
    else if (m_Relation == FltRel_IsNot)
    {
        return (0 != str.compare(m_StrValue, Qt::CaseSensitivity::CaseInsensitive)) ? true : false;
    }
    else if (m_Relation == FltRel_Contain)
    {
        return (str.indexOf(m_StrValue, 0, Qt::CaseSensitivity::CaseInsensitive) != -1) ? true : false;
    }
    else if (m_Relation == FltRel_NotContain)
    {
        return (str.indexOf(m_StrValue, 0, Qt::CaseSensitivity::CaseInsensitive) == -1) ? true : false;
    }
	//Should not go here

	return false;
}

bool CEventFilter_ProcessPath::DoFilter(const CUniqueEvent *ev)
{
    QString str = ev->GetProcessPath();
    if (m_Relation == FltRel_Is)
    {
        return (0 == str.compare(m_StrValue, Qt::CaseSensitivity::CaseInsensitive)) ? true : false;
    }
    else if (m_Relation == FltRel_IsNot)
    {
        return (0 != str.compare(m_StrValue, Qt::CaseSensitivity::CaseInsensitive)) ? true : false;
    }
    else if (m_Relation == FltRel_Contain)
    {
        return (str.indexOf(m_StrValue, 0, Qt::CaseSensitivity::CaseInsensitive) != -1) ? true : false;
    }
    else if (m_Relation == FltRel_NotContain)
    {
        return (str.indexOf(m_StrValue, 0, Qt::CaseSensitivity::CaseInsensitive) == -1) ? true : false;
    }
	//Should not go here

	return false;
}

bool CEventFilter_EventPath::DoFilter(const CUniqueEvent *ev)
{
    QString str = ev->GetEventPath();
    if (m_Relation == FltRel_Is)
    {
        return (0 == str.compare(m_StrValue, Qt::CaseSensitivity::CaseInsensitive)) ? true : false;
    }
    else if (m_Relation == FltRel_IsNot)
    {
        return (0 != str.compare(m_StrValue, Qt::CaseSensitivity::CaseInsensitive)) ? true : false;
    }
    else if (m_Relation == FltRel_Contain)
    {
        return (str.indexOf(m_StrValue, 0, Qt::CaseSensitivity::CaseInsensitive) != -1) ? true : false;
    }
    else if (m_Relation == FltRel_NotContain)
    {
        return (str.indexOf(m_StrValue, 0, Qt::CaseSensitivity::CaseInsensitive) == -1) ? true : false;
    }
	//Should not go here

	return false;
}

bool CEventFilter_Arch::DoFilter(const CUniqueEvent *ev)
{
	if (m_Relation == FltRel_Is)
	{
        return (ev->GetUniqueProcess()->m_bIs64Bit == m_bBinary) ? true : false;
	}
	else if (m_Relation == FltRel_IsNot)
	{
        return (ev->GetUniqueProcess()->m_bIs64Bit != m_bBinary) ? true : false;
	}
	//Should not go here

	return false;
}

bool CEventFilter_SessionId::DoFilter(const CUniqueEvent *ev)
{
	if (m_Relation == FltRel_Is)
	{
        return ((int)ev->GetUniqueProcess()->m_SessionId == m_NumberValue) ? true : false;
	}
	else if (m_Relation == FltRel_IsNot)
	{
        return ((int)ev->GetUniqueProcess()->m_SessionId != m_NumberValue) ? true : false;
	}
	else if (m_Relation == FltRel_LargerThan)
	{
        return ((int)ev->GetUniqueProcess()->m_SessionId >= m_NumberValue) ? true : false;
	}
	else if (m_Relation == FltRel_SmallerThan)
	{
        return ((int)ev->GetUniqueProcess()->m_SessionId <= m_NumberValue) ? true : false;
	}
	//Should not go here

	return false;
}

bool CEventFilter_EventType::DoFilter(const CUniqueEvent *ev)
{
	if (m_Relation == FltRel_Is)
	{
		return (ev->GetEventType() == m_EventType) ? true : false;
	}
	else if (m_Relation == FltRel_IsNot)
	{
		return (ev->GetEventType() != m_EventType) ? true : false;
	}
	//Should not go here

	return false;
}

bool CEventFilter_EventClass::DoFilter(const CUniqueEvent *ev)
{
	if (m_Relation == FltRel_Is)
	{
		return (ev->GetEventClassify() == m_EventClass) ? true : false;
	}
	else if (m_Relation == FltRel_IsNot)
	{
		return (ev->GetEventClassify() != m_EventClass) ? true : false;
	}
	//Should not go here

	return false;
}

bool CEventFilter_BriefResult::DoFilter(const CUniqueEvent *ev)
{
    QString str;
    ev->GetBriefResult(str);
    if (m_Relation == FltRel_Is)
    {
        return (0 == str.compare(m_StrValue, Qt::CaseSensitivity::CaseInsensitive)) ? true : false;
    }
    else if (m_Relation == FltRel_IsNot)
    {
        return (0 != str.compare(m_StrValue, Qt::CaseSensitivity::CaseInsensitive)) ? true : false;
    }
    else if (m_Relation == FltRel_Contain)
    {
        return (str.indexOf(m_StrValue, 0, Qt::CaseSensitivity::CaseInsensitive) != -1) ? true : false;
    }
    else if (m_Relation == FltRel_NotContain)
    {
        return (str.indexOf(m_StrValue, 0, Qt::CaseSensitivity::CaseInsensitive) == -1) ? true : false;
    }
    //Should not go here

    return false;
}
