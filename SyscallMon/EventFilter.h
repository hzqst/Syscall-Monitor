#pragma once

#include <Windows.h>
#include <QString>
#include <string>

class CUniqueEvent;
enum EventType_t;
enum EventClass_t;

enum filter_key
{
	FltKey_PID,
	FltKey_ProcessName,
	FltKey_ProcessPath,
	FltKey_EventPath,
	FltKey_Arch,
	FltKey_SessionId,
	FltKey_EventType,
	FltKey_EventClass,
    FltKey_BriefResult,

	//Do not use this
    FltKey_Max,
};

enum filter_rel
{
	FltRel_Is,
	FltRel_IsNot,
	FltRel_LargerThan,
	FltRel_SmallerThan,
	FltRel_Contain,
	FltRel_NotContain,

    //Do not use this
    FltRel_Max,
};

class CEventFilter
{
public:
	CEventFilter(filter_rel Relation, bool bInclude)
	{
		m_Relation = Relation;
		m_Include = bInclude;
        m_RefCount = 1;
    }
    virtual filter_key GetKey(void) const = 0;
    virtual bool DoFilter(const CUniqueEvent *ev) = 0;
    virtual QString GetDisplayValue(void) const { return m_DisplayValue; }
    void Reference();
    void Dereference();
public:
    QString m_DisplayValue;
	filter_rel m_Relation;
    bool m_Include;
    LONG m_RefCount;
};

//template

class CEventFilter_Number : public CEventFilter
{
public:
    CEventFilter_Number(int NumberValue, filter_rel Relation, bool bInclude) : CEventFilter(Relation, bInclude)
    {
        m_NumberValue = NumberValue;
        m_DisplayValue = QString::number(NumberValue);
    }
public:
    int m_NumberValue;
};

class CEventFilter_String : public CEventFilter
{
public:
    CEventFilter_String(QString StringValue, filter_rel Relation, bool bInclude) : CEventFilter(Relation, bInclude)
    {
        m_StrValue = StringValue;
        m_DisplayValue = StringValue;
    }
public:
    QString m_StrValue;
};

class CEventFilter_Binary : public CEventFilter
{
public:
    CEventFilter_Binary(bool bBinary, filter_rel Relation, bool bInclude) : CEventFilter(Relation, bInclude)
    {
        m_bBinary = bBinary;
    }
public:
    bool m_bBinary;
};

class CEventFilter_Hex64 : public CEventFilter
{
public:
    CEventFilter_Hex64(ULONG64 HexValue, filter_rel Relation, bool bInclude);
public:
    ULONG64 m_HexValue;
};

//implement

class CEventFilter_PID : public CEventFilter_Number
{
public:
    CEventFilter_PID(ULONG ProcessId, filter_rel Relation, bool bInclude);
    virtual filter_key GetKey(void) const { return FltKey_PID; }
    virtual bool DoFilter(const CUniqueEvent *ev);
};

class CEventFilter_ProcessName : public CEventFilter_String
{
public:
    CEventFilter_ProcessName(QString val, filter_rel Relation, bool bInclude);

    virtual filter_key GetKey(void) const { return FltKey_ProcessName; }
    virtual bool DoFilter(const CUniqueEvent *ev);
};

class CEventFilter_ProcessPath : public CEventFilter_String
{
public:
    CEventFilter_ProcessPath(QString val, filter_rel Relation, bool bInclude);

    virtual filter_key GetKey(void) const { return FltKey_ProcessPath; }
    virtual bool DoFilter(const CUniqueEvent *ev);
};

class CEventFilter_EventPath : public CEventFilter_String
{
public:
    CEventFilter_EventPath(QString val, filter_rel Relation, bool bInclude);

    virtual filter_key GetKey(void) const { return FltKey_EventPath; }
    virtual bool DoFilter(const CUniqueEvent *ev);
};

class CEventFilter_Arch : public CEventFilter_Binary
{
public:
    CEventFilter_Arch(bool bIs64Bit, filter_rel Relation, bool bInclude);

    virtual filter_key GetKey(void) const { return FltKey_Arch; }
    virtual bool DoFilter(const CUniqueEvent *ev);
};

class CEventFilter_SessionId : public CEventFilter_Number
{
public:
    CEventFilter_SessionId(ULONG SessionId, filter_rel Relation, bool bInclude);

    virtual filter_key GetKey(void) const { return FltKey_SessionId; }
    virtual bool DoFilter(const CUniqueEvent *ev);
};

class CEventFilter_EventType : public CEventFilter
{
public:
    CEventFilter_EventType(EventType_t eventType, filter_rel Relation, bool bInclude);

    virtual filter_key GetKey(void) const { return FltKey_EventType; }
    virtual bool DoFilter(const CUniqueEvent *ev);
public:
	EventType_t m_EventType;
};

class CEventFilter_EventClass : public CEventFilter
{
public:
    CEventFilter_EventClass(EventClass_t eventClass, filter_rel Relation, bool bInclude);

    virtual filter_key GetKey(void) const { return FltKey_EventClass; }
    virtual bool DoFilter(const CUniqueEvent *ev);
public:
	EventClass_t m_EventClass;
};

class CEventFilter_BriefResult : public CEventFilter_String
{
public:
    CEventFilter_BriefResult(QString val, filter_rel Relation, bool bInclude);

    virtual filter_key GetKey(void) const { return FltKey_EventPath; }
    virtual bool DoFilter(const CUniqueEvent *ev);
};

typedef std::vector<CEventFilter *> CFilterList;
