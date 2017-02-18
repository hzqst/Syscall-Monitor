#pragma once

#include <QObject>
#include <QIcon>
#include <QTimer>

#include <Windows.h>
#include <vector>
#include <boost/functional/hash.hpp>
#include <boost/unordered_map.hpp>

#include "ModuleMgr.h"

class CUniqueProcessKey
{
public:
    CUniqueProcessKey(ULONG dwProcessId, ULONG64 createTime)
	{
		m_ProcessId = dwProcessId;
        m_CreateTime = createTime;
	}
	bool operator==(const CUniqueProcessKey &key)const
	{
        if (key.m_ProcessId == this->m_ProcessId && key.m_CreateTime == this->m_CreateTime)
			return true;

		return false;
	}
public:
    ULONG m_ProcessId;
    ULONG64 m_CreateTime;
};

class CUniqueProcessHasher
{
public:
	std::size_t operator()(const CUniqueProcessKey& key) const
	{
		using boost::hash_value;
		using boost::hash_combine;
		// Start with a hash value of 0 .
		std::size_t seed = 0;
		// Return the result.
		boost::hash_combine(seed, hash_value(key.m_ProcessId));
        boost::hash_combine(seed, hash_value(key.m_CreateTime));
		return seed;
	}
};

class CUniqueProcess;

typedef std::vector<CUniqueProcess *> CProcessList;
typedef boost::unordered_map<CUniqueProcessKey, CUniqueProcess *, CUniqueProcessHasher> CProcessKeyMap;
typedef boost::unordered_multimap<ULONG, CUniqueProcess *> CProcessIdMap;
typedef boost::unordered_map<std::wstring, QIcon *> CUniqueIconMap;
typedef std::vector<CUniqueModule *> CModuleList;

class CUniqueProcess
{
public:
    CUniqueProcess(ULONG ProcessId, ULONG ParentProcessId,
                   ULONG64 CreateTime, bool bIs64Bit,
                   ULONG SessionId,  LPCWSTR szImagePath,
                   LPCWSTR szCommandLine, LPCWSTR szCurDirectory, QIcon *Icon);
    ~CUniqueProcess();
    bool operator==(const CUniqueProcess &key)const;
    CUniqueModule *GetModuleFromAddress(ULONG64 BaseAddress);
    QString GetDisplayName(void);
    QString GetDisplayNameWithPID(void);
public:
    ULONG m_ProcessId;
    ULONG m_ParentProcessId;
    ULONG64 m_CreateTime;
    ULONG m_SessionId;
    QString m_ProcessName;
    QString m_ImagePath;
    QString m_CommandLine;
    QString m_CurDirectory;
	CUniqueProcess *m_pParentProcess;
	CProcessList m_ChildProcesses;
    CModuleList m_ModuleList;

	bool m_bAlive;
    bool m_bIs64Bit;

    QIcon *m_Icon;
};

class CDelayProcessTimer : public QTimer
{
    Q_OBJECT
public:
    explicit CDelayProcessTimer(CUniqueProcess *up, int delayAction, QObject *parent = Q_NULLPTR);

    int m_DelayAction;
    CUniqueProcess *m_UniqueProcess;
private slots:
    void TimerExpired();
};

class CProcessMgr : public QObject
{
    Q_OBJECT
public:
    explicit CProcessMgr(QObject *parent = Q_NULLPTR);
    ~CProcessMgr();
    CUniqueProcess *Find(ULONG dwProcessId, ULONG64 CreateTime);
    CUniqueProcess *Find(ULONG dwProcessId);

    void InsertProcess(CUniqueProcess *up);
    void FillParent(CUniqueProcess *up);
    void FillModules(CUniqueProcess *up);
    QIcon *GetImageFileIcon(std::wstring &ImageFilePath);

    void FillList(void);
    void Initialize(void);
    void Uninitialize(void);
    void EnumSystemModuleProc(ULONG64 ImageBase, ULONG ImageSize, LPCWSTR szImagePath, int LoadOrderIndex);
    void EnumProcessProc(ULONG ProcessId);

signals:
    void AddProcessItem(CUniqueProcess *up);
    void UnfreshProcessItem(CUniqueProcess *up);
    void KillProcessItem(CUniqueProcess *up);
    void RemoveProcessItem(CUniqueProcess *up);

public:
	CProcessList m_List;
	CProcessKeyMap m_KeyMap;
	CProcessIdMap m_IdMap;
    CUniqueIconMap m_UniqueIconMap;
    CUniqueProcess *m_PsSystemProcess;
    HANDLE m_hReadyEvent;
};

extern CProcessMgr *m_ProcessMgr;
