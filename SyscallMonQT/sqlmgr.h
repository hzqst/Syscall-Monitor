#ifndef SQLMGR_H
#define SQLMGR_H

#include <QObject>
#include <QSqlQuery>
#include <QSqlDatabase>

class CUniqueEvent;

class CSqlMgr : QObject
{
    Q_OBJECT
public:
    CSqlMgr(QObject *parent = NULL);
    bool Initialize(void);
    void Uninitialize(void);

    bool InsertEvent(const CUniqueEvent *ev);
    void Commit(void);
private:
    QSqlQuery *m_query_insertEvent;
    QSqlDatabase m_db;
};

extern CSqlMgr *m_SqlMgr;


#endif // SQLMGR_H
