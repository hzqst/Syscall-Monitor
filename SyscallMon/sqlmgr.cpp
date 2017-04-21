#include <QSqlDatabase>
#include <QSqlQuery>
#include <QSqlError>
#include <QVariant>
#include <QMessageBox>

#include "sqlmgr.h"
#include "EventMgr.h"

CSqlMgr *m_SqlMgr = NULL;

CSqlMgr::CSqlMgr(QObject *parent) : QObject(parent)
{
    m_SqlMgr = this;
}

bool CSqlMgr::Initialize(void)
{
    m_db = QSqlDatabase::addDatabase("QSQLITE");
    m_db.setDatabaseName("database.db");
    m_db.setUserName("root");
    m_db.setPassword("123456");

    if(!m_db.open())
    {
        QMessageBox::critical(NULL, tr("Fatal Error"), tr("Failed to open sql database!"), QMessageBox::Yes);
        return false;
    }

    if(!m_db.transaction()){
        QMessageBox::critical(NULL, tr("Fatal Error"), tr("Failed to begin transaction!"), QMessageBox::Yes);
        return false;
    }

    QSqlQuery sql_query;
    sql_query.exec("DROP TABLE t_event;");
    if(!sql_query.exec("CREATE TABLE t_event (id bigint identity(1,1) primary key, "
                   "type int, "
                   "pid int, "
                   "tid int, "
                   "time bigint, "
                   "process_name varchar(64), "
                   "image_path varchar(255), "
                   "path varchar(255), "
                   "brief_result varchar(255), "
                   "brief_argument varchar(255), "
                   "full_argument text"
                   ");")){
            QMessageBox::critical(NULL, tr("Fatal Error"), tr("Failed to create table!"), QMessageBox::Yes);
            return false;
        }

    m_query_insertEvent = new QSqlQuery(m_db);
    if(!m_query_insertEvent->prepare("INSERT INTO t_event ("
                          "type, "
                          "pid, "
                          "tid, "
                          "time, "
                          "process_name, "
                          "image_path, "
                          "path, "
                          "brief_result, "
                          "brief_argument, "
                          "full_argument"
                          ") values (?,?,?,?,?,?,?,?,?,?);")){
        QMessageBox::critical(NULL, tr("Fatal Error"), tr("Failed to prepare query!\n%1").arg(m_query_insertEvent->lastError().text()), QMessageBox::Yes);
        return false;
    }

    if(!m_db.commit()){
        QMessageBox::critical(NULL, tr("Fatal Error"), tr("Failed to commit transaction!"), QMessageBox::Yes);
        return false;
    }

    m_db.transaction();

    return true;
}

void CSqlMgr::Uninitialize(void)
{
    m_db.commit();
    m_db.close();
    delete m_query_insertEvent;
}

void CSqlMgr::Commit(void)
{
    m_db.commit();
    m_db.transaction();
}

bool CSqlMgr::InsertEvent(const CUniqueEvent *ev)
{
    m_query_insertEvent->bindValue(0, QVariant((int)ev->GetEventType()));
    m_query_insertEvent->bindValue(1, QVariant((int)ev->GetProcessId()));
    m_query_insertEvent->bindValue(2, QVariant((int)ev->GetThreadId()));
    m_query_insertEvent->bindValue(3, QVariant((qlonglong)ev->GetEventTime()));
    m_query_insertEvent->bindValue(4, ev->GetProcessName());
    m_query_insertEvent->bindValue(5, ev->GetUniqueProcess()->m_ImagePath);
    m_query_insertEvent->bindValue(6, ev->GetEventPath());

    QString res;
    ev->GetBriefResult(res);
    m_query_insertEvent->bindValue(7, res);

    QString arg;
    ev->GetBriefArgument(arg);
    m_query_insertEvent->bindValue(8, arg);

    QString fullarg;
    ev->GetFullArgument(fullarg);
    m_query_insertEvent->bindValue(9, fullarg);

    if(!m_query_insertEvent->exec()){
        OutputDebugStringW((LPCWSTR)m_query_insertEvent->lastError().databaseText().utf16());
        return false;
    }
    return true;
}
