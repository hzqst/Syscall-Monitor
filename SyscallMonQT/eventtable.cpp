#include <QDateTime>
#include "EventTable.h"

//Event Table

CEventTableModel::CEventTableModel(QObject *parent) : QAbstractTableModel(parent)
{

}

void CEventTableModel::appendRow(CUniqueEvent *ev)
{
    int row = rowCount();

    beginInsertRows(QModelIndex(), row, row);

    m_List.push_back(ev);

    endInsertRows();
}

void CEventTableModel::appendRows(QEventList &evs)
{
    int row = rowCount();

    beginInsertRows(QModelIndex(), row, row + (int)evs.size() - 1);

    m_List.reserve(m_List.size() + evs.size());
    m_List.append(evs);

    endInsertRows();
}

void CEventTableModel::appendRows(QEventLinkedList &evs)
{
    int row = rowCount();

    beginInsertRows(QModelIndex(), row, row + (int)evs.size() - 1);

    for(QEventLinkedList::iterator it = evs.begin(); it != evs.end(); ++it){
        m_List.push_back(*it);
    }

    endInsertRows();
}

bool CEventTableModel::removeRow(int position, const QModelIndex &parent)
{
    bool success = false;

    if(position >= 0 && position < m_List.size())
    {
        beginRemoveRows(parent, position, position);
        m_List.erase(m_List.begin() + position);
        success = true;
        endRemoveRows();
    }

    return success;
}

bool CEventTableModel::removeRows(int position, int count, const QModelIndex &parent)
{
    bool success = false;

    if(count > 0 && position >= 0 && position + count - 1 < m_List.size())
    {
        beginRemoveRows(parent, position, position + count - 1);
        m_List.erase(m_List.begin() + position, m_List.begin() + position + count);
        success = true;
        endRemoveRows();
    }

    return success;
}

void CEventTableModel::setHeaderString(const QStringList &header)
{
    beginResetModel();
    m_HeaderString = header;
    endResetModel();
}

Qt::ItemFlags CEventTableModel::flags(const QModelIndex &index) const
{
    if (!index.isValid())
        return 0;

    return (Qt::ItemIsEnabled | Qt::ItemIsSelectable);
}

int CEventTableModel::rowCount(const QModelIndex &parent) const
{
    UNREFERENCED_PARAMETER(parent);
    return (int)m_List.size();
}

int CEventTableModel::columnCount(const QModelIndex &parent) const
{
    UNREFERENCED_PARAMETER(parent);
    return m_HeaderString.size();
}

QModelIndex CEventTableModel::index(int row, int column, const QModelIndex &parent) const
{
    UNREFERENCED_PARAMETER(parent);
    if (row < 0 || column < 0 || row >= m_List.size())
        return QModelIndex();

    return createIndex(row, column, m_List[row]);
}

QModelIndex CEventTableModel::parent(const QModelIndex &index) const
{
    UNREFERENCED_PARAMETER(index);
    return QModelIndex();
}

CUniqueEvent *CEventTableModel::eventFromIndex(const QModelIndex &index) const
{
        if (index.isValid()) {
                return static_cast<CUniqueEvent *>(index.internalPointer());
        } else {
                return NULL;
        }
}

QVariant CEventTableModel::data(const QModelIndex &index, int role) const
{
    const CUniqueEvent *ev = eventFromIndex(index);
    if(ev)
    {
        if (role == Qt::DisplayRole)
        {
            switch(index.column())
            {
            case 0:
            {
                    QDateTime date;
                    date.setTime_t(ev->GetEventTime() / 1000);
                    QString str = date.toString("HH:mm:ss");
                    str.append(QString::asprintf(" %03d", ev->GetEventTime() % 1000));
                    return str;
            }
            case 1:
                return ev->GetDisplayName();
            case 2:
                return QString::number(ev->GetProcessId());
            case 3:
                return ev->GetEventName();
            case 4:
                return ev->GetEventPath();
            case 5:
            {
                QString str;
                ev->GetBriefArgument(str);
                return str;
            }
            case 6:{
                QString str;
                ev->GetBriefResult(str);
                return str;
            }
            }
        }
        else if (role == Qt::DecorationRole)
        {
            if(index.column() == 1)
                return *ev->GetUniqueProcess()->m_Icon;
        }
        else if (role == Qt::TextAlignmentRole)
        {
            return int(Qt::AlignLeft | Qt::AlignVCenter);
        }
    }
    return QVariant();
}

QVariant CEventTableModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (orientation == Qt::Horizontal && role == Qt::DisplayRole && section >= 0 && section < m_HeaderString.size())
          return m_HeaderString[section];

    return QVariant();
}
