#include "filtertable.h"
#include "filterdialog.h"
//Event Table

CFilterTableModel::CFilterTableModel(CFilterList *List, QObject *parent) : QAbstractTableModel(parent)
{
    m_List = List;
}

void CFilterTableModel::appendRow(CEventFilter *flt)
{
    int row = rowCount();

    beginInsertRows(QModelIndex(), row, row);
    m_List->push_back(flt);
    endInsertRows();
}

bool CFilterTableModel::removeRow(int position, const QModelIndex &parent)
{
    bool success = false;

    if(position >= 0 && position < (int)m_List->size())
    {
        beginRemoveRows(parent, position, position);
        m_List->erase(m_List->begin() + position);
        success = true;
        endRemoveRows();
    }

    return success;
}

bool CFilterTableModel::removeRows(int position, int count, const QModelIndex &parent)
{
    bool success = false;

    if(count > 0 && position >= 0 && position + count - 1 < (int)m_List->size())
    {
        beginRemoveRows(parent, position, position + count - 1);
        m_List->erase(m_List->begin() + position, m_List->begin() + position + count);
        success = true;
        endRemoveRows();
    }

    return success;
}

void CFilterTableModel::setHeaderString(const QStringList &header)
{
    beginResetModel();
    m_HeaderString = header;
    endResetModel();
}

Qt::ItemFlags CFilterTableModel::flags(const QModelIndex &index) const
{
    if (!index.isValid())
        return 0;

    return (Qt::ItemIsEnabled | Qt::ItemIsSelectable);
}

int CFilterTableModel::rowCount(const QModelIndex &parent) const
{
    UNREFERENCED_PARAMETER(parent);
    return (int)m_List->size();
}

int CFilterTableModel::columnCount(const QModelIndex &parent) const
{
    UNREFERENCED_PARAMETER(parent);
    return m_HeaderString.size();
}

QModelIndex CFilterTableModel::index(int row, int column, const QModelIndex &parent) const
{
    UNREFERENCED_PARAMETER(parent);
    if (row < 0 || column < 0 || row >= (int)m_List->size())
        return QModelIndex();

    return createIndex(row, column, m_List->at(row));
}

QModelIndex CFilterTableModel::parent(const QModelIndex &index) const
{
    UNREFERENCED_PARAMETER(index);
    return QModelIndex();
}

CEventFilter *CFilterTableModel::fltFromIndex(const QModelIndex &index) const
{
        if (index.isValid()) {
                return static_cast<CEventFilter *>(index.internalPointer());
        } else {
                return NULL;
        }
}

QVariant CFilterTableModel::data(const QModelIndex &index, int role) const
{
    CEventFilter *flt = fltFromIndex(index);
    if(flt)
    {
        if (role == Qt::DisplayRole)
        {
            switch(index.column())
            {
            case 0:
            {
                if(flt->GetKey() >= 0 && flt->GetKey() < FltKey_Max)
                    return m_EventMgr->m_FltKeyTable[flt->GetKey()];
            }
            case 1:
            {
                if(flt->m_Relation >= 0 && flt->m_Relation < FltRel_Max)
                    return m_EventMgr->m_FltRelTable[flt->m_Relation];
            }
            case 2:
                return flt->GetDisplayValue();
            case 3:
                return m_EventMgr->m_FltIncTable[flt->m_Include ? 0 : 1];
            }
        }
        else if (role == Qt::TextAlignmentRole)
        {
            return int(Qt::AlignLeft | Qt::AlignVCenter);
        }
    }
    return QVariant();
}

QVariant CFilterTableModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if(orientation == Qt::Horizontal && section >= 0 && section < m_HeaderString.size())
    {
        if (role == Qt::DisplayRole)
            return m_HeaderString[section];
        else if (role == Qt::TextAlignmentRole)
            return int(Qt::AlignLeft | Qt::AlignVCenter);
    }
    return QVariant();
}
