#include "callstacktable.h"

CCallStackTableModel::CCallStackTableModel(QObject *parent) : QAbstractTableModel(parent)
{
    m_Event = NULL;
}

void CCallStackTableModel::setHeaderString(const QStringList &header)
{
    beginResetModel();
    m_HeaderString = header;
    endResetModel();
}

void CCallStackTableModel::setEvent(CUniqueEvent *ev)
{
    beginResetModel();
    m_Event = ev;
    endResetModel();
}

void CCallStackTableModel::updateRows(int beginRow, int endRow)
{
    dataChanged(index(beginRow, 0), index(endRow, columnCount()));
}

void CCallStackTableModel::clearRows(void)
{
    beginRemoveRows(QModelIndex(), 0, rowCount());
    endRemoveRows();
}

Qt::ItemFlags CCallStackTableModel::flags(const QModelIndex &index) const
{
    if (!index.isValid())
        return 0;

    return (Qt::ItemIsEnabled | Qt::ItemIsSelectable);
}

int CCallStackTableModel::rowCount(const QModelIndex &parent) const
{
    UNREFERENCED_PARAMETER(parent);

    if(!m_Event) return 0;

    return (int)m_Event->m_CallStacks.size();
}

int CCallStackTableModel::columnCount(const QModelIndex &parent) const
{
    UNREFERENCED_PARAMETER(parent);
    return m_HeaderString.size();
}

QModelIndex CCallStackTableModel::index(int row, int column, const QModelIndex &parent) const
{
    UNREFERENCED_PARAMETER(parent);

    if (!m_Event || row < 0 || column < 0 || row >= (int)m_Event->m_CallStacks.size() )
        return QModelIndex();

    void *nullp = NULL;
    return createIndex(row, column, nullp);
}

QModelIndex CCallStackTableModel::parent(const QModelIndex &index) const
{
    UNREFERENCED_PARAMETER(index);
    return QModelIndex();
}

QVariant CCallStackTableModel::data(const QModelIndex &index, int role) const
{
    if(!m_Event || index.row() < 0 || index.row() >= (int)m_Event->m_CallStacks.size() )
        return QVariant();

    CCallStack &cs = m_Event->m_CallStacks.at(index.row());
    if (role == Qt::DisplayRole) {
        switch(index.column())
        {
        case 0:
            return QString::number(index.row());
        case 1:
            if(cs.m_UniqueModule)
            {
                std::string funcName;
                ULONG offset = cs.GetClosestFunctionOffset(funcName);
                if(offset)
                {
                    return QString("%1!%2+0x%3").arg(
                                cs.m_UniqueModule->m_UniqueImage->m_FileName,
                                QString::fromStdString(funcName),
                                FormatHexString(cs.m_ReturnAddress - cs.m_UniqueModule->m_ImageBase - offset, 0));
                }
                else
                {
                    return QString("%1+0x%2").arg(
                                cs.m_UniqueModule->m_UniqueImage->m_FileName,
                                FormatHexString(cs.m_ReturnAddress - cs.m_UniqueModule->m_ImageBase, 0));
                }
            }
            else
            {
                int hexWidth;
                if(cs.m_UniqueModule)
                    hexWidth = cs.m_UniqueModule->m_UniqueImage->m_bIs64Bit ? 16 : 8;
                else
                    hexWidth = cs.m_ReturnAddress > 0xffffffff ? 16 : 8;
                return QString("0x%1").arg( FormatHexString(cs.m_ReturnAddress, hexWidth) );
            }
        case 2:
            int hexWidth;
            if(cs.m_UniqueModule)
                hexWidth = cs.m_UniqueModule->m_UniqueImage->m_bIs64Bit ? 16 : 8;
            else
                hexWidth = cs.m_ReturnAddress > 0xffffffff ? 16 : 8;
            return QString("0x%1").arg( FormatHexString(cs.m_ReturnAddress, hexWidth) );
        case 3:
            if(cs.m_UniqueModule)
                return cs.m_UniqueModule->m_UniqueImage->m_ImagePath;
        }
    } else if (role == Qt::TextAlignmentRole){
        return int(Qt::AlignLeft | Qt::AlignVCenter);
    }
    return QVariant();
}

QVariant CCallStackTableModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if(orientation == Qt::Horizontal && section >= 0 && section < m_HeaderString.size())
    {
        if (role == Qt::DisplayRole)
            return m_HeaderString[section];
        else if (role == Qt::TextAlignmentRole)
            return int(Qt::AlignHCenter | Qt::AlignVCenter);
    }
    return QVariant();
}
