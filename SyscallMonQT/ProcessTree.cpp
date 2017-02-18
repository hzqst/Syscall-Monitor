#include "ProcessTree.h"

//Process TreeModel

CProcessTreeItem::CProcessTreeItem(CProcessTreeItem *parent, CUniqueProcess *up, CProcessTreeModel *model)
{
    m_parentItem = parent;
    m_UniqueProcess = up;    
    m_model = model;
    m_displayState = 0;
}

CProcessTreeItem::~CProcessTreeItem()
{
    qDeleteAll(m_childItems);
}

bool CProcessTreeItem::insertItem(CProcessTreeItem *item, int position)
{
    if (position < 0 || position > m_childItems.size())
        return false;

    m_childItems.insert(position, item);

    return true;
}

bool CProcessTreeItem::removeItem(int position)
{
    if (position < 0 || position >= m_childItems.size())
        return false;

    m_childItems.takeAt(position);

    return true;
}

void CProcessTreeItem::setParentItem(CProcessTreeItem *parent)
{
    m_parentItem = parent;
}

CProcessTreeItem *CProcessTreeItem::parentItem() const
{
    return m_parentItem;
}

void CProcessTreeItem::setDisplayState(int displayState)
{
    m_displayState = displayState;
}

CProcessTreeItem *CProcessTreeItem::child(int row)
{
    return m_childItems.value(row);
}

int CProcessTreeItem::childCount() const
{
    return m_childItems.count();
}

QModelIndex CProcessTreeItem::index() const
{
    return m_model->indexFromItem((CProcessTreeItem *)this);
}

CProcessTreeModel *CProcessTreeItem::model() const
{
    return m_model;
}

int CProcessTreeItem::row() const
{
    if (m_parentItem)
        return m_parentItem->m_childItems.indexOf(const_cast<CProcessTreeItem*>(this));

    return 0;
}

int CProcessTreeItem::columnCount() const
{
    return m_model->columnCount();
}

QVariant CProcessTreeItem::data(int column, int role) const
{
    if(role == Qt::ItemDataRole::DisplayRole)
    {
        switch(column)
        {
        case 0:
            return m_UniqueProcess->GetDisplayName();
        case 1:
            return QString::number(m_UniqueProcess->m_ProcessId);
        case 2:
            return QString::number(m_UniqueProcess->m_ParentProcessId);
        case 3:
            return QString::number(m_UniqueProcess->m_SessionId);
        case 4:
            return m_UniqueProcess->m_ImagePath;
        }
    }
    else if(role == Qt::ItemDataRole::DecorationRole && column == 0)
    {
        if(m_UniqueProcess->m_Icon)
            return *m_UniqueProcess->m_Icon;
    }
    else if(role == Qt::ItemDataRole::BackgroundColorRole)
    {
        switch(m_displayState)
        {
        case 1:return QColor(0, 255, 0);
        case 2:return QColor(128, 128, 128);
        default:return QColor(255, 255, 255);
        }
    }

    return QVariant();
}

//Model implement

CProcessTreeModel::CProcessTreeModel(QObject *parent)
    : QAbstractItemModel(parent)
{
    m_rootItem = new CProcessTreeItem(NULL, NULL, this);
}

CProcessTreeModel::~CProcessTreeModel()
{
    delete m_rootItem;
}

bool CProcessTreeModel::insertRow(CProcessTreeItem *item, int position, const QModelIndex &parent)
{
    CProcessTreeItem *parentItem = getItem(parent);
    bool success;

    beginInsertRows(parent, position, position);
    success = parentItem->insertItem(item, position);
    endInsertRows();

    return success;
}

bool CProcessTreeModel::appendRow(CProcessTreeItem *item, const QModelIndex &parent)
{
    CProcessTreeItem *parentItem = getItem(parent);

    bool success = insertRow(item, parentItem->childCount(), parent);

    if(success && parentItem != m_rootItem)
    {
        expandItems(parentItem);
    }

    return success;
}

bool CProcessTreeModel::removeRow(CProcessTreeItem *item)
{
    CProcessTreeItem *parentItem = item->parentItem();
    return removeRow(item->row(), parentItem->index());
}

bool CProcessTreeModel::removeRow(int position, const QModelIndex &parent)
{
    CProcessTreeItem *parentItem = getItem(parent);
    bool success = true;

    beginRemoveRows(parent, position, position);
    success = parentItem->removeItem(position);
    endRemoveRows();

    return success;
}

QModelIndex CProcessTreeModel::indexFromItem(CProcessTreeItem *item)
{
    if(item != m_rootItem)
        return createIndex(item->row(), 0, item);
    return QModelIndex();
}

QModelIndex CProcessTreeModel::indexFromItemEnd(CProcessTreeItem *item)
{
    if(item != m_rootItem && m_HeaderString.size() > 0)
        return createIndex(item->row(), m_HeaderString.size() - 1, item);
    return QModelIndex();
}

QModelIndex CProcessTreeModel::indexFromProcess(CUniqueProcess *up)
{
    CProcessItemMap::iterator itor = m_processItemMap.find(up);
    if (itor == m_processItemMap.end())
        return QModelIndex();
    CProcessTreeItem *item = itor->second;

    return item->index();
}

CProcessTreeItem *CProcessTreeModel::getItem(const QModelIndex &index) const
{
    if (index.isValid())
    {
        CProcessTreeItem *item = static_cast<CProcessTreeItem*>(index.internalPointer());
        if (item)
            return item;
    }
    return m_rootItem;
}

int CProcessTreeModel::rowCount(const QModelIndex &parent) const
{
    CProcessTreeItem *parentItem = getItem(parent);

    return parentItem->childCount();
}

int CProcessTreeModel::columnCount(const QModelIndex &parent) const
{
    UNREFERENCED_PARAMETER(parent);
    return m_HeaderString.size();
}

QModelIndex CProcessTreeModel::index(int row, int column, const QModelIndex &parent) const
{
    if (parent.isValid() && parent.column() != 0)
        return QModelIndex();

    CProcessTreeItem *parentItem = getItem(parent);
    CProcessTreeItem *childItem = parentItem->child(row);
    if (childItem)
        return createIndex(row, column, childItem);

    return QModelIndex();
}

QModelIndex CProcessTreeModel::parent(const QModelIndex &index) const
{
    if (!index.isValid())
        return QModelIndex();

    CProcessTreeItem *childItem = getItem(index);
    CProcessTreeItem *parentItem = childItem->parentItem();
    if (parentItem == m_rootItem)
        return QModelIndex();

    return createIndex(parentItem->row(), 0, parentItem);
}

QVariant CProcessTreeModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid())
        return QVariant();

    CProcessTreeItem *item = getItem(index);

    return item->data(index.column(), role);
}

Qt::ItemFlags CProcessTreeModel::flags(const QModelIndex &index) const
{
    if (!index.isValid())
        return 0;

    return (Qt::ItemIsEnabled | Qt::ItemIsSelectable);
}

QVariant CProcessTreeModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (orientation == Qt::Horizontal && role == Qt::DisplayRole && section >= 0 && section < m_HeaderString.size())
        return m_HeaderString.at(section);

    return QVariant();
}

void CProcessTreeModel::setHeaderString(const QStringList &header)
{
    beginResetModel();
    m_HeaderString = header;
    endResetModel();
}

bool CProcessTreeModel::insertProcess(CUniqueProcess *up)
{
    if(up->m_pParentProcess && up->m_pParentProcess->m_bAlive)
    {
        CProcessItemMap::iterator itor = m_processItemMap.find(up->m_pParentProcess);
        if(itor != m_processItemMap.end())
        {
            return insertProcess(up, itor->second);
        }
    }
    else
    {
        return insertProcess(up, m_rootItem);
    }
    return false;
}

bool CProcessTreeModel::insertProcess(CUniqueProcess *up, CProcessTreeItem *parentItem)
{
    //already in tree, fail to insert
    if(m_processItemMap.find(up) != m_processItemMap.end())
        return false;

    if(parentItem)
    {
        CProcessTreeItem *item = new CProcessTreeItem(parentItem, up, this);

        appendRow(item, parentItem->index());

        m_processItemMap[up] = item;
        return true;
    }

    return false;
}

bool CProcessTreeModel::setProcessDisplayState(CUniqueProcess *up, int displayState)
{
    CProcessItemMap::iterator itor = m_processItemMap.find(up);
    if (itor == m_processItemMap.end())
        return false;
    CProcessTreeItem *item = itor->second;
    item->setDisplayState(displayState);

    QVector<int> roles;
    roles.append(Qt::BackgroundColorRole);
    dataChanged(indexFromItem(item), indexFromItemEnd(item), roles);

    return true;
}

bool CProcessTreeModel::removeProcess(CUniqueProcess *up)
{
    CProcessItemMap::iterator itor = m_processItemMap.find(up);
    if (itor == m_processItemMap.end())
        return false;

    QList<CProcessTreeItem *>itemsToMove;

    CProcessTreeItem *item = itor->second;

    for(int i = 0; i < item->childCount(); ++i)
    {
        itemsToMove.append(item->child(i));
    }

    for(int i = 0;i < itemsToMove.size(); ++i)
    {
        removeRow(itemsToMove[i]);
        itemsToMove[i]->setParentItem(m_rootItem);
        appendRow(itemsToMove[i], QModelIndex());
        expandItems(itemsToMove[i]);//fix
    }

    removeRow(item);

    Q_ASSERT(item->childCount() == 0);

    delete item;

    m_processItemMap.erase(itor);

    return true;
}

void CProcessTreeModel::expandItems(CProcessTreeItem *item)
{
    emit ExpandProcessItem(item->index());
    for(int i = 0;i < item->childCount(); ++i)
    {
        expandItems(item->child(i));
    }
}
