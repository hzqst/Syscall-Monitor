#ifndef PROCTREE_H
#define PROCTREE_H

#pragma once

#include <QAbstractItemModel>
#include <boost/unordered_map.hpp>

#include "ProcessMgr.h"

//Process Tree

class CProcessTreeModel;

class CProcessTreeItem
{
public:
    explicit CProcessTreeItem(CProcessTreeItem *parent, CUniqueProcess *up, CProcessTreeModel *model);
    ~CProcessTreeItem();

    bool insertItem(CProcessTreeItem *item, int position);
    bool removeItem(int position);
    void setDisplayState(int displayState);
    void setParentItem(CProcessTreeItem *parent);
    CProcessTreeItem *child(int row);
    int childCount() const;
    int columnCount() const;
    QVariant data(int column, int role) const;
    int row() const;
    QModelIndex index() const;
    CProcessTreeModel *model() const;
    CProcessTreeItem *parentItem() const;

public:
    CUniqueProcess *m_UniqueProcess;

private:
    QList<CProcessTreeItem *> m_childItems;
    CProcessTreeItem *m_parentItem;
    CProcessTreeModel *m_model;

    int m_displayState;
};

typedef boost::unordered_map<CUniqueProcess *, CProcessTreeItem *> CProcessItemMap;

class CProcessTreeModel : public QAbstractItemModel
{
    Q_OBJECT

public:
    explicit CProcessTreeModel(QObject *parent = Q_NULLPTR);
    ~CProcessTreeModel();

    bool insertRow(CProcessTreeItem *item, int position, const QModelIndex &parent);
    bool appendRow(CProcessTreeItem *item, const QModelIndex &parent);
    bool removeRow(int position, const QModelIndex &parent);
    bool removeRow(CProcessTreeItem *item);

    QModelIndex indexFromItem(CProcessTreeItem *item);
    QModelIndex indexFromItemEnd(CProcessTreeItem *item);
    QModelIndex indexFromProcess(CUniqueProcess *up);
    CProcessTreeItem *getItem(const QModelIndex &index) const;
    int rowCount(const QModelIndex &parent = QModelIndex()) const Q_DECL_OVERRIDE;
    int columnCount(const QModelIndex &parent = QModelIndex()) const Q_DECL_OVERRIDE;
    QModelIndex index(int row, int column, const QModelIndex &parent = QModelIndex()) const Q_DECL_OVERRIDE;
    QModelIndex parent(const QModelIndex &index) const Q_DECL_OVERRIDE;
    QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const Q_DECL_OVERRIDE;
    Qt::ItemFlags flags(const QModelIndex &index) const Q_DECL_OVERRIDE;
    QVariant headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const Q_DECL_OVERRIDE;

public://used
    void setHeaderString(const QStringList &header);
    bool insertProcess(CUniqueProcess *up);
    bool insertProcess(CUniqueProcess *up, CProcessTreeItem *parentItem);
    bool setProcessDisplayState(CUniqueProcess *up, int displayState);
    bool removeProcess(CUniqueProcess *up);
    void expandItems(CProcessTreeItem *item);
signals:
    void ExpandProcessItem(const QModelIndex &index);
private:
    CProcessTreeItem *m_rootItem;
    QStringList m_HeaderString;
    CProcessItemMap m_processItemMap;
};

#endif // PROCTREE_H
