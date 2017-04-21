#ifndef FILTERTABLE_H
#define FILTERTABLE_H

#pragma once

//Filter table

#include <QAbstractTableModel>
#include <QString>
#include <QList>
#include "EventMgr.h"

const filter_rel FltRelTable_Number[] = {
    FltRel_Is,
    FltRel_IsNot,
    FltRel_LargerThan,
    FltRel_SmallerThan,
};

const filter_rel FltRelTable_String[] = {
    FltRel_Is,
    FltRel_IsNot,
    FltRel_Contain,
    FltRel_NotContain,
};

const filter_rel FltRelTable_Binary[] = {
    FltRel_Is,
    FltRel_IsNot,
};

class CFilterTableModel : public QAbstractTableModel
{
    Q_OBJECT
public:
    //impl
    explicit CFilterTableModel(CFilterList *List, QObject *parent = Q_NULLPTR);
    int rowCount(const QModelIndex &parent = QModelIndex()) const;
    int columnCount(const QModelIndex &parent = QModelIndex()) const;
    QModelIndex index(int row, int column, const QModelIndex &parent = QModelIndex()) const;
    QModelIndex parent(const QModelIndex &index) const;
    QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const;
    QVariant headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const;
    Qt::ItemFlags flags(const QModelIndex &index) const;
    //util
    void setHeaderString(const QStringList &header);
    CEventFilter *fltFromIndex(const QModelIndex &index) const ;
    void appendRow(CEventFilter *flt);
    bool removeRow(int position, const QModelIndex &parent = QModelIndex());
    bool removeRows(int position, int count, const QModelIndex &parent = QModelIndex());
    void setRows(CFilterList &list);
private:
    CFilterList *m_List;
    QStringList m_HeaderString;
};

#endif // FILTERTABLE_H
