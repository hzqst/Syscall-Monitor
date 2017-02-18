#ifndef EVENTTABLE_H
#define EVENTTABLE_H

#pragma once

//Event table

#include <QAbstractTableModel>
#include <QList>
#include <QLinkedList>
#include <QFont>
#include "EventMgr.h"

class CEventTableModel : public QAbstractTableModel
{
    Q_OBJECT
public:
    //impl
    explicit CEventTableModel(QObject *parent = Q_NULLPTR);
    int rowCount(const QModelIndex &parent = QModelIndex()) const;
    int columnCount(const QModelIndex &parent = QModelIndex()) const;
    QModelIndex index(int row, int column, const QModelIndex &parent = QModelIndex()) const;
    QModelIndex parent(const QModelIndex &index) const;
    QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const;
    QVariant headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const;
    Qt::ItemFlags flags(const QModelIndex &index) const;
    //util
    void setHeaderString(const QStringList &header);
    CUniqueEvent *eventFromIndex(const QModelIndex &index) const ;
    void appendRow(CUniqueEvent *ev);
    void appendRows(QEventList &evs);
    void appendRows(QEventLinkedList &evs);
    bool removeRow(int position, const QModelIndex &parent = QModelIndex());
    bool removeRows(int position, int count, const QModelIndex &parent = QModelIndex());
private:
    QEventList m_List;
    QStringList m_HeaderString;
    QFont m_Font;
};

#endif // EVENTTABLE_H
