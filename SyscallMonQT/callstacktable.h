#ifndef CALLSTACKTABLE_H
#define CALLSTACKTABLE_H

#include <QAbstractTableModel>
#include "EventMgr.h"

class CCallStackTableModel : public QAbstractTableModel
{
    Q_OBJECT
public:
    //impl
    explicit CCallStackTableModel(QObject *parent = Q_NULLPTR);
    int rowCount(const QModelIndex &parent = QModelIndex()) const;
    int columnCount(const QModelIndex &parent = QModelIndex()) const;
    QModelIndex index(int row, int column, const QModelIndex &parent = QModelIndex()) const;
    QModelIndex parent(const QModelIndex &index) const;
    QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const;
    QVariant headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const;
    Qt::ItemFlags flags(const QModelIndex &index) const;
    //util
    void setHeaderString(const QStringList &header);
    void setRows(CCallStackList *list);
    void updateRows(int beginRow, int endRow);
    void clearRows(void);

private:
    CCallStackList *m_List;
    QStringList m_HeaderString;
};

#endif // CALLSTACKTABLE_H
