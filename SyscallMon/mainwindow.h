#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QMenu>

#include "ProcessTree.h"
#include "EventTable.h"
#include "filterdialog.h"

namespace Ui {
class MainWindow;
class FilterWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();

public:
    //Process View
    virtual void closeEvent(QCloseEvent *e);
    void InitProcessView(void);
    void AddProcessItem(CUniqueProcess *up, bool bInit);
    void UnfreshProcessItem(CUniqueProcess *up);
    void KillProcessItem(CUniqueProcess *up);
    void RemoveProcessItem(CUniqueProcess *up);

    //Event View
    void InitEventView(void);
    void AddEventItem(CUniqueEvent *ev, bool bDelay);
    //Common
private:
    Ui::MainWindow *ui;
    CProcessTreeModel *m_model_Process;
    CEventTableModel *m_model_Event;
    QEventList m_DelayEvents;
    QMenu *m_eventMenu;
    QMenu *m_processMenu;

    FilterDialog *m_filterDialog;

signals:
    void FilterFinishLoading();

private slots:
    void OnAddProcessItem(CUniqueProcess *up);
    void OnUnfreshProcessItem(CUniqueProcess *up);
    void OnKillProcessItem(CUniqueProcess *up);
    void OnRemoveProcessItem(CUniqueProcess *up);
    void OnDelayUpdate();
    void OnAddEventItem(CUniqueEvent *ev);
    void OnExpandProcessItem(const QModelIndex &index);
    void OnRefillEventItems(QEventList *evs);
    void OnShowEventMenu(const QPoint& pos);
    void OnShowProcessMenu(const QPoint& pos);
    void OnEventDetailAction(void);
    void OnEventFilterAction(void);
    void OnProcessDetailAction(void);
    void OnClearAllDisplayingEvents(void);
    void on_checkBox_EnableCapture_stateChanged(int arg1);
    void on_pushButton_OpenFilter_clicked();
    void on_checkBox_DropExclude_clicked(bool checked);
    void on_pushButton_ClearEvents_clicked();
};

#endif // MAINWINDOW_H
