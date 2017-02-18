#include <QTimer>
#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "eventinfodialog.h"
#include "processinfodialog.h"

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    m_filterDialog = new FilterDialog(this);

    InitProcessView();

    InitEventView();

    connect(m_ProcessMgr, &CProcessMgr::AddProcessItem, this, &MainWindow::OnAddProcessItem);
    connect(m_ProcessMgr, &CProcessMgr::UnfreshProcessItem, this, &MainWindow::OnUnfreshProcessItem);
    connect(m_ProcessMgr, &CProcessMgr::KillProcessItem, this, &MainWindow::OnKillProcessItem);
    connect(m_ProcessMgr, &CProcessMgr::RemoveProcessItem, this, &MainWindow::OnRemoveProcessItem);

    connect(m_EventMgr, &CEventMgr::AddEventItem, this, &MainWindow::OnAddEventItem);
    connect(m_EventMgr, &CEventMgr::RefillEventItems, this, &MainWindow::OnRefillEventItems, Qt::BlockingQueuedConnection);
    connect(m_EventMgr, &CEventMgr::ClearAllDisplayingEvents, this, &MainWindow::OnClearAllDisplayingEvents);

    OnDelayUpdate();

    QTimer *timer = new QTimer(this);
    connect(timer, SIGNAL(timeout()), this, SLOT(OnDelayUpdate()));
    timer->start(1000);

    m_EventMgr->StartParsing();
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::OnClearAllDisplayingEvents(void)
{
    m_DelayEvents.clear();

    if(m_model_Event->rowCount() > 0)
        m_model_Event->removeRows(0, m_model_Event->rowCount());

    QString st = tr("Current displaying: %1 of %2...").arg(0).arg(0);
    ui->labal_FilterStatus->setText(st);
}

void MainWindow::OnRefillEventItems(QEventList *evs)
{
    m_DelayEvents.clear();

    if(m_model_Event->rowCount() > 0)
       m_model_Event->removeRows(0, m_model_Event->rowCount(), QModelIndex());

    if(!evs->empty())
        m_model_Event->appendRows(*evs);

    delete evs;

    m_filterDialog->HideFilterLoading();
}

void MainWindow::OnDelayUpdate()
{
    if(!m_DelayEvents.empty())
        m_model_Event->appendRows(m_DelayEvents);
    m_DelayEvents.clear();

    QString st = tr("Current displaying: %1 of %2...")
            .arg(m_model_Event->rowCount())
            .arg(m_EventMgr->m_EventList.size());
    ui->labal_FilterStatus->setText(st);
}

//Recursively fill the process list
static void FillProcessList(CProcessList &newList, CProcessList &fromList, bool bRoot)
{
    for (size_t i = 0; i < fromList.size(); ++i)
    {
        CUniqueProcess *up = fromList[i];

        if (!up->m_pParentProcess && bRoot)
        {
            newList.push_back(up);
            FillProcessList(newList, up->m_ChildProcesses, false);
        }
        else if(!bRoot)
        {
            newList.push_back(up);
            FillProcessList(newList, up->m_ChildProcesses, false);
        }
    }
}

void MainWindow::AddProcessItem(CUniqueProcess *up, bool bInit)
{
    m_model_Process->insertProcess(up);

    if(!bInit)
    {
        m_model_Process->setProcessDisplayState(up, 1);

        CDelayProcessTimer *timer = new CDelayProcessTimer(up, 0, this);
        timer->setSingleShot(true);
        connect(timer,SIGNAL(timeout()),timer,SLOT(TimerExpired()));
        connect(timer,SIGNAL(timeout()),timer,SLOT(deleteLater()));
        timer->start( 2000 );
    }
}

void MainWindow::OnAddProcessItem(CUniqueProcess *up)
{
    AddProcessItem(up, false);
}

void MainWindow::UnfreshProcessItem(CUniqueProcess *up)
{
    if(up->m_bAlive)
       m_model_Process->setProcessDisplayState(up, 0);
}

void MainWindow::OnUnfreshProcessItem(CUniqueProcess *up)
{
    UnfreshProcessItem(up);
}

void MainWindow::KillProcessItem(CUniqueProcess *up)
{
    m_model_Process->setProcessDisplayState(up, 2);

    //Create a timer to remove the process
    CDelayProcessTimer *timer = new CDelayProcessTimer(up, 1, this);
    timer->setSingleShot(true);
    timer->connect(timer,SIGNAL(timeout()),timer,SLOT(TimerExpired()));
    timer->connect(timer,SIGNAL(timeout()),timer,SLOT(deleteLater()));
    timer->start( 2000 );
}

void MainWindow::OnKillProcessItem(CUniqueProcess *up)
{
    KillProcessItem(up);
}

void MainWindow::RemoveProcessItem(CUniqueProcess *up)
{
    m_model_Process->removeProcess(up);
}

void MainWindow::OnRemoveProcessItem(CUniqueProcess *up)
{
    RemoveProcessItem(up);
}

void MainWindow::InitProcessView(void)
{
    m_model_Process = new CProcessTreeModel(ui->treeView_Process);
    ui->treeView_Process->setModel(m_model_Process);
    ui->treeView_Process->setUniformRowHeights(true);

    QStringList hdr;
    hdr.append(tr("Process Name"));
    hdr.append(tr("PID"));
    hdr.append(tr("Parent PID"));
    hdr.append(tr("Session ID"));
    hdr.append(tr("Path"));
    m_model_Process->setHeaderString(hdr);

    CProcessList newList;
    FillProcessList(newList, m_ProcessMgr->m_List, true);

    for(size_t i = 0; i < newList.size(); ++i)
        AddProcessItem(newList[i], true);

    m_processMenu = new QMenu(this);
    connect(ui->treeView_Process,SIGNAL(customContextMenuRequested(const QPoint &)),this,SLOT(OnShowProcessMenu(const QPoint&)));

    connect(m_model_Process, &CProcessTreeModel::ExpandProcessItem, this, &MainWindow::OnExpandProcessItem);

    ui->treeView_Process->expandAll();
    ui->treeView_Process->resizeColumnToContents(0);
    ui->treeView_Process->resizeColumnToContents(1);
    ui->treeView_Process->resizeColumnToContents(2);
    ui->treeView_Process->resizeColumnToContents(3);
}

void MainWindow::OnExpandProcessItem(const QModelIndex &index)
{
    ui->treeView_Process->expand(index);
}

void MainWindow::OnShowProcessMenu(const QPoint& pos)
{
    QModelIndex modelIndex = ui->treeView_Process->indexAt(pos);
    if(modelIndex.isValid()) {
        auto processItem = m_model_Process->getItem(modelIndex);
        if(processItem) {
            m_processMenu->clear();
            auto detailAction = m_processMenu->addAction("Process Information...");
            detailAction->setData(QVariant::fromValue(modelIndex));
            connect(detailAction, SIGNAL(triggered(bool)), this, SLOT(OnProcessDetailAction(void)));
            m_processMenu->exec(QCursor::pos());
        }
    }
}

void MainWindow::OnProcessDetailAction(void)
{
    auto pAction = qobject_cast<QAction*>(sender());
    QModelIndex modelIndex = pAction->data().toModelIndex();
    auto processItem = m_model_Process->getItem(modelIndex);
    if(processItem) {
        const auto up = processItem->m_UniqueProcess;
        if(up){
            ProcessInfoDialog *dlg = new ProcessInfoDialog(this);
            dlg->SetProcess(up);
            dlg->show();
        }
    }
}

//Tree View

void MainWindow::InitEventView(void)
{
    m_model_Event = new CEventTableModel(ui->tableView_Event);
    ui->tableView_Event->setModel(m_model_Event);
    ui->tableView_Event->verticalHeader()->setDefaultSectionSize(18);

    QStringList hdr;
    hdr.append(tr("Time"));
    hdr.append(tr("Process"));
    hdr.append(tr("PID"));
    hdr.append(tr("Behavior"));
    hdr.append(tr("Path"));
    hdr.append(tr("Arguments"));
    hdr.append(tr("Result"));

    m_model_Event->setHeaderString(hdr);

    ui->tableView_Event->setColumnWidth(0, 90);
    ui->tableView_Event->setColumnWidth(1, 200);
    ui->tableView_Event->setColumnWidth(2, 75);
    ui->tableView_Event->setColumnWidth(3, 100);
    ui->tableView_Event->setColumnWidth(4, 300);
    ui->tableView_Event->setColumnWidth(5, 200);
    ui->tableView_Event->setColumnWidth(6, 200);

    m_eventMenu = new QMenu(this);
    connect(ui->tableView_Event,SIGNAL(customContextMenuRequested(const QPoint &)),this,SLOT(OnShowEventMenu(const QPoint&)));
}

void MainWindow::OnShowEventMenu(const QPoint& pos)
{
    QModelIndex modelIndex = ui->tableView_Event->indexAt(pos);
    if(modelIndex.isValid()) {
        const auto ev = m_model_Event->eventFromIndex(modelIndex);
        if(ev) {
            m_eventMenu->clear();
            QAction *detailAction = m_eventMenu->addAction("Detail...");
            detailAction->setData(QVariant::fromValue(modelIndex));
            connect(detailAction, SIGNAL(triggered(bool)), this, SLOT(OnEventDetailAction(void)));
            m_eventMenu->exec(QCursor::pos());
        }
    }
}

void MainWindow::OnEventDetailAction(void)
{
    auto pAction=qobject_cast<QAction*>(sender());
    QModelIndex modelIndex = pAction->data().toModelIndex();
    const auto ev = m_model_Event->eventFromIndex(modelIndex);
    if(ev) {
        EventInfoDialog *dlg = new EventInfoDialog(this);
        dlg->SetEventInfo(ev);
        dlg->show();
    }
}

void MainWindow::AddEventItem(CUniqueEvent *ev, bool bDelay)
{
    if(!bDelay)
        m_model_Event->appendRow(ev);
    else
        m_DelayEvents.push_back(ev);
}

void MainWindow::OnAddEventItem(CUniqueEvent *ev)
{
    AddEventItem(ev, false);
}

void MainWindow::on_checkBox_EnableCapture_stateChanged(int arg1)
{
    m_EventMgr->m_CaptureEnable = (!arg1) ? FALSE : TRUE;
}

void MainWindow::on_pushButton_OpenFilter_clicked()
{
    m_filterDialog->show();
}

void MainWindow::on_checkBox_DropExclude_clicked(bool checked)
{
    m_EventMgr->m_DropExclude = (!checked) ? FALSE : TRUE;
}

void MainWindow::on_pushButton_ClearEvents_clicked()
{
    m_EventMgr->ClearAllEvents();
}
