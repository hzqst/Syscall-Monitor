#include <QTimer>
#include "syscallmon.h"
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

    m_DelayEvents.reserve(10000);
    m_EventMgr->StartParsing();
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::closeEvent(QCloseEvent *e)
{
    m_SyscallMon->Uninitialize();
    e->accept();
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
            auto detailAction = m_processMenu->addAction(tr("Process Information..."));
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
    ui->tableView_Event->verticalHeader()->setDefaultSectionSize(15);

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

CEventFilter *GetNewFilter(filter_key key, filter_rel rel, int data, QString &str, bool bInclude);

const filter_key m_FilterKeyMappingTable[] = {
    FltKey_Max,
    FltKey_ProcessName,
    FltKey_PID,
    FltKey_EventType,
    FltKey_EventPath,
    FltKey_Max,
    FltKey_BriefResult,
};

const filter_rel m_FilterRelMappingTable[] = {
    FltRel_Max,
    FltRel_Is,
    FltRel_Is,
    FltRel_Is,
    FltRel_Contain,
    FltRel_Max,
    FltRel_Contain,
};

void MainWindow::OnShowEventMenu(const QPoint& pos)
{
    QModelIndex modelIndex = ui->tableView_Event->indexAt(pos);
    if(modelIndex.isValid())
    {
        const auto pEvent = m_model_Event->eventFromIndex(modelIndex);
        if(pEvent)
        {
            m_eventMenu->clear();

            QAction *detailAction = m_eventMenu->addAction(tr("Detail..."));
            detailAction->setData(QVariant::fromValue(modelIndex));
            connect(detailAction, SIGNAL(triggered(bool)), this, SLOT(OnEventDetailAction(void)));

            int columnIndex = modelIndex.column();
            if(m_FilterKeyMappingTable[columnIndex] != FltKey_Max)
            {
                QString cellText = m_model_Event->data(modelIndex).toString();
                if(columnIndex == 1)//Fix for process name
                    cellText = pEvent->GetProcessName();

                QAction *includeAction = m_eventMenu->addAction(tr("Include %1 ...").arg( cellText ));
                includeAction->setData(QVariant::fromValue(modelIndex));
                includeAction->setProperty("include", true);
                connect(includeAction, SIGNAL(triggered(bool)), this, SLOT(OnEventFilterAction(void)));

                QAction *excludeAction = m_eventMenu->addAction(tr("Exclude %1 ...").arg( cellText ));
                excludeAction->setData(QVariant::fromValue(modelIndex));
                excludeAction->setProperty("include", false);
                connect(excludeAction, SIGNAL(triggered(bool)), this, SLOT(OnEventFilterAction(void)));
            }
            m_eventMenu->exec(QCursor::pos());
        }
    }
}

void MainWindow::OnEventDetailAction(void)
{
    auto pAction=qobject_cast<QAction*>(sender());
    QModelIndex modelIndex = pAction->data().toModelIndex();
    const auto pEvent = m_model_Event->eventFromIndex(modelIndex);
    if(pEvent)
    {
        EventInfoDialog *dlg = new EventInfoDialog(this);
        dlg->SetEventInfo(pEvent);
        dlg->show();
    }
}

void MainWindow::OnEventFilterAction(void)
{
    auto pAction = qobject_cast<QAction*>(sender());
    auto modelIndex = pAction->data().toModelIndex();
    const auto pEvent = m_model_Event->eventFromIndex(modelIndex);
    if(pEvent)
    {
        const auto bIsInclude = pAction->property("include").toBool();
        const int columnIndex = modelIndex.column();

        auto key = m_FilterKeyMappingTable[columnIndex];
        if(key == FltKey_Max)
            return;

        auto rel = m_FilterRelMappingTable[columnIndex];
        if(rel == FltRel_Max)
            return;

        int intVal = 0;
        switch(key){
        case FltKey_EventType:
            intVal = (int)pEvent->GetEventType(); break;
        }
        QString strVal;
        switch(key){
        case FltKey_ProcessName:
            strVal = pEvent->GetProcessName(); break;
        case FltKey_PID:
            strVal = QString::number(pEvent->GetProcessId()); break;
        case FltKey_EventPath:
            strVal = pEvent->GetEventPath(); break;
        case FltKey_BriefResult:
            pEvent->GetBriefResult(strVal); break;
        }

        CEventFilter *pFilter = GetNewFilter(key, rel, intVal, strVal, bIsInclude);
        if(pFilter)
        {
            CFilterList list;
            m_EventMgr->GetFilters(list);
            list.push_back(pFilter);
            m_EventMgr->LoadFilters(list);
            m_EventMgr->StartFilter();
        }
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
    AddEventItem(ev, true);
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
