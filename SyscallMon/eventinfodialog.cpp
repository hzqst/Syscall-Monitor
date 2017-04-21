#include "eventinfodialog.h"
#include "processinfodialog.h"
#include "ui_eventinfodialog.h"
#include <QDateTime>
#include "EventMgr.h"

EventInfoDialog::EventInfoDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::EventInfoDialog)
{
    ui->setupUi(this);

    m_model_CallStack = new CCallStackTableModel(this);

    QStringList hdr;
    hdr.append(tr("Frame"));
    hdr.append(tr("Location"));
    hdr.append(tr("Address"));
    hdr.append(tr("Image Path"));
    m_model_CallStack->setHeaderString(hdr);

    ui->tableView_CallStack->setModel(m_model_CallStack);
    ui->tableView_CallStack->setColumnWidth(0, 60);
    ui->tableView_CallStack->setColumnWidth(1, 200);
    ui->tableView_CallStack->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeMode::Fixed);
    ui->tableView_CallStack->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeMode::Interactive);
    ui->tableView_CallStack->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeMode::ResizeToContents);
    ui->tableView_CallStack->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeMode::ResizeToContents);
    ui->tableView_CallStack->verticalHeader()->setDefaultSectionSize(18);

    connect(m_ModuleMgr, &CModuleMgr::UpdateModuleNotify, this, &EventInfoDialog::OnUpdateModuleNotify, Qt::QueuedConnection);
    connect(m_ModuleMgr, &CModuleMgr::UpdateImageNotify, this, &EventInfoDialog::OnUpdateImageNotify, Qt::QueuedConnection);
    connect(m_ModuleMgr, &CModuleMgr::LoadingImageNotify, this, &EventInfoDialog::OnLoadingImageNotify, Qt::QueuedConnection);
    connect(m_ModuleMgr, &CModuleMgr::LoadAllImageCompleteNotify, this, &EventInfoDialog::OnLoadAllImageCompleteNotify);
    connect(m_EventMgr, &CEventMgr::ClearAllDisplayingEvents, this, &EventInfoDialog::OnClearAllDisplayingEvents);
    connect(ui->lineEdit_Process, &ClickableLineEdit::click, this, &EventInfoDialog::OnOpenProcessDialog);

    setAttribute(Qt::WA_DeleteOnClose);
    Qt::WindowFlags flags=Qt::Dialog;
    flags |= Qt::WindowCloseButtonHint;
    setWindowFlags(flags);
}

EventInfoDialog::~EventInfoDialog()
{
    m_model_CallStack->removeRows(0, m_model_CallStack->rowCount());

    delete ui;
}

void EventInfoDialog::OnOpenProcessDialog(void)
{
    if(m_Event)
    {
        ProcessInfoDialog *dlg = new ProcessInfoDialog(this);
        dlg->SetProcess(m_Event->GetUniqueProcess());
        dlg->show();
    }
}

void EventInfoDialog::OnUpdateModuleNotify(CUniqueProcess *up, CUniqueModule *um)
{
     UNREFERENCED_PARAMETER(um);

    if(!m_Event)
        return;

    if(m_Event->GetUniqueProcess() != up)
        return;

    m_Event->FixCallStacks(false);
    m_model_CallStack->updateRows(0, m_model_CallStack->rowCount());
}

void EventInfoDialog::OnUpdateImageNotify(CUniqueImage *ui)
{
    UNREFERENCED_PARAMETER(ui);

    if(!m_Event)
        return;

    for(int i = 0;i < m_Event->m_CallStacks.size(); ++i)
    {
        if(m_Event->m_CallStacks[i].m_UniqueModule)
        {
            if(ui == m_Event->m_CallStacks[i].m_UniqueModule->m_UniqueImage &&
                    i < m_model_CallStack->rowCount())
            {
                m_model_CallStack->updateRows(i, i);
            }
        }
    }
}

void EventInfoDialog::SetEventInfo(CUniqueEvent *ev)
{
    m_Event = ev;

    QDateTime date;
    date.setTime_t(ev->GetEventTime() / 1000);

    QString dateStr = date.toString("yyyy-MM-dd HH:mm:ss") + " " + QString("%1").arg(ev->GetEventTime() % 1000, 3, 10, QChar('0'));
    ui->lineEdit_Date->setText(dateStr);
    ui->lineEdit_Process->setText(ev->GetUniqueProcess()->GetDisplayNameWithPID());
    ui->lineEdit_Thread->setText(QString::number(ev->GetThreadId()));
    ui->lineEdit_Type->setText(ev->GetEventName());
    ui->lineEdit_Class->setText(ev->GetEventClassName());
    ui->textEdit_Path->setText(ev->GetEventPath());

    QString str;
    ev->GetBriefResult(str);
    ui->lineEdit_Result->setText(str);

    ev->GetFullArgument(str);
    ui->textEdit_Arguments->setText(str);

    if(ev->GetUniqueProcess()->m_Icon)
        ui->lineEdit_Process->setIcon(ev->GetUniqueProcess()->m_Icon);

    ev->FixCallStacks(true);
    m_model_CallStack->setEvent(ev);
}

void EventInfoDialog::OnLoadingImageNotify(std::wstring moduleName)
{
    ui->label_LoadingSymbol->setText(tr("Loading symbol for %1...").arg(QString::fromStdWString(moduleName)));
}

void EventInfoDialog::OnLoadAllImageCompleteNotify(void)
{
    ui->label_LoadingSymbol->setText(QString());
}

void EventInfoDialog::OnClearAllDisplayingEvents(void)
{
    m_model_CallStack->setEvent(NULL);
    m_Event = NULL;
}
