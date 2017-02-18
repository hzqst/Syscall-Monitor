#include "filterdialog.h"
#include "ui_filterdialog.h"
#include "util.h"

FilterDialog::FilterDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::FilterDialog)
{
    ui->setupUi(this);

    m_LoadingDialog = new FilterLoadingDialog(this);

    m_model_Filter = new CFilterTableModel(&m_LocalFilterList, this);
    ui->tableView_Filter->setModel(m_model_Filter);
    ui->tableView_Filter->verticalHeader()->setDefaultSectionSize(18);

    QStringList hdr;
    hdr.append(tr("Attribute"));
    hdr.append(tr("Relation"));
    hdr.append(tr("Value"));
    hdr.append(tr("Then"));
    m_model_Filter->setHeaderString(hdr);

    ui->tableView_Filter->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeMode::Stretch);

    for(int i = 0; i < FltKey_Max; ++i)
        ui->comboBox_key->addItem(m_EventMgr->m_FltKeyTable[i], QVariant(i));
    ui->comboBox_key->setCurrentIndex(0);//this will trigger on_comboBox_key_currentIndexChanged

    //include & exclude
    ui->comboBox_action->addItem(m_EventMgr->m_FltIncTable[0], QVariant(0));
    ui->comboBox_action->addItem(m_EventMgr->m_FltIncTable[1], QVariant(1));
    ui->comboBox_action->setCurrentIndex(0);

    Qt::WindowFlags flags=Qt::Dialog;
    flags |=Qt::WindowCloseButtonHint;
    setWindowFlags(flags);
}

FilterDialog::~FilterDialog()
{
    delete ui;
}

void FilterDialog::HideFilterLoading(void)
{
    m_LoadingDialog->hide();
}

void FilterDialog::on_comboBox_key_currentIndexChanged(int index)
{
    ui->comboBox_relation->clear();
    ui->comboBox_value->clear();
    ui->comboBox_value->clearEditText();

    switch (index)
    {
    //PID (number)
    case FltKey_PID:case FltKey_SessionId:
    {
        for (int i = 0; i < _ARRAYSIZE(FltRelTable_Number); ++i)
            ui->comboBox_relation->addItem(m_EventMgr->m_FltRelTable[FltRelTable_Number[i]], QVariant(FltRelTable_Number[i]));

        ui->comboBox_relation->setCurrentIndex(0);
        break;
    }

    //process name, image path, event path (string)
    case FltKey_ProcessName:case FltKey_ProcessPath:case FltKey_EventPath:case FltKey_BriefResult:
    {
        for (int i = 0; i < _ARRAYSIZE(FltRelTable_String); ++i)
            ui->comboBox_relation->addItem(m_EventMgr->m_FltRelTable[FltRelTable_String[i]], QVariant(FltRelTable_String[i]));

        //default = contain
        ui->comboBox_relation->setCurrentIndex(2);

        if(index == FltKey_BriefResult){
            ui->comboBox_value->addItem("STATUS_SUCCESS");
            ui->comboBox_value->setCurrentIndex(0);
        }

        break;
    }
    //archtecture (bool)
    case FltKey_Arch:
    {
        for (int i = 0; i < _ARRAYSIZE(FltRelTable_Binary); ++i)
            ui->comboBox_relation->addItem(m_EventMgr->m_FltRelTable[FltRelTable_Binary[i]], QVariant(FltRelTable_Binary[i]));
        ui->comboBox_relation->setCurrentIndex(0);

        ui->comboBox_value->addItem(tr("x86"), QVariant(0));
        if (IsAMD64())
           ui->comboBox_value->addItem(tr("x64"), QVariant(1));
        ui->comboBox_value->setCurrentIndex(0);
        break;
    }
    //behavior (enum)
    case FltKey_EventType:
    {
        for (int i = 0; i < _ARRAYSIZE(FltRelTable_Binary); ++i)
            ui->comboBox_relation->addItem(m_EventMgr->m_FltRelTable[FltRelTable_Binary[i]], QVariant(FltRelTable_Binary[i]));
         ui->comboBox_relation->setCurrentIndex(0);

        for (int i = 0; i < EV_Maximum; ++i)
        {
           ui->comboBox_value->addItem(m_EventMgr->m_EventNames[i], QVariant(i));
        }
        ui->comboBox_value->setCurrentIndex(0);
        break;
    }
    //event classify (enum)
    case FltKey_EventClass:
    {
        for (int i = 0; i < _ARRAYSIZE(FltRelTable_Binary); ++i)
            ui->comboBox_relation->addItem(m_EventMgr->m_FltRelTable[FltRelTable_Binary[i]], QVariant(FltRelTable_Binary[i]));
         ui->comboBox_relation->setCurrentIndex(0);

        for (int i = 0; i < EVClass_Maximum; ++i)
        {
            ui->comboBox_value->addItem(m_EventMgr->m_EventClassNames[i], QVariant(i));
        }
        ui->comboBox_value->setCurrentIndex(0);
        break;
    }
    }
}

static bool ValidateRelation(filter_rel rel, const filter_rel *rels, const size_t arraySize)
{
    for (size_t i = 0; i < arraySize; ++i)
    {
        if (rels[i] == rel)
        {
            return true;
        }
    }

    return false;
}

void FilterDialog::on_pushButton_add_clicked()
{
    filter_key key = (filter_key)ui->comboBox_key->currentData().toInt();
    filter_rel rel = (filter_rel)ui->comboBox_relation->currentData().toInt();
    int valData = ui->comboBox_value->currentData().toInt();
    QString valStr = ui->comboBox_value->currentText();
    bool bInclude = (ui->comboBox_action->currentIndex() == 0) ? true : false;

    CEventFilter *flt = NULL;
    switch (key)
    {
        case FltKey_PID:
        {
            if (ValidateRelation(rel, FltRelTable_Number, _ARRAYSIZE(FltRelTable_Number)))
            {
                bool ok = false;
                ULONG ProcessId = valStr.toULong(&ok);
                if (ok)
                {
                    flt = new CEventFilter_PID(ProcessId, rel, bInclude);
                }
            }
            break;
        }
        case FltKey_ProcessName:
        {
            if (!valStr.isEmpty() && ValidateRelation(rel, FltRelTable_String, _ARRAYSIZE(FltRelTable_String)))
                flt = new CEventFilter_ProcessName(valStr, rel, bInclude);
            break;
        }
        case FltKey_ProcessPath:
        {
            if (!valStr.isEmpty() && ValidateRelation(rel, FltRelTable_String, _ARRAYSIZE(FltRelTable_String)))
                flt = new CEventFilter_ProcessPath(valStr, rel, bInclude);
            break;
        }
        case FltKey_EventPath:
        {
            if (!valStr.isEmpty() && ValidateRelation(rel, FltRelTable_String, _ARRAYSIZE(FltRelTable_String)))
                flt = new CEventFilter_EventPath(valStr, rel, bInclude);
            break;
        }
        case FltKey_Arch:
        {
            if (ValidateRelation(rel, FltRelTable_Binary, _ARRAYSIZE(FltRelTable_Binary)))
            {
                flt = new CEventFilter_Arch((valData == 1) ? true : false, rel, bInclude);
            }
            break;
        }
        case FltKey_SessionId:
        {
            if (ValidateRelation(rel, FltRelTable_Number, _ARRAYSIZE(FltRelTable_Number)))
            {
                bool ok = false;
                ULONG SessionId = valStr.toULong(&ok);
                if (ok)
                {
                    flt = new CEventFilter_SessionId(SessionId, rel, bInclude);
                }
            }

            break;
        }
        case FltKey_EventType:
        {
            if (ValidateRelation(rel, FltRelTable_Binary, _ARRAYSIZE(FltRelTable_Binary)))
            {
                if (valData >= 0 && valData < EV_Maximum)
                {
                    flt = new CEventFilter_EventType((EventType_t)valData, rel, bInclude);
                }
            }
            break;
        }
        case FltKey_EventClass:
        {
            if (ValidateRelation(rel, FltRelTable_Binary, _ARRAYSIZE(FltRelTable_Binary)))
            {
                if (valData >= 0 && valData < EVClass_Maximum)
                {
                    flt = new CEventFilter_EventClass((EventClass_t)valData, rel, bInclude);
                }
            }
            break;
        }
        case FltKey_BriefResult:
        {
            if (!valStr.isEmpty() && ValidateRelation(rel, FltRelTable_String, _ARRAYSIZE(FltRelTable_String)))
                flt = new CEventFilter_BriefResult(valStr, rel, bInclude);
            break;
        }
    }

    if (flt)
    {
        //no need to reference the flt since it's refcount = 1 when construct
        m_model_Filter->appendRow(flt);
        m_bModified = true;
        ui->pushButton_apply->setEnabled(true);
    }
}

void FilterDialog::on_pushButton_remove_clicked()
{
    QModelIndex index = ui->tableView_Filter->currentIndex();

    if(index.isValid() && index.row() >= 0 && index.row() < (int)m_LocalFilterList.size())
    {
        CEventFilter *flt = m_LocalFilterList.at(index.row());

        m_model_Filter->removeRow(index.row(), QModelIndex());

        flt->Dereference();

        m_bModified = true;
        ui->pushButton_apply->setEnabled(true);
    }
}

void FilterDialog::on_pushButton_apply_clicked()
{
    if(!m_bModified)
        return;

    m_bModified = false;
    ui->pushButton_apply->setEnabled(false);
    m_LoadingDialog->show();

    //Copy local list to EventMgr's list
    m_EventMgr->Lock();
    {
        for(size_t i = 0;i < FltKey_Max; ++i)
            m_EventMgr->m_KeyFilterList[i].clear();
        for(size_t i = 0;i < m_LocalFilterList.size(); ++i)
        {
            m_EventMgr->m_KeyFilterList[ (int)m_LocalFilterList[i]->GetKey() ].push_back(m_LocalFilterList[i]);
            m_LocalFilterList[i]->Reference();
        }

        //delete all flt which is not referenced anymore
        for(size_t i = 0;i < m_EventMgr->m_FilterList.size(); ++i)
            m_EventMgr->m_FilterList[i]->Dereference();

        //Copy list
        m_EventMgr->m_FilterList = m_LocalFilterList;
    }
    m_EventMgr->Unlock();

    m_EventMgr->StartFilter();
}

void FilterDialog::closeEvent(QCloseEvent *e)
{
    //refill the event list...

    e->ignore();
    hide();

    if(m_bModified)
    {
        ui->pushButton_apply->click();
    }
}

void FilterDialog::showEvent(QShowEvent *e)
{
    UNREFERENCED_PARAMETER(e);

    m_bModified = false;
    ui->pushButton_apply->setEnabled(false);

    //Synchronize the local list from eventmgr's list

    m_model_Filter->removeRows(0, m_model_Filter->rowCount());
    m_EventMgr->Lock();
    for(size_t i = 0;i < m_EventMgr->m_FilterList.size(); ++i)
    {
        m_model_Filter->appendRow(m_EventMgr->m_FilterList[i]);
    }
    m_EventMgr->Unlock();
}
