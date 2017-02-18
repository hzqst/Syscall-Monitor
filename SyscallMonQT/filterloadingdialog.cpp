#include "filterloadingdialog.h"
#include "ui_filterloadingdialog.h"

FilterLoadingDialog::FilterLoadingDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::FilterLoadingDialog)
{
    ui->setupUi(this);

    ui->progressBar_loading->setMinimum(0);
    ui->progressBar_loading->setMaximum(100);

    Qt::WindowFlags flags=Qt::Dialog;
    flags |=Qt::WindowCloseButtonHint;
    setWindowFlags(flags);

    connect(m_EventMgr, &CEventMgr::FilterUpdatePercent, this, &FilterLoadingDialog::OnFilterUpdatePercent, Qt::QueuedConnection);
}

FilterLoadingDialog::~FilterLoadingDialog()
{
    delete ui;
}

void FilterLoadingDialog::closeEvent(QCloseEvent *e)
{
    e->ignore();
}

void FilterLoadingDialog::OnFilterUpdatePercent(size_t curEvent, size_t totalEvents)
{
    QString str = tr("Filtering %1 / %2.").arg(curEvent).arg(totalEvents);

    ui->label_loading->setText(str);

    ui->progressBar_loading->setMaximum((int)totalEvents);
    ui->progressBar_loading->setValue((int)curEvent);
}
