#include "processinfodialog.h"
#include "ui_processinfodialog.h"
#include <QDateTime>
#include "ProcessMgr.h"
#include "util.h"
#include "nt.h"

ProcessInfoDialog::ProcessInfoDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::ProcessInfoDialog)
{
    ui->setupUi(this);

    connect(m_ModuleMgr, &CModuleMgr::UpdateImageFileInfoNotify, this, &ProcessInfoDialog::OnUpdateImageFileInfoNotify);

    setAttribute(Qt::WA_DeleteOnClose);

    Qt::WindowFlags flags=Qt::Dialog;
    flags |=Qt::WindowCloseButtonHint;
    setWindowFlags(flags);
}

ProcessInfoDialog::~ProcessInfoDialog()
{
    delete ui;
}

void ProcessInfoDialog::OnUpdateImageFileInfoNotify(std::wstring ImagePath, CImageFileInfo *info)
{
    QString qImagePath = QString::fromStdWString(ImagePath);
    if(m_ProcessImagePath == qImagePath){
        ui->lineEdit_CompanyName->setText(info->companyName);
        ui->lineEdit_FileDesc->setText(info->fileDesc);
        ui->lineEdit_Copyright->setText(info->copyRights);
        ui->lineEdit_ProductVersion->setText(info->productVer);
        ui->lineEdit_ProductName->setText(info->productName);
        ui->lineEdit_FileSize->setText(FormatFileSizeString(info->fileSize));
        ui->lineEdit_ProductVersion->setText(QString("%1.%2.%3.%4").arg(info->proVer[0]).arg(info->proVer[1]).arg(info->proVer[2]).arg(info->proVer[3]));
        ui->lineEdit_FileVersion->setText(QString("%1.%2.%3.%4").arg(info->fileVer[0]).arg(info->fileVer[1]).arg(info->fileVer[2]).arg(info->fileVer[3]));
    }
}

void ProcessInfoDialog::SetProcess(CUniqueProcess *up)
{
    m_ProcessImagePath = up->m_ImagePath;

    ui->lineEdit_FileName->setText(up->m_ProcessName);
    ui->textEdit_ImagePath->setText(up->m_ImagePath);
    ui->textEdit_CommandLine->setText(up->m_CommandLine);
    ui->lineEdit_CurrentDirectory->setText(up->m_CurDirectory);
    ui->lineEdit_Arch->setText((up->m_bIs64Bit) ? QObject::tr("x64") : QObject::tr("x86"));

    QDateTime date;
    date.setTime_t(FileTimeToUnixTime((FILETIME *)&up->m_CreateTime));

    QString dateStr = date.toString("yyyy-MM-dd HH:mm:ss");
    ui->lineEdit_CreateTime->setText(dateStr);

    if(up->m_Icon){
        int wh = ui->label_ImageIcon->height();
        m_IconPixmap = up->m_Icon->pixmap(wh).scaled(wh, wh);
        ui->label_ImageIcon->setPixmap(m_IconPixmap);
    }

    ui->lineEdit_SessionId->setText(QString::number(up->m_SessionId));
    ui->lineEdit_Status->setText((up->m_bAlive) ? QObject::tr("Alive") : QObject::tr("Dead"));
    ui->lineEdit_PID->setText(QString::number(up->m_ProcessId));
    if(up->m_pParentProcess){
        ui->lineEdit_ParentProcess->setText(up->m_pParentProcess->GetDisplayNameWithPID());
        if(up->m_pParentProcess->m_Icon)
            ui->lineEdit_ParentProcess->setIcon(up->m_pParentProcess->m_Icon);
    }else{
        ui->lineEdit_ParentProcess->setText(tr("#%1 <Non-existent Process>").arg(up->m_ParentProcessId));
    }

    std::wstring imagePath = up->m_ImagePath.toStdWString();
    CImageFileInfo *info = m_ModuleMgr->GetImageFileInfo(imagePath);
    if(info)
        OnUpdateImageFileInfoNotify(imagePath, info);
    else
        m_ModuleMgr->QueuedGetImageFileInfo(imagePath);
}
