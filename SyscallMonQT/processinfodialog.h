#ifndef PROCESSINFODIALOG_H
#define PROCESSINFODIALOG_H

#include <QDialog>
#include <QPixmap>

class CUniqueProcess;
class CImageFileInfo;
namespace Ui {
class ProcessInfoDialog;
}

class ProcessInfoDialog : public QDialog
{
    Q_OBJECT

public:
    explicit ProcessInfoDialog(QWidget *parent = 0);
    ~ProcessInfoDialog();
    void SetProcess(CUniqueProcess *up);

private:
    Ui::ProcessInfoDialog *ui;
    QPixmap m_IconPixmap;
    QString m_ProcessImagePath;

private slots:
    void OnUpdateImageFileInfoNotify(std::wstring ImagePath, CImageFileInfo *info);
};

#endif // PROCESSINFODIALOG_H
