#ifndef SYMLOADDIALOG_H
#define SYMLOADDIALOG_H

#include <QDialog>
#include <QCloseEvent>
#include "ModuleMgr.h"

namespace Ui {
class SymLoadDialog;
}

class SymLoadDialog : public QDialog
{
    Q_OBJECT

public:
    explicit SymLoadDialog(QWidget *parent = 0);
    ~SymLoadDialog();
    void closeEvent(QCloseEvent *e);
    void EnumSystemModuleProc(ULONG64 ImageBase, ULONG ImageSize, LPCWSTR szImagePath, int LoadOrderIndex);

private slots:
    void on_pushButton_load_clicked();
    void OnLoadAllImageCompleteNotify(void);
    void OnLoadingImageNotify(std::wstring moduleName);

private:
    Ui::SymLoadDialog *ui;
    bool m_bLoadingSymbol;
};

#endif // SYMLOADDIALOG_H
