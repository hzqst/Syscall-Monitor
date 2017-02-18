#ifndef EVENTINFODIALOG_H
#define EVENTINFODIALOG_H

#include <QDialog>
#include "CallStackTable.h"

class CUniqueImage;
class CUniqueProcess;
class CUniqueModule;

namespace Ui {
class EventInfoDialog;
}

class EventInfoDialog : public QDialog
{
    Q_OBJECT

public:
    explicit EventInfoDialog(QWidget *parent = 0);
    ~EventInfoDialog();

    void SetEventInfo(CUniqueEvent *ev);

private:
    Ui::EventInfoDialog *ui;

    CUniqueEvent *m_Event;

    CCallStackTableModel *m_model_CallStack;

private slots:
    void OnUpdateModuleNotify(CUniqueProcess *up, CUniqueModule *um);
    void OnUpdateImageNotify(CUniqueImage *ui);
    void OnLoadingImageNotify(std::wstring moduleName);
    void OnLoadAllImageCompleteNotify(void);
    void OnClearAllDisplayingEvents(void);
    void OnOpenProcessDialog(void);
};

#endif // EVENTINFODIALOG_H
