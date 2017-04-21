#ifndef FILTERLOADINGDIALOG_H
#define FILTERLOADINGDIALOG_H

#include <QDialog>
#include <QCloseEvent>
#include "EventMgr.h"

namespace Ui {
class FilterLoadingDialog;
}

class FilterLoadingDialog : public QDialog
{
    Q_OBJECT

public:
    explicit FilterLoadingDialog(QWidget *parent = 0);
    ~FilterLoadingDialog();
    void closeEvent(QCloseEvent *e);
private slots:
    void OnFilterUpdatePercent(size_t curEvent, size_t totalEvents);

private:
    Ui::FilterLoadingDialog *ui;
};

#endif // FILTERLOADINGDIALOG_H
