#ifndef FILTERDIALOG_H
#define FILTERDIALOG_H

#include <QDialog>
#include <QShowEvent>
#include <QCloseEvent>
#include "EventFilter.h"
#include "EventMgr.h"
#include "filtertable.h"
#include "filterloadingdialog.h"

namespace Ui {
class FilterDialog;
}

class FilterDialog : public QDialog
{
    Q_OBJECT

public:
    explicit FilterDialog(QWidget *parent = 0);
    ~FilterDialog();
    void showEvent(QShowEvent * e);
    void closeEvent(QCloseEvent *e);

    void HideFilterLoading(void);

private slots:
    void on_comboBox_key_currentIndexChanged(int index);
    void on_pushButton_add_clicked();
    void on_pushButton_remove_clicked();

    void on_pushButton_apply_clicked();

private:
    Ui::FilterDialog *ui;
    CFilterTableModel *m_model_Filter;
    CFilterList m_LocalFilterList;
    bool m_bModified;
    FilterLoadingDialog *m_LoadingDialog;
};

#endif // FILTERDIALOG_H
