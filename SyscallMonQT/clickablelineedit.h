#ifndef CLICKABLELINEEDIT_H
#define CLICKABLELINEEDIT_H

#include <QLineEdit>
#include <QMouseEvent>
#include <QPaintEvent>
#include <QPixmap>
#include <QIcon>

class ClickableLineEdit : public QLineEdit
{
    Q_OBJECT
public:
    explicit ClickableLineEdit(QWidget *parent = 0);
    void setIcon(QIcon *icon);
protected:
    //重写mousePressEvent事件
    virtual void mousePressEvent(QMouseEvent *event);
    virtual void paintEvent(QPaintEvent *e);
private:
    QPixmap m_IconPixmap;

signals:
    void click();

public slots:

};

#endif // CLICKABLELINEEDIT_H
