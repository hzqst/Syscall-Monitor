#include "ClickableLineEdit.h"
#include <QPainter>

ClickableLineEdit::ClickableLineEdit(QWidget *parent) :
    QLineEdit(parent)
{
}

void ClickableLineEdit::setIcon(QIcon *icon)
{
    m_IconPixmap = icon->pixmap(size().height(), size().height());

    int left, top, right, bot;
    getTextMargins(&left, &top, &right, &bot);
    setTextMargins(size().height() + left - 8, top, right , bot);

    setStyleSheet(styleSheet() + "color:#00f;text-decoration:underline;");
}

void ClickableLineEdit::mousePressEvent(QMouseEvent *event) {
    if (event->button() == Qt::LeftButton) {
         emit click();
    }
    QLineEdit::mousePressEvent(event);
}

void ClickableLineEdit::paintEvent(QPaintEvent *e)
{
    QLineEdit::paintEvent(e);

    QPainter painter(this);
    painter.drawPixmap(0, 0, size().height(), size().height(), m_IconPixmap);
}
