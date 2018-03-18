#include "txtable.h"
#include <QDebug>
#include <QMouseEvent>
#include <QTableWidget>
#include <QMenu>
#include <QScrollArea>

void TxTable::Init(QWidget *parent) {
    Q_UNUSED(parent);
    setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOn);
    setTabKeyNavigation(false);
    setContextMenuPolicy(Qt::CustomContextMenu);
}

void TxTable::mouseDoubleClickEvent(QMouseEvent *event)
{
    auto button = event->button();
    if (button == Qt::MouseButton::LeftButton)
        QTableWidget::mouseDoubleClickEvent(event);
}

