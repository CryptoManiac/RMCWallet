#ifndef TXTABLE_H
#define TXTABLE_H

#include <QTableWidget>
#include <QMenu>

class TxTable : public QTableWidget
{
public:
    explicit TxTable(QWidget *parent = nullptr) : QTableWidget(parent) { Init(parent); }
    TxTable(int rows, int columns, QWidget *parent = nullptr) : QTableWidget(rows, columns, parent) { Init(parent); }

private:
    void Init(QWidget *parent);

protected:
    void mouseDoubleClickEvent(QMouseEvent *event);
};

#endif // TXTABLE_H
