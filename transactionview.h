#ifndef TRANSACTIONVIEW_H
#define TRANSACTIONVIEW_H

#include <QDialog>

namespace Ui {
class transactionview;
}

class TransactionView : public QDialog
{
    Q_OBJECT

public:
    explicit TransactionView(QWidget *parent = nullptr, const QString& txJson = "");
    ~TransactionView();

private:
    Ui::transactionview *ui;
};

#endif // TRANSACTIONVIEW_H
