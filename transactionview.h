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

private Q_SLOTS:

    void on_changeViewButton_clicked();

private:
    Ui::transactionview *ui;

    QString txJsonHumanView;
    QString txJsonRawView;
    bool isHumanView = false;
};

#endif // TRANSACTIONVIEW_H
