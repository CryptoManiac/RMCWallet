#include "transactionview.h"
#include "ui_transactionview.h"

TransactionView::TransactionView(QWidget *parent, const QString& txJson) :
    QDialog(parent),
    ui(new Ui::transactionview)
{
    ui->setupUi(this);
    ui->txBrowser->setText(txJson);
}

TransactionView::~TransactionView()
{
    delete ui;
}
