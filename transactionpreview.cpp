#include <QJsonArray>
#include <QJsonObject>
#include <QJsonDocument>

#include "transactionpreview.h"
#include "ui_transactionpreview.h"

#include "msgkind.h"

TransactionPreview::TransactionPreview(QWidget *parent, const QString& txJson, const QString& txHex) :
    QDialog(parent),
    ui(new Ui::TransactionPreview)
{
    ui->setupUi(this);
    this->txJson = txJson;
    this->txHex = txHex;
    ui->txBrowser->setText(txJson);
}

TransactionPreview::~TransactionPreview()
{
    delete ui;
}

void TransactionPreview::on_switchFormat_clicked()
{
    if (isHex)
    {
        ui->txBrowser->setText(txJson);
        ui->switchFormat->setText("Switch to Hex");
    }
    else
    {
        ui->txBrowser->setText(txHex);
        ui->switchFormat->setText("Switch to JSON");
    }
    isHex = !isHex;
}

