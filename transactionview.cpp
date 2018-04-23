#include <QDateTime>

#include "transactionview.h"
#include "ui_transactionview.h"
#include "format.h"

#include <QJsonObject>
#include <QJsonDocument>

TransactionView::TransactionView(QWidget *parent, const QString& txJson) :
    QDialog(parent),
    ui(new Ui::transactionview)
{
// prepare txJsonHumanView and txJsonRawView
    QByteArray arrTx;
    arrTx.append(txJson);
    QJsonDocument TxRec(QJsonDocument::fromJson(arrTx));
    QJsonObject Tx(TxRec.object());
    Tx.insert("Amount", Amount(Tx["Amount"].toString().toLongLong()));
    Tx.insert("Fee", Amount(Tx["Fee"].toString().toLongLong()));
    Tx.insert("date", timeFormat(Tx["date"].toDouble()));
    if (static_cast<uint32_t>(Tx["Flags"].toDouble()) == 0x80000000u)
        Tx.insert("Flags", "tfFullyCanonicalSig");
    else Tx.insert("Flags", "todo: fix output");
    TxRec.setObject(Tx);
    txJsonHumanView = TxRec.toJson(QJsonDocument::Indented);
    txJsonRawView = txJson;
// setup gui
    ui->setupUi(this);
    ui->txBrowser->setText(txJson);
}

TransactionView::~TransactionView()
{
    delete ui;
}

void TransactionView::on_changeViewButton_clicked()
{
    if (isHumanView != true){
        ui->txBrowser->setText(txJsonHumanView);
        ui->changeViewButton->setText("Raw View");
        isHumanView = true;
        }
    else {
        ui->txBrowser->setText(txJsonRawView);
        ui->changeViewButton->setText("Human View");
        isHumanView = false;
        }
}
