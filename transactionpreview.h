#ifndef TRANSACTIONPREVIEW_H
#define TRANSACTIONPREVIEW_H

#include <QDialog>
#include <QtWebSockets/QWebSocket>

namespace Ui {
class TransactionPreview;
}

class TransactionPreview : public QDialog
{
    Q_OBJECT

public:
    explicit TransactionPreview(QWidget *parent = 0, const QString& txJson = "", const QString& txHex = "");
    ~TransactionPreview();

private slots:
    void on_switchFormat_clicked();

private:
    Ui::TransactionPreview *ui;
    QString txJson;
    QString txHex;

    bool isHex = false;
};

#endif // TRANSACTIONPREVIEW_H
