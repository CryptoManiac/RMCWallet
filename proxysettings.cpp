#include "proxysettings.h"
#include "ui_proxysettings.h"

#include <QNetworkProxy>

QNetworkProxy proxy;

ProxySettings::ProxySettings(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::ProxySettings)
{
    ui->setupUi(this);
    proxy = QNetworkProxy::applicationProxy();
    if (proxy.type() == QNetworkProxy::NoProxy) return;
    ui->lineProxyAddress->setText(QString(proxy.hostName()));
    ui->lineProxyPort->setText(QString::number(proxy.port()));
    if (proxy.type() == QNetworkProxy::Socks5Proxy)
        {
        ui->comboProxyType->setCurrentIndex(1);
        return;
        }
    if (proxy.type() == QNetworkProxy::HttpProxy)
        {
        ui->comboProxyType->setCurrentIndex(2);
        return;
        }
}

ProxySettings::~ProxySettings()
{
    delete ui;
}

void ProxySettings::updateProxy()
{
    if (ui->lineProxyAddress->text() == "0.0.0.0" || ui->comboProxyType->currentText() == "NoProxy")
    {
        QNetworkProxy::setApplicationProxy(QNetworkProxy::NoProxy);
        return;
    }
    // See comboProxyType list
    switch (ui->comboProxyType->currentIndex())
    {
    case 1: proxy.setType(QNetworkProxy::Socks5Proxy);
        break;
    case 2: proxy.setType(QNetworkProxy::HttpProxy);
        break;
    default: {}; // 0 NoProxy
    }
    proxy.setHostName(ui->lineProxyAddress->text());
    proxy.setPort(ui->lineProxyPort->text().toUShort());
    QNetworkProxy::setApplicationProxy(proxy);
}
