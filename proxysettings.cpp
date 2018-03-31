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
}

ProxySettings::~ProxySettings()
{
    delete ui;
}

void ProxySettings::updateProxy()
{
    if (ui->lineProxyAddress->text() == "0.0.0.0")
    {
        QNetworkProxy::setApplicationProxy(QNetworkProxy::NoProxy);
        return;
    }
    proxy.setType(QNetworkProxy::Socks5Proxy);
    proxy.setHostName(ui->lineProxyAddress->text());
    proxy.setPort(ui->lineProxyPort->text().toShort());
    QNetworkProxy::setApplicationProxy(proxy);
}
