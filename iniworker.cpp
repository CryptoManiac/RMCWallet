#include "iniworker.h"

#include <QJsonArray>
#include <QJsonObject>
#include <QJsonDocument>
#include <QStandardPaths>
#include <QDir>
#include <QNetworkProxy>

CIniworker::CIniworker()
{
    iniFile.setFileName(QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation) + QDir::separator() + "RMCSettings.json");
    iniFile.open(QIODevice::ReadWrite | QIODevice::Text);
    if (iniFile.size() == 0)
    {
        Write(CIniworker::W_DUMMY);
    }
}

CIniworker::~CIniworker()
{
    iniFile.close();
}

void CIniworker::Write(const CIniworker::JobType& action)
{
    iniFile.seek(0);
    QByteArray iniData = iniFile.readAll();
    QJsonDocument iniDoc(QJsonDocument::fromJson(iniData));
    QJsonObject iniObjects(iniDoc.object());
    switch (action)
    {
    case CIniworker::W_PROXY:
    {
        QNetworkProxy proxy = QNetworkProxy::applicationProxy();
        QJsonObject proxyObj
        {
            { "proxyType", proxy.type() },
            { "proxyAddress", proxy.hostName() },
            { "proxyPort", proxy.port() }
        };
        iniObjects.insert("Proxy", proxyObj);
        auto walletSettings = QJsonDocument (iniObjects).toJson();
        iniFile.resize(0);
        iniFile.write(walletSettings, walletSettings.size());
        iniFile.seek(0);
        break;
    }
    case CIniworker::W_DUMMY:
    {
        iniObjects.insert("Dummy", 0);
        auto walletSettings = QJsonDocument (iniObjects).toJson();
        iniFile.write(walletSettings, walletSettings.size());
        iniFile.seek(0);
        break;
    }
    default: {};
    }
}

void CIniworker::Read(const CIniworker::JobType &action)
{
    iniFile.seek(0);
    QByteArray iniData = iniFile.readAll();
    QJsonDocument iniDoc(QJsonDocument::fromJson(iniData));
    QJsonObject iniObjects(iniDoc.object());
    if ( action == CIniworker::R_PROXY)
    {
        if ( iniObjects.contains("Proxy") && iniObjects["Proxy"].isObject() )
        {
            QNetworkProxy proxy = QNetworkProxy::applicationProxy();
            QJsonObject proxyObj(iniObjects["Proxy"].toObject());
            proxy.setType(static_cast<QNetworkProxy::ProxyType>(proxyObj["proxyType"].toInt()));
            proxy.setHostName(proxyObj["proxyAddress"].toString());
            proxy.setPort(static_cast<qint16>(proxyObj["proxyPort"].toInt()));
            QNetworkProxy::setApplicationProxy(proxy);
        };
    }
}
