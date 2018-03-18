#include "errors.h"
#include <QMessageBox>
#include <tuple>

Error noError = Error(E_NONE, "none", "none");
Error noPassword = Error(E_NONE, "password", "password");
Error noWif = Error(E_NONE, "wif", "wif");

void Show(const Error& peErr)
{
    ErrorType errT;
    QString errCap, errStr;
    std::tie(errT, errCap, errStr) = peErr;
    if (errT == E_NONE) return;

    QMessageBox messageBox;
    if (errT == E_INFO)
        messageBox.information(nullptr, errCap, errStr);
    if (errT == E_WARN)
        messageBox.warning(nullptr, errCap, errStr);
    if (errT == E_FATAL)
        messageBox.critical(nullptr, errCap, errStr);
    messageBox.setFixedSize(500, 200);
}

void Show(const QString& psCaption, const QString& psMsg, ErrorType errT)
{
    QMessageBox messageBox;
    if (errT == E_INFO)
        messageBox.information(nullptr, psCaption, psMsg);
    if (errT == E_WARN)
        messageBox.warning(nullptr, psCaption, psMsg);
    if (errT == E_FATAL)
        messageBox.critical(nullptr, psCaption, psMsg);
    messageBox.setFixedSize(500, 200);
}
