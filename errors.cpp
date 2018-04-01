#include "errors.h"
#include <QMessageBox>
#include <tuple>

Error eNone = Error(E_NONE, "none", "none");
Error eNoPassword = Error(E_NONE, "password", "password");
Error eNoWif = Error(E_NONE, "wif", "wif");

void Show(const QString& psCaption, const QString& psMsg, const ErrorType& errT)
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

void Show(const Error& peErr)
{
    if (std::get<0>(peErr) == E_NONE) return;
    Show(std::get<1>(peErr), std::get<2>(peErr), std::get<0>(peErr));
}
