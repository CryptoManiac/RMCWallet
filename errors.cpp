#include "errors.h"
#include <QMessageBox>
#include <tuple>

void Show(const Error& err)
{
    ErrorType errT;
    QString errCap, errStr;
    std::tie(errT, errCap, errStr) = err;
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

void Show(const QString& caption, const QString& message, ErrorType errT)
{
    QMessageBox messageBox;
    if (errT == E_INFO)
        messageBox.information(nullptr, caption, message);
    if (errT == E_WARN)
        messageBox.warning(nullptr, caption, message);
    if (errT == E_FATAL)
        messageBox.critical(nullptr, caption, message);
    messageBox.setFixedSize(500, 200);
}
