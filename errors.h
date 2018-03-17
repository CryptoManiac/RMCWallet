#ifndef ERRORS_H
#define ERRORS_H

#include <QString>

enum ErrorType
{
    E_NONE=-1,
    E_INFO=0,
    E_WARN=1,
    E_FATAL=2
};

typedef std::tuple<ErrorType, QString, QString> Error;

void Show(const Error& err);
void Show(const QString& caption, const QString& message, ErrorType);

#endif // ERRORS_H
