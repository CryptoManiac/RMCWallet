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

extern Error eNone;
extern Error eNoneCallReqHandlers;
extern Error eNoPassword;
extern Error eNoWif;

void Show(const QString& psCaption, const QString& psMsg, const ErrorType&);
void Show(const Error& peErr);

#endif // ERRORS_H
