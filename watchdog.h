#ifndef WATCHDOG_H
#define WATCHDOG_H

#include <QtGlobal>

#if (QT_VERSION < QT_VERSION_CHECK(5, 9, 4))
#    error "Use at least Qt 5.9.4 version"
#endif
#ifdef QT_NO_SSL
#    error "SSL support is required"
#endif

#endif // WATCHDOG_H
