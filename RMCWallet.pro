#-------------------------------------------------
#
# Project created by QtCreator 2018-02-19T17:26:33
#
#-------------------------------------------------

QT       += core gui websockets

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = RMCWallet
TEMPLATE = app

# The following define makes your compiler emit warnings if you use
# any feature of Qt which has been marked as deprecated (the exact warnings
# depend on your compiler). Please consult the documentation of the
# deprecated API in order to know how to port your code away from it.
DEFINES += QT_DEPRECATED_WARNINGS

CONFIG += strict_c++
CONFIG -= c++11
CONFIG += c++14

#QMAKE_CXXFLAGS = -std=c++14

BOOST_INCLUDE_PATH=../boost_1_68_0/include
BOOST_LIB_PATH=../boost_1_68_0/lib
BOOST_SUFFIX=

OPENSSL_INCLUDE_PATH=
OPENSSL_LIB_PATH=

unix {
    macx {
        # Use Homebrew packages for Mac OS X builds

        BOOST_INCLUDE_PATH += /usr/local/Cellar/boost/1.68.0/include
        BOOST_LIB_PATH = /usr/local/Cellar/boost/1.68.0/lib
        BOOST_SUFFIX=-mt

        OPENSSL_INCLUDE_PATH += /usr/local/Cellar/openssl/1.0.2q/include
        OPENSSL_LIB_PATH = /usr/local/Cellar/openssl/1.0.2q/lib
    }

    INCLUDEPATH += ../rmc-libpp/extras/rmcd/src
    INCLUDEPATH += $$BOOST_INCLUDE_PATH $$OPENSSL_INCLUDE_PATH
    LIBS += -L../rmc-libpp/build/extras/rmcd -lsecp256k1 -lxrpl_core
    LIBS += $$join(OPENSSL_LIB_PATH,,-L,) -lssl -lcrypto
    LIBS += $$join(BOOST_LIB_PATH,,-L,) \
            \
            -lboost_chrono$$BOOST_SUFFIX \
            -lboost_coroutine$$BOOST_SUFFIX \
            -lboost_context$$BOOST_SUFFIX \
            -lboost_date_time$$BOOST_SUFFIX \
            -lboost_filesystem$$BOOST_SUFFIX \
            -lboost_program_options$$BOOST_SUFFIX \
            -lboost_regex$$BOOST_SUFFIX \
            -lboost_system$$BOOST_SUFFIX \
            -lboost_thread$$BOOST_SUFFIX \
            -lboost_serialization$$BOOST_SUFFIX

    linux {
        # Linuxism
        LIBS += -lrt -ldl
    }
}

win32 {
        INCLUDEPATH += C:\MyProjects\deps\rmclibpp-static\include

        INCLUDEPATH += C:\MyProjects\deps\openssl-static\include
        INCLUDEPATH += C:\MyProjects\deps\boost-static\include

        LIBS += -LC:\MyProjects\deps\rmclibpp-static\lib -lrmclibpp
        LIBS += -LC:\MyProjects\deps\openssl-static\lib -llibeay32 -lssleay32 -llegacy_stdio_definitions -ladvapi32 -lgdi32
        LIBS += -LC:\MyProjects\deps\boost-static\lib \
                \
                -llibboost_atomic-vc141-mt-s-x64-1_68 \
                -llibboost_chrono-vc141-mt-s-x64-1_68 \
                -llibboost_coroutine-vc141-mt-s-x64-1_68 \
                -llibboost_context-vc141-mt-s-x64-1_68 \
                -llibboost_date_time-vc141-mt-s-x64-1_68 \
                -llibboost_filesystem-vc141-mt-s-x64-1_68 \
                -llibboost_program_options-vc141-mt-s-x64-1_68 \
                -llibboost_regex-vc141-mt-s-x64-1_68 \
                -llibboost_system-vc141-mt-s-x64-1_68 \
                -llibboost_thread-vc141-mt-s-x64-1_68 \
                -llibboost_serialization-vc141-mt-s-x64-1_68
}

SOURCES += \
        walletmain.cpp \
    transactionpreview.cpp \
    importdialog.cpp \
    enterpassword.cpp \
    encryption.cpp \
    transactionview.cpp \
    aboutdialog.cpp \
    txtable.cpp \
    switchaccount.cpp \
    errors.cpp \
    proxysettings.cpp \
    iniworker.cpp \
    keymanagement.cpp

HEADERS += watchdog.h \
    walletmain.h \
    doublevalidator.h \
    transactionpreview.h \
    msgkind.h \
    importdialog.h \
    enterpassword.h \
    encryption.h \
    transactionview.h \
    aboutdialog.h \
    intvalidator.h \
    txtable.h \
    switchaccount.h \
    errors.h \
    secure.h \
    format.h \
    proxysettings.h \
    iniworker.h \
    money.h \
    keymanagement.h

FORMS += walletmain.ui \
    transactionpreview.ui \
    importdialog.ui \
    enterpassword.ui \
    transactionview.ui \
    aboutdialog.ui \
    switchaccount.ui \
    proxysettings.ui

macx:ICON = RMC.icns
win32:RC_ICONS += RMC.ico

RESOURCES += \
    resources.qrc

