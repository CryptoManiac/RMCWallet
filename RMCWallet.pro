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

# You can also make your code fail to compile if you use deprecated APIs.
# In order to do so, uncomment the following line.
# You can also select to disable deprecated APIs only up to a certain version of Qt.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

CONFIG += strict_c++
CONFIG -= c++11
CONFIG += c++14

#QMAKE_CXXFLAGS = -std=c++14

unix {
    INCLUDEPATH += ../rmc-libpp/extras/rmcd/src

    INCLUDEPATH += /usr/local/Cellar/openssl/1.0.2n/include/
    INCLUDEPATH += /usr/local/Cellar/boost/1.66.0/include/

    LIBS += -L../rmc-libpp/build/src/unity -lrmclibpp
    LIBS += -L/usr/local/Cellar/openssl/1.0.2n/lib/ -lssl -lcrypto
    LIBS += -L/usr/local/Cellar/boost/1.66.0/lib \
            \
            -lboost_chrono-mt \
            -lboost_coroutine-mt \
            -lboost_context-mt \
            -lboost_date_time-mt \
            -lboost_filesystem-mt \
            -lboost_program_options-mt \
            -lboost_regex-mt \
            -lboost_system-mt \
            -lboost_thread-mt \
            -lboost_serialization-mt
}

win32 {
    contains(QT_ARCH, i386) {
        INCLUDEPATH += C:\MyProjects32\deps\rmclibpp-static\include

        INCLUDEPATH += C:\MyProjects32\deps\openssl-static\include
        INCLUDEPATH += C:\MyProjects32\deps\boost-static\include

        LIBS += -LC:\MyProjects32\deps\rmclibpp-static\lib -lrmclibpp
        LIBS += -LC:\MyProjects32\deps\openssl-static\lib -llibeay32 -lssleay32 -llegacy_stdio_definitions -ladvapi32 -lgdi32
        LIBS += -LC:\MyProjects32\deps\boost-static\lib \
                \
                -llibboost_chrono-vc141-mt-s-x32-1_66 \
                -llibboost_coroutine-vc141-mt-s-x32-1_66 \
                -llibboost_context-vc141-mt-s-x32-1_66 \
                -llibboost_date_time-vc141-mt-s-x32-1_66 \
                -llibboost_filesystem-vc141-mt-s-x32-1_66 \
                -llibboost_program_options-vc141-mt-s-x32-1_66 \
                -llibboost_regex-vc141-mt-s-x32-1_66 \
                -llibboost_system-vc141-mt-s-x32-1_66 \
                -llibboost_thread-vc141-mt-s-x32-1_66 \
                -llibboost_serialization-vc141-mt-s-x32-1_66
    } else {
        INCLUDEPATH += C:\MyProjects\deps\rmclibpp-static\include

        INCLUDEPATH += C:\MyProjects\deps\openssl-static\include
        INCLUDEPATH += C:\MyProjects\deps\boost-static\include

        LIBS += -LC:\MyProjects\deps\rmclibpp-static\lib -lrmclibpp
        LIBS += -LC:\MyProjects\deps\openssl-static\lib -llibeay32 -lssleay32 -llegacy_stdio_definitions -ladvapi32 -lgdi32
        LIBS += -LC:\MyProjects\deps\boost-static\lib \
                \
                -llibboost_chrono-vc141-mt-s-x64-1_66 \
                -llibboost_coroutine-vc141-mt-s-x64-1_66 \
                -llibboost_context-vc141-mt-s-x64-1_66 \
                -llibboost_date_time-vc141-mt-s-x64-1_66 \
                -llibboost_filesystem-vc141-mt-s-x64-1_66 \
                -llibboost_program_options-vc141-mt-s-x64-1_66 \
                -llibboost_regex-vc141-mt-s-x64-1_66 \
                -llibboost_system-vc141-mt-s-x64-1_66 \
                -llibboost_thread-vc141-mt-s-x64-1_66 \
                -llibboost_serialization-vc141-mt-s-x64-1_66
    }
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
    switchaccount.cpp

HEADERS += walletmain.h \
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
    switchaccount.h


FORMS += walletmain.ui \
    transactionpreview.ui \
    importdialog.ui \
    enterpassword.ui \
    transactionview.ui \
    aboutdialog.ui \
    switchaccount.ui

macx:ICON = RMC.icns
win32:RC_ICONS += RMC.ico

RESOURCES += \
    resources.qrc

