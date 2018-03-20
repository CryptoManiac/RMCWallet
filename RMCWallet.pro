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
DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

CONFIG += strict_c++
CONFIG -= c++11
CONFIG += c++14

#QMAKE_CXXFLAGS = -std=c++14

BOOST_INCLUDE_PATH=../boost_1_66_0/include
BOOST_LIB_PATH=../boost_1_66_0/lib
BOOST_SUFFIX=

OPENSSL_INCLUDE_PATH=
OPENSSL_LIB_PATH=

unix {
    macx {
        # Use Homebrew packages for Mac OS X builds

        BOOST_INCLUDE_PATH += /usr/local/Cellar/boost/1.66.0/include
        BOOST_LIB_PATH = /usr/local/Cellar/boost/1.66.0/lib
        BOOST_SUFFIX=-mt

        OPENSSL_INCLUDE_PATH += /usr/local/Cellar/openssl/1.0.2n/include
        OPENSSL_LIB_PATH = /usr/local/Cellar/openssl/1.0.2n/lib
    }

    INCLUDEPATH += ../rmc-libpp/extras/rmcd/src
    INCLUDEPATH += $$BOOST_INCLUDE_PATH $$OPENSSL_INCLUDE_PATH
    LIBS += -L../rmc-libpp/build/src/unity -lrmclibpp
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
        LIBS += -lrt
    }
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
    switchaccount.cpp \
    errors.cpp

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
    switchaccount.h \
    errors.h \
    secure.h \
    format.h


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

