TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lpcap

SOURCES += \
        ethhdr.cpp \
        ip.cpp \
        iphdr.cpp \
        mac.cpp \
        main.cpp \
        tcphdr.cpp

HEADERS += \
    ethhdr.h \
    ip.h \
    iphdr.h \
    mac.h \
    tcphdr.h
