TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt

# pi rootfs includes
INCLUDEPATH += /home/faddistr/raspi/sysroot/usr/include/
INCLUDEPATH += /home/faddistr/raspi/sysroot/usr/include/cjson
INCLUDEPATH += /home/faddistr/raspi/sysroot/usr/lib/gcc/arm-linux-gnueabihf/8/include
INCLUDEPATH += /home/faddistr/raspi/sysroot/usr/include/arm-linux-gnueabihf

target.path = raspi
INSTALLS += target
LIBS += -L/home/faddistr/raspi/sysroot/usr/lib/arm-linux-gnueabihf/ -lusb-1.0 -lcjson -lpthread -lrt -lcurl

SOURCES += \
        main.c \
    starline.c \
 telegram/src/telegram.c \
 telegram/src/telegram_parse.c \
 telegram/src/telegram_utils.c \
 telegram/src/telegram_getter_nix.c \
    telegram/src/telegram_io_hal_nix.c \
    telegram/src/telegram_io.c \
    config.c

HEADERS += \
    starline.h \
   telegram/inc/telegram.h \
   telegram/inc/telegram_getter.h \
   telegram/inc/telegram_io.h \
   telegram/inc/telegram_parse.h \
   telegram/inc/telegram_log.h \
   telegram/inc/telegram_hal.h \
    telegram/inc/telegram_io_hal.h \
    config.h
INCLUDEPATH += telegram/inc
