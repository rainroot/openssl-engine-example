#!/bin/sh

OPENSSL_PATH=/usr/local/ssl/

make clean

CC=${CROSS_COMPILE}gcc \
CXX=${CROSS_COMPILE}g++ \
LD=${CROSS_COMPILE}ld \
AR="${CROSS_COMPILE}ar  " \
STRIP=${CROSS_COMPILE}strip \
RANLIB=${CROSS_COMPILE}ranlib \
OPENSSL_INC="-I${OPENSSL_PATH}/include  " \
OPENSSL_LIB="-L${OPENSSL_PATH}/lib -lcrypto -lssl " \
make

cp libopenssl_engine.so ${OPENSSL_PATH}/lib/engines/
