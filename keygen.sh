#!/bin/bash


KS_NAME=$PWD/app/src/main/res/raw/extracas/ks.pem

openssl genrsa 2048 > $KS_NAME
echo 'AR
All world
Yerevan
Small HTTP server
VPN
Small HTTP VPN



' | openssl req -nodes -x509 -new -key $KS_NAME -days 3650 >> $KS_NAME

