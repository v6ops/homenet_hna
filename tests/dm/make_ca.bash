#!/bin/bash
if [ $# -ne 1 ]
then
  echo "The script needs a passphrase for the secret key as the first arg"
  exit
fi

echo "Generating CA Root key homenetdnsCA.key using secret " $1 
PASSWD=$1
/usr/bin/openssl genrsa -passout pass:$PASSWD -aes256 -out homenetdnsCA.key 2048

echo "Generating CA Root Certificate"
openssl req -x509 -new -config ./openssl.conf -key homenetdnsCA.key -passin pass:$PASSWD -passout pass:$PASSWD -sha256 -days 3650 -out homenetdnsCA.pem

