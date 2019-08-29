#!/bin/bash
if [ $# -ne 1 ]
then
  echo "The script needs a zone name as the first arg e.g. reytt4.homenetdns.com"
  exit
fi

if [ -z $1 ]
then
  echo "The script needs a zone name as the first arg e.g. reytt4.homenetdns.com"
  exit
fi
ZONE=$1

PASSWD=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)

# echo "Generating zone key zone key " $ZONE".key with password $PASSWD" 
#/usr/bin/openssl genrsa -passout pass:$PASSWD -aes256 -out $ZONE.key 2048
echo "Generating zone key zone key " $ZONE".key without password" 
/usr/bin/openssl genrsa -out $ZONE.key 2048
PRE="/CN="
POST=""
SUBJECT="$PRE$ZONE$POST"
echo "Common Name is " $SUBJECT

# echo "Generating Certificate Signing Request for $ZONE"
# openssl req -new -config ./openssl.conf -key $ZONE.key -passin pass:$PASSWD -passout pass:$PASSWD -sha256 -out $ZONE.csr -subj $SUBJECT
echo "Generating Certificate Signing Request for $ZONE"
openssl req -new -config ./openssl.conf -key $ZONE.key -passout pass:$PASSWD -sha256 -out $ZONE.csr -subj $SUBJECT
#openssl req -new -config ./openssl.conf -newkey rsa:2048 -keyout -sha256 -days 1825 -out $ZONE.csr -subj $SUBJECT

echo "Signing Request for $ZONE"
openssl x509 -req -in $ZONE.csr -CA homenetdnsCA.pem -CAkey homenetdnsCA.key -CAcreateserial \
       	 -sha256 -days 1825 -outform PEM -out $ZONE.pem
