#!/bin/bash
if [ $# -ne 1 ]
then
  echo "The script needs a dm name as the first arg e.g. dm1.homenetdns.com"
  exit
fi

if [ -z $1 ]
then
  echo "The script needs a dm name as the first arg e.g. dm1.homenetdns.com"
  exit
fi
SERVER=$1

PASSWD=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)

echo "Generating server key " $SERVER".key without password" 
/usr/bin/openssl genrsa -out $SERVER.key 2048
PRE="/CN="
POST=""
SUBJECT="$PRE$SERVER$POST"
echo "Common Name is " $SUBJECT

echo "Generating Certificate Signing Request for $SERVER"
openssl req -new -config ./openssl.conf -key $SERVER.key -passout pass:$PASSWD -sha256 -out $SERVER.csr -subj $SUBJECT

echo "Signing Request for $SERVER"
openssl x509 -req -in $SERVER.csr -CA homenetdnsCA.pem -CAkey homenetdnsCA.key -CAcreateserial \
       	 -sha256 -days 1825 -outform PEM -out $SERVER.pem

cat $SERVER.pem homenetdnsCA.pem >fullchain.pem
cp $SERVER.key key.pem
