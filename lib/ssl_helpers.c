/* homenet ssl_helpers.cpp
  
* Copyright (c) 2019 Ray Hunter

* Permission is hereby granted, free of charge, to any person obtaining
* a copy of this software and associated documentation files (the
* "Software"), to deal in the Software without restriction, including
* without limitation the rights to use, copy, modify, merge, publish,
* distribute, sublicense, and/or sell copies of the Software, and to
* permit persons to whom the Software is furnished to do so, subject to
* the following conditions:

* The above copyright notice and this permission notice shall be
* included in all copies or substantial portions of the Software.

* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
* EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
* MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
* NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
* LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
* OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
* WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*
*/
#include "ssl_helpers.h"

ldns_pkt * ssl_helpers_bio2pkt(BIO *bio) {
  // ldns and wire packets
  ldns_pkt *pkt;
  size_t temp=0;
  ldns_status status;
  unsigned char len1;
  unsigned char len2;
  int response_length=0;
  unsigned char tmpbuf[LDNS_MAX_PACKETLEN];
  char buf[80];

  BIO *out;
  out = BIO_new_fp(stdout, BIO_NOCLOSE);

  BIO_read(bio, &len1, 1);
  BIO_puts(out,"got len1\n");
  BIO_read(bio, &len2, 1);
  BIO_puts(out,"got len2\n");
  response_length= len1 <<8;
  response_length+= len2;
  sprintf(buf, "Reading packet length %u\n",response_length);
  BIO_puts(out, buf);
  BIO_read(bio, tmpbuf, response_length);

  pkt=ldns_pkt_new();
  status = ldns_wire2pkt(&pkt,tmpbuf,response_length);

  if (status != LDNS_STATUS_OK) {
    printf("Got bad packet: %s\n", ldns_get_errorstr_by_id(status));
    ldns_pkt_free(pkt);
    return NULL;
  } else {
    printf("Got good packet length: %i\n", response_length);
    ldns_pkt_print(stdout, pkt);
    return pkt;
  }
}

int ssl_helpers_pkt2bio(ldns_pkt *pkt,BIO *bio) {
  // ldns and wire packets
  uint8_t *wire = NULL;
  size_t wiresize = 0;
  size_t temp=0;
  ldns_status status;
  unsigned char len1;
  unsigned char len2;

  status = ldns_pkt2wire(&wire, pkt, &wiresize);
  if(wiresize == 0) {
    printf("Error converting packet to hex.\n");
    return -1; 
  }

  temp=wiresize;
  len2=(unsigned char) (temp & 0xff);
  len1=(unsigned char) (temp>>8 & 0xff) ;
  printf("length %u %02x %02x\n",(int)temp,len1,len2);
  // this isn't as recommended in RFC 7858 as it uses three separate write calls
  BIO_write(bio,&len1,1);
  BIO_write(bio,&len2,1);
  BIO_write(bio,wire,wiresize);
  BIO_flush(bio);
  return 0;
}


//int ssl_helpers_check_cert_cn(BIO *bio, const char *cn) {
int ssl_helpers_check_cert_cn(SSL *ssl, const char *cn) {
//  SSL *ssl;
  X509 *cert;
  long v;
  char expected_cn[ldns_helpers_max_buffer_size];
  for (int i=0; i<ldns_helpers_max_buffer_size; i++) {expected_cn[i]='\0';}
  strcpy(expected_cn,"/CN=");
  strcat(expected_cn,cn);

//  BIO_get_ssl(bio, &ssl);

  if (ssl) {
    v=SSL_get_verify_result(ssl);
    if (v==X509_V_OK) {
      printf ("ssl_helpers_check_cert_cn: Verify Passed\n");
    } else {
      printf ("ssl_helpers_check_cert_cn: Verify Failed %lu\n",v);
      return -1;
    }
  } else {
    printf ("ssl_helpers_check_cert_cn: No SSL found\n");
    return -1;
  }

  cert=SSL_get_peer_certificate(ssl);
  if (cert) {
    char *subj = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
    printf("Subject %s\n",subj);
    if(strcmp(subj,expected_cn)==0) {
	  printf("ssl_helpers_check_cert_cn: Subjects Match %s %s\n",subj,expected_cn);
	  return 1;
    } else {
	  printf("ssl_helpers_check_cert_cn: Subjects Don't Match %s %s\n",subj,expected_cn);
	  return 0;
    }
  } else {
    printf("ssl_helpers_check_cert_cn: Can't get cert\n");
    return -1;
  }
}
