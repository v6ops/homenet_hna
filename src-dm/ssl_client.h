#ifndef SSL_CLIENT_INCLUDED
#define SSL_CLIENT_INCLUDED

#include <stdio.h>
#include <stdlib.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>

#define DNSOVERTLS_WAITING_LEN1 1
#define DNSOVERTLS_WAITING_LEN2 2
#define DNSOVERTLS_WAITING_QUERY 3
#define DNSOVERTLS_PROCESS_QUERY 4
#define DNSOVERTLS_ERROR 5

/**
 * Struct to carry around SSL connection (client)-specific data.
 * Kept separate from libevent client as combines 2 different libraries
 */

/* An instance of this object is created each time a client connection is
 * accepted. It stores the client file descriptor, the SSL objects, and data
 * which is waiting to be either written to socket or encrypted. */

struct ssl_client
{
  int fd;

  SSL *ssl;

  BIO *rbio; /* SSL reads from, we write to. */
  BIO *wbio; /* SSL writes to, we read from. */

  /* Bytes waiting to be written to socket. This is data that has been generated
   * by the SSL object, either due to encryption of user input, or, writes
   * requires due to peer-requested SSL renegotiation. */
  char* write_buf;
  size_t write_len;

  /* Bytes waiting to be encrypted by the SSL object. */
  char* encrypt_buf;
  size_t encrypt_len;

  /* Store the previous state string */
  const char * last_state;

  /* Method to invoke when unencrypted bytes are available. */
  // note difference (passes whole struct,rather than just buf)
  // void (*io_on_read)(char *buf, size_t len);
  void (*io_on_read)(struct ssl_client *p, char *buf, size_t len);

  // The number of times called (future rate limiting)
  int cb_read_count ;

  /* The callback to send data to this client.        */
  /* expects a dns reply packet in wire format        */
  int (*packet_write)(struct ssl_client *p_ssl_client, char *response, size_t response_len);

  /* the query packet in wire format */
  char *query;

  // for libevent
  /* The bufferedevent for this client. */
  struct bufferevent *bev;

// for dns over tls
    /* The status of the DNS over SSL stream for this client. */
    int status;

    /* The expected number of octets in this query */
    //unsigned int expected_octets;
    size_t expected_octets;

    /* The 1st octet of the length field (rfc7858 rfc1035) */
    unsigned char len1;

    /* The 2nd octet of the length field. SHOULD be sent with len1 but not guar
anteed */
    unsigned char len2;

    /* The received number of octets in this query (1 DNS query can span multip
le SSL packets)*/
    //unsigned int query_len;
    size_t query_len;


} ;

#endif // SSL_CLIENT_INCLUDED
