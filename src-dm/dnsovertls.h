#ifndef DNSOVERTLS_INCLUDED
#define DNSOVERTLS_INCLUDED
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <openssl/ssl.h>

#ifndef WITH_SSL // needs SSL specific code
#define WITH_SSL
#endif

#include "util.h" 
#include "dm_worker.h" 

// defined in common.h but need template here
void send_unencrypted_bytes(struct ssl_client *p, const char *buf, size_t len);

/*
typedef enum{
  DNSOVERTLS_WAITING_LEN1,
  DNSOVERTLS_WAITING_LEN2,
  DNSOVERTLS_WAITING_QUERY,
  DNSOVERTLS_PROCESS_QUERY,
  DNSOVERTLS_ERROR
} dnsovertls_status_t;

typedef struct dm_query dm_query_t;

// struct to pass inbound query data to the dm_worker threads(s)
typedef struct dm_query {

  // the inbound query in wire format
  char *query;

  // The received number of octets in this query
   * (1 DNS query can span multiple SSL packets or buffer read calls)
  size_t query_len;

  // The ssl for this dm_query. Used for checking certs versus the query
  struct ssl_dm_query *p_ssl_dm_query;

  // The callback to send data to this dm_query.
  // expects a dns reply packet in wire format
  int (*packet_write)(dm_query_t *p_dm_query, char *response, size_t response_len);

  // The status of the DNS stream for this dm_query.
  dnsovertls_status_t status;

  // The expected number of octets in this query
  size_t expected_octets;

  // The 1st octet of the length field (rfc7858 rfc1035)
  unsigned char len1;

  // The 2nd octet of the length field. SHOULD be sent with len1 but not guaranteed
  unsigned char len2;

} dm_query_t;
*/

// clear the dns over tls status to be ready for the next query packet
void dnsovertls_reset(struct ssl_client *p_ssl_client);

// callback to write to the tls session
int dnsovertls_write (struct ssl_client *p_ssl_client, char *response, size_t response_len);

// callback to read from the tls session
void dnsovertls_read (struct ssl_client *p_ssl_client, char *buf, size_t octets_available);
#endif // DNSOVERTLS_INCLUDED
