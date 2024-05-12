/** Routines to shim between a transport stream (over TLS)
 *  and the dm_worker that processes DNS packets.
 *
 *  The TLS transport stream may deliver DNS wire packets inconsistently
 *  so these have to be buffered before being dispatched to the dm_worker.
 *  The DNS wire packet is encoded as in RFC7858.
 *
 *  The results from the dm_worker is a raw wire DNS packet that
 *  is then encoded in dnsovertls format, before being queued and
 *  encrypted over the TLS session.
 *
 *     (c) Ray Hunter <v6ops@globis.net> April 2024
 * 
 */
#include "dnsovertls.h"

// clear the dns over tls status to be ready for the next query packet
void dnsovertls_reset(struct ssl_client *p_ssl_client)
{
  if (p_ssl_client!=NULL) {
    p_ssl_client->status=DNSOVERTLS_WAITING_LEN1;
    p_ssl_client->expected_octets=0;
    p_ssl_client->len1=0;
    p_ssl_client->len2=0;
        if (p_ssl_client->query != NULL) {
        free(p_ssl_client->query);
        p_ssl_client->query = NULL;
    }
  }
}


/* write wire packet back to SSL. Format is per RFC7858 */
int dnsovertls_write (struct ssl_client *p_ssl_client, char *response, size_t response_len) {
  printf("Sending packet length %i\n",(int)response_len);

  unsigned int temp=(unsigned int)response_len;
  char len2=(char) (temp & 0xff);
  char len1=(char) (temp>>8 & 0xff) ;
  printf("Sending packet length %u %02x %02x\n",(int)temp,len1,len2);
  // This just queues asynch to ssl encrypt_buffer so no harm in 3 calls.
  // encryption and sending happen later in one call.
  send_unencrypted_bytes(p_ssl_client, &len1, sizeof(len1));
  send_unencrypted_bytes(p_ssl_client, &len2, sizeof(len2));
  send_unencrypted_bytes(p_ssl_client, response, response_len);
  return response_len;
}

/* The input is a stream and it's unpredictable whether a single
 * whole DNS packet will arrive at once over SSL so we have to re-buffer
 * and convert to a stand alone DNS packet for later processing.
 * A great example of buffer bloat.
 * The inbound buffer is fixed length, so we have to consume the entire
 * content before returning. That may be more than one request */
void dnsovertls_read (struct ssl_client *p_ssl_client, char *buf, size_t octets_available) {
  size_t octets_read=0;      // number of octets actually read from this buf
  int i=0; // loop counter for while for too long packet or parse errors

   /* There is no way to recover from an error
   * so just pretend we've read the data      */
  if (octets_available==0 || p_ssl_client->status==DNSOVERTLS_ERROR) {
    return;
  }

  printf("client [%d] status %i octets available %i\n", p_ssl_client->fd,(int)p_ssl_client->status, (int)octets_available);
  if (p_ssl_client->status<1 || p_ssl_client->status>5) {
    printf("client [%d] Unexpected dnsovertls status %i",p_ssl_client->fd,(int)p_ssl_client->status);
    p_ssl_client->status=DNSOVERTLS_ERROR;
    return;
  }

  while (octets_available > 0) {

    i++;
    if (i>100000) {
      p_ssl_client->status=DNSOVERTLS_ERROR;
      printf("dnsovertls packet parse error\n");
      return;
    }

    // waiting 1st char of DNS over SSL = msb length
    if (octets_available>0 && p_ssl_client->status==DNSOVERTLS_WAITING_LEN1) {
      p_ssl_client->len1=(unsigned char)buf[octets_read];
      octets_read++;
      octets_available--;
      p_ssl_client->status=DNSOVERTLS_WAITING_LEN2;
      printf("Received %zu octet. Set len1 to %d.\n",octets_read,(int)p_ssl_client->len1);
    }
    // waiting 2nd char of DNS over SSL = lsb length
    if (octets_available>0 && p_ssl_client->status==DNSOVERTLS_WAITING_LEN2) {
      p_ssl_client->len2=(unsigned char)buf[octets_read];
      octets_read++;
      octets_available--;

      // set up a query buffer now we know the expected length
      p_ssl_client->expected_octets= p_ssl_client->len1 <<8;
      p_ssl_client->expected_octets+= p_ssl_client->len2;
      printf("Set expected_octets %zu len1 %d len2 %d.\n",p_ssl_client->expected_octets,(int)p_ssl_client->len1,(int)p_ssl_client->len2);

      p_ssl_client->query_len=0;
      p_ssl_client->status=DNSOVERTLS_WAITING_QUERY;

      // Create a packet buffer for the inbound request.
      // uses realloc as it's in a loop.
      char *p_tmp;
      p_tmp=(char *)realloc(p_ssl_client->query, p_ssl_client->expected_octets);
      if (p_tmp == NULL){
        die ("Failed to allocate space for p_ssl_client->query query packet\n");
      }
      p_ssl_client->query=p_tmp;
      memset(p_ssl_client->query, 0, p_ssl_client->expected_octets);
    }

    // Read as many expected octets as needed to complete the query
    if (octets_available>0 && p_ssl_client->status==DNSOVERTLS_WAITING_QUERY) {
      size_t octets_to_copy;
      size_t octets_needed;
      // Are there more available than needed? Then only copy needed.
      // Otherwise copy what is available.
      octets_needed=p_ssl_client->expected_octets-p_ssl_client->query_len;
      octets_to_copy =(octets_needed<octets_available ? octets_needed : octets_available);
      memcpy(p_ssl_client->query+p_ssl_client->query_len, buf+octets_read, octets_to_copy);
      octets_read+=octets_to_copy;
      p_ssl_client->query_len+=octets_to_copy;
      octets_available-=octets_to_copy;

      printf("query_len %zu Expected %zu Read %zu left over %zu.\n",p_ssl_client->query_len,p_ssl_client->expected_octets,octets_read,octets_available);
    } //read all

    // Do we have a query ready for dispatch?
    if (p_ssl_client->status==DNSOVERTLS_WAITING_QUERY && p_ssl_client->expected_octets==p_ssl_client->query_len) {
      printf("Query ready for dispatch\n");
      p_ssl_client->status=DNSOVERTLS_PROCESS_QUERY;

      // Check the transport callback is set. Could be done elsewhere.
      //if (p_ssl_client->packet_write == NULL) {
      //  p_ssl_client->packet_write=dnsovertls_write;   //  callback to send a packet
      //}

      /* Dispatch this query to the DM worker.
       * At the moment there is only a single worker per client.
       * That seems sensible given that DNS operations can also write
       * and change the state of the zone for future queries.         */
      dm_worker(p_ssl_client);
      // The dm_worker queues any repsonse packet before returning.
 
      // Reset the query for the next query in the stream.
      // Assuming that there is one.

      dnsovertls_reset(p_ssl_client);
    } //dispatch
    printf("Status %i\n", (int)p_ssl_client->status);
  } // while
} 
