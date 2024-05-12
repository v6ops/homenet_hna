/* libevent_dm

* Copyright (c) 2020 Ray Hunter

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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <err.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include <event.h>
#include <event2/listener.h>
#include <event2/bufferevent_ssl.h>

#include "client.h"
#include "util.h"
#include "ssl_client.h"
#include "dm_worker.h"
#include "../lib/ssl_session.h"

//#include "homenet_dm.h"

/* Number of worker threads.  Should match number of CPU cores reported in /proc/cpuinfo. */
#define NUM_THREADS 1

// Global to hold the accept base event (for kill_server)
static struct event_base *evbase_accept;

// Global to hold the work queue thread status
static workqueue_t workqueue;

/* Signal handler function (defined below). */
static void sig_handler(int signal);

/*
// Struct to carry around connection (client)-specific data.
typedef struct client {
    // client's SSL CTX
    SSL *ssl;

    // The client's socket.
    int sock;

    // client's address 
    struct sockaddr *sa;

    // client's address length 
    int sa_len;

    // The event_base for this client. 
    struct event_base *evbase;

    // The bufferedevent for this client. 
    struct bufferevent *bev;

    // Here you can add your own application-specific attributes which
    // are connection-specific. 

    // The status of the DNS over SSL stream for this client. 
    int status;

    // The expected number of octets in this query 
    //unsigned int expected_octets;
    size_t expected_octets;

    // The 1st octet of the length field (rfc7858 rfc1035) 
    unsigned char len1;

    // The 2nd octet of the length field. SHOULD be sent with len1 but not guaranteed 
    unsigned char len2;

    // The received number of octets in this query (1 DNS query can span multiple SSL packets)
    //unsigned int query_len;
    size_t query_len;

    // the query packet in wire format 
    char *query;

} client_t;

#define DNSOVERTLS_WAITING_LEN1 1
#define DNSOVERTLS_WAITING_LEN2 2
#define DNSOVERTLS_WAITING_QUERY 3
*/

void ssl_dnsovertls_reset(struct ssl_client *p_ssl_client) {

    if (p_ssl_client==NULL) return;
    p_ssl_client->status=DNSOVERTLS_WAITING_LEN1;
    p_ssl_client->len1=0;
    p_ssl_client->len2=0;
    p_ssl_client->expected_octets=0;
    if (p_ssl_client->query != NULL) {
        free(p_ssl_client->query);
        p_ssl_client->query = NULL;
    }
}

//int dnsovertls_write(dm_query_t *p_dm_query, char *response, size_t response_len)
int dnsovertls_write(struct ssl_client *p_ssl_client, char *response, size_t response_len)
{
  struct bufferevent *bev = p_ssl_client->bev;
  size_t temp=0;
  unsigned char len1;
  unsigned char len2;
  int result=0;

  temp=response_len;
  len2=(unsigned char) (temp & 0xff);
  len1=(unsigned char) (temp>>8 & 0xff) ;
  printf("Sending packet length %u %02x %02x\n",(int)temp,len1,len2);
  // this isn't as recommended in RFC 7858 as it uses three separate write calls
  result=bufferevent_write(bev,&len1,1);
  // if (result==0) printf ("written %i to buffer\n",(int)len1);
  result=bufferevent_write(bev,&len2,1);
  // if (result==0) printf ("written %i to buffer\n",(int)len2);
  result=bufferevent_write(bev,response,response_len);
  // if (result==0) printf ("written %i to buffer\n",(int)response_len);
  result=bufferevent_flush(bev,EV_WRITE,BEV_FLUSH);
  // if (result==1) printf ("flushed buffer\n");
  return response_len;
}


// echo dns queries and debug
// the input is a stream and it's unpredictable whether a single
// whole DNS packet will arrive at once so we have to re-buffer
// and convert to a stand alone DNS packet for later processing
// the pointer to client struct is passed between callbacks to maintain state
static void
ssl_dnsovertls_echo_readcb(struct bufferevent * bev, void * arg)

{
    size_t octets_available; // number of octets ready to read
    size_t octets_read;      // number of octets actually read in last op

    // get a pointer to the buffer event input stream
    struct evbuffer *in = bufferevent_get_input(bev);
    octets_available=evbuffer_get_length(in);

    // not using a case as more than one item can be triggered per callback
    if (!(octets_available>0)) {
        printf("Received %zu bytes. Doing nothing.\n",octets_available);
        return;
    }

    // get the pointer to the client state information
    // this is probably not good practice but it's a result of mixing C and C++
    // In this code there's no reason for C++ so maybe switch the whole project back to C
    //client_t *client = static_cast<client_t *>(arg);
    client_t *client = arg;
    struct ssl_client *p_ssl_client=client->p_ssl_client;
    //dm_query_t *dm_query; // the user data passed to the worker thread

    /* Working cert checking. Has to be in read cb. Not accept cb*/
/*
    X509* cert = SSL_get_peer_certificate(client->ssl);
    if (cert == NULL) {
        fprintf(stderr,"No cert\n");
    } else if (SSL_get_verify_result(client->ssl) == X509_V_OK) {
        fprintf(stderr,"Cert verified\n");
        X509_NAME* iname = cert ? X509_get_issuer_name(cert) : NULL;
        print_cn_name("Issuer (cn)", iname);
        X509_NAME* sname = cert ? X509_get_subject_name(cert) : NULL;
        print_cn_name("subject (sn)", sname);
    }
*/


    // waiting 1st char of DNS over SSL = msb length
    if (octets_available>0 && p_ssl_client->status==DNSOVERTLS_WAITING_LEN1) {
        octets_read=evbuffer_remove(in,&p_ssl_client->len1,1);
        if (octets_read!=1) {
            printf("Error. Read %zu octets. Expected 1.\n",octets_read);
            return;
        }
        octets_available--;
        p_ssl_client->status=DNSOVERTLS_WAITING_LEN2;
        printf("Received %zu octet. Set len1 to %u.\n",octets_read,(unsigned int)p_ssl_client->len1);
    }
    
    // waiting 2nd char of DNS over SSL = lsb length
    if (octets_available>0 && p_ssl_client->status==DNSOVERTLS_WAITING_LEN2) {
        octets_read=evbuffer_remove(in,&p_ssl_client->len2,1);
        if (octets_read!=1) {
            printf("Error. Read %zu octets. Expected 1.\n",octets_read);
            return;
        }
        octets_available--;

        // set up a query buffer now we know the expected length
        p_ssl_client->expected_octets= p_ssl_client->len1 <<8;
        p_ssl_client->expected_octets+= p_ssl_client->len2;
            printf("Set expected_octets %zu len1 %d len2 %d.\n",p_ssl_client->expected_octets,(int)p_ssl_client->len1,(int)p_ssl_client->len2);
 
        //client->query=(char*) malloc (client->expected_octets);
	char *p_tmp;
	p_tmp=realloc(p_ssl_client->query,p_ssl_client->expected_octets);
        if (p_tmp==NULL) {
            warn ("Failed to allocate space for client query\n");
            return;
        }
	p_ssl_client->query=p_tmp;
        p_ssl_client->query_len=0;
        p_ssl_client->status=DNSOVERTLS_WAITING_QUERY;
        printf("Received %zu octet. Set len2 to %u.\n",octets_read,(unsigned int)p_ssl_client->len2);
    }

    // Read as many expected octets as needed tocomplete the query
    if (octets_available>0 && p_ssl_client->status==DNSOVERTLS_WAITING_QUERY) {
        octets_read=evbuffer_remove(in,&p_ssl_client->query[p_ssl_client->query_len],p_ssl_client->expected_octets-p_ssl_client->query_len);
        if (octets_read<1) {
            printf("Error. Read %zu octets. Expected %zu.\n",octets_read,p_ssl_client->expected_octets-p_ssl_client->query_len);
            return;
        }
        octets_available-=octets_read;
        p_ssl_client->query_len+=octets_read;

        printf("query_len %zu Expected %zu Read %zu left over %zu.\n",p_ssl_client->query_len,p_ssl_client->expected_octets,octets_read,octets_available);
    }

    // do we have a query ready for dispatch?

    if (p_ssl_client->status==DNSOVERTLS_WAITING_QUERY && p_ssl_client->expected_octets==p_ssl_client->query_len) {
        printf("Query ready for dispatch\n");
        /* Create a dm_query object. */
     //   if ((dm_query= (dm_query_t *) malloc(sizeof(*dm_query))) == NULL) {
     //     warn("failed to allocate memory for dm_query state");
     //     return;
     //   }
     //   memset(dm_query, 0, sizeof(*dm_query));

     //   dm_query->bev=client->bev;
     //   dm_query->query=client->query;
     //   dm_query->query_len=client->query_len;
     //   dm_query->ssl=client->ssl;
//	dm_query->packet_write=dnsovertls_write;   //  callback to send a packet
//	set up callback
	p_ssl_client->bev=client->bev;
	p_ssl_client->packet_write=dnsovertls_write; //  callback to send a packet

        //bufferevent_write(bev,client->query,client->query_len);
        //client->query=NULL; // the query memory has to be freed by the worked
        // at the moment process everything in one thread
        // but this prepares us for the future
        //dm_worker(dm_query);
        dm_worker(p_ssl_client);
	//dm_query_free (dm_query); // free up the memory of the inbound query
        ssl_dnsovertls_reset(p_ssl_client);
    }

    printf("Status %i\n", p_ssl_client->status);
    
//    printf("Received %zu bytes\n", evbuffer_get_length(in));
//    printf("----- data ----\n");
//    printf("%.*s\n", (int)evbuffer_get_length(in), evbuffer_pullup(in, -1));

//    bufferevent_write_buffer(bev, in);
}




static void
ssl_readcb(struct bufferevent * bev, void * arg)
{
    struct evbuffer *in = bufferevent_get_input(bev);

    printf("Received %zu bytes\n", evbuffer_get_length(in));
    printf("----- data ----\n");
    printf("%.*s\n", (int)evbuffer_get_length(in), evbuffer_pullup(in, -1));

    bufferevent_write_buffer(bev, in);
}

static void
ssl_acceptcb(struct evconnlistener *serv, int sock, struct sockaddr *sa,
             int sa_len, void *arg)
{
    struct event_base *evbase;
    struct bufferevent *bev;
    SSL_CTX *server_ctx;
    SSL *client_ssl;
    client_t *client;
    struct ssl_client *p_ssl_client;

    /* Create a client object. */
    if ((client = (client_t *) malloc(sizeof(*client))) == NULL) {
        warn("failed to allocate memory for client state");
        //socket is closed by the listener close(sock); 
        return;
    }
	memset(client, 0, sizeof(*client));

    // now the extra SSL portion
   if ((p_ssl_client = (struct ssl_client *) malloc(sizeof(*p_ssl_client))) == NULL) {
        die("failed to allocate memory for SSL client state");
    }
    memset(p_ssl_client, 0, sizeof(*p_ssl_client));

    server_ctx = (SSL_CTX *)arg;
    client_ssl = SSL_new(server_ctx);
    client->ssl=client_ssl; // original ssl in this code
    p_ssl_client->ssl=client_ssl;
    client->p_ssl_client=p_ssl_client; // extra for new struct

    //dnsovertls_reset(client->p_ssl_client);

    client->sock=sock;
    client->sa=sa;
    client->sa_len=sa_len;
    printf ("Before reset\n");
    ssl_dnsovertls_reset(client->p_ssl_client);

    client->evbase = evbase = evconnlistener_get_base(serv);

    client->bev = bev = bufferevent_openssl_socket_new(evbase, sock, client_ssl,
                                         BUFFEREVENT_SSL_ACCEPTING,
                                         BEV_OPT_CLOSE_ON_FREE);

    bufferevent_enable(bev, EV_READ);
    // simple echo
    // bufferevent_setcb(bev, ssl_readcb, NULL, NULL, NULL);
    // dns echo
    bufferevent_setcb(bev, ssl_dnsovertls_echo_readcb, NULL, NULL, client);
}

static SSL_CTX *
evssl_init(void)
{
    SSL_CTX  *server_ctx;

    /* Initialize the OpenSSL library */
    SSL_load_error_strings();
    SSL_library_init();

    /* We MUST have entropy, or else there's no point to crypto. */
    if (!RAND_poll())
        return NULL;

    server_ctx = SSL_CTX_new(SSLv23_server_method());

    if (! SSL_CTX_use_certificate_chain_file(server_ctx, "cert") ||
        ! SSL_CTX_use_PrivateKey_file(server_ctx, "pkey", SSL_FILETYPE_PEM)) {
        puts("Couldn't read 'pkey' or 'cert' file.  To generate a key\n"
           "and self-signed certificate, run:\n"
           "  openssl genrsa -out pkey 2048\n"
           "  openssl req -new -key pkey -out cert.req\n"
           "  openssl x509 -req -days 365 -in cert.req -signkey pkey -out cert");
        return NULL;
    }
    SSL_CTX_set_options(server_ctx, SSL_OP_NO_SSLv2);

    return server_ctx;
}

int run_server(void)
{
    SSL_CTX *ctx;
    struct evconnlistener *listener;
//    struct event_base *evbase;

    struct sockaddr_in6 sin6;
    memset(&sin6, 0, sizeof(sin6));

    // char ipv6_address[40]="2001:470:1f15:62e:d6a1:add0:b140:448";

    sin6.sin6_family = AF_INET6;
    sin6.sin6_flowinfo = 0;
    sin6.sin6_port = htons(443);
    //inet_pton(AF_INET6, ipv6_address, &sin6.sin6_addr);
    sin6.sin6_addr = in6addr_any;

    /* Initialize libevent. */
    event_init();

    /* Initialize the OpenSSL library */
    //ctx = evssl_init();
    //init_openssl();
    //
    ctx = create_server_context();
    configure_server_context(ctx);

    // Set signal handlers
    sigset_t sigset;
    sigemptyset(&sigset);
    struct sigaction siginfo;
        siginfo.sa_handler = sig_handler;
        siginfo.sa_mask = sigset;
        siginfo.sa_flags = SA_RESTART;
    sigaction(SIGINT, &siginfo, NULL);
    sigaction(SIGTERM, &siginfo, NULL);

    /* Initialize work queue. */
    if (workqueue_init(&workqueue, NUM_THREADS)) {
        perror("Failed to create work queue");
        workqueue_shutdown(&workqueue);
        return 1;
    }

    evbase_accept=event_base_new();
    listener = evconnlistener_new_bind(
                         evbase_accept, ssl_acceptcb, (void *)ctx,
                         LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE
#ifdef LEV_OPT_BIND_IPV6ONLY
                         | LEV_OPT_BIND_IPV6ONLY
#endif
                         , -1,
                         (struct sockaddr*) &sin6, sizeof(sin6));
   if (!listener) {
        perror("Couldn't create listener");
        return 1;
    }

    printf("Server running.\n");

    event_base_loop(evbase_accept, 0);

    evconnlistener_free(listener);
    event_base_free(evbase_accept); 
    SSL_CTX_free(ctx);
    /*if (client->p_ssl_client->query != NULL ) {
      free(client->p_ssl_client->query);
      client->p_ssl_client=NULL;
    }
    if (client->p_ssl_client != NULL ) {
      free(client->p_ssl_client);
      client->p_ssl_client=NULL;
    }
    if (client != NULL ) {
      free(client);
      client=NULL;
    }
    */

    printf("Server shutdown.\n");

    return 0;
}


/**
 * Kill the server.  This function can be called from another thread to kill the
 * server, causing run_server() to return.
 */
void kill_server(void) {
    fprintf(stdout, "Stopping socket listener accept event loop.\n");
    if (event_base_loopexit(evbase_accept, NULL)) {
        perror("Error shutting down server");
    }
    fprintf(stdout, "Stopping workers.\n");
    workqueue_shutdown(&workqueue);
}

static void sig_handler(int signal) {
    fprintf(stdout, "Received signal %d: %s.  Shutting down.\n", signal, strsignal(signal));
    kill_server();
}

int main(int argc, char *argv[]) {
	return run_server();
}
