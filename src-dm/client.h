#ifndef CLIENT_INCLUDED
#define CLIENT_INCLUDED

#include <stdio.h>
#include <stdlib.h>
#include <openssl/ssl.h>

/**
 * Struct to carry around connection (client)-specific data.
 */
typedef struct client client_t;

typedef struct client {
    // The client's socket.
    int fd;

    // The bufferedevent for this client.
    struct bufferevent *buf_ev;

    // The output buffer for this client.
    struct evbuffer *output_buffer;

    // The number of times called (future rate limiting)
    int cb_read_count ;

    // The ssl for this client. Used for checking certs versus the query
    struct ssl_client *p_ssl_client;

    // original libevent
    /* client's SSL CTX */
    SSL *ssl;

    /* The client's socket. */
    int sock;

    /* client's address */
    struct sockaddr *sa;

    /* client's address length */
    int sa_len;

    /* The event_base for this client. */
    struct event_base *evbase;

    /* The bufferedevent for this client. */
    struct bufferevent *bev;

    /* Here you can add your own application-specific attributes which
     * are connection-specific. */

} client_t;

#endif // CLIENT_INCLUDED
