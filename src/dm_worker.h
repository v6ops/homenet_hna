#ifndef DM_WORKER_INCLUDED
#define DM_WORKER_INCLUDED

#include <stdio.h>
#include <iostream>
#include <unistd.h>
#include <string.h>
// #include "../lib/ssl_session.h"
#include "../lib/ldns_helpers.h"
#include "../lib/ssl_helpers.h"
#include "../lib/workqueue.h"

#include <event.h>
#include <event2/listener.h>
#include <event2/bufferevent_ssl.h>

/* struct to pass inbound query data to the dm_worker threads(s) */
/* note storage is allocated in the man thread and freed in the worker thread */
typedef struct dm_query {
    /* the inbound query in wire format */
    char *query;
    /* the length of the query in wire format */
    unsigned int len;
    /* The bufferedevent for this client. This is where the output is sent */
    struct bufferevent *bev;
    /* The ssl for this client. Used for checking certs */
    SSL *ssl;
} dm_query_t;

int dm_query_free (dm_query_t * dm_query);
int ssl_dnsovertls_pkt2bev(struct bufferevent * bev, ldns_pkt *pkt);
int dm_worker(dm_query_t * dm_query);

#endif // DM_WORKER_INCLUDED
