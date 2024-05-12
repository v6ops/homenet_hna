#ifndef DM_WORKER_INCLUDED
#define DM_WORKER_INCLUDED

#include <stdio.h>
//#include <iostream>
#include <unistd.h>
#include <string.h>
// #include "../lib/ssl_session.h"
#include "../lib/ldns_helpers.h"
#include "../lib/ssl_helpers.h"
#include "../lib/workqueue.h"

#include <event.h>
#include <event2/listener.h>
#include <event2/bufferevent_ssl.h>
#include "ssl_client.h"

//int dm_query_free (dm_query_t * dm_query);
// write a ldns packet to the wire
//int write_ldns_pkt_to_wire(dm_query_t *p_dm_query, ldns_pkt *pkt);
// write a ldns packet to the buffer event (deprecated)
//int ssl_dnsovertls_pkt2bev(struct bufferevent * bev, ldns_pkt *pkt);
// main function to process a DNS packet
// takes a raw query packet in, and returns a raw DNS packet
//int dm_worker(dm_query_t * dm_query);
int dm_worker(struct ssl_client *p_ssl_client);

#endif // DM_WORKER_INCLUDED
