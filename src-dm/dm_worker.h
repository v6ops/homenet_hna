#ifndef DM_WORKER_INCLUDED
#define DM_WORKER_INCLUDED

#include <stdio.h>
//#include <iostream>
#include <unistd.h>
#include <string.h>
#include <sys/time.h>

// #include "../lib/ssl_session.h"
#include "../lib/ldns_helpers.h"
#include "../lib/ssl_helpers.h"
#include "../lib/workqueue.h"

#include <event.h>
#include <event2/listener.h>
#include <event2/bufferevent_ssl.h>
#include "ssl_client.h"

#ifdef WITH_TOFU
#include "dm_tofu.h"
#endif

//int dm_query_free (dm_query_t * dm_query);
// write a ldns packet to the wire
//int write_ldns_pkt_to_wire(dm_query_t *p_dm_query, ldns_pkt *pkt);
// write a ldns packet to the buffer event (deprecated)
//int ssl_dnsovertls_pkt2bev(struct bufferevent * bev, ldns_pkt *pkt);
// main function to process a DNS packet
// takes a raw query packet in, and returns a raw DNS packet
//int dm_worker(dm_query_t * dm_query);
//
// write a ldns packet to the wire (SSL)
int write_ldns_pkt_to_wire(struct ssl_client *p_ssl_client, ldns_pkt *pkt);

// process and incoming notify packet 
ldns_pkt * dm_worker_notify(ldns_pkt *notify_pkt, struct ssl_client *p_ssl_client) ; // 1st arg = packet, 2nd arg=SSL client (for cert)

// process and incoming axfr query packet 
ldns_pkt * dm_worker_query_axfr(ldns_pkt *query, struct ssl_client *p_ssl_client) ; // 1st arg = packet, 2nd arg=SSL client (for cert)

// process and incoming update packet 
ldns_pkt * dm_worker_update(ldns_pkt *update_pkt, struct ssl_client *p_ssl_client); // 1st arg = packet, 2nd arg=SSL client (for cert)

int dm_worker(struct ssl_client *p_ssl_client);

#endif // DM_WORKER_INCLUDED
