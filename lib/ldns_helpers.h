/* ldns_helper.h

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
#ifndef FUNCTIONS_ldns_helpers_INCLUDED
#define FUNCTIONS_ldns_helpers_INCLUDED
#define LDNS_MAX_FILENAME_LEN 250

const int ldns_helpers_max_retry_count = 5; // try 3 times
const int ldns_helpers_timeout_retry   = 2; // 2 seconds per try
const int ldns_helpers_max_buffer_size     = 2048; // 2048 packet buffer

const int ldns_helpers_verbose =1;

//#include "config.h"
#include "../config.h"
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <ldns/ldns.h>
#include <ldns/host2str.h>
#include <errno.h>
#include <time.h> 
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include "knot_helpers.h"


ldns_zone * ldns_helpers_load_template (char *filename);
ldns_zone * ldns_helpers_zone_read(const char * zone_file);
ldns_zone * ldns_helpers_zone_template_new (char *zone_name);

void ldns_helpers_notify_via_socket(int s, struct addrinfo* res, uint8_t* wire, size_t wiresize, const char* addrstr);

int ldns_helpers_notify_host(const char *zone_name,char *hostname);

ldns_pkt  * ldns_helpers_notify_new(const char *zone_name) ;
ldns_pkt  * ldns_helpers_axfr_query_new(const char *zone_name) ;
ldns_pkt  * ldns_helpers_axfr_response_new(ldns_pkt *query_pkt) ;
ldns_zone * ldns_helpers_axfr_pkt2zone(ldns_pkt *response_pkt);
ldns_pkt  * ldns_helpers_ns_query_new(const char *zone_name) ;
ldns_rr   * ldns_helpers_soa_rr_new(const char *zone_name) ;

ldns_pkt  * ldns_helpers_ns_update_new(const char *zone_name, const char *listen_string);
ldns_pkt  * ldns_helpers_ds_update_new(const char *zone_name);

ldns_rr_list * ldns_helpers_listen_string2rr_list(const char *listen_string);
int ldns_helpers_rr_list2listen_string(ldns_rr_list *rrl, const char *owner, char *listen_string) ;

void        ldns_helpers_zone_to_configfile(ldns_zone *z,char *outputfile_name); // write a template zone as a bind zone config

int ldns_rr_soa_set_mname  ( ldns_rr *soa_rr, char *mname );
int ldns_dname_2str (char *str, const ldns_rdf *r);
void ldns_helpers_strip_trailing_dot(char *zone_name);
void ldns_helpers_add_trailing_dot(char *zone_name);
void ldns_helpers_parent_domain(const char *domain, char *parent);

ldns_rr_list * get_rrset(const ldns_zone *zone, const ldns_rdf *owner_name, const ldns_rr_type qtype, const ldns_rr_class qclass);

void ldns_helpers_pkt_free(ldns_pkt *pkt);
void ldns_helpers_zone_free(ldns_zone *z);
void ldns_helpers_rdf_free(ldns_rdf *rdf);
void ldns_helpers_rr_list_free(ldns_rr_list *rr_list);

#endif
