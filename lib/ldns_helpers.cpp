/* homenet_hna ldns_helpers.cpp

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
#include "ldns_helpers.h"


bool print_soa = true;

ldns_zone* ldns_helpers_load_template (char *filename) {

  FILE *fp;
  int line_nr = 0;
  ldns_zone *z;
  ldns_status s;

  fp = fopen(filename, "r");
  if (!fp) {
    fprintf(stderr, "Unable to open %s: %s\n", filename, strerror(errno));
    return NULL;
  }

  s = ldns_zone_new_frm_fp_l(&z, fp, NULL, 0, LDNS_RR_CLASS_IN, &line_nr);

  if (s != LDNS_STATUS_OK) {
    fprintf(stderr, "Error %s\n",ldns_get_errorstr_by_id(s));
    return NULL;
  }
  fclose(fp);

  return z;
}

ldns_zone * ldns_helpers_zone_template_new (char *zone_name) { // fill the template for a particular sub zone
  /* this is static hard coded for now, but obviously the RR's could be zone specific e.g. to allow load balancing */
  ldns_zone *z; 	
  ldns_rr   *rr;
  ldns_rdf *prev=NULL;
  ldns_buffer *tmp_buf;
  ldns_status status;
  char *ptr;
  int rr_c=0;

  char ns1[]="ns1.homenetinfra.com.";
  char ns2[]="ns2.homenetinfra.com.";

  z=ldns_zone_new (); // create a new zone
  ldns_zone_set_soa(z,ldns_helpers_soa_rr_new(zone_name)); //add the soa

  // Add 2 NS RR
  tmp_buf=ldns_buffer_new(ldns_helpers_max_buffer_size);
  ldns_buffer_printf(tmp_buf, "%s IN NS %s", zone_name, ns1);
  ptr=ldns_buffer_export2str(tmp_buf);
  status = ldns_rr_new_frm_str(&rr, ptr, 3600, NULL, &prev);
  LDNS_FREE(ptr);
  ldns_buffer_free(tmp_buf);
  if(status != LDNS_STATUS_OK) {
    printf("Error adding RR to zone: %s\n", ldns_get_errorstr_by_id(status));
  } else {
    if (ldns_zone_push_rr(z,rr)==true) rr_c++;
  }

  tmp_buf=ldns_buffer_new(ldns_helpers_max_buffer_size);
  ldns_buffer_printf(tmp_buf, "%s IN NS %s", zone_name, ns2);
  ptr=ldns_buffer_export2str(tmp_buf);
  status = ldns_rr_new_frm_str(&rr, ptr, 3600, NULL, &prev);
  LDNS_FREE(ptr);
  ldns_buffer_free(tmp_buf);
  if(status != LDNS_STATUS_OK) {
    printf("Error adding RR to zone: %s\n", ldns_get_errorstr_by_id(status));
  } else {
    if (ldns_zone_push_rr(z,rr)==true) rr_c++;
  }

  if (rr_c>0) {
    return z;
  } else {
    ldns_zone_free(z);
    return NULL;
  }

}

/* ldns_helpers_notify_via_socket basis taken from NLnetLabs Examples ldns_notify */
/* send notify packet to one host: blocks waiting for reply or timeout */
void ldns_helpers_notify_via_socket(int s, struct addrinfo* res, uint8_t* wire, size_t wiresize, const char* addrstr)
{
  int timeout_retry = ldns_helpers_max_retry_count ; /* seconds */
  int num_retry = ldns_helpers_max_retry_count;
  fd_set rfds;
  struct timeval tv;
  int retval = 0;
  ssize_t received = 0;
  int got_ack = 0;
  socklen_t addrlen = 0;
  uint8_t replybuf[ldns_helpers_max_buffer_size];
  ldns_status status;
  ldns_pkt* pkt = NULL;
  
  while(!got_ack) {
    /* send it */
    if(sendto(s, wire, wiresize, 0, res->ai_addr, res->ai_addrlen) == -1) {
      printf("warning: send to %s failed: %s\n", addrstr, strerror(errno));
      close(s);
      return;
    }

    /* wait for ACK packet */
    FD_ZERO(&rfds);
    FD_SET(s, &rfds);
    tv.tv_sec = timeout_retry; /* seconds */
    tv.tv_usec = 0; /* microseconds */
    retval = select(s + 1, &rfds, NULL, NULL, &tv);
    if (retval == -1) {
      printf("error waiting for reply from %s: %s\n",
        addrstr, strerror(errno));
      close(s);
      return;
    }
    if(retval == 0) {
      num_retry--;
      if(num_retry == 0) {
        printf("error: failed to send notify to %s.\n",
          addrstr);
        return;
      }
      printf("timeout (%d s) expired, retry notify to %s.\n",
        timeout_retry, addrstr);
    }
    if (retval == 1) {
      got_ack = 1;
    }
  }

  /* got reply */
  addrlen = res->ai_addrlen;
  received = recvfrom(s, replybuf, sizeof(replybuf), 0, res->ai_addr, &addrlen);
  res->ai_addrlen = addrlen;

  close(s);
  if (received == -1) {
    printf("recv %s failed: %s\n", addrstr, strerror(errno));
    return;
  }

  /* check reply */
  status = ldns_wire2pkt(&pkt, replybuf, (size_t)received);
  if(status != LDNS_STATUS_OK) {
    ssize_t i;
    printf("Could not parse reply packet: %s\n", ldns_get_errorstr_by_id(status));
    printf("hexdump of reply: ");
    for(i=0; i<received; i++)
      printf("%02x", (unsigned)replybuf[i]);
    printf("\n");
    exit(1);
  }

  if(ldns_helpers_verbose) {
    ssize_t i;
    printf("# reply from %s:\n", addrstr);
    ldns_pkt_print(stdout, pkt);
    
    printf("hexdump of reply: ");
    for(i=0; i<received; i++)
      printf("%02x", (unsigned)replybuf[i]);
    printf("\n");
  }
  ldns_pkt_free(pkt);
}


int ldns_helpers_notify_host(const char *zone_name,char *hostname) {
  /* LDNS types */
  ldns_pkt *notify;
  ldns_rr *question;
  ldns_resolver *res;
  ldns_rdf *ldns_zone_name = NULL;
  ldns_status status;
  // const char *zone_name = NULL;
  int include_soa = 1;
  uint32_t soa_version = 0;
  ldns_tsig_credentials tsig_cred = {0,0,0};
  int do_hexdump = 1;
  uint8_t *wire = NULL;
  size_t wiresize = 0;
  char const *port = "53";

  int i;

  srandom(time(NULL) ^ getpid());

  /* setup the zone name */
  ldns_zone_name = ldns_dname_new_frm_str(zone_name);
  if(!ldns_zone_name) {
    printf("cannot parse zone name: %s\n",zone_name);
    return -1;
  }

  
  notify = ldns_pkt_new();
  question = ldns_rr_new();
  res = ldns_resolver_new();

  /* create the rr for inside the pkt */
  ldns_rr_set_class(question, LDNS_RR_CLASS_IN);
  ldns_rr_set_owner(question, ldns_zone_name);
  ldns_rr_set_type(question, LDNS_RR_TYPE_SOA);
  ldns_pkt_set_opcode(notify, LDNS_PACKET_NOTIFY);
  ldns_pkt_push_rr(notify, LDNS_SECTION_QUESTION, question);
  ldns_pkt_set_aa(notify, true);
  ldns_pkt_set_id(notify, random()&0xffff);
  if(include_soa) {
    char buf[ldns_helpers_max_buffer_size];
    ldns_rr *soa_rr=NULL;
    ldns_rdf *prev=NULL;
    snprintf(buf, sizeof(buf), "%s 3600 IN SOA . . %u 0 0 0 0",
      zone_name, (unsigned)soa_version);
    /*printf("Adding soa %s\n", buf);*/
    status = ldns_rr_new_frm_str(&soa_rr, buf, 3600, NULL, &prev);
    if(status != LDNS_STATUS_OK) {
      printf("Error adding SOA version: %s\n",
        ldns_get_errorstr_by_id(status));
    }
    ldns_pkt_push_rr(notify, LDNS_SECTION_ANSWER, soa_rr);
  }
  /* tsig goes here */

  /*verbose*/
  if(ldns_helpers_verbose) {
    printf("# Sending packet:\n");
    ldns_pkt_print(stdout, notify);

  }

  /* setup packet */

  status = ldns_pkt2wire(&wire, notify, &wiresize);
  if(wiresize == 0) {
    printf("Error converting notify packet to hex.\n");
    exit(1);
  }

  if(do_hexdump && ldns_helpers_verbose) {
    printf("Hexdump of notify packet:\n");
    for(i=0; i<(int)wiresize; i++)
      printf("%02x", (unsigned)wire[i]);
    printf("\n");
  }
  struct addrinfo hints, *result0, *result;
  int error;
  int default_family = AF_INET;

  if(ldns_helpers_verbose) {
    printf("# sending to %s\n", hostname);
    ldns_pkt_print(stdout, notify);
  }

  status = ldns_pkt2wire(&wire, notify, &wiresize);

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = default_family;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_protocol = IPPROTO_UDP;
  error = getaddrinfo(hostname, port, &hints, &result0);
  if (error) {
    printf("skipping bad addresults: %s: %s\n", hostname,
      gai_strerror(error));
    return -1;
  }
  for (result = result0; result; result = result->ai_next) {
    int s = socket(result->ai_family, result->ai_socktype, 
      result->ai_protocol);
    if(s == -1)
      return -1;
    /* send the notify */
    ldns_helpers_notify_via_socket(s, result, wire, wiresize, hostname);
  }
  freeaddrinfo(result0);

  ldns_pkt_free(notify);
  free(wire);
      return 0;
}

// make a new notify packet. Don't forget to free after use with ldns_pkt_free()
ldns_pkt * ldns_helpers_notify_new(const char *zone_name) {
  /* LDNS types */
  ldns_pkt *notify;
  ldns_rr *question;
  ldns_rr *soa_rr;
  ldns_rdf *ldns_zone_name = NULL;
  ldns_status status;
  int include_soa = 1;
  // ldns_tsig_credentials tsig_cred = {0,0,0};

  srandom(time(NULL) ^ getpid());

  /* setup the zone name */
  ldns_zone_name = ldns_dname_new_frm_str(zone_name);
  if(!ldns_zone_name) {
    printf("cannot parse zone name: %s\n",zone_name);
    return NULL;
  }

  notify = ldns_pkt_new();
  question = ldns_rr_new();

  /* create the rr for inside the pkt */
  ldns_rr_set_class(question, LDNS_RR_CLASS_IN);
  ldns_rr_set_owner(question, ldns_zone_name);
  ldns_rr_set_type(question, LDNS_RR_TYPE_SOA);
  ldns_pkt_set_opcode(notify, LDNS_PACKET_NOTIFY);
  ldns_pkt_push_rr(notify, LDNS_SECTION_QUESTION, question);
  ldns_pkt_set_aa(notify, true);
  ldns_pkt_set_id(notify, random()&0xffff);
  if(include_soa) {
    soa_rr=ldns_helpers_soa_rr_new(zone_name);
    ldns_pkt_push_rr(notify, LDNS_SECTION_ANSWER, soa_rr);
  }
  /* tsig goes here */

  return notify;
}

ldns_pkt * ldns_helpers_axfr_query_new(const char *zone_name) {
  /* LDNS types */
  ldns_pkt *axfr_query_pkt;
  ldns_status status;
  ldns_rr *question;
  ldns_rdf *ldns_zone_name = NULL;

  srandom(time(NULL) ^ getpid());

  ldns_zone_name = ldns_dname_new_frm_str(zone_name);
  if(!ldns_zone_name) {
    printf("cannot parse zone name: %s\n",zone_name);
    return NULL;
  }


  axfr_query_pkt = ldns_pkt_new();
  question = ldns_rr_new();

  /* create the rr for inside the pkt */
  ldns_rr_set_class(question, LDNS_RR_CLASS_IN);
  ldns_rr_set_owner(question, ldns_zone_name);
  ldns_rr_set_type(question, LDNS_RR_TYPE_AXFR);
  ldns_pkt_set_opcode(axfr_query_pkt, LDNS_PACKET_QUERY);
  ldns_pkt_set_id(axfr_query_pkt, random()&0xffff);
  ldns_pkt_push_rr(axfr_query_pkt, LDNS_SECTION_QUESTION, question);

  return axfr_query_pkt;
}

ldns_pkt * ldns_helpers_axfr_response_new(ldns_pkt *query_pkt) {
  /* LDNS types */
  ldns_pkt *axfr_response_pkt;
  ldns_status status;
  ldns_rr *question;
  ldns_rdf *ldns_zone_name = NULL;

  ldns_zone *z;

  ldns_rr *query_question_rr;
  ldns_rr *rr;
  ldns_rr_list *response_qr;
  ldns_rr_list *response_an;
  ldns_rr_list *response_ns;
  ldns_rr_list *response_ad;
  ldns_rdf  *owner;

  char zone_name[ldns_helpers_max_buffer_size]="\0";

  axfr_response_pkt= ldns_pkt_new();

  response_qr = ldns_rr_list_new();
  response_an = ldns_rr_list_new();
  response_ns = ldns_rr_list_new();
  response_ad = ldns_rr_list_new();

  ldns_pkt_set_qr(axfr_response_pkt, 1); // response
  ldns_pkt_set_aa(axfr_response_pkt, 1); // authorative
  ldns_pkt_set_id(axfr_response_pkt, ldns_pkt_id(query_pkt)); // answers this query

  query_question_rr = ldns_rr_list_rr(ldns_pkt_question(query_pkt), 0);

  ldns_rr_list_push_rr(response_qr, ldns_rr_clone(query_question_rr)); // copy the question section from the query to the response

  owner=ldns_rr_owner(query_question_rr);
  ldns_dname_2str(zone_name,owner);

  z=ldns_helpers_zone_template_new (zone_name); // create the new template zone for this zone_name

  ldns_rr_list_push_rr(response_an,ldns_rr_clone(ldns_zone_soa(z)));
  // clone the rr's from the zone to the axfr packet
  while (rr=ldns_rr_list_pop_rr(ldns_zone_rrs(z))) {
  	ldns_rr_list_push_rr(response_an,ldns_rr_clone(rr));
		  }
  // ldns_rr_list_push_rr_list(response_an,ldns_zone_rrs(z));
  ldns_rr_list_push_rr(response_an,ldns_rr_clone(ldns_zone_soa(z)));
  
  ldns_pkt_push_rr_list(axfr_response_pkt, LDNS_SECTION_QUESTION, response_qr);
  ldns_pkt_push_rr_list(axfr_response_pkt, LDNS_SECTION_ANSWER, response_an);
  ldns_pkt_push_rr_list(axfr_response_pkt, LDNS_SECTION_AUTHORITY, response_ns);
  ldns_pkt_push_rr_list(axfr_response_pkt, LDNS_SECTION_ADDITIONAL, response_ad);

  ldns_zone_free(z);

  return axfr_response_pkt;
}

// take an axfr packet and return a zone
// Note this assumes a single ldns packet (65535 octets),
// which will break for very large updates.
// To do update to accept multiple packets
ldns_zone * ldns_helpers_axfr_pkt2zone(ldns_pkt *response_pkt) {
  /* LDNS types */
  ldns_rr *soa;
  ldns_rr *response_answer_rr;
  ldns_rr_list *response_answer_rr_list;
  int done=0;
  int soa_found=0;
  ldns_zone *z;
  printf("Starting ldns_helpers_axfr_pkt2zone\n");

  z=ldns_zone_new(); // if no zone passed, create one

  // pop records off in reverse order, but that's OK as it's a soa sandwich
  response_answer_rr_list=ldns_rr_list_clone(ldns_pkt_answer(response_pkt));
  while ((!done) && (response_answer_rr = ldns_rr_list_pop_rr(response_answer_rr_list))){
	  if ((ldns_rr_get_type(response_answer_rr) == LDNS_RR_TYPE_SOA  )) {
		  if (soa_found ==0)  {
	  		// remember the soa
			soa_found++;
		 	soa=ldns_rr_clone(response_answer_rr);
			ldns_zone_set_soa(z,soa);
			continue;
	//	  } else if (soa && ldns_rr_compare(soa,response_answer_rr)==0) {
		  } else if (ldns_rr_compare(soa,response_answer_rr)==0) {
			// compare is probably a bit ott
			// this is the soa at the end of the list
			done =1;
			soa_found++;
			continue;
		} else {
			printf("Error. Found second SOA in AXFR which doesn't match first\n");
		}
	} else {
	  	ldns_zone_push_rr(z,ldns_rr_clone(response_answer_rr));
	}
  }
  ldns_rr_list_free(response_answer_rr_list);

  return z;
}




ldns_pkt * ldns_helpers_ns_query_new(const char *zone_name) {
  /* LDNS types */
  ldns_pkt *ns_query_pkt;
  ldns_status status;
  ldns_rr *question;
  ldns_rdf *ldns_zone_name = NULL;

  srandom(time(NULL) ^ getpid());

  ldns_zone_name = ldns_dname_new_frm_str(zone_name);
  if(!ldns_zone_name) {
    printf("cannot parse zone name: %s\n",zone_name);
    return NULL;
  }

  ns_query_pkt = ldns_pkt_new();
  question = ldns_rr_new();

  /* create the rr for inside the pkt */
  ldns_rr_set_class(question, LDNS_RR_CLASS_IN);
  ldns_rr_set_owner(question, ldns_zone_name);
  ldns_rr_set_type(question, LDNS_RR_TYPE_NS);
  ldns_pkt_set_opcode(ns_query_pkt, LDNS_PACKET_QUERY);
  ldns_pkt_set_id(ns_query_pkt, random()&0xffff);
  ldns_pkt_push_rr(ns_query_pkt, LDNS_SECTION_QUESTION, question);

  return ns_query_pkt;
}


// make a new spoofed soa rr. Don't forget to free after use with ldns_rr_free()
// This can be used for the template replies and axfr
ldns_rr * ldns_helpers_soa_rr_new(const char *zone_name) {
  /* LDNS types */
  ldns_rdf *ldns_zone_name = NULL;
  ldns_status status;
  uint32_t soa_version = (uint32_t)time(NULL); // use current local systime for the soa version, so will always be fresh
  uint32_t soa_refresh = 86400;    // default refresh time from RIPE
  uint32_t soa_retry   = 7200;     // default retry time from RIPE
  uint32_t soa_expire  = 3600000;  // default expire time from RIPE
  uint32_t soa_minttl  = 600;      // our default expire

  /* setup the zone name */
  ldns_zone_name = ldns_dname_new_frm_str(zone_name);
  if(!ldns_zone_name) {
    printf("cannot parse zone name: %s\n",zone_name);
    return NULL;
  }

  /* create the rr for inside the pkt */
  char buf[ldns_helpers_max_buffer_size];
  ldns_rr *soa_rr=NULL;
  ldns_rdf *prev=NULL;
  snprintf(buf, sizeof(buf), "%s 3600 IN SOA . . %u %u %u %u %u",
    zone_name, (unsigned)soa_version,soa_refresh,soa_retry,soa_expire,soa_minttl);
  status = ldns_rr_new_frm_str(&soa_rr, buf, 3600, NULL, &prev);
  if(status != LDNS_STATUS_OK) {
    printf("Error adding SOA version: %s\n",
      ldns_get_errorstr_by_id(status));
  }
  return soa_rr;
}


/* there are routines that return a buffer, but that seems to mean more casting, so I rolled my own */
int ldns_dname_2str (char *str, const ldns_rdf *r)
{
        uint16_t src_pos;
        uint16_t len;
        size_t r_size;
	uint8_t dest_pos=0;
	uint8_t i=0;


        if (!r) {
                str[dest_pos]='\0';
		return -1;
        }

        src_pos = 0;
        r_size = ldns_rdf_size(r);

        if (ldns_rdf_get_type(r) != LDNS_RDF_TYPE_DNAME) {
                str[dest_pos]='\0';
                return -1;
        } else if ( r_size > 255 ) { /* max length label string */
                str[dest_pos]='\0';
                return -1;
        } else {
                len = ldns_rdf_data(r)[src_pos]; /* start of the label */

                /* single root label */
                if (1 == r_size) {
                        str[dest_pos]='.';
			dest_pos++;
                        str[dest_pos]='\0';
                        return dest_pos;
                } else {
                        while (src_pos < r_size && (len > 0) && ((dest_pos+len) <255) ) {
                                src_pos++;
				// copy across the label
				for(i=0;i<len;i++) {
                                  //src_pos += len;
				  char c;
				  c= ldns_rdf_data(r)[src_pos];
				  /* only copy printable ascii from the label that is not a dot */
				  /* this is not strict RFC compliant, but multi-character is difficult, see RFC8324 */
				  if (c>32 && c<128 && c != 46 ) {
				    str[dest_pos]=c;
				    dest_pos++;
				  }
                                  src_pos++;
				}
				str[dest_pos]='.';
				dest_pos++;
				// take the next label if we're not at the end
                                if (src_pos < r_size ) len = ldns_rdf_data(r)[src_pos];
                        }
                        str[dest_pos]='\0';
        		return dest_pos;
                }
        }
}

/* copied from https://github.com/threatstack/libldns/blob/master/examples/ldnsd.c */
ldns_rr_list *
get_rrset(const ldns_zone *zone, const ldns_rdf *owner_name, const ldns_rr_type qtype, const ldns_rr_class qclass)
{
	uint16_t i;
	ldns_rr_list *rrlist = ldns_rr_list_new();
	ldns_rr *cur_rr;
	if (!zone || !owner_name) {
		return rrlist;
	}

	for (i = 0; i < ldns_zone_rr_count(zone); i++) {
		cur_rr = ldns_rr_list_rr(ldns_zone_rrs(zone), i);
		if (ldns_dname_compare(ldns_rr_owner(cur_rr), owner_name) == 0 &&
		    ldns_rr_get_class(cur_rr) == qclass &&
		    ldns_rr_get_type(cur_rr) == qtype
		   ) {
			ldns_rr_list_push_rr(rrlist, ldns_rr_clone(cur_rr));
		}
	}

	return rrlist;
}

// strip a trailing dot from a c string, but only if neccesary
void ldns_helpers_strip_trailing_dot(char *str) {
  int i;
  int null_found=0;
  for (i=0;i<(ldns_helpers_max_buffer_size-1);i++) {
    if (str[i] == '\0') {
	    null_found=1;
	    break;
    }
  }
  // zone is longer than /.\0/ and last char is a dot
  if (i>1 && null_found==1) {
    i--;
    if (str[i] == '.') {
      str[i] = '\0';
    }
  }
}

// add a trailing dot to a c string, but only if neccesary
void ldns_helpers_add_trailing_dot(char *str) {
  int i;
  int null_found=0;
  for (i=0;i<(ldns_helpers_max_buffer_size-1);i++) {
    if (str[i] == '\0') {
	    null_found=1;
	    break;
    }
  }
  // zone is longer than '\0' and last char is not a dot
  if (i>0 && null_found==1 && str[i-1] != '.') {
    str[i] = '.';
    i++;
    str[i] = '\0';
  }
}

// return the parent domain name
void ldns_helpers_parent_domain(const char *domain,char *parent) {
  int i;
  int null_found=-1;
  int dot_found=-1;
  char *start;
  for (i=0;i<(ldns_helpers_max_buffer_size-1);i++) {
    if (domain[i] == '\0') {
	    null_found=i;
	    break;
    }
    else if (dot_found<0 && domain[i] == '.') { 
	    dot_found=i; // first dot
    }
  }
  // no terminator found, null parent
  if (null_found <0) {
    parent[0]='\0';
    return;
  }
  // no dot found, null parent
  if (dot_found <0) {
    parent[0]='\0';
    return;
  }
  // copy across the parent domain portion including trailing null
  for (i=0;i<null_found-dot_found;i++) {
    parent[i]=domain[dot_found+i+1];
  }
}

int ldns_rr_soa_set_mname  ( ldns_rr *soa_rr, char *mname ) {

  ldns_rdf *prev_rdf=NULL;
  ldns_rdf *new_rdf=NULL;

  size_t  position=0; //mname is the 1st rdf in a soa rr and it is of type LDNS_RDF_TYPE_DNAME (rr.c line 1489)

  if ( ldns_rr_get_type(soa_rr) != LDNS_RR_TYPE_SOA ) {
    fprintf(stderr, "ldns_soa_set_mname: not a SOA RR\n");
    return -1;
  }

  if ( (mname==NULL) || (strlen(mname)<1) ) {
          fprintf(stderr, "ldns_soa_set_mname: no mname\n");
          return -1;
  }
    fprintf(stderr, "ldns_soa_set_mname: mname %s\n", mname);

  new_rdf=ldns_rdf_new_frm_str(LDNS_RDF_TYPE_DNAME,mname);

  prev_rdf=ldns_rr_set_rdf(soa_rr,new_rdf,position);

  ldns_rdf_free(prev_rdf);

  return 0;
}

// write a template zone as a bind zone config
void ldns_helpers_zone_to_configfile(ldns_zone *z,char *outputfile_name) {
  FILE *outputfile;
  ldns_rr *soa_rr;
  ldns_rdf *zone_name_rdf;
  char zone_name[ldns_helpers_max_buffer_size]="\0";
  char mname[ldns_helpers_max_buffer_size]="\0";

  // get the zone name from the soa
  soa_rr=ldns_zone_soa(z);
  ldns_dname_2str(zone_name,ldns_rr_owner(soa_rr));


  // strip trailing dot for filename
  ldns_helpers_strip_trailing_dot(zone_name);

  if (!zone_name) {
    fprintf(stderr, "ldns_helpers_zone_to_config: Unable to determine zone name\n");
    return;
  }

  if (!outputfile_name) {
    outputfile_name = LDNS_XMALLOC(char, LDNS_MAX_FILENAME_LEN);
    snprintf(outputfile_name, LDNS_MAX_FILENAME_LEN, "/usr/local/etc/knot/templates/%s.zone", zone_name);
  }

  gethostname(mname,ldns_helpers_max_buffer_size);
  strcat(mname,".");
  strcat(mname,zone_name);

  ldns_rr_soa_set_mname( soa_rr, mname);

  if (z) {
    outputfile = fopen(outputfile_name, "w");
    if (!outputfile) {
      fprintf(stderr, "ldns_helpers_zone_to_config: Unable to open %s for writing: %s\n",
      outputfile_name, strerror(errno));
    } else {
      ldns_zone_print(outputfile,z);
      fclose(outputfile);
    }
  }
}

// convert a rr_list to a string. NB you are responsible for blanking the string in advance if necessary.
int ldns_helpers_rr_list2listen_string(ldns_rr_list *rrl, const char *owner, char *listen_string) {
  int ret=0;
  char *str;
  ldns_rr *rr;
  size_t i;
  size_t j;


  // cycle through the rr_list looking for A and AAAA rr
  for (i = 0; i < ldns_rr_list_rr_count(rrl); i++) {
    rr = ldns_rr_list_rr(rrl, i);
    str=ldns_rdf2str(ldns_rr_owner(rr));

    // Check this RR matches the rdf of the RR in the update rr_list
    if (owner && strlen(owner)>0) {
      if (strcmp(str,owner) != 0) {
        printf("ldns_helpers_rr_list2listen_string: Skipping %s as it is does not match owner %s\n",str,owner);
	LDNS_FREE(str);
        continue;
      }
    }

    if (ldns_rr_get_type(rr) == LDNS_RR_TYPE_AAAA || ldns_rr_get_type(rr) == LDNS_RR_TYPE_A) {
      for (j=0; j<ldns_rr_rd_count(rr);j++) {
         if(ret >0) {
           strcat(listen_string,",");
         }
         strcat(listen_string,ldns_rdf2str(ldns_rr_rdf(rr,j)));
      }
      ret++;
    } else {
        printf("ldns_helpers_rr_list2listen_string: Skipping non A or AAAA RR %s\n",str);
    }
    LDNS_FREE(str);
  }

  return ret;
}

ldns_rr_list * ldns_helpers_listen_string2rr_list(const char *name, const char *listen_string) {
  ldns_rr *new_rr;
  ldns_rr_list *new_rr_list;
  int i;
  int j=0;
  int k=0;
  int port=0;
  int last =0; // breal the loop on \0
  char new_rr_str[ldns_helpers_max_buffer_size]="\0";
  char address_buf[ldns_helpers_max_buffer_size]="\0";
  char port_buf[ldns_helpers_max_buffer_size]="\0";
  char tmp_buf[ldns_helpers_max_buffer_size]="\0";

  new_rr_list=ldns_rr_list_new();
  printf ("ldns_helpers_listen_string2rr_list: Parsing listen_string :%s:\n",listen_string);

  // parse the listen string
  for (i=0;i<(ldns_helpers_max_buffer_size);i++) {
    // is this the start of a port?
    if (listen_string[i] == '@') {
      port=1;
    } else if (listen_string[i] == '[') { // throw away stuff before [
      continue;
    // end of token?
    } else if ((listen_string[i] == '\0')||(listen_string[i] == ',')||(listen_string[i] == ']')) {
      // terminate the address string
      if (j>0) {
        j++;
        address_buf[j]='\0';
      }
      // terminate the port string
      if (k>0) {
        k++;
        port_buf[k]='\0';
      }
      // process this address if we have anything in the address string
      // TODO do something with the port string (SRV record?)
      if (address_buf[0] !='\0') {

        // check if we have IPv6 in which case make a AAAA RR
        if (inet_pton(AF_INET6, (const char*)address_buf, tmp_buf) == 1) {
          strcpy(new_rr_str,name);
          ldns_helpers_add_trailing_dot(new_rr_str);
          strcat(new_rr_str,"\t3600\tAAAA ");
          strcat(new_rr_str,address_buf);
          printf( "Making AAAA %s\n",new_rr_str);
          ldns_rr_new_frm_str(&new_rr,new_rr_str, 0, NULL, NULL);
          ldns_rr_list_push_rr(new_rr_list, new_rr);
        // check if we have IPv4 in which case make a A RR
        } else if (inet_pton(AF_INET, (const char*)address_buf, tmp_buf) == 1) {
          strcpy(new_rr_str,name);
          ldns_helpers_add_trailing_dot(new_rr_str);
          strcat(new_rr_str,"\t3600\tA ");
          strcat(new_rr_str,address_buf);
          printf( "Making A %s\n",new_rr_str);
          ldns_rr_new_frm_str(&new_rr,new_rr_str, 0, NULL, NULL);
          ldns_rr_list_push_rr(new_rr_list, new_rr);
        } else {
          printf("ldns_helpers_listen_string2rr_list: Skipping unknown format address string %s\n",address_buf);
        }
        // get ready to start again
        address_buf[0]='\0';
        port_buf[0]='\0';
        j=0;
        k=0;
	port=0;
      }
      if (listen_string[i] == '\0'||listen_string[i] == ']') {
        break; // we're done
      }
    } else if (port ==1) { // copy current char to the end of the port or address buffer
      port_buf[k]=listen_string[i];
      k++;
    } else {
      address_buf[j]=listen_string[i];
      j++;
    }
  }

  return new_rr_list;

}



// create an update packet from the zone name and the hna client config bind string
ldns_pkt * ldns_helpers_ns_update_new(const char *zone_name, const char *listen_string) {
  /* LDNS types */
  ldns_pkt *update;
  ldns_rdf *ldns_zone_dname = NULL;
  ldns_rr_list *prerequisites=ldns_rr_list_new();
  ldns_rr *ns_rr;
  ldns_rr_list *updates=ldns_rr_list_new();
  ldns_rr_list *additional; //=ldns_rr_list_new();
  ldns_rr_class c = LDNS_RR_CLASS_IN;
  ldns_status status=LDNS_STATUS_OK;
  char hna_name[ldns_helpers_max_buffer_size]="\0";
  char parent[ldns_helpers_max_buffer_size]="\0";
  char new_rr_str[ldns_helpers_max_buffer_size]="\0";

  gethostname(hna_name,ldns_helpers_max_buffer_size);
  strcat(hna_name,".");
  strcat(hna_name,zone_name);

  strcat(new_rr_str,zone_name);
  strcat(new_rr_str,"\t3600\tNS ");
  strcat(new_rr_str,hna_name);
  ldns_helpers_add_trailing_dot(new_rr_str);

  printf( "Making NS %s\n",new_rr_str);

  ldns_rr_new_frm_str(&ns_rr,new_rr_str, 0, NULL, NULL);
  updates=ldns_rr_list_new();
  ldns_rr_list_push_rr(updates, ns_rr);

  ldns_helpers_parent_domain(zone_name,parent);
  ldns_str2rdf_dname(&ldns_zone_dname ,parent);

  additional=ldns_helpers_listen_string2rr_list(hna_name,listen_string);

  update= ldns_update_pkt_new(ldns_zone_dname, c, prerequisites, updates, additional);
  return update;
}



// create an update packet for the DS SET
ldns_pkt * ldns_helpers_ds_update_new(const char *zone_name) {
  /* LDNS types */
  ldns_pkt *update;
  ldns_rdf *ldns_zone_dname = NULL;
  ldns_rr_list *prerequisites=ldns_rr_list_new();
  ldns_rr *ds_rr;
  ldns_rr_list *updates=ldns_rr_list_new();
  ldns_rr_list *additional=ldns_rr_list_new();
  ldns_rr_class c = LDNS_RR_CLASS_IN;
  ldns_status status=LDNS_STATUS_OK;
  char parent[ldns_helpers_max_buffer_size]="\0";
  //char new_rr_str[ldns_helpers_max_buffer_size]="\0";
  char * new_rr_str = NULL;
  char ds_file[LDNS_MAX_FILENAME_LEN]="\0";
  FILE *ds_fp;
  size_t len = 0;
  size_t len_zone_name = strlen(zone_name);
  ssize_t read;

  updates=ldns_rr_list_new();

  strcpy(ds_file,"/usr/local/etc/knot/ds/ds.");
  strcat(ds_file,zone_name);
  strcat(ds_file,".zone");

  // call knot keymgr external prorgramme and write results to file
  fork_make_knot_ds(zone_name,ds_file);

  printf("Reading DS file %s\n", ds_file);
  ds_fp = fopen(ds_file, "r");
  if (!ds_fp) {
    fprintf(stderr, "Unable to open %s: %s\n", ds_file, strerror(errno));
    return NULL;
  }

  while ((read = getline(&new_rr_str, &len, ds_fp)) != -1) {
    //printf("Retrieved DS of length %zu:\n", read);
    if (strncmp(zone_name,new_rr_str,len_zone_name) !=0) {
	    //printf ("Ignoring garbage %s\n",new_rr_str);
	    continue;
    }
    
    //printf( "Making DS %s\n",new_rr_str);
    ldns_rr_new_frm_str(&ds_rr,new_rr_str, 0, NULL, NULL);
    ldns_rr_list_push_rr(updates, ds_rr);
    //printf( "Made DS %s\n",new_rr_str);
  } 

  fclose(ds_fp);
  if (new_rr_str) {
    free(new_rr_str);
  }

  ldns_helpers_parent_domain(zone_name,parent);
  ldns_str2rdf_dname(&ldns_zone_dname ,parent);

  update= ldns_update_pkt_new(ldns_zone_dname, c, prerequisites, updates, additional);
  return update;
}

