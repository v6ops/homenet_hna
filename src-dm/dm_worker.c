/* dm_worker.cpp the worker callback functions that handle the DNS queries

* Copyright (c) 2019-2020 Ray Hunter

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
//#include "dm_query.h"
#include "dm_worker.h"

// write a ldns packet to the wire
//int write_ldns_pkt_to_wire(dm_query_t *p_dm_query, ldns_pkt *pkt)
int write_ldns_pkt_to_wire(struct ssl_client *p_ssl_client, ldns_pkt *pkt)
{
  // ldns and wire packets
  uint8_t *response = NULL;
  size_t response_len = 0;
  ldns_status status;
  int result;

  status = ldns_pkt2wire(&response, pkt, &response_len);
  if(status != LDNS_STATUS_OK) {
    printf("Error converting packet to hex %s.\n", ldns_get_errorstr_by_id(status));
    return -1;
  }
  // use the transport callback to send
  printf("send packet %i\n",(int)response_len);
  result = p_ssl_client->packet_write(p_ssl_client, (char *)response, response_len);
  printf("free packet\n");
  // free up the buffer
  if (response != NULL) {
    free(response);
    response =NULL;
  }
  return result;
}

//int dm_worker(dm_query_t * dm_query)
int dm_worker(struct ssl_client *p_ssl_client)
{
  /* dns */
  ldns_pkt *query_pkt;
  //ldns_rr_list *query_answer_section;
  ldns_rr *query_answer_rr;
  ldns_rr *query_authority_rr;
  ldns_rdf  *owner;
  ldns_status status;
  ldns_pkt *response_pkt;
  ldns_rr *query_question_rr;
  ldns_rr_list *response_qr;
  ldns_rr_list *response_an;
  ldns_rr_list *response_ns;
  ldns_rr_list *response_ad;

  ldns_rdf *origin = NULL;
  ldns_str2rdf_dname(&origin, "homenetdns.com");
  char buf[80];

  /* zone */
  const char *zone_file="../tests/testdata/fwd.homenetdns.com.db";
  ldns_zone *zone;
  zone=ldns_helpers_zone_read(zone_file);

  /* Handle query */
   status=ldns_wire2pkt(&query_pkt,(const uint8_t*)p_ssl_client->query,p_ssl_client->query_len);
   if (status!=LDNS_STATUS_OK ) {
      printf( "Invalid incoming packet.\n");
   } else {
      printf( "Incoming packet\n");
      ldns_pkt_print(stdout, query_pkt);

    // check the opcode and process appropriately
    // start NOTIFY
    if(ldns_pkt_get_opcode(query_pkt)==LDNS_PACKET_NOTIFY) {
      sprintf(buf, "incoming notify\n");
      printf("%s",buf);

      while ( (query_answer_rr=ldns_rr_list_pop_rr(ldns_pkt_answer(query_pkt))) ){
        sprintf(buf, "processing RR\n");
        printf("%s",buf);

        owner=ldns_rr_owner(query_answer_rr);
        ldns_dname_2str(buf,owner);
        printf("%s",buf);
      }
      ldns_helpers_pkt_free(query_pkt);  
    } // end NOTIFY
    else if(ldns_pkt_get_opcode(query_pkt)==LDNS_PACKET_UPDATE) {
      // start UPDATE
      sprintf(buf, "incoming update\n");
      printf("%s",buf);

      int pass_sanity=1;
      ldns_rdf *rdf;
      ldns_rdf *soa_owner_rdf;
      ldns_rdf *ns_owner_rdf;
      char soa_owner[ldns_helpers_max_buffer_size]="\0";
      char ns_owner[ldns_helpers_max_buffer_size]="\0";
      char ds_owner[ldns_helpers_max_buffer_size]="\0";
      //char ns_data[ldns_helpers_max_buffer_size]="\0";
      char listen_string[ldns_helpers_max_buffer_size]="\0";
      // Question should contain exactly 1 RR, which is a SOA, and the owner should match one of our parent zones 

      if (ldns_rr_list_rr_count(ldns_pkt_question(query_pkt)) !=1) {
	 printf("Expected 1 RR in the question\n");
	 pass_sanity=0;
      } else if (ldns_rr_get_type(ldns_rr_list_rr(ldns_pkt_question(query_pkt),0)) != LDNS_RR_TYPE_SOA ) {
	printf("Expected SOA RR in the question\n");
	 pass_sanity=0;
      } else {
        soa_owner_rdf=ldns_rr_owner(ldns_rr_list_rr(ldns_pkt_question(query_pkt),0));
        ldns_dname_2str(soa_owner,soa_owner_rdf);
	char my_root[ldns_helpers_max_buffer_size]="homenetdns.com\0"; // TODO remove hard coding of parent zone
	size_t	len=strlen(my_root);
	if (strncmp(my_root,soa_owner,len) !=0) {
	  printf("Expected owner of the SOA in the UPDATE is %s, got %s\n",my_root,soa_owner);
	  pass_sanity=0;
	}
      }
      if (pass_sanity ==1) {
        printf("Incoming update passed sanity checks\n");

	// check if we have DS or NS in the Authority
        while ( (query_authority_rr=ldns_rr_list_pop_rr(ldns_pkt_authority(query_pkt))) ){
          sprintf(buf, "processing RR\n");
          printf("%s",buf);

	  if (ldns_rr_get_type(query_authority_rr) == LDNS_RR_TYPE_NS ) {
            printf("Got an NS RR in the authority section\n");
            ns_owner_rdf=ldns_rr_owner(query_authority_rr);
            ldns_dname_2str(ns_owner,ns_owner_rdf);
	    ldns_helpers_strip_trailing_dot(ns_owner);
            printf("NS RR Owner %s\n",ns_owner);
	    // Check this NS RR falls within the parent
            if (ldns_dname_is_subdomain(ns_owner_rdf,soa_owner_rdf) == false) {
              printf("Skipping NS RR %s as it is not a subdomain of %s\n",ns_owner,soa_owner);
              continue;
            }
            // TODO check certificate DN against owner of the NS RR
	    printf("Checking cert matches RR owner %s\n",ns_owner);
	    if(ssl_helpers_check_cert_cn(p_ssl_client->ssl, ns_owner) !=1) {
		    printf ("Warning cert does not match RR owner %s\n",ns_owner);
	    }
	    // TODO additional checks to match the RDF of the NS RR to the owner of the A and AAAA RRs
	    strcpy(listen_string,"[\0");
	    while ( (rdf=ldns_rr_pop_rdf(query_authority_rr)) ) {
	      char *ptr;
	      ptr=ldns_rdf2str(rdf);
	      ldns_helpers_rdf_free(rdf);
	      printf("Checking RDF %s from additional section\n",ptr);

	      ldns_helpers_rr_list2listen_string(ldns_pkt_additional(query_pkt),ptr,listen_string);
	      LDNS_FREE(ptr);
	    }
	    strcat(listen_string,"]\0");
            //printf("Listen String %s\n",listen_string);
	    if (strlen(listen_string)>2) {
	      printf("Saving %s %s from authority section\n",ns_owner,listen_string);
	      fork_make_knot_dm_config(ns_owner,listen_string);

	    }

	  } else if (ldns_rr_get_type(query_authority_rr) == LDNS_RR_TYPE_DS ) {
            printf("Got an DS RR in the authority section\n");
            owner=ldns_rr_owner(query_authority_rr);
            ldns_dname_2str(ds_owner,owner);
	    ldns_helpers_strip_trailing_dot(ds_owner);
            printf("Owner %s\n",ds_owner);
            // TODO check certificate DN against RR owner
	    printf("Checking cert matches RR owner %s\n",ds_owner);
	    if(ssl_helpers_check_cert_cn(p_ssl_client->ssl, ds_owner) !=1) {
	      printf ("Warning cert does not match RR owner %s\n",ds_owner);
	    }
            printf("Saving DS\n");
	    ldns_rr_print(stdout,query_authority_rr);
	    char *rr_ptr;
	    rr_ptr=ldns_rr2str(query_authority_rr);
	    fork_make_knot_dm_ds(rr_ptr);
	    LDNS_FREE(rr_ptr);
            printf("Saved DS\n");
	  }
        }
      }


      ldns_helpers_pkt_free(query_pkt);  
    } // end UPDATE
    else if(ldns_pkt_get_opcode(query_pkt)==LDNS_PACKET_QUERY) {
      sprintf(buf, "incoming query\n");
      printf("%s",buf);

      query_question_rr = ldns_rr_list_rr(ldns_pkt_question(query_pkt), 0);
      if (ldns_rr_get_type(query_question_rr) == LDNS_RR_TYPE_AXFR ) {
        // answer  AXFR with a template
        sprintf(buf, "incoming AXFR\n");
        printf("%s",buf);
        response_pkt =  ldns_helpers_axfr_response_new(query_pkt);
        sprintf(buf, "Created AXFR\n");
        printf("%s",buf);
        ldns_helpers_pkt_free(query_pkt);  
        printf( "Freed query\n");
        printf( "Sending AXFR\n");
        ldns_pkt_print(stdout, response_pkt);
	// ssl_helpers_pkt2bio(response_pkt,sbio);
	// ssl_dnsovertls_pkt2bev(dm_query->bev, response_pkt);
	write_ldns_pkt_to_wire(p_ssl_client, response_pkt);
        ldns_helpers_pkt_free(response_pkt);
        printf( "Sent AXFR\n");

        printf( "Done axfr\n");

      } else {
        response_qr = ldns_rr_list_new();
        ldns_rr_list_push_rr(response_qr, ldns_rr_clone(query_question_rr));

        /* get matching RR set from the zone */
        response_an = get_rrset(zone, ldns_rr_owner(query_question_rr), ldns_rr_get_type(query_question_rr), ldns_rr_get_class(query_question_rr));
        response_ns = ldns_rr_list_new();
        response_ad = ldns_rr_list_new();

        response_pkt = ldns_pkt_new();
        ldns_pkt_set_qr(response_pkt, 1);
        ldns_pkt_set_aa(response_pkt, 1);
        ldns_pkt_set_id(response_pkt, ldns_pkt_id(query_pkt));

        ldns_pkt_push_rr_list(response_pkt, LDNS_SECTION_QUESTION, response_qr);
        ldns_pkt_push_rr_list(response_pkt, LDNS_SECTION_ANSWER, response_an);
        ldns_pkt_push_rr_list(response_pkt, LDNS_SECTION_AUTHORITY, response_ns);
        ldns_pkt_push_rr_list(response_pkt, LDNS_SECTION_ADDITIONAL, response_ad);

        printf( "Sending reponse\n");
        ldns_pkt_print(stdout, response_pkt);
	//ssl_helpers_pkt2bio(response_pkt,sbio);
	//ssl_dnsovertls_pkt2bev(dm_query->bev, response_pkt);
	write_ldns_pkt_to_wire(p_ssl_client, response_pkt);
        printf( "Sent response\n");
    
        ldns_helpers_pkt_free(query_pkt);
        ldns_helpers_pkt_free(response_pkt);
        // following are freed by freeing the packet
        // ldns_helpers_rr_list_free(response_qr);
        // ldns_helpers_rr_list_free(response_an);
        // ldns_helpers_rr_list_free(response_ns);
        // ldns_helpers_rr_list_free(response_ad);
        printf( "Done other query\n");

      }
    } // end QUERY
    else { // handle other queries
      sprintf(buf, "incoming not implemented\n");
      printf("%s",buf);
    } // other queries
   } // got query pkt
  //dm_query_free (dm_query); // free up the memory of the inbound query
  return 0;
}
