/* homenet_hna homenet_dm

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
#include "homenet_dm.h"



int main(int argc, char **argv)
{
  std::cout << "Main Starting\n" << std::flush;
  SSL_CTX *ctx;

  init_openssl();
  ctx = create_server_context();

  configure_server_context(ctx);

  //char ipv6_address[40]="2001:470:1f15:62e:21c::2";
  //sock = create_ssl_socket(4433,ipv6_address);
  //
  BIO *sbio, *bbio, *acpt, *out;
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

  /* zone */
  const char *zone_file="../tests/testdata/fwd.homenetdns.com.db";
  ldns_zone *zone;
  int line_nr;
  FILE *zone_fp;

  //ldns_rdf *origin = NULL;
  char buf[80];

  SSL *ssl;
  int c=0;


  out = BIO_new_fp(stdout, BIO_NOCLOSE);

  printf("Reading zone file %s\n", zone_file);
  zone_fp = fopen(zone_file, "r");
  if (!zone_fp) {
    fprintf(stderr, "Unable to open %s: %s\n", zone_file, strerror(errno));
    exit(EXIT_FAILURE);
  }
  
  line_nr = 0;
  status = ldns_zone_new_frm_fp_l(&zone, zone_fp, origin, 0, LDNS_RR_CLASS_IN, &line_nr);

  if (status != LDNS_STATUS_OK) {
    printf("Zone reader failed, aborting\n");
    exit(EXIT_FAILURE);
  } else {
    printf("Read %u resource records in zone file\n", (unsigned int) ldns_zone_rr_count(zone));
  }
  fclose(zone_fp);

  // for testing only service 10 requests
  while (c<10) {
  c++;

  BIO_puts(out, "Set Up Connection\n");
  /* New SSL BIO setup as server */
  sbio=BIO_new_ssl(ctx,0);

  BIO_get_ssl(sbio, &ssl);

  if(!ssl) {
    fprintf(stderr, "Can't locate SSL pointer\n");
    abort();
  }

  /* Don't want any retries */
  SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

  /* Create the buffering BIO */
  bbio = BIO_new(BIO_f_buffer());

  /* Add openssl to the BIO chain */
  sbio = BIO_push(bbio, sbio);
  //char host_port[40]="[2001:470:1f15:62e:21c::2]:4433";
  //char host_port[40]="[fe80::2d05:39:3294:453b]:4433";
  char host_port[40]="192.168.1.18:4433";

  // Create the listening socket
  acpt=BIO_new_accept(host_port);

 /* By doing this when a new connection is established
  * we automatically have sbio inserted into it. The
  * BIO chain is now 'swallowed' by the accept BIO and
  * will be freed when the accept BIO is freed.
  */

  BIO_set_accept_bios(acpt,sbio);

  /* Setup accept BIO */
  if(BIO_do_accept(acpt) <= 0) {
    fprintf(stderr, "Error setting up accept BIO\n");
    ERR_print_errors_fp(stderr);
    return 0;
  }
  BIO_puts(out, "Waiting for Connection\n");

  /* Now wait for incoming connection */
  if(BIO_do_accept(acpt) <= 0) {
    fprintf(stderr, "Error in connection\n");
    ERR_print_errors_fp(stderr);
    return 0;
  }

  /* We only want one connection so remove and free
   * accept BIO
   */

  sbio = BIO_pop(acpt);

  BIO_free_all(acpt);

  if(BIO_do_handshake(sbio) <= 0) {
    fprintf(stderr, "Error in SSL handshake\n");
    ERR_print_errors_fp(stderr);
    return 0;
  }

  //printf("Checking cert matches soa owner %s\n","sub.homenetdns.com");
  //if(ssl_helpers_check_cert_cn(sbio, "sub.homenetdns.com") !=1) {
  //  printf ("Warning cert does not match soa owner %s\n","sub.homenetdns.com");
  //} else {
  //  printf("Cert Matches\n");
  // }

  BIO_puts(out, "Established Connection including SSL handshake\n");


  /* Handle connections */
  while(1) {
   if ( ( query_pkt=ssl_helpers_bio2pkt(sbio) )==NULL ) {
     break;
   } else {
      BIO_puts(out, "Incoming packet\n");
      ldns_pkt_print(stdout, query_pkt);

    // check the opcode and process appropriately
    // start NOTIFY
    if(ldns_pkt_get_opcode(query_pkt)==LDNS_PACKET_NOTIFY) {
      sprintf(buf, "incoming notify\n");
      BIO_puts(out, buf);

      while ( (query_answer_rr=ldns_rr_list_pop_rr(ldns_pkt_answer(query_pkt))) ){
        sprintf(buf, "processing RR\n");
        BIO_puts(out, buf);

        owner=ldns_rr_owner(query_answer_rr);
        ldns_dname_2str(buf,owner);
      }
      ldns_pkt_free(query_pkt);  
    } // end NOTIFY
    else if(ldns_pkt_get_opcode(query_pkt)==LDNS_PACKET_UPDATE) {
      // start UPDATE
      sprintf(buf, "incoming update\n");
      BIO_puts(out, buf);

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
          BIO_puts(out, buf);

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
	    if(ssl_helpers_check_cert_cn(sbio, ns_owner) !=1) {
		    printf ("Warning cert does not match RR owner %s\n",ns_owner);
	    }
	    // TODO additional checks to match the RDF of the NS RR to the owner of the A and AAAA RRs
	    strcpy(listen_string,"[\0");
	    while ( (rdf=ldns_rr_pop_rdf(query_authority_rr)) ) {
	      char *ptr;
	      ptr=ldns_rdf2str(rdf);
	      ldns_rdf_free(rdf);
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
	    if(ssl_helpers_check_cert_cn(sbio, ds_owner) !=1) {
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


      ldns_pkt_free(query_pkt);  
    } // end UPDATE
    else { // handle other queries
      sprintf(buf, "incoming query\n");
      BIO_puts(out, buf);

      query_question_rr = ldns_rr_list_rr(ldns_pkt_question(query_pkt), 0);
      if (ldns_rr_get_type(query_question_rr) == LDNS_RR_TYPE_AXFR ) {
        // answer  AXFR with a template
        sprintf(buf, "incoming AXFR\n");
        BIO_puts(out, buf);
        response_pkt =  ldns_helpers_axfr_response_new(query_pkt);
        sprintf(buf, "Created AXFR\n");
        BIO_puts(out, buf);
        ldns_pkt_free(query_pkt);  
        BIO_puts(out, "Freed query\n");
        BIO_puts(out, "Sending AXFR\n");
        ldns_pkt_print(stdout, response_pkt);
	ssl_helpers_pkt2bio(response_pkt,sbio);
        ldns_pkt_free(response_pkt);
        BIO_puts(out, "Sent AXFR\n");

        BIO_puts(out, "Done axfr\n");

      } else {
        response_qr = ldns_rr_list_new();
        ldns_rr_list_push_rr(response_qr, ldns_rr_clone(query_question_rr));

        response_an = get_rrset(zone, ldns_rr_owner(query_question_rr), ldns_rr_get_type(query_question_rr), ldns_rr_get_class(query_question_rr));
        response_pkt = ldns_pkt_new();
        response_ns = ldns_rr_list_new();
        response_ad = ldns_rr_list_new();
    
        ldns_pkt_set_qr(response_pkt, 1);
        ldns_pkt_set_aa(response_pkt, 1);
        ldns_pkt_set_id(response_pkt, ldns_pkt_id(query_pkt));

        ldns_pkt_push_rr_list(response_pkt, LDNS_SECTION_QUESTION, response_qr);
        ldns_pkt_push_rr_list(response_pkt, LDNS_SECTION_ANSWER, response_an);
        ldns_pkt_push_rr_list(response_pkt, LDNS_SECTION_AUTHORITY, response_ns);
        ldns_pkt_push_rr_list(response_pkt, LDNS_SECTION_ADDITIONAL, response_ad);

        BIO_puts(out, "Sending reponse\n");
        ldns_pkt_print(stdout, response_pkt);
	ssl_helpers_pkt2bio(response_pkt,sbio);
        BIO_puts(out, "Sent response\n");
    
        ldns_pkt_free(query_pkt);
        ldns_pkt_free(response_pkt);
        ldns_rr_list_free(response_qr);
        ldns_rr_list_free(response_an);
        ldns_rr_list_free(response_ns);
        ldns_rr_list_free(response_ad);
        BIO_puts(out, "Done other query\n");

      }
    } // other queries
   } // got query pkt
  }  // end while handle connections

  /* Since there is a buffering BIO present we had better flush it */
  BIO_flush(sbio);
  BIO_free_all(sbio);
  }

  SSL_CTX_free(ctx);
  cleanup_openssl();
}
