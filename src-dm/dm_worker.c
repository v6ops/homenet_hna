/* dm_worker.c the worker callback functions that handle the DNS queries

* Copyright (c) 2019-2025 Ray Hunter

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


// process and incoming notify packet
ldns_pkt * dm_worker_notify(ldns_pkt *notify_pkt, struct ssl_client *p_ssl_client) // 1st arg = packet, 2nd arg=SSL client (for cert)
{
  ldns_rr *query_answer_rr=NULL;
  ldns_pkt *response_pkt=NULL;
  ldns_rdf *owner=NULL;
  char buf[80];
  // some sanity checking
  if (!notify_pkt) {
    sprintf(buf, "Blank packet passed to notify\n");
    printf("%s",buf);
    return NULL;
  }
  if(ldns_pkt_get_opcode(notify_pkt)!=LDNS_PACKET_NOTIFY) {
    sprintf(buf, "Unexpected type passed to notify\n");
    printf("%s",buf);
    return NULL;
  }

  // this does nothing at the moment except print the notify RRs
  while ( (query_answer_rr=ldns_rr_list_pop_rr(ldns_pkt_answer(notify_pkt))) ){
    sprintf(buf, "processing RR\n");
    printf("%s",buf);

    owner=ldns_rr_owner(query_answer_rr);
    ldns_dname_2str(buf,owner);
    printf("%s",buf);
  }
  return response_pkt;
}

// process and incoming axfr query packet
ldns_pkt * dm_worker_query_axfr(ldns_pkt *query_pkt, struct ssl_client *p_ssl_client) // 1st arg = packet, 2nd arg=SSL client (for cert)
{
  ldns_rr *query_question_rr;
  ldns_pkt *response_pkt=NULL;
  char buf[80];

  // some sanity checking
  if (!query_pkt) {
    sprintf(buf, "Blank packet passed to AXFR\n");
    printf("%s",buf);
    return NULL;
  }
  query_question_rr = ldns_rr_list_rr(ldns_pkt_question(query_pkt), 0);
  if (ldns_rr_get_type(query_question_rr) != LDNS_RR_TYPE_AXFR ) {
    sprintf(buf, "Unexpected type passed to AXFR\n");
    printf("%s",buf);
    response_pkt=ldns_helpers_pkt_error(query_pkt,LDNS_RCODE_FORMERR);
    return response_pkt;
  }
  // answer  AXFR with a template
  response_pkt =  ldns_helpers_axfr_response_new(query_pkt);
  return response_pkt;
}

// prescan an update packet as per RFC2136 section 3.4.1 plus local policy checks
// returns an LDNS packet error code
int dm_worker_update_prescan(const ldns_pkt *p, struct ssl_client *p_ssl_client ) {
/*

   CLASS    TYPE     RDATA    TTL  Meaning
   ---------------------------------------------------------
   ANY      ANY      empty         Delete all RRsets from a name
   ANY      rrset    empty         Delete an RRset
   NONE     rrset    rr            Delete an RR from an RRset
   zone     rrset    rr            Add to an RRset

        [rr] for rr in updates
           if (zone_of(rr.name) != ZNAME)
                return (NOTZONE);

           if (rr.class == zclass)
                if (rr.type & ANY|AXFR|MAILA|MAILB) // add must be specific type
                     return (FORMERR)

           elsif (rr.class == ANY)
                if (rr.ttl != 0 || rr.rdlength != 0 // delete must have no rdata and ttl==0
                    || rr.type & AXFR|MAILA|MAILB)  // these types cannot be deleted
                     return (FORMERR)

           elsif (rr.class == NONE)
                if (rr.ttl != 0 || rr.type & ANY|AXFR|MAILA|MAILB) // specific RR to delete must have ttl==0
                     return (FORMERR)

           else   // rr.class!=zclass||ANY||NONE
                return (FORMERR)
*/

  char rr_owner[ldns_helpers_max_buffer_size]="\0";
  ldns_pkt_opcode l_opcode=0; // check this is an update packet. Otherwise we shouldn't have got here.
  l_opcode=ldns_pkt_get_opcode(p);
  if (l_opcode !=  LDNS_PACKET_UPDATE) {
    printf("dm_tofu_update_prescan: unexpected opcode in update packet. %i\n",l_opcode);
    return LDNS_RCODE_FORMERR;
  }

  // get the zone name from the question/zone section
  char zname[LDNS_MAX_DOMAINLEN];
  // check there is exactly 1 RR in the zone/question section
  uint16_t l_qdcount=ldns_pkt_qdcount(p);
  if (l_qdcount!=1) {
    printf("dm_tofu_update_prescan: unexpected number of zones in zone/question section. %i\n",l_qdcount);
    return LDNS_RCODE_FORMERR;
  }

  ldns_rr_list *l_rr_question_list;
  l_rr_question_list=ldns_pkt_question(p);
  if (l_rr_question_list==NULL) { // if there no zone list
    printf("dm_tofu_update_prescan: no zone list in zone/question section. %i\n",l_qdcount);
    return LDNS_RCODE_FORMERR;
  }
  uint16_t l_nscount=ldns_pkt_nscount(p);
  if (l_nscount<1) {
    printf("dm_tofu_update_prescan: unexpected number of rr in update/authority section. %i\n",l_nscount);
    return LDNS_RCODE_FORMERR;
  }
  ldns_rr_list *l_rr_auth_list;
  l_rr_auth_list=ldns_pkt_authority(p);
  if (l_rr_auth_list==NULL) { // if there no update list
    printf("dm_tofu_update_prescan: no update list in update/authority section. %i\n",l_nscount);
    return LDNS_RCODE_FORMERR;
  }
  ldns_rr *l_rr_zone;
  l_rr_zone=ldns_rr_list_rr(l_rr_question_list,0);
  if (l_rr_zone==NULL) { // if there's no 1st element
    printf("dm_tofu_update_prescan: no zone in question section. %i\n",l_qdcount);
    return LDNS_RCODE_FORMERR;
  }
  uint16_t l_rdcount=ldns_rr_rd_count(l_rr_zone);
  if (l_rdcount!=0) { // if there's rdata in the soa
    printf("dm_tofu_update_prescan: unexpected number of rdf in zone. %i\n",l_rdcount);
    return LDNS_RCODE_FORMERR;
  }
  if (ldns_rr_get_type(l_rr_zone) != LDNS_RR_TYPE_SOA ) { // if the rr isn't a SOA
    printf("dm_tofu_update_prescan: rdf in zone is not a SOA. %i\n",l_rdcount);
    return LDNS_RCODE_FORMERR;
  }

  ldns_buffer *buf1=ldns_buffer_new(LDNS_MAX_DOMAINLEN);
  ldns_rdf *zrdf=ldns_rr_owner(l_rr_zone);
  ldns_status l_status = ldns_rdf2buffer_str_dname(buf1, zrdf);
  if (l_status!=LDNS_STATUS_OK ) {
    return LDNS_RCODE_FORMERR;
  }
  char *tmp1=ldns_buffer_export2str(buf1);
  strcpy(zname,tmp1);
  ldns_buffer_free(buf1); // doesn't free buffer data
  LDNS_FREE(tmp1);

  ldns_rr_class zclass=ldns_rr_get_class (l_rr_zone);
  // we only serve class IN as our own local policy decision
  if (zclass!=LDNS_RR_CLASS_IN) {
    printf("dm_tofu_update_prescan: don't serve this class. %i\n",zclass);
    return LDNS_RCODE_REFUSED;
  }

  printf("zname %s zclass %i\n",zname,zclass);

  // Check zname is contained in one of our parents.
#ifdef WITH_TOFU
  //char *my_parent=dm_tofu_get_parent(p_ssl_client->db, zname);
  // exact matches only for now.
  int my_parent=dm_tofu_count_parent(p_ssl_client->db, zname);
  if (my_parent!=1) {
    printf("dm_tofu_update_prescan: don't serve this parent. %s\n",zname);
    return LDNS_RCODE_NOTAUTH;
  }
#else
  // static comparison with hard coded parent
  char my_root[ldns_helpers_max_buffer_size]="homenetdns.com\0"; // parent zone is hard coded when there is no db.
  size_t len=strlen(my_root);
  if (strncmp(my_root,zname,len) !=0) {
    printf("dm_tofu_update_prescan: don't serve this parent. %s\n",zname);
    return LDNS_RCODE_NOTAUTH;
  }
#endif // WITH_TOFU

  // Step through the authority/update section
  uint16_t i;
  int seen_ns=0; // remember if an NS has been seen
  for (i=0;i<l_nscount;i++) {
    ldns_rr *rr;
    rr=ldns_rr_list_rr(l_rr_auth_list,i);
    // if (zone_of(rr.name) != ZNAME)
    //   return (NOTZONE);
    ldns_rdf *rdf=ldns_rr_owner(rr);
    if (!ldns_rr_owner(rr)) {
      return LDNS_RCODE_NOTZONE;
    }
    // the rr and zone are not equal and rr is not a subzone of zone
    if ( (ldns_dname_compare(rdf,zrdf)!=0) && (!ldns_dname_is_subdomain(rdf,zrdf)) ) {
      return LDNS_RCODE_NOTZONE;
    }

    // if (rr.class == zclass)
    //   if (rr.type & ANY|AXFR|MAILA|MAILB) // add must be specific type
    //     return (FORMERR)
    if (ldns_rr_get_class(rr) == zclass) {
      if ((ldns_rr_get_type(rr)==LDNS_RR_TYPE_ANY) || (ldns_rr_get_type(rr)==LDNS_RR_TYPE_AXFR)
           || (ldns_rr_get_type(rr)==LDNS_RR_TYPE_MAILA) || (ldns_rr_get_type(rr)==LDNS_RR_TYPE_MAILB) )  {
        return LDNS_RCODE_FORMERR;
      } else {
        // this rr is OK. nothing to do.
	// return LDNS_RCODE_NOERROR;
      }
    } else
    //  elsif (rr.class == ANY)
    //    if (rr.ttl != 0 || rr.rdlength != 0 // delete must have no rdata and ttl==0
    //        || rr.type & AXFR|MAILA|MAILB)  // these types cannot be deleted
    //      return (FORMERR)
    if (ldns_rr_get_class(rr) == LDNS_RR_CLASS_ANY) {
      if ( (ldns_rr_ttl(rr) !=0) || (ldns_rr_rd_count(rr) !=0) || ( (ldns_rr_get_type(rr)==LDNS_RR_TYPE_AXFR)
           || (ldns_rr_get_type(rr)==LDNS_RR_TYPE_MAILA) || (ldns_rr_get_type(rr)==LDNS_RR_TYPE_MAILB) ) ) {
        return LDNS_RCODE_FORMERR;
      } else {
        // this rr is OK. nothing to do.
        // return LDNS_RCODE_NOERROR;
      }
    } else
    //  elsif (rr.class == NONE)
    //    if (rr.ttl != 0 || rr.type & ANY|AXFR|MAILA|MAILB) // specific RR to delete must have ttl==0
    //      return (FORMERR)
    if (ldns_rr_get_class(rr) == LDNS_RR_CLASS_NONE) {
      if ( (ldns_rr_ttl(rr) !=0) || ( (ldns_rr_get_type(rr)==LDNS_RR_TYPE_ANY) || (ldns_rr_get_type(rr)==LDNS_RR_TYPE_AXFR)
           || (ldns_rr_get_type(rr)==LDNS_RR_TYPE_MAILA) || (ldns_rr_get_type(rr)==LDNS_RR_TYPE_MAILB) ) ) {
        return LDNS_RCODE_FORMERR;
      } else {
        // this rr is OK. nothing to do.
        // return LDNS_RCODE_NOERROR;
      }
    } else {
      return LDNS_RCODE_FORMERR;
    }

    // *** local policy ***
    // from name delegation draft
    // this could be more efficient, but wanted to preserve non tofu code.
    //
    if ( (ldns_rr_get_type(rr)==LDNS_RR_TYPE_NS) ) {
      seen_ns++;
    } 

   
    // check certificate DN against text version of owner of the DS NS RR
    if ( (ldns_rr_get_type(rr)==LDNS_RR_TYPE_NS) || (ldns_rr_get_type(rr)==LDNS_RR_TYPE_DS) ) {
      ldns_buffer *buf2=ldns_buffer_new(LDNS_MAX_DOMAINLEN);
      l_status = ldns_rdf2buffer_str_dname(buf2, ldns_rr_owner(rr));
      if (l_status!=LDNS_STATUS_OK ) {
         return LDNS_RCODE_FORMERR;
      }
      char *tmp2=ldns_buffer_export2str(buf2);
      strcpy(rr_owner,tmp2);
      ldns_buffer_free(buf2); // doesn't free buffer data
      LDNS_FREE(tmp2); // free the buffer data
      if (p_ssl_client->ssl==NULL) {
        printf("WARNING: no SSL connection. Not Checking cert matches RR owner %s\n",rr_owner);
      } else {
        printf("Checking cert matches RR owner %s\n",rr_owner);
        if(ssl_helpers_check_cert_cn(p_ssl_client->ssl, rr_owner) !=1) {
          printf ("Warning cert does not match RR owner %s\n",rr_owner);
          return LDNS_RCODE_REFUSED;
        }
      }
#ifdef WITH_TOFU
      // Also check whether we know this zone in the database.
      // Future versions might allow dynamic zone creation, but currently we pre-create zones to rate limit
      int zone_id=dm_tofu_select_zone_id(p_ssl_client->db, rr_owner);
      if (zone_id<1) {
        printf("Warning: RR with unknown zone in authority section\n");
        return LDNS_RCODE_REFUSED; // RR for a domain we don't know
      }
#endif // end WITH_TOFU
    } // end type = NS || DS
#ifdef WITH_TOFU
    else if ( (ldns_rr_get_type(rr)==LDNS_RR_TYPE_AAAA) ) {
      // must match an existing NS. Possible use for renumbering.
      // TODO
    }
    // we also accept TXT without a cert
    else if ( (ldns_rr_get_type(rr)==LDNS_RR_TYPE_TXT) ) {
      // get the owner and check against IP of this session in the infra table (which was updated by the offer request)
      // also implies zone is known in the db.
      ldns_buffer *buf3=ldns_buffer_new(LDNS_MAX_DOMAINLEN);
      l_status = ldns_rdf2buffer_str_dname(buf3, ldns_rr_owner(rr));
      if (l_status!=LDNS_STATUS_OK ) {
         return LDNS_RCODE_FORMERR;
      }
      char *tmp3=ldns_buffer_export2str(buf3);
      strcpy(rr_owner,tmp3);
      ldns_buffer_free(buf3); // doesn't free buffer data
      LDNS_FREE(tmp3); // free the buffer data
      printf("Checking client ip matches previous ip of offer request %s\n",rr_owner);
      if (dm_tofu_check_txt_tofu(rr_owner, p_ssl_client) !=0) {
          printf ("Warning ip does not match ip of offer request %s\n",rr_owner);
          return LDNS_RCODE_REFUSED;
      }
    }
#endif // end WITH_TOFU

    else { // we don't know what to do with this RR
      printf ("Warning unknown RR TYPE in update: %i.\n",ldns_rr_get_type(rr));
      return LDNS_RCODE_REFUSED;
    }

      
  } // end NS for loop
    
  // Check NS from update section and AAAA from additional section match up if NS seen.
  // NS have all been checked before here. Done this way to avoid alloc & free linked lists
  if (seen_ns==1) { //process additional section
    ldns_rr *query_additional_rr;
    uint16_t l_arcount=ldns_pkt_arcount(p);

    for (i=0;i<l_arcount;i++) {
      query_additional_rr=ldns_rr_list_rr(ldns_pkt_additional(p),i);
      if ( (ldns_rr_get_type(query_additional_rr)==LDNS_RR_TYPE_AAAA) ) {
	 printf("Warning: non AAAA RR in additional section\n");
         return LDNS_RCODE_FORMERR;
      } 
      ldns_rdf *rr_aaaa_rdf=ldns_rr_owner(query_additional_rr);
      uint16_t j;
      int related_ns=0; // flag if there is a related ns found
      for (j=0;j<l_nscount;j++) {
        ldns_rr *query_authority_rr=ldns_rr_list_rr(ldns_pkt_authority(p),j);
	size_t rd_count=ldns_rr_rd_count(query_authority_rr);
	size_t k=0;
        for (k=0;k<rd_count;k++) {
	  ldns_rdf *ns_rdf=ldns_rr_rdf(query_authority_rr,k);
	  if (ldns_rdf_get_type(ns_rdf) != LDNS_RDF_TYPE_DNAME) {
            continue;
	  }
	  if (ldns_rdf_compare(ns_rdf,rr_aaaa_rdf) ==0 ) { // check if the AAAA owner matches an RDF in the NS
            related_ns=1;
	    break;
          }
	} // for RDF in NS RR
      } // for authoritive RR
      if (related_ns != 1) {
        printf("Warning: AAAA RR in additional section without matchin NS\n");
      return LDNS_RCODE_REFUSED;
      }
    } // for additional RR
  } // end seen_ns=1

  // all checks passed
  return LDNS_RCODE_NOERROR;
}

// process and incoming update packet
ldns_pkt * dm_worker_update(ldns_pkt *update_pkt, struct ssl_client *p_ssl_client) // 1st arg = packet, 2nd arg=SSL client (for cert)
{
  ldns_pkt *response_pkt=NULL;
  char buf[80];

  ldns_rr *query_authority_rr;
  ldns_rdf *soa_owner_rdf;
  char soa_owner[ldns_helpers_max_buffer_size]="\0";
  //char ns_data[ldns_helpers_max_buffer_size]="\0";

  // some sanity checking
  if (!update_pkt) {
    sprintf(buf, "Blank packet passed to update\n");
    printf("%s",buf);
    return NULL;
  }

  // perform prescan checks on the incoming update packet
  int l_error=dm_worker_update_prescan(update_pkt, p_ssl_client);
  if (l_error != LDNS_RCODE_NOERROR) {
    response_pkt=ldns_helpers_pkt_error(update_pkt,l_error); // we reject this packet so don't process further
    return response_pkt;
  }

  printf("Incoming update passed sanity checks\n");
  soa_owner_rdf=ldns_rr_owner(ldns_rr_list_rr(ldns_pkt_question(update_pkt),0));
  ldns_dname_2str(soa_owner,soa_owner_rdf);

  // check if we have DS or NS in the Authority

  uint16_t l_nscount=0;
  l_nscount=ldns_pkt_nscount(update_pkt);
  uint16_t i=0;
#ifdef WITH_TOFU
  time_t slot_time=get_time_slot(0);
  int seen_ns=0;
  char rr_owner[ldns_helpers_max_buffer_size]="\0";
  while (i<l_nscount) {
    query_authority_rr=ldns_rr_list_rr(ldns_pkt_authority(update_pkt),i);
    ldns_rdf *rr_owner_rdf=ldns_rr_owner(query_authority_rr);
    ldns_dname_2str(rr_owner,rr_owner_rdf);
    char *zone_name=dm_tofu_get_zone(p_ssl_client->db, rr_owner);
    if (zone_name==NULL) {
      continue; // this should have been picked up in prescan
    }
    int zone_id=dm_tofu_select_zone_id(p_ssl_client->db, zone_name);
    free(zone_name);
    zone_name=NULL;
    if (zone_id<1) {
      continue; // also should be picked up in prescan
    }
    if (ldns_rr_get_type(query_authority_rr) == LDNS_RR_TYPE_NS ) {
      seen_ns=1; // remember whether an NS has been seen. If so process addtional section.
    }
    int res=dm_tofu_insert_rr(p_ssl_client->db, zone_id, query_authority_rr, slot_time) ;
    if (res !=LDNS_RCODE_NOERROR) {
      printf("Unexpected error when inserting into db %u\n",res);
      break;
    }
    i++;
  } // while RR
  if (seen_ns==1) { //process additional section
    uint16_t l_arcount=0;
    ldns_rr *query_additional_rr;
    l_arcount=ldns_pkt_arcount(update_pkt);
    i=0;
    while (i<l_arcount) {
      query_additional_rr=ldns_rr_list_rr(ldns_pkt_additional(update_pkt),i);
      ldns_rdf *rr_owner_rdf=ldns_rr_owner(query_additional_rr);
      ldns_dname_2str(rr_owner,rr_owner_rdf);
      char *zone_name=dm_tofu_get_zone(p_ssl_client->db, rr_owner);
      if (zone_name==NULL) {
        continue; // this should have been picked up in prescan
      }
      int zone_id=dm_tofu_select_zone_id(p_ssl_client->db, zone_name);
      free(zone_name);
      zone_name=NULL;
      if (zone_id<1) {
        continue; // also should be picked up in prescan
      }
      int res=dm_tofu_insert_rr(p_ssl_client->db, zone_id, query_additional_rr, slot_time) ;
      if (res !=LDNS_RCODE_NOERROR) {
        printf("Unexpected error when inserting into db %u\n",res);
        break;
      }
      i++;
    }
  } // while addtional RR
#else // no WITH_TOFU
  char ns_owner[ldns_helpers_max_buffer_size]="\0";
  ldns_rdf *ns_owner_rdf;
  char ds_owner[ldns_helpers_max_buffer_size]="\0";
  ldns_rdf  *owner;
  ldns_rdf *rdf;
  char listen_string[ldns_helpers_max_buffer_size]="\0";
  while (i<l_nscount) {
    query_authority_rr=ldns_rr_list_rr(ldns_pkt_authority(update_pkt),i);

    sprintf(buf, "processing RR\n");
    printf("%s",buf);

    // NS Update
    if (ldns_rr_get_type(query_authority_rr) == LDNS_RR_TYPE_NS ) {
      printf("Got an NS RR in the authority section\n");
      ns_owner_rdf=ldns_rr_owner(query_authority_rr);
      ldns_dname_2str(ns_owner,ns_owner_rdf);
      ldns_helpers_strip_trailing_dot(ns_owner);
      printf("NS RR Owner %s\n",ns_owner);
      // additional checks to match the RDF of the NS RR to the owner of the A and AAAA RRs is done in ldns_helpers_rr_list2listen_string
      strcpy(listen_string,"[\0");
      while ( (rdf=ldns_rr_pop_rdf(query_authority_rr)) ) {
        char *ptr;
        ptr=ldns_rdf2str(rdf);
        ldns_helpers_rdf_free(rdf);
        printf("Checking RDF %s from additional section\n",ptr);

        ldns_helpers_rr_list2listen_string(ldns_pkt_additional(update_pkt),ptr,listen_string);
	LDNS_FREE(ptr);
      }
      strcat(listen_string,"]\0");
      //printf("Listen String %s\n",listen_string);
      if (strlen(listen_string)>2) {
        printf("Saving %s %s from additional section\n",ns_owner,listen_string);
        fork_make_knot_dm_config(ns_owner,listen_string);
      }
      printf("Saved NS\n");

    // DS Update
    } else if (ldns_rr_get_type(query_authority_rr) == LDNS_RR_TYPE_DS ) {
      printf("Got an DS RR in the authority section\n");
      owner=ldns_rr_owner(query_authority_rr);
      ldns_dname_2str(ds_owner,owner);
      ldns_helpers_strip_trailing_dot(ds_owner);
      printf("Owner %s\n",ds_owner);
      printf("Saving DS\n");
      ldns_rr_print(stdout,query_authority_rr);
      char *rr_ptr;
      rr_ptr=ldns_rr2str(query_authority_rr);
      fork_make_knot_dm_ds(rr_ptr);
      LDNS_FREE(rr_ptr);
      printf("Saved DS\n");
    }
    i++;
  } // while RR
#endif // end WITH_TOFU
  // we're done. return no error.
  response_pkt=ldns_helpers_pkt_error(update_pkt,LDNS_RCODE_NOERROR);
  return response_pkt;
}

//int dm_worker(dm_query_t * dm_query)
int dm_worker(struct ssl_client *p_ssl_client)
{
  /* dns */
  ldns_pkt *query_pkt;
  //ldns_rr_list *query_answer_section;
  //ldns_rr *query_answer_rr;
  //ldns_rr *query_authority_rr;
  //ldns_rdf  *owner;
  ldns_status status;
  ldns_pkt *response_pkt=NULL;
  ldns_rr *query_question_rr;
  ldns_rr_list *response_qr;
  ldns_rr_list *response_an;
  ldns_rr_list *response_ns;
  ldns_rr_list *response_ad;

  ldns_rdf *origin = NULL;
  ldns_str2rdf_dname(&origin, "homenetdns.com");
  char buf[80];

  struct timeval rx; // arrival time of the packet
  gettimeofday(&rx,NULL);

  /* load base zone from file for unknown queries */
  const char *zone_file="../tests/testdata/fwd.homenetdns.com.db";
  ldns_zone *zone;
  zone=ldns_helpers_zone_read(zone_file);

  /* Import DNS packet from the wire and handle query */
  status=ldns_wire2pkt(&query_pkt,(const uint8_t*)p_ssl_client->query,p_ssl_client->query_len);
  if (status!=LDNS_STATUS_OK ) {
     // there was no packet. Do nothing.
     printf( "Invalid incoming packet.\n");
     return 1;
  }

  // We have a valid packet. Process it.
  printf( "Incoming packet\n");
  ldns_pkt_print(stdout, query_pkt);

  // check the opcode and process appropriately
  //
  // start NOTIFY
  if(ldns_pkt_get_opcode(query_pkt)==LDNS_PACKET_NOTIFY) {
    sprintf(buf, "incoming notify\n");
    printf("%s",buf);
    response_pkt=dm_worker_notify(query_pkt,p_ssl_client);
  } // end NOTIFY
  else if(ldns_pkt_get_opcode(query_pkt)==LDNS_PACKET_UPDATE) {
    // start UPDATE
    sprintf(buf, "incoming update\n");
    printf("%s",buf);
    response_pkt=dm_worker_update(query_pkt,p_ssl_client);
        
  } // end UPDATE
  else if(ldns_pkt_get_opcode(query_pkt)==LDNS_PACKET_QUERY) {
    sprintf(buf, "incoming query\n");
    printf("%s",buf);

    query_question_rr = ldns_rr_list_rr(ldns_pkt_question(query_pkt), 0);
    if (ldns_rr_get_type(query_question_rr) == LDNS_RR_TYPE_AXFR ) {
      // answer  AXFR with a template
      sprintf(buf, "incoming AXFR\n");
      printf("%s",buf);
      response_pkt=dm_worker_query_axfr(query_pkt,p_ssl_client);
      sprintf(buf, "Created AXFR\n");
      printf("%s",buf);
      printf( "Done axfr\n");

#ifdef WITH_TOFU
    // we also answer special PTR queries with a synthesized response from the mysql db
    } else if (ldns_rr_get_type(query_question_rr) == LDNS_RR_TYPE_PTR ) {
      // answer PTR with a potentially delegated zone
      sprintf(buf, "incoming PTR\n");
      printf("%s",buf);
      response_pkt=dm_worker_query_ptr(query_pkt,p_ssl_client);
      sprintf(buf, "Created PTR\n");
      printf("%s",buf);
      printf( "Done PTR\n");
#endif


    } else {
      sprintf(buf, "incoming other query\n");
      printf("%s",buf);
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

    }
  } // end QUERY
  else { // handle other queries
    sprintf(buf, "Incoming request not implemented\n");
    printf("%s",buf);
  } // other queries

  // if we have a response packet, send it
  if (response_pkt) {
    printf( "Sending response\n");
    ldns_helpers_pkt_set_times(response_pkt,&rx,NULL);
    ldns_pkt_print(stdout, response_pkt);
    write_ldns_pkt_to_wire(p_ssl_client, response_pkt);
    printf( "Sent response\n");
    ldns_helpers_pkt_free(response_pkt);
  } else {
    printf( "No response\n");
  }
  ldns_helpers_pkt_free(query_pkt);
  return 0;
}
