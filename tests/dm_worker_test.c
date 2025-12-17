/* dm_worker_test.c 

* Copyright (c) 2025 Ray Hunter

*/
#include "dm_worker_test.h"
#include "test_harness.h"

#include <CUnit/CUnit.h>

ldns_pkt * create_update_pkt(const char *parent_name, ldns_rr_list *updates, ldns_rr_list *additional) {
  ldns_rr_list *prerequisites=ldns_rr_list_new();
  ldns_rdf *ldns_zone_dname = NULL;
  ldns_str2rdf_dname(&ldns_zone_dname ,parent_name);
  ldns_pkt *update= ldns_update_pkt_new(ldns_zone_dname, LDNS_RR_CLASS_IN, prerequisites, updates, additional);

  if (additional == NULL) {
    additional=ldns_rr_list_new();
  }
  // set QD to one question (the zone to update)
  ldns_pkt_set_qdcount(update,1);
  // set NS to one update (the RR to update)
  ldns_pkt_set_nscount(update,1);
  // Set random ID for the query
  ldns_pkt_set_random_id(update);
  // Clear RD (Recursion Desired) flag
  ldns_pkt_set_rd(update, false);
  // Clear QR (Question Response) flag
  ldns_pkt_set_qr(update, false);
  // ldns_helpers_pkt_set_times(update,NULL,NULL);
  update->timestamp.tv_sec = 1763551210; // hard coded for testing to ease compare
  update->timestamp.tv_usec = 0;
  ldns_pkt_set_id(update, 0x1); // hard coded for testing to ease compare
  // ldns_update_pkt_new clones the rr_list so free before returning
  if (prerequisites!=NULL) {
    ldns_rr_list_deep_free(prerequisites);
  }
  if (updates!=NULL) {
    ldns_rr_list_deep_free(updates);
  }
  if (additional!=NULL) {
    ldns_rr_list_deep_free(additional);
  }
  return update;
}

void dm_worker_test(void) {

  MYSQL *db;
  ldns_rr *rr=NULL;
  ldns_rdf *prev=NULL;
  ldns_status l_status=LDNS_RCODE_NOERROR;
  int ret;
  ldns_rdf *origin = NULL;

  CU_ASSERT(0 == 0);

  printf("start test_dm_worker\n");
  db=testdb_init();
  testdb_connect(db);
  CU_ASSERT( db!=NULL );

  printf("Reset knot: this may display errors if the zones don't exist from previous tests\n");
  exec_bash("./testdata/reset_knot.bash");

  printf("Reset test db\n");
  set_testdb("./testdata/reset_testdb.sql");
  printf("Add additional test data to db\n");
  set_testdb("./testdata/dm_worker_add_testdata.sql");
  printf("continue test_dm_worker\n");
  // check the test harness is working OK
  CU_ASSERT(0==cmp_file("./testdata/key.pem","./testdata/key.pem"));
  CU_ASSERT(0!=cmp_file("./testdata/key.pem","./testdata/fullchain.pem"));
  get_testdb("./testdata/got_dm_worker_testdb.sql");
  CU_ASSERT(0==cmp_file("./testdata/expected_dm_worker_testdb.sql","./testdata/got_dm_worker_testdb.sql"));

  ldns_pkt *input_pkt_ds;
  ldns_pkt *input_pkt_ns;
  ldns_pkt *input_pkt_txt;
  ldns_pkt *input_pkt_aaaa;
  ldns_pkt *input_pkt_aaaa2;
  ldns_pkt *output_pkt;

  // spoof test ssl object
  struct ssl_client *p_ssl_client;
  if ((p_ssl_client = (struct ssl_client *) malloc(sizeof(*p_ssl_client))) == NULL) {
    printf("failed to allocate memory for SSL client state\n");
    exit(0);
  }
  memset(p_ssl_client, 0, sizeof(*p_ssl_client));
  p_ssl_client->db=db;
  p_ssl_client->ssl=NULL;

  // DS 
  /*
  input_pkt_ds=ldns_helpers_ds_update_new("linear.realm.piece.floor.example.com","example.com","");
  ldns_pkt_print(stdout,input_pkt_ds);
  l_status=dm_worker_update_prescan(input_pkt_ds,p_ssl_client);
  printf("l_status: %i\n",l_status);
  CU_ASSERT(LDNS_RCODE_NOERROR==l_status);
  ldns_helpers_pkt_free(input_pkt_ds);
  */

  // create an TXT PKT
  printf("start TXT\n");
  char *rr_string_txt = "_acme-challenge.device.vertex.deck.glad.example.com.  600     IN	TXT	\"Welcome to the example domain!\"";
  ldns_rr *txt_rr=NULL;
  ldns_rr_list *txt_rr_list=ldns_rr_list_new();
  l_status = ldns_rr_new_frm_str(&txt_rr,rr_string_txt,600,origin,&prev);
  if (prev!=NULL) {
    ldns_rdf_deep_free(prev);
    prev=NULL;
  }
  ldns_rr_set_push_rr(txt_rr_list,txt_rr);
  CU_ASSERT(LDNS_STATUS_OK==l_status);
  ldns_rr_print(stdout, txt_rr);
  input_pkt_txt=create_update_pkt("example.com.",txt_rr_list,NULL);
  // first check the packet is as expected
  FILE *fptr_txt=fopen("./testdata/got_dm_worker_pkt_txt.txt","w");
  CU_ASSERT(NULL!=fptr_txt);
  ldns_pkt_print(fptr_txt,input_pkt_txt);
  fclose(fptr_txt);
  CU_ASSERT(0==cmp_file("./testdata/got_dm_worker_pkt_txt.txt","./testdata/expected_dm_worker_pkt_txt.txt"));

  // test prescan. This will fail on no IP on ssl
  char *zone_name1=dm_tofu_get_zone(db,"_acme-challenge.device.vertex.deck.glad.example.com");
  CU_ASSERT(zone_name1!=NULL);
  if (zone_name1 !=NULL) {
    CU_ASSERT(0==(strcmp(zone_name1,"device.vertex.deck.glad.example.com")));
    free(zone_name1);
  }


  l_status=dm_worker_update_prescan(input_pkt_txt,p_ssl_client);
  printf("l_status: %i\n",l_status);
  CU_ASSERT(LDNS_RCODE_REFUSED==l_status);
  // ldns_helpers_pkt_free(input_pkt_txt);

  // change the client ip and retest. will still fail because ip doesn't match the offer for this zone.
  strcpy(p_ssl_client->client_addr,"2001:2::1");
  l_status=dm_worker_update_prescan(input_pkt_txt,p_ssl_client);
  printf("l_status: %i\n",l_status);
  CU_ASSERT(LDNS_RCODE_REFUSED==l_status);
  // ldns_helpers_pkt_free(input_pkt_txt);

  // change the client ip and retest. will succeed.
  strcpy(p_ssl_client->client_addr,"2001:4::1");
  l_status=dm_worker_update_prescan(input_pkt_txt,p_ssl_client);
  printf("l_status: %i\n",l_status);
  CU_ASSERT(LDNS_RCODE_NOERROR==l_status);
  ldns_helpers_pkt_free(input_pkt_txt);

  // create an DS PKT
  printf("start DS\n");
  char *rr_string_ds = "jaguar.oak.guess.lord.example.com.  600     IN      DS      26160 5 2 ce0eb9e59ee1de2c681a330e3a7c08376f28602cdf990ee4ec88d2a8bdb51539";
  ldns_rr *ds_rr=NULL;
  ldns_rr_list *ds_rr_list=ldns_rr_list_new();
  l_status = ldns_rr_new_frm_str(&ds_rr,rr_string_ds,600,origin,&prev);
  if (prev!=NULL) {
    ldns_rdf_deep_free(prev);
    prev=NULL;
  }
  ldns_rr_set_push_rr(ds_rr_list,ds_rr);
  CU_ASSERT(LDNS_STATUS_OK==l_status);
  ldns_rr_print(stdout, ds_rr);
  input_pkt_ds=create_update_pkt("example.com.",ds_rr_list,NULL);
  // test prescan
  FILE *fptr_ds=fopen("./testdata/got_dm_worker_pkt_ds.txt","w");
  CU_ASSERT(NULL!=fptr_ds);
  ldns_pkt_print(fptr_ds,input_pkt_ds);
  fclose(fptr_ds);
  CU_ASSERT(0==cmp_file("./testdata/got_dm_worker_pkt_ds.txt","./testdata/expected_dm_worker_pkt_ds.txt"));
  l_status=dm_worker_update_prescan(input_pkt_ds,p_ssl_client);
  printf("l_status: %i\n",l_status);
  CU_ASSERT(LDNS_RCODE_NOERROR==l_status);
  ldns_helpers_pkt_free(input_pkt_ds);

  // NS 
  input_pkt_ns=ldns_helpers_ns_update_new("linear.realm.piece.floor.example.com","example.com","");
  printf("start NS\n");
  ldns_pkt_print(stdout,input_pkt_ns);
  l_status=dm_worker_update_prescan(input_pkt_ns,p_ssl_client);
  printf("l_status: %i\n",l_status);
  CU_ASSERT(LDNS_RCODE_NOERROR==l_status);
  ldns_helpers_pkt_free(input_pkt_ns);

  // create an AAAA PKT. Generally AAAA would be associated directly with an NS via the additional section, but could be useful for renumbering events
  printf("start AAAA\n");
  char *rr_string_aaaa = "www.example.com.	600	IN	AAAA 2001:470:1f15:62e:21c:c4ff:fec9:de16";
  ldns_rr *aaaa_rr=NULL;
  ldns_rr_list *aaaa_rr_list=ldns_rr_list_new();
  l_status = ldns_rr_new_frm_str(&aaaa_rr,rr_string_aaaa,600,origin,&prev);
  if (prev!=NULL) {
    ldns_rdf_deep_free(prev);
    prev=NULL;
  }
  ldns_rr_set_push_rr(aaaa_rr_list,aaaa_rr);
  CU_ASSERT(LDNS_STATUS_OK==l_status);
  ldns_rr_print(stdout, aaaa_rr);
  input_pkt_aaaa=create_update_pkt("example.com.",aaaa_rr_list,NULL);
  // test prescan
  FILE *fptr_aaaa=fopen("./testdata/got_dm_worker_pkt_aaaa.txt","w");
  CU_ASSERT(NULL!=fptr_aaaa);
  ldns_pkt_print(fptr_aaaa,input_pkt_aaaa);
  fclose(fptr_aaaa);
  CU_ASSERT(0==cmp_file("./testdata/got_dm_worker_pkt_aaaa.txt","./testdata/expected_dm_worker_pkt_aaaa.txt"));
  l_status=dm_worker_update_prescan(input_pkt_aaaa,p_ssl_client);
  printf("l_status: %i\n",l_status);
  CU_ASSERT(LDNS_RCODE_REFUSED==l_status); // www.example.com has no existing NS
  ldns_helpers_pkt_free(input_pkt_aaaa);

  
  // create a valid AAAA PKT.
  char *rr_string_aaaa2 = "dm1.linear.realm.piece.floor.example.com.	600	IN	AAAA 2001:470:1f15:62e:21c:c4ff:fec9:de16";
  ldns_rr *aaaa_rr2=NULL;
  ldns_rr_list *aaaa_rr_list2=ldns_rr_list_new();
  l_status = ldns_rr_new_frm_str(&aaaa_rr2,rr_string_aaaa2,600,origin,&prev);
  if (prev!=NULL) {
    ldns_rdf_deep_free(prev);
    prev=NULL;
  }
  ldns_rr_set_push_rr(aaaa_rr_list2,aaaa_rr2);
  CU_ASSERT(LDNS_STATUS_OK==l_status);
  ldns_rr_print(stdout, aaaa_rr2);
  input_pkt_aaaa2=create_update_pkt("example.com.",aaaa_rr_list2,NULL);
  // test prescan
  FILE *fptr_aaaa2=fopen("./testdata/got_dm_worker_pkt_aaaa2.txt","w");
  CU_ASSERT(NULL!=fptr_aaaa2);
  ldns_pkt_print(fptr_aaaa2,input_pkt_aaaa2);
  fclose(fptr_aaaa2);
  CU_ASSERT(0==cmp_file("./testdata/got_dm_worker_pkt_aaaa2.txt","./testdata/expected_dm_worker_pkt_aaaa2.txt"));
  l_status=dm_worker_update_prescan(input_pkt_aaaa2,p_ssl_client);
  printf("l_status: %i\n",l_status);
  CU_ASSERT(LDNS_RCODE_NOERROR==l_status); // dm1.linear.realm.piece.floor.example.com has an existing NS
  ldns_helpers_pkt_free(input_pkt_aaaa2);

  
  
  
  goto the_end; // skip further tests
  
  // create an AAAA RR
  char *rr_string2 = "www.example.com.	600	IN	AAAA 2001:470:1f15:62e:21c:c4ff:fec9:de16";
  l_status = ldns_rr_new_frm_str(&rr,rr_string2,600,origin,&prev);
  CU_ASSERT(LDNS_STATUS_OK==l_status);
  ldns_rr_print(stdout, rr);

  char *str = ldns_rr2str_fmt(ldns_output_format_default, rr);
  if (str) {
    printf("RR %s", str);
    CU_ASSERT(0==cmp_array(str,"www.example.com.	600	IN	AAAA	2001:470:1f15:62e:21c:c4ff:fec9:de16\n",strlen(str)));
    LDNS_FREE(str);
  }
  // inserting to the DB with success
  // ret=dm_tofu_insert_rr(db,1,rr,1762328400);

  CU_ASSERT(LDNS_RCODE_NOERROR==ret); // 1 record inserted

  ldns_rr_free(rr);
  rr=NULL;
  if (prev) {
    ldns_rdf_deep_free(prev);
    prev=NULL;
  }
  get_testdb("./testdata/got_dm_worker101.sql");
  CU_ASSERT(0==cmp_file("./testdata/got_dm_worker101.sql","./testdata/expected_dm_worker101.sql"));



  // create an NS RR
  char *rr_string4 = "www.example.com.	600	IN	NS ns1.zone1.homenetinfra.com.";
  l_status = ldns_rr_new_frm_str(&rr,rr_string4,600,origin,&prev);
  CU_ASSERT(LDNS_STATUS_OK==l_status);
  ldns_rr_print(stdout, rr);

  str = ldns_rr2str_fmt(ldns_output_format_default, rr);
  if (str) {
    printf("RR %s", str);
    CU_ASSERT(0==cmp_array(str,"www.example.com.	600	IN	NS	ns1.zone1.homenetinfra.com.\n",strlen(str)));
    LDNS_FREE(str);
  }
  // inserting to the DB with success
  // ret=dm_tofu_insert_rr(db,1,rr,1762328400);

  CU_ASSERT(LDNS_RCODE_NOERROR==ret); // 1 record inserted

  ldns_rr_free(rr);
  rr=NULL;
  if (prev) {
    ldns_rdf_deep_free(prev);
    prev=NULL;
  }

  get_testdb("./testdata/got_dm_worker102.sql");
  CU_ASSERT(0==cmp_file("./testdata/got_dm_worker102.sql","./testdata/expected_dm_worker102.sql"));


  // create an TXT RR
  char *rr_string5 = "www.example.com.	600	IN	TXT	\"Welcome to the example domain!\"";
  l_status = ldns_rr_new_frm_str(&rr,rr_string5,600,origin,&prev);
  CU_ASSERT(LDNS_STATUS_OK==l_status);
  ldns_rr_print(stdout, rr);

  str = ldns_rr2str_fmt(ldns_output_format_default, rr);
  if (str) {
    printf("RR %s", str);
    CU_ASSERT(0==cmp_array(str,"www.example.com.	600	IN	TXT	\"Welcome to the example domain!\"\n",strlen(str)));
    LDNS_FREE(str);
  }
  // inserting to the DB with success
  // ret=dm_tofu_insert_rr(db,1,rr,1762328400);

  CU_ASSERT(LDNS_RCODE_NOERROR==ret); // 1 record inserted

  ldns_rr_free(rr);
  rr=NULL;
  if (prev) {
    ldns_rdf_deep_free(prev);
    prev=NULL;
  }

  get_testdb("./testdata/got_dm_worker103.sql");
  CU_ASSERT(0==cmp_file("./testdata/got_dm_worker103.sql","./testdata/expected_dm_worker103.sql"));


  // create an DS RR
  char *rr_string6 = "www.example.com.	600	IN	DS      26160 5 2 ce0eb9e59ee1de2c681a330e3a7c08376f28602cdf990ee4ec88d2a8bdb51539";
  l_status = ldns_rr_new_frm_str(&rr,rr_string6,600,origin,&prev);
  CU_ASSERT(LDNS_STATUS_OK==l_status);
  ldns_rr_print(stdout, rr);

  str = ldns_rr2str_fmt(ldns_output_format_default, rr);
  if (str) {
    printf("RR %s", str);
    CU_ASSERT(0==cmp_array(str,"www.example.com.	600	IN	DS	26160 5 2 ce0eb9e59ee1de2c681a330e3a7c08376f28602cdf990ee4ec88d2a8bdb51539\n",strlen(str)));
    LDNS_FREE(str);
  }
  // inserting to the DB with success
  // ret=dm_tofu_insert_rr(db,1,rr,1762328400);

  CU_ASSERT(LDNS_RCODE_NOERROR==ret); // 1 record inserted

  ldns_rr_free(rr);
  rr=NULL;
  if (prev) {
    ldns_rdf_deep_free(prev);
    prev=NULL;
  }

  get_testdb("./testdata/got_dm_worker104.sql");
  CU_ASSERT(0==cmp_file("./testdata/got_dm_worker104.sql","./testdata/expected_dm_worker104.sql"));

the_end:
  free(p_ssl_client);
  testdb_close(db);
}
