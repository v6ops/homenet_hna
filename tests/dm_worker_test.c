/* dm_worker_test.c 

* Copyright (c) 2025 Ray Hunter

*/
#include "dm_worker_test.h"
#include "test_harness.h"

#include <CUnit/CUnit.h>

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
  printf("continue test_dm_worker\n");
  // check the test harness is working OK
  CU_ASSERT(0==cmp_file("./testdata/key.pem","./testdata/key.pem"));
  CU_ASSERT(0!=cmp_file("./testdata/key.pem","./testdata/fullchain.pem"));
  get_testdb("./testdata/got_testdb.sql");
  CU_ASSERT(0==cmp_file("./testdata/expected_testdb.sql","./testdata/expected_testdb.sql"));

  ldns_pkt *input_pkt;
  ldns_pkt *output_pkt;

  // spoof test ssl object
  struct ssl_client *p_ssl_client;
  if ((p_ssl_client = (struct ssl_client *) malloc(sizeof(*p_ssl_client))) == NULL) {
    printf("failed to allocate memory for SSL client state\n");
    exit(0);
  }
  memset(p_ssl_client, 0, sizeof(*p_ssl_client));
  p_ssl_client->db=db;
 
  input_pkt=ldns_helpers_ns_update_new("linear.realm.piece.floor.example.com","example.com","");
  ldns_pkt_print(stdout,input_pkt);
  l_status=dm_worker_update_prescan(input_pkt,p_ssl_client);
  printf("l_status: %i\n",l_status);
  CU_ASSERT(LDNS_RCODE_NOERROR==l_status);
  ldns_helpers_pkt_free(input_pkt);

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
