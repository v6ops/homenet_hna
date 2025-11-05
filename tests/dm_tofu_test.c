/* dm_tofu_test.c 

* Copyright (c) 2025 Ray Hunter

*/
#include "dm_tofu_test.h"
#include "test_harness.h"

#include <CUnit/CUnit.h>

void dm_tofu_test(void) {

  MYSQL *db;

  CU_ASSERT(0 == 0);

  printf("start test_dm_tofu\n");
  db=testdb_init();
  testdb_connect(db);
  CU_ASSERT( db!=NULL );

  printf("Reset knot: this may display errors if the zones don't exist from previous tests\n");
  exec_bash("./testdata/reset_knot.bash");

  printf("Reset test db\n");
  set_testdb("./testdata/reset_testdb.sql");
  printf("continue test_dm_tofu\n");
  // check the test harness is working OK
  CU_ASSERT(0==cmp_file("./testdata/key.pem","./testdata/key.pem"));
  CU_ASSERT(0!=cmp_file("./testdata/key.pem","./testdata/fullchain.pem"));
  //printf("cmp_file %i\n",cmp_file("./testdata/key.pem","./testdata/fullchain.pem"));
  get_testdb("./testdata/got_testdb.sql");
  CU_ASSERT(0==cmp_file("./testdata/expected_testdb.sql","./testdata/got_testdb.sql"));

  // TIME1 = recent time2 = very old (to check timeouts)
#define TIME1 31708800 // 367 days in seconds
#define TIME2 960
#define PARENT_NAME "example.com"
#define NODE1 "2001:1::1"
#define NODE2 "2001:2::1"
#define NODE3 "2001:3::1"
#define NODE4 "2001:4::1"
  // move zones through the state machine, leaving zones in each possible state, some with an old timeout and some more recent
  //
  // DB Test 1. create 5 zones in creating state at TIME2
  create_zones(db, "example.com", 5 , TIME2);
  get_testdb("./testdata/got_dm_tofu01.sql");
  CU_ASSERT(0==cmp_file("./testdata/expected_dm_tofu01.sql","./testdata/got_dm_tofu01.sql"));

  // try finding some ids of the created zones
  CU_ASSERT(-1==dm_tofu_select_zone_id(db, "nonsense.zone.name"));
  CU_ASSERT(1==dm_tofu_select_zone_id(db, "linear.realm.piece.floor.example.com"));
  CU_ASSERT(2==dm_tofu_select_zone_id(db, "basket.delay.need.sweet.example.com"));
  CU_ASSERT(3==dm_tofu_select_zone_id(db, "jaguar.oak.guess.lord.example.com"));
  CU_ASSERT(4==dm_tofu_select_zone_id(db, "device.vertex.deck.glad.example.com"));
  CU_ASSERT(5==dm_tofu_select_zone_id(db, "fabric.shine.flip.any.example.com"));
  
  // DBTest 2. move all 5 of them to created state at TIME2+60
  dm_tofu_creating_to_created(db, "example.com", TIME2+60);
  get_testdb("./testdata/got_dm_tofu02.sql");
  CU_ASSERT(0==cmp_file("./testdata/expected_dm_tofu02.sql","./testdata/got_dm_tofu02.sql"));
  
  // DB Test 3. Move 4 zones from created into offered state TIME2+60
  char *zone1=NULL;
  char *zone2=NULL;
  char *zone3=NULL;
  char *zone4=NULL;
  zone1=offer_zone(db, PARENT_NAME, NODE1, TIME2+60);
  CU_ASSERT(0==cmp_array(zone1,"linear.realm.piece.floor.example.com",strlen(zone1)));
  if (zone1!=NULL) {
	  free(zone1);
  }
  // check for repeat requests on one IP. Should return the same zone
  zone1=offer_zone(db, PARENT_NAME, NODE1, TIME2+60);
  CU_ASSERT(0==cmp_array(zone1,"linear.realm.piece.floor.example.com",strlen(zone1)));
  zone2=offer_zone(db, PARENT_NAME, NODE2, TIME2+60);
  CU_ASSERT(0==cmp_array(zone2,"basket.delay.need.sweet.example.com",strlen(zone2)));
  zone3=offer_zone(db, PARENT_NAME, NODE3, TIME2+60);
  CU_ASSERT(0==cmp_array(zone3,"jaguar.oak.guess.lord.example.com",strlen(zone3)));
  zone4=offer_zone(db, PARENT_NAME, NODE4, TIME2+60);
  CU_ASSERT(0==cmp_array(zone4,"device.vertex.deck.glad.example.com",strlen(zone4)));
  if (zone1!=NULL) {
	  free(zone1);
  }
  if (zone2!=NULL) {
	  free(zone2);
  }
  if (zone3!=NULL) {
	  free(zone3);
  }
  if (zone4!=NULL) {
	  free(zone4);
  }
  get_testdb("./testdata/got_dm_tofu03.sql");
  //CU_ASSERT(0==cmp_file("./testdata/expected_dm_tofu03.sql","./testdata/got_dm_tofu03.sql"));


  // DB Test 4. Move 3 zone into assigned state


  // DB Test 10. check RR Insertion
  // create an A RR
  ldns_rr *rr=NULL;
  ldns_rdf *prev=NULL;
  ldns_status l_status;
  int ret;
  ldns_rdf *origin = NULL;
  const char *rr_string = "www.example.com.	3600	IN	A	192.168.1.1";
  l_status = ldns_rr_new_frm_str(&rr,rr_string,600,origin,&prev);
  CU_ASSERT(LDNS_STATUS_OK==l_status);
  ldns_rr_print(stdout, rr);

  char *str = ldns_rr2str_fmt(ldns_output_format_default, rr);
  if (str) {
    printf("RR %s", str);
    CU_ASSERT(0==cmp_array(str,"www.example.com.	3600	IN	A	192.168.1.1\n",strlen(str)));
    LDNS_FREE(str);
  }
  // inserting to the DB will fail with LDNS_RCODE_REFUSED
  ret=dm_tofu_insert_rr(db,"example.com.",rr,0);
  CU_ASSERT(LDNS_RCODE_REFUSED==ret); // we don't do A RR

  ldns_rr_free(rr);
  rr=NULL;
  if (prev) {
    ldns_rdf_deep_free(prev);
    prev=NULL;
  }


  // create an AAAA RR
  char *rr_string2 = "www.example.com.	600	IN	AAAA 2001:470:1f15:62e:21c:c4ff:fec9:de16";
  l_status = ldns_rr_new_frm_str(&rr,rr_string2,600,origin,&prev);
  CU_ASSERT(LDNS_STATUS_OK==l_status);
  ldns_rr_print(stdout, rr);

  str = ldns_rr2str_fmt(ldns_output_format_default, rr);
  if (str) {
    printf("RR %s", str);
    CU_ASSERT(0==cmp_array(str,"www.example.com.	600	IN	AAAA	2001:470:1f15:62e:21c:c4ff:fec9:de16\n",strlen(str)));
    LDNS_FREE(str);
  }
  // inserting to the DB with success
  ret=dm_tofu_insert_rr(db,"example.com.",rr,1762328400);

  CU_ASSERT(LDNS_RCODE_NOERROR==ret); // 1 record inserted

  ldns_rr_free(rr);
  rr=NULL;
  if (prev) {
    ldns_rdf_deep_free(prev);
    prev=NULL;
  }

  get_testdb("./testdata/got_dm_tofu10.sql");
  CU_ASSERT(0==cmp_file("./testdata/expected_dm_tofu10.sql","./testdata/got_dm_tofu10.sql"));

  // delete an AAAA RR ttl 0 class none
  char *rr_string3 = "www.example.com.	0	NONE	AAAA 2001:470:1f15:62e:21c:c4ff:fec9:de16";
  l_status = ldns_rr_new_frm_str(&rr,rr_string3,600,origin,&prev);
  CU_ASSERT(LDNS_STATUS_OK==l_status);
  ldns_rr_print(stdout, rr);

  str = ldns_rr2str_fmt(ldns_output_format_default, rr);
  if (str) {
    printf("RR %s", str);
    CU_ASSERT(0==cmp_array(str,"www.example.com.	0	NONE	AAAA	2001:470:1f15:62e:21c:c4ff:fec9:de16\n",strlen(str)));
    LDNS_FREE(str);
  }
  // delte to the DB with success
  ret=dm_tofu_insert_rr(db,"example.com.",rr,1762328460);

  CU_ASSERT(LDNS_RCODE_NOERROR==ret); // 1 record updated

  ldns_rr_free(rr);
  rr=NULL;
  if (prev) {
    ldns_rdf_deep_free(prev);
    prev=NULL;
  }

  get_testdb("./testdata/got_dm_tofu11.sql");
  CU_ASSERT(0==cmp_file("./testdata/expected_dm_tofu11.sql","./testdata/got_dm_tofu11.sql"));


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
  ret=dm_tofu_insert_rr(db,"example.com.",rr,1762328400);

  CU_ASSERT(LDNS_RCODE_NOERROR==ret); // 1 record inserted

  ldns_rr_free(rr);
  rr=NULL;
  if (prev) {
    ldns_rdf_deep_free(prev);
    prev=NULL;
  }

  get_testdb("./testdata/got_dm_tofu12.sql");
  CU_ASSERT(0==cmp_file("./testdata/expected_dm_tofu12.sql","./testdata/got_dm_tofu12.sql"));


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
  ret=dm_tofu_insert_rr(db,"example.com.",rr,1762328400);

  CU_ASSERT(LDNS_RCODE_NOERROR==ret); // 1 record inserted

  ldns_rr_free(rr);
  rr=NULL;
  if (prev) {
    ldns_rdf_deep_free(prev);
    prev=NULL;
  }

  get_testdb("./testdata/got_dm_tofu13.sql");
  CU_ASSERT(0==cmp_file("./testdata/expected_dm_tofu13.sql","./testdata/got_dm_tofu13.sql"));


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
  ret=dm_tofu_insert_rr(db,"example.com.",rr,1762328400);

  CU_ASSERT(LDNS_RCODE_NOERROR==ret); // 1 record inserted

  ldns_rr_free(rr);
  rr=NULL;
  if (prev) {
    ldns_rdf_deep_free(prev);
    prev=NULL;
  }

  get_testdb("./testdata/got_dm_tofu14.sql");
  CU_ASSERT(0==cmp_file("./testdata/expected_dm_tofu14.sql","./testdata/got_dm_tofu14.sql"));



  // create 5 zones in creating state at TIME1
  //create_zones(db, "example.com", 5 , TIME1);
  //get_testdb("./testdata/got_dm_tofu04.sql");
  //CU_ASSERT(0==cmp_file("./testdata/expected_dm_tofu04.sql","./testdata/got_dm_tofu04.sql"));
  // move 7 of them to created state at TIME2+1
  // move 6 of them to offered state at TIME1+2
  // move 6 of them to offered state at TIME2+2
  // move 5 of them to assigning state at TIME1+3
  // move 5 of them to assigning state at TIME2+3
  // move 4 of them to assigned state at TIME1+4
  // move 4 of them to assigned state at TIME2+4
  // move 3 of them to delegating state at TIME1+5
  // move 3 of them to delegating state at TIME2+5
  // move 2 of them to delegated state at TIME1+6
  // move 2 of them to delegated state at TIME2+6
  // move 1 of them to deleting state at TIME1+7 (no NS left)
  // move 1 of them to deleting state at TIME2+7 (no NS left)
  // #define DM_TOFU_SLOT_LENGTH 60 // slot length in seconds. default 1 minute.
  // timeout TIME2 + T2 30*DM_TOFU_SLOT_LENGTH
  // timeout TIME2 + T3 60*DM_TOFU_SLOT_LENGTH
  // timeout TIME2 + T1 31*24*60*DM_TOFU_SLOT_LENGTH
  // timeout TIME2 + T4 366*24*60*DM_TOFU_SLOT_LENGTH
  //
  testdb_close(db);
}
