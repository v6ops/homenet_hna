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
  ret=dm_tofu_insert_rr(db,1,rr,0);
  CU_ASSERT(LDNS_RCODE_REFUSED==ret); // we don't do A RR

  ldns_rr_free(rr);
  rr=NULL;
  if (prev) {
    ldns_rdf_deep_free(prev);
    prev=NULL;
  }


  // create an AAAA RR RFC 2136 2.5.1
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
  ret=dm_tofu_insert_rr(db,1,rr,1762328400);

  CU_ASSERT(LDNS_RCODE_NOERROR==ret); // 1 record inserted

  ldns_rr_free(rr);
  rr=NULL;
  if (prev) {
    ldns_rdf_deep_free(prev);
    prev=NULL;
  }

  get_testdb("./testdata/got_dm_tofu10.sql");
  CU_ASSERT(0==cmp_file("./testdata/expected_dm_tofu10.sql","./testdata/got_dm_tofu10.sql"));

  // delete an AAAA RR ttl 0 class none RFC 2136 2.5.4
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
  ret=dm_tofu_insert_rr(db,1,rr,1762328460);

  CU_ASSERT(LDNS_RCODE_NOERROR==ret); // 1 record updated

  ldns_rr_free(rr);
  rr=NULL;
  if (prev) {
    ldns_rdf_deep_free(prev);
    prev=NULL;
  }

  get_testdb("./testdata/got_dm_tofu11.sql");
  CU_ASSERT(0==cmp_file("./testdata/expected_dm_tofu11.sql","./testdata/got_dm_tofu11.sql"));


  // create an NS RR RFC 2136 2.5.1
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
  ret=dm_tofu_insert_rr(db,1,rr,1762328400);

  CU_ASSERT(LDNS_RCODE_NOERROR==ret); // 1 record inserted

  ldns_rr_free(rr);
  rr=NULL;
  if (prev) {
    ldns_rdf_deep_free(prev);
    prev=NULL;
  }

  get_testdb("./testdata/got_dm_tofu12.sql");
  CU_ASSERT(0==cmp_file("./testdata/expected_dm_tofu12.sql","./testdata/got_dm_tofu12.sql"));


  // create an TXT RR RFC 2136 2.5.1
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
  ret=dm_tofu_insert_rr(db,1,rr,1762328400);

  CU_ASSERT(LDNS_RCODE_NOERROR==ret); // 1 record inserted

  ldns_rr_free(rr);
  rr=NULL;
  if (prev) {
    ldns_rdf_deep_free(prev);
    prev=NULL;
  }

  get_testdb("./testdata/got_dm_tofu13.sql");
  CU_ASSERT(0==cmp_file("./testdata/expected_dm_tofu13.sql","./testdata/got_dm_tofu13.sql"));


  // create an DS RR RFC 2136 2.5.1
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
  ret=dm_tofu_insert_rr(db,1,rr,1762328400);

  CU_ASSERT(LDNS_RCODE_NOERROR==ret); // 1 record inserted

  ldns_rr_free(rr);
  rr=NULL;
  if (prev) {
    ldns_rdf_deep_free(prev);
    prev=NULL;
  }

  get_testdb("./testdata/got_dm_tofu14.sql");
  CU_ASSERT(0==cmp_file("./testdata/expected_dm_tofu14.sql","./testdata/got_dm_tofu14.sql"));


  // create 2nd DS RR with a separate key tag RFC 2136 2.5.1
  char *rr_string7 = "www.example.com.	600	IN	DS      26161 5 2 ee0eb9e59ee1de2c681a330e3a7c08376f28602cdf990ee4ec88d2a8bdb51539";
  l_status = ldns_rr_new_frm_str(&rr,rr_string7,600,origin,&prev);
  CU_ASSERT(LDNS_STATUS_OK==l_status);
  ldns_rr_print(stdout, rr);

  str = ldns_rr2str_fmt(ldns_output_format_default, rr);
  if (str) {
    printf("RR %s", str);
    CU_ASSERT(0==cmp_array(str,"www.example.com.	600	IN	DS	26161 5 2 ee0eb9e59ee1de2c681a330e3a7c08376f28602cdf990ee4ec88d2a8bdb51539\n",strlen(str)));
    LDNS_FREE(str);
  }
  // inserting to the DB with success
  ret=dm_tofu_insert_rr(db,1,rr,1762328400);

  CU_ASSERT(LDNS_RCODE_NOERROR==ret); // 1 record inserted

  ldns_rr_free(rr);
  rr=NULL;
  if (prev) {
    ldns_rdf_deep_free(prev);
    prev=NULL;
  }

  get_testdb("./testdata/got_dm_tofu15.sql");
  CU_ASSERT(0==cmp_file("./testdata/expected_dm_tofu15.sql","./testdata/got_dm_tofu15.sql"));

  // delete all DS RR Set for all key tags RFC 2136 2.5.2
  //char *rr_string8 = "www.example.com.	0	ANY	DS	26163 5 2 ee0eb9e59ee1de2c681a330e3a7c08376f28602cdf990ee4ec88d2a8bdb51539";
  // rdata = blank. ttl 0. class any. type DS
  char *rr_string8 = "www.example.com.	0	ANY	DS	\\# 0";
  l_status = ldns_rr_new_frm_str(&rr,rr_string8,000,origin,&prev);
  CU_ASSERT(LDNS_STATUS_OK==l_status);
  ldns_rr_print(stdout, rr);

  str = ldns_rr2str_fmt(ldns_output_format_default, rr);
  if (str) {
    printf("RR %s", str);
    //CU_ASSERT(0==cmp_array(str,"www.example.com.	0	ANY	DS	26163 5 2 ee0eb9e59ee1de2c681a330e3a7c08376f28602cdf990ee4ec88d2a8bdb51539\n",strlen(str)));
    CU_ASSERT(0==cmp_array(str,"www.example.com.	0	ANY	DS	\\# 0\n",strlen(str)));
    LDNS_FREE(str);
  }
  // inserting to the DB with success
  ret=dm_tofu_insert_rr(db,1,rr,1762328400);

  CU_ASSERT(LDNS_RCODE_NOERROR==ret); // 2 DS records updated

  ldns_rr_free(rr);
  rr=NULL;
  if (prev) {
    ldns_rdf_deep_free(prev);
    prev=NULL;
  }

  get_testdb("./testdata/got_dm_tofu16.sql");
  CU_ASSERT(0==cmp_file("./testdata/expected_dm_tofu16.sql","./testdata/got_dm_tofu16.sql"));

  // delete all RR for all name www.example.com RFC 2136 2.5.3
  // strictly speaking the rdata should be blank but can't figure out how to create that in ldns. Problem for later
  //char *rr_string9 = "www.example.com.	0	ANY	ANY";
  //l_status = ldns_rr_new_frm_str(&rr,rr_string9,000,origin,&prev);
  rr=ldns_rr_new();
  ldns_rr_set_class(rr,LDNS_RR_CLASS_ANY);
  ldns_rr_set_ttl(rr,0);
  ldns_rr_set_type(rr,LDNS_RR_TYPE_ANY);
  ldns_rr_set_rd_count(rr,0); // no rdata
  ldns_rdf *rd;
  ldns_str2rdf_dname(&rd,"www.example.com.");
  ldns_rr_set_owner(rr,rd);

  //CU_ASSERT(LDNS_STATUS_OK==l_status);
  ldns_rr_print(stdout, rr);

  str = ldns_rr2str_fmt(ldns_output_format_default, rr);
  if (str) {
    printf("RR %s", str);
    CU_ASSERT(0==cmp_array(str,"www.example.com.	0	ANY	ANY	\\# 0\n",strlen(str)));
    LDNS_FREE(str);
  }
  // inserting to the DB with success
  ret=dm_tofu_insert_rr(db,1,rr,1762328400);

  CU_ASSERT(LDNS_RCODE_NOERROR==ret); // 1 NS & 1 TXT records updated

  ldns_rr_free(rr);
  rr=NULL;
  if (prev) {
    ldns_rdf_deep_free(prev);
    prev=NULL;
  }
  get_testdb("./testdata/got_dm_tofu17.sql");
  CU_ASSERT(0==cmp_file("./testdata/expected_dm_tofu17.sql","./testdata/got_dm_tofu17.sql"));

  // test change of status of rr
  CU_ASSERT(1==dm_tofu_update_rr_status(db, 1, "created", 1762328480));
  CU_ASSERT(1==dm_tofu_update_rr_status(db, 3, "created", 1762328560));
  CU_ASSERT(-1==dm_tofu_update_rr_status(db, 4, "garbage", 1762328560));
  get_testdb("./testdata/got_dm_tofu18.sql");
  CU_ASSERT(0==cmp_file("./testdata/got_dm_tofu18.sql","./testdata/expected_dm_tofu18.sql"));

  // clean these rr's from the db for subsequent tests
  CU_ASSERT(1==dm_tofu_delete_rr(db, 1));
  CU_ASSERT(1==dm_tofu_delete_rr(db, 2));
  CU_ASSERT(1==dm_tofu_delete_rr(db, 3));
  CU_ASSERT(1==dm_tofu_delete_rr(db, 4));
  CU_ASSERT(1==dm_tofu_delete_rr(db, 5));


  // DB Test 4. Move 3 zone into assigning state
  //
  // 1,'linear.realm.piece.floor.example.com',NULL,0,'example.com',0,'assigning',960),
  // (2,'basket.delay.need.sweet.example.com',NULL,0,'example.com',0,'assigning',960),
  // (3,'jaguar.oak.guess.lord.example.com',NULL,0,'example.com',0,'assigning',960)
  //
  // create an TXT RR ACME challenge
  char *rr_string9 = "_acme-challenge.linear.realm.piece.floor.example.com.  600     IN      TXT     Challeng1HEX";
  l_status = ldns_rr_new_frm_str(&rr,rr_string9,600,origin,&prev);
  CU_ASSERT(LDNS_STATUS_OK==l_status);
  ldns_rr_print(stdout, rr);
  // inserting rr to the DB with success
  ret=dm_tofu_insert_rr(db,1,rr,TIME2+120);
  CU_ASSERT(LDNS_RCODE_NOERROR==ret); // 1 record inserted
  ldns_rr_free(rr);
  if (prev) {
    ldns_rdf_deep_free(prev);
    prev=NULL;
  }
  // update the zone status
  CU_ASSERT(1==dm_tofu_update_zone_status(db,1,"assigning",TIME2+120));
  char *rr_string10 = "_acme-challenge.basket.delay.need.sweet.example.com.  600     IN      TXT     Challeng2HEX";
  l_status = ldns_rr_new_frm_str(&rr,rr_string10,600,origin,&prev);
  CU_ASSERT(LDNS_STATUS_OK==l_status);
  ldns_rr_print(stdout, rr);
  // inserting rr to the DB with success
  ret=dm_tofu_insert_rr(db,2,rr,TIME2+120);
  CU_ASSERT(LDNS_RCODE_NOERROR==ret); // 1 record inserted
  ldns_rr_free(rr);
  if (prev) {
    ldns_rdf_deep_free(prev);
    prev=NULL;
  }
  CU_ASSERT(1==dm_tofu_update_zone_status(db,2,"assigning",TIME2+120));
  char *rr_string11 = "_acme-challenge.jaguar.oak.guess.lord.example.com.  600     IN      TXT     Challeng3HEX";
  l_status = ldns_rr_new_frm_str(&rr,rr_string11,600,origin,&prev);
  CU_ASSERT(LDNS_STATUS_OK==l_status);
  ldns_rr_print(stdout, rr);
  // inserting rr to the DB with success
  ret=dm_tofu_insert_rr(db,3,rr,TIME2+120);
  CU_ASSERT(LDNS_RCODE_NOERROR==ret); // 1 record inserted
  ldns_rr_free(rr);
  if (prev) {
    ldns_rdf_deep_free(prev);
    prev=NULL;
  }
  CU_ASSERT(1==dm_tofu_update_zone_status(db,3,"assigning",TIME2+120));

  get_testdb("./testdata/got_dm_tofu19.sql");
  CU_ASSERT(0==cmp_file("./testdata/got_dm_tofu19.sql","./testdata/expected_dm_tofu19.sql"));

  // DBTest 5. move 3 of them to assigned state at TIME2+180
  dm_tofu_assigning_to_assigned(db, "example.com", TIME2+180);
  get_testdb("./testdata/got_dm_tofu05.sql");
  CU_ASSERT(0==cmp_file("./testdata/got_dm_tofu05.sql","./testdata/expected_dm_tofu05.sql"));
  
  // DB Test 6. Move 2 zones into delegating state
  //
  // 1,'linear.realm.piece.floor.example.com',NULL,0,'example.com',0,'delegating',960),
  // (2,'basket.delay.need.sweet.example.com',NULL,0,'example.com',0,'delegating',960),
  //
  // create DS RR 
  char *rr_string20 = "linear.realm.piece.floor.example.com.	600	IN	DS      26161 5 2 ee0eb9e59ee1de2c681a330e3a7c08376f28602cdf990ee4ec88d2a8bdb51539";
  l_status = ldns_rr_new_frm_str(&rr,rr_string20,600,origin,&prev);
  CU_ASSERT(LDNS_STATUS_OK==l_status);
  ldns_rr_print(stdout, rr);

  str = ldns_rr2str_fmt(ldns_output_format_default, rr);
  if (str) {
    printf("RR %s", str);
    CU_ASSERT(0==cmp_array(str,"linear.realm.piece.floor.example.com.	600	IN	DS	26161 5 2 ee0eb9e59ee1de2c681a330e3a7c08376f28602cdf990ee4ec88d2a8bdb51539\n",strlen(str)));
    LDNS_FREE(str);
  }
  // inserting to the DB with success
  ret=dm_tofu_insert_rr(db,1,rr,TIME2+240);

  CU_ASSERT(LDNS_RCODE_NOERROR==ret); // 1 record inserted

  ldns_rr_free(rr);
  rr=NULL;
  if (prev) {
    ldns_rdf_deep_free(prev);
    prev=NULL;
  }
  CU_ASSERT(1==dm_tofu_update_zone_status(db,1,"delegating",TIME2+240));

  get_testdb("./testdata/got_dm_tofu20.sql");
  CU_ASSERT(0==cmp_file("./testdata/got_dm_tofu20.sql","./testdata/expected_dm_tofu20.sql"));

  // create DS RR 
  char *rr_string21 = "basket.delay.need.sweet.example.com.	600	IN	DS      26162 5 2 fe0eb9e59ee1de2c681a330e3a7c08376f28602cdf990ee4ec88d2a8bdb51539";
  l_status = ldns_rr_new_frm_str(&rr,rr_string21,600,origin,&prev);
  CU_ASSERT(LDNS_STATUS_OK==l_status);
  ldns_rr_print(stdout, rr);

  str = ldns_rr2str_fmt(ldns_output_format_default, rr);
  if (str) {
    printf("RR %s", str);
    CU_ASSERT(0==cmp_array(str,"basket.delay.need.sweet.example.com.	600	IN	DS	26162 5 2 fe0eb9e59ee1de2c681a330e3a7c08376f28602cdf990ee4ec88d2a8bdb51539\n",strlen(str)));
    LDNS_FREE(str);
  }
  // inserting to the DB with success
  ret=dm_tofu_insert_rr(db,1,rr,TIME2+240);

  CU_ASSERT(LDNS_RCODE_NOERROR==ret); // 1 record inserted

  ldns_rr_free(rr);
  rr=NULL;
  if (prev) {
    ldns_rdf_deep_free(prev);
    prev=NULL;
  }
  CU_ASSERT(1==dm_tofu_update_zone_status(db,2,"delegating",TIME2+240));

  get_testdb("./testdata/got_dm_tofu21.sql");
  CU_ASSERT(0==cmp_file("./testdata/got_dm_tofu21.sql","./testdata/expected_dm_tofu21.sql"));


  // DBTest 7. move 2 of them to delegated state at TIME2+300
  dm_tofu_delegating_to_delegated(db, "example.com", TIME2+300);
  get_testdb("./testdata/got_dm_tofu22.sql");
  CU_ASSERT(0==cmp_file("./testdata/got_dm_tofu22.sql","./testdata/expected_dm_tofu22.sql"));
  

  // DB Test 8. Move 1 zone into delegating state with an NS
  //
  // 1,'linear.realm.piece.floor.example.com',NULL,0,'example.com',0,'delegating',960),
  //
  // create an NS RR
  char *rr_string23 = "linear.realm.piece.floor.example.com.	600	IN	NS	hna-1.linear.realm.piece.floor.example.com.";
  l_status = ldns_rr_new_frm_str(&rr,rr_string23,600,origin,&prev);
  CU_ASSERT(LDNS_STATUS_OK==l_status);
  ldns_rr_print(stdout, rr);

  str = ldns_rr2str_fmt(ldns_output_format_default, rr);
  if (str) {
    printf("RR %s", str);
    CU_ASSERT(0==cmp_array(str,"linear.realm.piece.floor.example.com.	600	IN	NS	hna-1.linear.realm.piece.floor.example.com.\n",strlen(str)));
    LDNS_FREE(str);
  }
  // inserting to the DB with success
  ret=dm_tofu_insert_rr(db,1,rr,TIME2+360);

  CU_ASSERT(LDNS_RCODE_NOERROR==ret); // 1 record inserted

  ldns_rr_free(rr);
  rr=NULL;
  if (prev) {
    ldns_rdf_deep_free(prev);
    prev=NULL;
  }
  // create an AAAA RR glue
  char *rr_string24 = "hna-1.linear.realm.piece.floor.example.com.	600	IN	AAAA 2001:470:1f15:62e:21c:c4ff:fec9:de16";
  l_status = ldns_rr_new_frm_str(&rr,rr_string24,600,origin,&prev);
  CU_ASSERT(LDNS_STATUS_OK==l_status);
  ldns_rr_print(stdout, rr);

  str = ldns_rr2str_fmt(ldns_output_format_default, rr);
  if (str) {
    printf("RR %s", str);
    CU_ASSERT(0==cmp_array(str,"hna-1.linear.realm.piece.floor.example.com.	600	IN	AAAA	2001:470:1f15:62e:21c:c4ff:fec9:de16\n",strlen(str)));
    LDNS_FREE(str);
  }
  // inserting to the DB with success
  ret=dm_tofu_insert_rr(db,1,rr,TIME2+360);

  CU_ASSERT(LDNS_RCODE_NOERROR==ret); // 1 record inserted

  ldns_rr_free(rr);
  rr=NULL;
  if (prev) {
    ldns_rdf_deep_free(prev);
    prev=NULL;
  }
  CU_ASSERT(1==dm_tofu_update_zone_status(db,1,"delegating",TIME2+360));

  get_testdb("./testdata/got_dm_tofu24.sql");
  CU_ASSERT(0==cmp_file("./testdata/expected_dm_tofu24.sql","./testdata/got_dm_tofu24.sql"));



  // DBTest 9. move 1 of them to delegated state at TIME2+420
  dm_tofu_delegating_to_delegated(db, "example.com", TIME2+420);
  get_testdb("./testdata/got_dm_tofu25.sql");
  CU_ASSERT(0==cmp_file("./testdata/got_dm_tofu25.sql","./testdata/expected_dm_tofu25.sql"));
  









  // create 5 zones in creating state at TIME1
  //create_zones(db, "example.com", 5 , TIME1);
  //get_testdb("./testdata/got_dm_tofu06.sql");
  //CU_ASSERT(0==cmp_file("./testdata/expected_dm_tofu06.sql","./testdata/got_dm_tofu06.sql"));
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
