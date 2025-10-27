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
  CU_ASSERT(-1==select_zone_id(db, "nonsense.zone.name"));
  CU_ASSERT(1==select_zone_id(db, "linear.realm.piece.floor.example.com"));
  CU_ASSERT(2==select_zone_id(db, "basket.delay.need.sweet.example.com"));
  CU_ASSERT(3==select_zone_id(db, "jaguar.oak.guess.lord.example.com"));
  CU_ASSERT(4==select_zone_id(db, "device.vertex.deck.glad.example.com"));
  CU_ASSERT(5==select_zone_id(db, "fabric.shine.flip.any.example.com"));
  
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




  // create 5 zones in creating state at TIME1
  create_zones(db, "example.com", 5 , TIME1);
  get_testdb("./testdata/got_dm_tofu04.sql");
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
