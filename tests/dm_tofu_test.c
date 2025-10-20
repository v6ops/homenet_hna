/* dm_tofu_test.c 

* Copyright (c) 2025 Ray Hunter

*/
#include "dm_tofu_test.h"
#include "test_harness.h"

#include <CUnit/CUnit.h>

void dm_tofu_test(void) {

  CU_ASSERT(0 == 0);

  printf("start test_dm_tofu\n");
  set_testdb("./testdata/reset_testdb.sql");
  printf("continue test_dm_tofu\n");
  CU_ASSERT(0==cmp_file("./testdata/key.pem","./testdata/key.pem"));
  CU_ASSERT(0!=cmp_file("./testdata/key.pem","./testdata/fullchain.pem"));
  printf("cmp_file %i\n",cmp_file("./testdata/key.pem","./testdata/fullchain.pem"));

}
