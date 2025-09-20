/* simple routines to test the db */
#include "db.h"
#include "dm_tofu.h"

/**
 *  Main function for demonstrating the db server.
 */
int main(int argc, char *argv[]) {
  MYSQL *db;

  db=db_init();
  db_connect(db,DB_SERVER, DB_USER, DB_PASSWORD, DB_DATABASE);

  printf("hello\n");
  ll_zone_t *ll_zone_head=NULL;
  dm_tofu_select_zone_status(db,"homenetdns.com","creating",&ll_zone_head);
  printf("hello\n");
  dm_tofu_print_ll_zone(ll_zone_head);
  ll_zone_head=NULL;
  dm_tofu_select_zone_status(db,"homenetdns.com","offered",&ll_zone_head);
  dm_tofu_print_ll_zone(ll_zone_head);


  db_close(db);

}

