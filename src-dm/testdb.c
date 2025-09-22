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

  ll_secondary_ns_t *ll_ns_head= dm_tofu_get_secondary_ns(db, "homenetdns.com") ;
  dm_tofu_print_ll_ns(ll_ns_head);

  char *ns=dm_tofu_get_ns(db, "homenetdns.com");
  printf("%s\n",ns) ;
  if (ns !=NULL) {
    free(ns);
    ns=NULL;
  }

  ll_parent_t *ll_parent_head=NULL;
  int rc= dm_tofu_select_parent_ns(db,&ll_parent_head);
  dm_tofu_print_ll_parent(ll_parent_head); // also does free
  ll_parent_head=NULL;
  rc= dm_tofu_select_parent_dm(db,&ll_parent_head);
  dm_tofu_print_ll_parent(ll_parent_head); // also does free


  // printf("%i\n",dm_tofu_update_zone_status(db, 673, "crap"));
  // printf("%i\n",dm_tofu_update_zone_status(db, 673, "created"));
  // printf("%i\n",dm_tofu_update_zone_status(db, 672, "deleting"));

  db_close(db);

}

