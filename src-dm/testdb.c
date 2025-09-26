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

/*
int res=0;
char message[]="test message 22";
size_t message_len=strlen(message);
char key[]="privatekey";
size_t key_len=strlen(key);
size_t len=32; // SHA256
printf("len %li\n",len);

unsigned char *digest=(unsigned char*)malloc(len);
memset(digest,'\0',len);
size_t *digest_len=&len;

res=do_EVP_HMACSHA256((const unsigned char *)message, message_len, (const unsigned char *)key, key_len, &digest, digest_len);
printf("res %i\n",res);
printf("len %li\n",*digest_len);

  // output the result for debug
  for (size_t i = 0; i < *digest_len; i++) {
    printf("%02x", digest[i]);
  }
  putchar('\n');

exit(0);
*/

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
  //
  // test timeouts
  // 31536300 is 5 minutes later
  dm_tofu_timeout_created_zone(db,"homenetdns.com",31536000);
  dm_tofu_timeout_offered_zone(db,"homenetdns.com",31536300);
  dm_tofu_timeout_assigned_zone(db,"homenetdns.com",31536300);
  dm_tofu_timeout_delegated_zone(db,"homenetdns.com",31536300);

  db_close(db);


  char *fn=knot_helpers_create_file();
  printf("filename %s\n",fn);
  free(fn);

}

