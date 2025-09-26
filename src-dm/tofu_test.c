#include <stdlib.h>
#include <stdio.h>

//#include <iostream>
#include <unistd.h>
#include <string.h>
#include <sys/time.h>

// #include "../lib/ssl_session.h"
#include "../lib/ldns_helpers.h"
#include "../lib/ssl_helpers.h"
#include "../lib/workqueue.h"

#include <event.h>
#include <event2/listener.h>
#include <event2/bufferevent_ssl.h>
#include "ssl_client.h"


#include "dm_tofu.h"

int main(void) {
  dm_tofu_thread_t *my_thread_struct;
  int result_code;
  MYSQL *db;
  db=db_init();
  db_connect(db,DB_SERVER, DB_USER, DB_PASSWORD, DB_DATABASE);

  my_thread_struct = dm_tofu_bg_start(1);
  printf("In main: background thread is created.\n");

  sleep(10);

  printf("In main: woke up.\n");

  // test round robin
  int ns1,ns2,ns3;
  int i,j;
  char buf[7]="zone00";
  char *ptr=buf+4;
  for (i=0;i<3;i++) {
  for (j=0;j<3;j++) {
    *ptr=i+48;
    *(ptr+1)=j+48;
    round_robin_ns(buf, &ns1, &ns2, &ns3 );
    printf("%s %i,%i,%i\n",buf,ns1,ns2,ns3);
  }
  }


  // test making some zones 
  //
  #include <sys/time.h>
   struct timeval start, end;
  // start timer.
  gettimeofday(&start, NULL);
  printf("start db\n");
  time_t now = get_time_slot(0);

  printf("create zones at slot %li\n",now);
  create_zones(db,"homenetdns.com", 5, now-DM_TOFU_SLOT_LENGTH*2);
  create_zones(db,"homenetdns.com", 5, now);

  char *zn=NULL;
  zn=offer_zone(db,"homenetdns.com","2001:abcd::1",0);
  printf("Offered zone %s\n",zn);
  if (zn != NULL) { free(zn); }
  zn=offer_zone(db,"homenetdns.com","2001:abcd::1",0);
  printf("Offered zone %s\n",zn);
  if (zn != NULL) { free(zn); }
  zn=offer_zone(db,"homenetdns.com","2001:abcd::2",0);
  printf("Offered zone %s\n",zn);
  if (zn != NULL) { free(zn); }
  zn=offer_zone(db,"homenetdns.com","2001:abcd::2",0);
  printf("Offered zone %s\n",zn);
  if (zn != NULL) { free(zn); }
  zn=offer_zone(db,"homenetdns.com","2001:abcd::3",0);
  printf("Offered zone %s\n",zn);
  if (zn != NULL) { free(zn); }
  zn=offer_zone(db,"homenetdns.com","2001:abcd::3",0);
  printf("Offered zone %s\n",zn);
  if (zn != NULL) { free(zn); }
  zn=offer_zone(db,"homenetdns.com","2001:abcd::4",0);
  printf("Offered zone %s\n",zn);
  if (zn != NULL) { free(zn); }
  zn=offer_zone(db,"homenetdns.com","",0);
  printf("Offered zone %s\n",zn);
  if (zn != NULL) { free(zn); }
  printf("end db\n");

  //dm_tofu_ns_batch();
  // dm_tofu_creating_to_created("homenetdns.com","ns1.homenetdns.com");

  double time_taken;

  time_taken = (end.tv_sec - start.tv_sec) * 1e6;
  time_taken = (time_taken + (end.tv_usec -
                              start.tv_usec)) * 1e-6;


  printf("end db\n");
  db_close(db);

  printf("In main: Time taken by program is %f\n",time_taken);
  sleep(30);
  char *fn;
  //fn=knot_helpers_create_file();
  //knot_helpers_delete_file(fn);
  sleep(60);
  printf("In main: woke up again.\n");

  // stop the background thread

  result_code = dm_tofu_bg_stop(&my_thread_struct);

  printf("Main program has ended.\n");
  return 0;
}

