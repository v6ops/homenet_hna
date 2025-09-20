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

  // test get domain name 
struct addrinfo hints, *info, *p;
int gai_result;

char hostname[1024];
hostname[1023] = '\0';
gethostname(hostname, 1023);

memset(&hints, 0, sizeof hints);
hints.ai_family = AF_UNSPEC; /*either IPV4 or IPV6*/
hints.ai_socktype = SOCK_STREAM;
hints.ai_flags = AI_CANONNAME;

if ((gai_result = getaddrinfo(hostname, "http", &hints, &info)) != 0) {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(gai_result));
    exit(1);
}

for(p = info; p != NULL; p = p->ai_next) {
    printf("hostname: %s\n", p->ai_canonname);
}

freeaddrinfo(info);

  // test making some zones 
  //
  #include <sys/time.h>
   struct timeval start, end;
  // start timer.
  gettimeofday(&start, NULL);

  printf("start db\n");
  char *zn=NULL;
  zn=offer_zone("homenetdns.com","2001:abcd::1",0);
  printf("Offered zone %s\n",zn);
  if (zn != NULL) { free(zn); }
  zn=offer_zone("homenetdns.com","2001:abcd::1",0);
  printf("Offered zone %s\n",zn);
  if (zn != NULL) { free(zn); }
  zn=offer_zone("homenetdns.com","2001:abcd::2",0);
  printf("Offered zone %s\n",zn);
  if (zn != NULL) { free(zn); }
  zn=offer_zone("homenetdns.com","2001:abcd::2",0);
  printf("Offered zone %s\n",zn);
  if (zn != NULL) { free(zn); }
  zn=offer_zone("homenetdns.com","2001:abcd::3",0);
  printf("Offered zone %s\n",zn);
  if (zn != NULL) { free(zn); }
  zn=offer_zone("homenetdns.com","2001:abcd::3",0);
  printf("Offered zone %s\n",zn);
  if (zn != NULL) { free(zn); }
  zn=offer_zone("homenetdns.com","2001:abcd::4",0);
  printf("Offered zone %s\n",zn);
  if (zn != NULL) { free(zn); }
  zn=offer_zone("homenetdns.com","",0);
  printf("Offered zone %s\n",zn);
  if (zn != NULL) { free(zn); }
  int deleting;
  deleting=timeout_created_zone("homenetdns.com",0);
  printf("Deleting %i created zones\n",deleting);
  deleting=timeout_offered_zone("homenetdns.com",0);
  printf("Deleting %i offered zones\n",deleting);
  deleting=timeout_assigned_zone("homenetdns.com",0);
  printf("Deleting %i assigned zones\n",deleting);
  printf("end db\n");

  //dm_tofu_ns_batch();
  // dm_tofu_creating_to_created("homenetdns.com","ns1.homenetdns.com");

  double time_taken;

  time_taken = (end.tv_sec - start.tv_sec) * 1e6;
  time_taken = (time_taken + (end.tv_usec -
                              start.tv_usec)) * 1e-6;

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

