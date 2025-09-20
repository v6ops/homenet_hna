/* dm_tofu.c handles the Trust on First Use self-registration

* Copyright (c) 2024-2025 Ray Hunter

* Permission is hereby granted, free of charge, to any person obtaining
* a copy of this software and associated documentation files (the
* "Software"), to deal in the Software without restriction, including
* without limitation the rights to use, copy, modify, merge, publish,
* distribute, sublicense, and/or sell copies of the Software, and to
* permit persons to whom the Software is furnished to do so, subject to
* the following conditions:

* The above copyright notice and this permission notice shall be
* included in all copies or substantial portions of the Software.

* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
* EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
* MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
* NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
* LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
* OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
* WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*
*/
#include "dm_tofu.h"


// print a linked list of zones
int dm_tofu_print_ll_zone(ll_zone_t *ll_zone_head) {

  ll_zone_t *ll_zone_tmp=NULL;
  ll_zone_t *ll_zone_current=NULL;
  ll_zone_current=ll_zone_head;
  while (ll_zone_current != NULL) {
    printf("Zone_name %s zone_id %i\n",ll_zone_current->zone_name,ll_zone_current->zone_id);
    ll_zone_tmp=ll_zone_current->next;
    free(ll_zone_current);
    ll_zone_current=ll_zone_tmp;
  }
}

// print a linked list of ns
int dm_tofu_print_ll_ns(ll_secondary_ns_t *ll_ns_head) {

  ll_secondary_ns_t *ll_ns_tmp=NULL;
  ll_secondary_ns_t *ll_ns_current=NULL;
  ll_ns_current=ll_ns_head;
  while (ll_ns_current != NULL) {
    printf("NS %s infra_id %i\n",ll_ns_current->ns_name,ll_ns_current->infra_id);
    ll_ns_tmp=ll_ns_current->next;
    free(ll_ns_current);
    ll_ns_current=ll_ns_tmp;
  }
}





int tmp_main () {

  // create a global storage
  unsigned char *md; 
  md=(unsigned char *)OPENSSL_malloc(EVP_MD_size(EVP_sha256()));
  memset(md,'\0',32*sizeof(unsigned char));
  unsigned char *str="Hi There";
  unsigned int *digest_length;
  *digest_length=EVP_MD_size(EVP_sha256());
  printf("len %i",*digest_length);
  do_EVP(str, (size_t)strlen(str), &md, digest_length);
  int i;
  for (i=0;i<32;i++) {
    printf("%x",md[i]);
  }
  printf("\n");
  printf(":%s:\n", dm_tofu_cp_name("asa/dns.com"));
  printf(":%s:\n", dm_tofu_cp_name(NULL));
  str="123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890";
  printf(":%s:\n", dm_tofu_cp_name(str));
  create_zones("homenetdns.com",100,0);

  offer_zone("homenetdns.com","2001:abcd::1",0);
  offer_zone("homenetdns.com","2001:abcd::1",0);
  offer_zone("homenetdns.com","2001:abcd::2",0);
  offer_zone("homenetdns.com","2001:abcd::2",0);
  offer_zone("homenetdns.com","2001:abcd::3",0);
  offer_zone("homenetdns.com","2001:abcd::3",0);
  offer_zone("homenetdns.com","2001:abcd::4",0);
  offer_zone("homenetdns.com","2001:abcd::5",0);
  offer_zone("homenetdns.com","",0);
  offer_zone("homenetdns.com","",0);


  exit(0);
}

// crude round robin on NS names
// not sensible except for multiple parents running in one infra
void round_robin_ns(char *parent_name, int *ns1_id, int *ns2_id, int *ns3_id ) {
//	TODO
}

// Convert an ascii encoded hex string to decimal
// Each char is 4 bits
// limited to 32 bits (8 hex chars)
uint32_t hexstr2dec(unsigned char *hex, int len) {
  int i;
  int c=0;
  uint32_t result=0;
  int l=len;
  if (l>8) {
    l=8;
  }
  for (i=0;i<l;i++) {
    c*=16;
    if ((hex[i]>='a') && (hex[i]<='f')) {
      c+=hex[i]-'a'+10;
    } else if ((hex[i]>='A') && (hex[i]<='F')) {
      c+=hex[i]-'A'+10;
    } else if ((hex[i]>='0') && (hex[i]<='9')) {
      c+=hex[i]-'0';
    } else {
      return -1;
    }
  }
  return c;
}


// take a string buffer and return the sha256 message digest
// md must be SHA256_DIGEST_LENGTH (32) char long
int do_EVP(const unsigned char *message, size_t message_len, unsigned char **digest, unsigned int *digest_len) {

    EVP_MD_CTX *mdctx;

    if((mdctx = EVP_MD_CTX_create()) == NULL) {
      printf("do_EVP: Can't create CTX\n");
      return -1;
    }

    if(1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL)) {
      printf("do_EVP: Can't init CTX\n");
      return -1;
    }

    if(1 != EVP_DigestUpdate(mdctx, message, message_len)) {
      printf("do_EVP: Can't update digest\n");
      return -1;
    }

    if(1 != EVP_DigestFinal_ex(mdctx, *digest, digest_len)) {
      printf("do_EVP: Can't finalise digest\n");
      return -1;
    }

    EVP_MD_CTX_destroy(mdctx);
    return 0;
}

// Initialise a dictionary of words to use as tokens
// feel free to use your own language/ words
// the pointer should have storage for 1024 words and 8 chars
// second literal = longest word + 1 (for the null)
// Kudos to https://github.com/pera/simple1024
char dict[1024][8]={ 
DICT
 };

// Convert a decimal to a word token
// Each token represents 10 bits of information (1024 words in the dictionary)
// Returns the length of the word added to the buffer.
// The buffer must be large enough and is not checked.
size_t dec2word(int dec, char *buf) {
  int d=dec % 1024; // limit to our dictionary length
  char *word;
  word=dict[d];
  size_t i;
  // copy into the buffer
  for (i=0;i<8;i++) { // longest word is max 7 chars
    buf[i]=word[i];
    if (word[i]=='\0') break;
  }
  word[7]='\0'; // just in case
  return i;
}


// create an invariant opaque pass phrase zone name like dog.cat.zoo.here
// remember to free once used
char *make_zone_name (unsigned long seed, int nwords) {
  printf("make_zone_name: %li %i\n",seed,nwords);

  if (nwords>16) { nwords=16; } // md is 32 chars with 2 chars per word

  // create sufficient storage for zone name, including dots and null.
  // assumes each word max 7 chars plus \0
  char *zn=calloc(nwords*8,sizeof(char));
  if (zn == NULL) {
    printf("make_zone_name: Cannot allocate memory\n");
    exit(-1);
  }

  size_t pos=0; // position in the output
  // create a global storage
  unsigned char *md; 
  // zalloc also does memset
  md=(unsigned char *)OPENSSL_zalloc(EVP_MD_size(EVP_sha256()));
  //memset(md,'\0',32*sizeof(unsigned char));
  unsigned int *digest_length;
  unsigned int len=EVP_MD_size(EVP_sha256());
  digest_length=&len;
  int d;        // temp decimal

  char buf[21]; // unsigned long is max 21 chars (inc \0)
  snprintf(buf, 21, "%li", seed); // is null terminated

  // create a message digest.
  // Does not have to be crypto secure but this yields
  // hard to guess zone names if people are abusive,
  // provided the seed is good.
  do_EVP(buf, (size_t)strlen(buf), &md, digest_length);

  int i=0;
  while (i<nwords) { // passphrase length
    d=md[i*2]*256+md[i*2+1];// take a couple of octets from the md
    pos+=dec2word(d,zn+pos);
    if(i<nwords-1) {
      zn[pos]='.'; // separate word with a dot
      pos++;
    }
    i++;
  } 
  zn[pos]='\0'; // terminate with a null char
  zn=(char *)realloc(zn,(pos+1)*sizeof(char)); // shorten to the minimum
  //printf("Zone %s\n",zn);
  OPENSSL_free(md);
  return zn;
}

// return the current time slot
time_t get_time_slot(time_t now){
  time_t slot;
  slot=(now!=0) ?  now : (time_t)time(NULL); // local time since 1970
  slot=slot/60*60;           // time slot ot the nearest minute
  return slot;
}

 
// Create nzones zones under parent in the db.
// There can be collisions with existing names because the hash is truncated.
// A "unique" constraint on `name` will force this insert to fail gracefully.
void create_zones(char *parent_name, int nzones, time_t now){
  MYSQL *db;
  char *zn;
  char buf[MYSQL_STRLEN]; // length database name field
  memset(buf,'\0',MYSQL_STRLEN*sizeof(char));
  time_t slot;
  MYSQL_STMT *stmt;
  MYSQL_BIND bind[3];
  memset(bind, 0, sizeof(MYSQL_BIND));
  size_t len1,len2;

  printf("create_zones :parent_name %s nzones %i now %li \n",parent_name,nzones,now);

  slot=get_time_slot(now);
  printf("Creating zones at slot %lu\n",slot);

  db=db_init(); 
  db_connect(db, DB_SERVER, DB_USER, DB_PASSWORD, DB_DATABASE);

  stmt=mysql_stmt_init(db);
  char *stmt_str="INSERT INTO zone (zone_name,parent_name,zone_status,zone_status_time) VALUES (?,?,'creating',?);";
  if (mysql_stmt_prepare(stmt, stmt_str, strlen(stmt_str))) {
    printf("create_zones: Can't prepare stmt. %s %s",stmt_str,mysql_error(db));
    exit(0);
  }

  int i=0;
  int collisions=0; // track failed inserts (asssume due to name collisions)
  while(i<nzones) {
    i++;
    zn=make_zone_name(slot+i+OFFSET,4);
    snprintf(buf,MYSQL_STRLEN,"%s.%s",zn,parent_name); // concat with max MYSQL_STRLEN char
    free(zn);

    bind[0].buffer_type= MYSQL_TYPE_STRING;
    bind[0].buffer= (char *)buf;
    bind[0].buffer_length= MYSQL_STRLEN;
    bind[0].is_null= 0;
    len1=strlen(buf);
    bind[0].length= &len1;

    bind[1].buffer_type= MYSQL_TYPE_STRING;
    bind[1].buffer= (char *)parent_name;
    bind[1].buffer_length= MYSQL_STRLEN;
    bind[1].is_null= 0;
    len2=strlen(parent_name);
    bind[1].length= &len2;
    
    bind[2].buffer_type= MYSQL_TYPE_LONGLONG;
    bind[2].buffer= (char *)&slot;
    bind[2].is_null= 0;
    bind[2].length= 0;

    mysql_stmt_bind_param(stmt, bind);

    if (mysql_stmt_execute(stmt)) {
      // ignore errors on duplicates row entries = name collision
      if(mysql_stmt_errno(stmt)!=1062) {
        fprintf(stderr, " mysql_stmt_execute(), 1 failed\n");
        fprintf(stderr, " %s\n", mysql_stmt_error(stmt));
        exit(0);
      }
    }
    uint64_t affected_rows;
    affected_rows= mysql_stmt_affected_rows(stmt);

    if (affected_rows != 1) { /* expect 1  affected row per insert*/
      collisions++;
      if (collisions >10000) {
       fprintf(stderr, " Too many collissions on zone creation\n");
       exit(0);
      }
    } else {
      // successful insert
      i++;
    }

    // free results
    mysql_stmt_free_result(stmt);
  }
  // close statement and free
  mysql_stmt_close(stmt);
  db_close(db);
}

// Offer 1 zone_name under parent in the db
// Uses Innodb atomic transaction to ensure uniqueness.
// Blank zone_name for failure (no more slots)
// The zone is then "locked" to the HNA via IP address
char* offer_zone(char *parent_name, char *ipv6, time_t now){
  MYSQL *db;
  int ret;
  char zone_name[MYSQL_STRLEN];
  char name[MYSQL_STRLEN]; // infra table
  char buf[MYSQL_STRLEN]; // length database name field
  memset(buf,'\0',sizeof(buf));
  time_t start_slot,end_slot;
  MYSQL_STMT *stmt;
  MYSQL_RES *result;
  MYSQL_ROW row;
  MYSQL_BIND bind[3];
  unsigned int num_fields;
  unsigned int zone_id;
  unsigned int infra_id;
  memset(bind, 0, sizeof(bind));
  size_t len1,len2,len3,len4;
  int rc=0;  // row count

  int status;
  MYSQL_BIND bindout[2];
  memset(bindout, 0, sizeof(bindout));
  unsigned long length[2];
  bool is_null[2];
  bool error[2];

  start_slot=get_time_slot(0);
  end_slot=start_slot+60;
  printf("Assigning zones at slot %lu\n",start_slot);

  if ( (ipv6==NULL) || (strlen(ipv6)<2) ) {
    printf("offer_zone: needs an IPv6 address\n");
    return NULL;
  }

  db=db_init(); 
  db_connect(db, DB_SERVER, DB_USER, DB_PASSWORD, DB_DATABASE);

  stmt=mysql_stmt_init(db);
  // start a transaction
  if (mysql_query(db,"BEGIN")) {
    printf ("offer_zone: Error. Can't start transaction\n");
    return NULL;
  }
  result=mysql_use_result(db);
  mysql_free_result(result);
  mysql_stmt_close(stmt);

  // Check if there's already a reservation from this IPv4 or IPv6
  // that is awaiting delegation. If there is repeat the reply.
  // This to prevent resource exhaustion from a single HNA.
  // This will lock for other threads until the transaction commits
  printf("Check for existing reservation.\n");
  stmt=mysql_stmt_init(db);
  //char *stmt_str="SELECT A.zone_id, A.zone_name FROM zone AS A,infra AS B WHERE A.parent_name=? AND A.status='offered' AND B.infra_id = A.hna AND ((LENGTH(B.ipv4)>0 AND B.ipv4 = ?) OR (LENGTH(B.ipv6)>0 AND B.ipv6 = ?)) FOR UPDATE";
  char *stmt_str="SELECT A.zone_id, A.zone_name FROM zone AS A,infra AS B WHERE A.parent_name=? AND A.zone_status='offered' AND B.infra_id = A.hna AND ((LENGTH(B.ipv6)>0 AND B.ipv6 = ?)) FOR UPDATE";

  if (mysql_stmt_prepare(stmt, stmt_str, strlen(stmt_str))) {
    printf ("offer_zone: prepare failed. %s\n",mysql_stmt_error(stmt));
    mysql_rollback(db);
    return NULL;
  }

  bind[0].buffer_type= MYSQL_TYPE_STRING;
  bind[0].buffer= (char *)parent_name;
  bind[0].buffer_length= MYSQL_STRLEN;
  bind[0].is_null= 0;
  len1=strlen(parent_name);
  bind[0].length= &len1;
/*
  bind[1].buffer_type= MYSQL_TYPE_STRING;
  bind[1].buffer= (char *)ipv4;
  bind[1].buffer_length= 15;
  bind[1].is_null= 0;
  len2=strlen(ipv4);
  bind[1].length= &len2;
  */

  bind[1].buffer_type= MYSQL_TYPE_STRING;
  bind[1].buffer= (char *)ipv6;
  bind[1].buffer_length= 39;
  bind[1].is_null= 0;
  len3=strlen(ipv6);
  bind[1].length= &len3;

  if (mysql_stmt_bind_param(stmt, bind) ) {
    printf ("offer_zone: bind failed. %s\n",mysql_error(db));
    mysql_stmt_close(stmt);
    mysql_rollback(db);
    return NULL;
  }
  if (mysql_stmt_execute(stmt) ) {
    printf ("offer_zone: exec failed. %s\n",mysql_error(db));
    mysql_stmt_close(stmt);
    mysql_rollback(db);
    return NULL;
  }

  /* INTEGER COLUMN zone_id */
  bindout[0].buffer_type= MYSQL_TYPE_LONG;
  bindout[0].buffer= (char *)&zone_id;
  bindout[0].is_null= &is_null[0];
  bindout[0].length= &length[0];
  bindout[0].error= &error[0];
 
  /* STRING COLUMN zone_name */
  bindout[1].buffer_type= MYSQL_TYPE_STRING;
  bindout[1].buffer= (char *)&zone_name;
  bindout[1].buffer_length= MYSQL_STRLEN;
  bindout[1].is_null= &is_null[1];
  bindout[1].length= &length[1];
  bindout[1].error= &error[1];

  if (mysql_stmt_bind_result(stmt, bindout)) {
    fprintf(stderr, " mysql_stmt_bind_result() failed\n");
    fprintf(stderr, " %s\n", mysql_stmt_error(stmt));
    mysql_stmt_close(stmt);
    mysql_rollback(db);
    return NULL;
  }

  // While rows to read.
  rc=0;  // row count
  while (1) {
    status = mysql_stmt_fetch(stmt);
    if (status == MYSQL_NO_DATA && rc==0) {
      printf ("offer_zone: normal. No existing zone_name. Continuing\n");
      break; 
    } else if (status == MYSQL_NO_DATA && rc>0) {
      break; // Last line. Normal end of read after match.
    } else if (status == 1 ) {
      printf ("offer_zone: Error. Can't check current status for request from %s %s\n",ipv6,mysql_error(db));
    mysql_rollback(db);
    mysql_stmt_close(stmt);
    return NULL;
    } 
    // We have a match on existing request.
    // Could break here on 1st match.
    rc++;
    printf("rc %i zone_name %.*s id %i\n",rc,(int)length[1],zone_name,zone_id);
  }

  if (rc>0) { // repeat the last response
    printf("Existing reservation found rc %i zone_name %.*s id %i\n",rc,(int)length[1],zone_name,zone_id);
    mysql_stmt_close(stmt);
    mysql_rollback(db);
    return dm_tofu_cp_name(zone_name);
  }
  mysql_stmt_close(stmt);

  // reserve one row that has not been assigned
  // and is in the current time slot
  // and parent matches.
  // This will lock this row for other threads until the transaction commits. Skipped locked means another thread can continue and find the next row.
  printf("Reserve zone\n");
  stmt=mysql_stmt_init(db);
  stmt_str="SELECT zone_id, zone_name FROM zone WHERE (zone_status='creating' AND parent_name =? AND zone_status_time >=? AND zone_status_time <? ) ORDER BY zone_id LIMIT 1 FOR UPDATE SKIP LOCKED";

  if (mysql_stmt_prepare(stmt, stmt_str, strlen(stmt_str))) {
    printf ("Reserve zone: prepare failed. %s\n",mysql_stmt_error(stmt));
    mysql_rollback(db);
    return NULL;
  }
  // parent_name start_slot end_slot
  memset(bind, 0, sizeof(bind));
  bind[0].buffer_type= MYSQL_TYPE_STRING;
  bind[0].buffer= (char *)parent_name;
  bind[0].buffer_length= MYSQL_STRLEN;
  bind[0].is_null= 0;
  len1=strlen(parent_name);
  bind[0].length= &len1;

  bind[1].buffer_type= MYSQL_TYPE_LONGLONG;
  bind[1].buffer= (char *)&start_slot;
  bind[1].is_null= 0;
  bind[1].length= 0;

  bind[2].buffer_type= MYSQL_TYPE_LONGLONG;
  bind[2].buffer= (char *)&end_slot;
  bind[2].is_null= 0;
  bind[2].length= 0;

  if (mysql_stmt_bind_param(stmt, bind)) {
    printf("Reserve zone: bind failed %s\n",mysql_stmt_error(stmt));
    mysql_stmt_close(stmt);
    mysql_rollback(db);
    return NULL;
  }
  if (mysql_stmt_execute(stmt)) {
    printf ("offer_zone: exec failed. %s\n",mysql_error(db));
    mysql_stmt_close(stmt);
    mysql_rollback(db);
    return NULL;
  }

  // re-use bindout
  memset(bindout, 0, sizeof(bindout));

  /* INTEGER COLUMN zone_id */
  bindout[0].buffer_type= MYSQL_TYPE_LONG;
  bindout[0].buffer= (char *)&zone_id;
  bindout[0].is_null= &is_null[0];
  bindout[0].length= &length[0];
  bindout[0].error= &error[0];
 
  /* STRING COLUMN zone_name */
  bindout[1].buffer_type= MYSQL_TYPE_STRING;
  bindout[1].buffer= (char *)&zone_name;;
  bindout[1].buffer_length= MYSQL_STRLEN;
  bindout[1].is_null= &is_null[1];
  bindout[1].length= &length[1];
  bindout[1].error= &error[1];

  if (mysql_stmt_bind_result(stmt, bindout)) {
    fprintf(stderr, " mysql_stmt_bind_result() failed\n");
    fprintf(stderr, " %s\n", mysql_stmt_error(stmt));
    mysql_rollback(db);
    return NULL;
  }

  // While rows to read. For this query there is only 0 or 1.
  rc=0;  // row count
  while (1) {
    status = mysql_stmt_fetch(stmt);
    if (status == 1 ) {
      printf ("Offer_zone: Error. Can't reserve a zone_name %s\n",mysql_error(db));
      mysql_rollback(db);
      return NULL;
    } else if (status == MYSQL_NO_DATA && rc==0) {
      printf ("Offer_zone: Info. Can't reserve a zone_name. No slots available.\n");
      mysql_rollback(db);
      return NULL;
    } else if (status == MYSQL_NO_DATA) {
      break; // last line. normal end of read
    }
    rc++;
    printf("rc %i zone_name %.*s id %i\n",rc,(int)length[1],zone_name,zone_id);
  }
  mysql_stmt_close(stmt);

  // create an HNA entry in infra
  printf("Create HNA\n");
  stmt=mysql_stmt_init(db);
  //stmt_str="INSERT INTO infra (name,created,assigned,ipv4,ipv6,node_type) VALUES (?,?,?,?,?,'hna')";
  stmt_str="INSERT INTO infra (`name`,`infra_status`,`infra_status_time`,`ipv6`,`node_type`) VALUES (?,'creating',?,?,'hna');";
  if (mysql_stmt_prepare(stmt, stmt_str, strlen(stmt_str))) {
    printf ("Insert infra: prepare failed. %s\n",mysql_stmt_error(stmt));
    mysql_rollback(db);
    return NULL;
  }
  memset(buf,'\0',sizeof(buf));
  snprintf(buf,MYSQL_STRLEN,"%s%s","hna-",zone_name); // concat with max MYSQL_STRLEN char

  MYSQL_BIND bind_infra[5];
  memset(bind_infra, 0, sizeof(bind_infra));

  bind_infra[0].buffer_type= MYSQL_TYPE_STRING;
  bind_infra[0].buffer= (char *)buf;
  bind_infra[0].buffer_length= MYSQL_STRLEN;
  bind_infra[0].is_null= 0;
  len1=strlen(buf);
  bind_infra[0].length= &len1;

  bind_infra[1].buffer_type= MYSQL_TYPE_LONGLONG;
  bind_infra[1].buffer= (char *)&start_slot;
  bind_infra[1].is_null= 0;
  bind_infra[1].length= 0;

  /*
  bind_infra[2].buffer_type= MYSQL_TYPE_LONGLONG;
  bind_infra[2].buffer= (char *)&start_slot;
  bind_infra[2].is_null= 0;
  bind_infra[2].length= 0;

  printf("ipv4:%s: %li\n",ipv4,strlen(ipv4));
  bind_infra[3].buffer_type= MYSQL_TYPE_STRING;
  bind_infra[3].buffer= (char *)ipv4;
  bind_infra[3].buffer_length= 15;
  bind_infra[3].is_null= 0;
  len2=strlen(ipv4);
  bind_infra[3].length= &len2;
  */

  bind_infra[2].buffer_type= MYSQL_TYPE_STRING;
  bind_infra[2].buffer= (char *)ipv6;
  bind_infra[2].buffer_length= 39;
  bind_infra[2].is_null= 0;
  len3=strlen(ipv6);
  bind_infra[2].length= &len3;

  if (mysql_stmt_bind_param(stmt, bind_infra)) {
    printf("Insert HNA: bind_infra failed %s\n",mysql_stmt_error(stmt));
    mysql_stmt_close(stmt);
    mysql_rollback(db);
    return NULL;
  }
  if (mysql_stmt_execute(stmt)) {
    printf ("Insert HNA: exec failed. %s\n",mysql_error(db));
    mysql_stmt_close(stmt);
    mysql_rollback(db);
    return NULL;
  }

  mysql_stmt_close(stmt);

  // get the newly created HNA entry infra_id back. We're the only process inserting on this table so this has no contention.
  printf("Get HNA\n");
  stmt=mysql_stmt_init(db);
  stmt_str="SELECT infra_id, name FROM infra WHERE name =? AND infra_status_time =? AND infra_status ='creating' ORDER BY infra_id DESC LIMIT 1";

  if (mysql_stmt_prepare(stmt, stmt_str, strlen(stmt_str))) {
    printf ("Get HNA: prepare failed. %s\n",mysql_stmt_error(stmt));
    mysql_rollback(db);
    return NULL;
  }
  // similar to previous so re-use bind
  memset(bind, 0, sizeof(bind));
  bind[0].buffer_type= MYSQL_TYPE_STRING;
  bind[0].buffer= (char *)buf;
  bind[0].buffer_length= MYSQL_STRLEN;
  bind[0].is_null= 0;
  len1=strlen(buf);
  bind[0].length= &len1;

  bind[1].buffer_type= MYSQL_TYPE_LONGLONG;
  bind[1].buffer= (char *)&start_slot;
  bind[1].is_null= 0;
  bind[1].length= 0;
/*
  bind[2].buffer_type= MYSQL_TYPE_LONGLONG;
  bind[2].buffer= (char *)&start_slot;
  bind[2].is_null= 0;
  bind[2].length= 0;
 */

  if (mysql_stmt_bind_param(stmt, bind)) {
    printf("Select HNA: bind failed %s\n",mysql_stmt_error(stmt));
    mysql_stmt_close(stmt);
    mysql_rollback(db);
    return NULL;
  }
  if (mysql_stmt_execute(stmt)) {
    printf ("Select HNA: exec failed. %s\n",mysql_error(db));
    mysql_stmt_close(stmt);
    mysql_rollback(db);
    return NULL;
  }

  // similar to previous so re-use bindout
  /* INTEGER COLUMN infra_id */
  memset(bindout, 0, sizeof(bindout));
  bindout[0].buffer_type= MYSQL_TYPE_LONG;
  bindout[0].buffer= (char *)&infra_id;
  bindout[0].is_null= &is_null[0];
  bindout[0].length= &length[0];
  bindout[0].error= &error[0];
  /* STRING COLUMN name */
  bindout[1].buffer_type= MYSQL_TYPE_STRING;
  bindout[1].buffer= (char *)&name;;
  bindout[1].buffer_length= MYSQL_STRLEN;
  bindout[1].is_null= &is_null[1];
  bindout[1].length= &length[1];
  bindout[1].error= &error[1];

  if (mysql_stmt_bind_result(stmt, bindout)) {
    fprintf(stderr, " mysql_stmt_bind_result() failed\n");
    fprintf(stderr, " %s\n", mysql_stmt_error(stmt));
    mysql_rollback(db);
    return NULL;
  }

  // While rows to read. For this query there is only 1.
  rc=0;  // row count
  while (1) {
    status = mysql_stmt_fetch(stmt);
    if (status == 1 || (status == MYSQL_NO_DATA && rc==0)) {
      printf ("make_zone: Error. Can't find infra id %s\n",mysql_error(db));
      mysql_rollback(db);
      return NULL;
    } else if (status == MYSQL_NO_DATA) {
      break; // last line. normal end of read
    }
    rc++;
    printf("rc %i name %.*s id %i\n",rc,(int)length[1],name,infra_id);
  }
  mysql_stmt_close(stmt);

  // update the reservation
  printf("UPDATE zone\n");
  stmt=mysql_stmt_init(db);
  stmt_str="UPDATE zone SET hna=? , zone_status='offered', zone_status_time=? WHERE zone_id =?";
  printf("UPDATE zone SET hna=%i,zone_status_time= %li WHERE zone_id=%i\n",infra_id,start_slot,zone_id);

  if (mysql_stmt_prepare(stmt, stmt_str, strlen(stmt_str))) {
    printf ("Update zone: prepare failed. %s\n",mysql_stmt_error(stmt));
    mysql_rollback(db);
    return NULL;
  }
  // similar to previous so re-use bind
  memset(bind, 0, sizeof(bind));
  bind[0].buffer_type= MYSQL_TYPE_LONG;
  bind[0].buffer= (char *)&infra_id;
  bind[0].is_null= 0;
  bind[0].length= 0;

  bind[1].buffer_type= MYSQL_TYPE_LONGLONG;
  bind[1].buffer= (char *)&start_slot;
  bind[1].is_null= 0;
  bind[1].length= 0;

  bind[2].buffer_type= MYSQL_TYPE_LONG;
  bind[2].buffer= (char *)&zone_id;
  bind[2].is_null= 0;
  bind[2].length= 0;

  if (mysql_stmt_bind_param(stmt, bind)) {
    printf("Select HNA: bind failed %s\n",mysql_stmt_error(stmt));
    mysql_stmt_close(stmt);
    mysql_rollback(db);
    return NULL;
  }
  if (mysql_stmt_execute(stmt)) {
    printf ("Select HNA: exec failed. %s\n",mysql_error(db));
    mysql_stmt_close(stmt);
    mysql_rollback(db);
    return NULL;
  }

  mysql_stmt_close(stmt);
  // commit the transaction
  mysql_commit(db);

  db_close(db);
  return dm_tofu_cp_name(zone_name);
}







// #######

/*
// create an invariant opaque pass phrase zone name like horse.dog.cat.zoo.here
// remember to free once used
char *make_zone_name (unsigned long seed, int nwords) ;

// return the current time slot
// can be called with 0 to use current time
time_t get_time_slot(time_t time);

// Create nzones zones under parent in the db.
// There can be collisions with existing names because the hash is truncated.
// A "unique" constraint on `name` will force this insert to fail gracefully.
// nzones is how many additional zones should be created
void create_zones(char *parent, int nzones ,time_t time_slot);
*/

// copy from temporary storage to something more permanent that can be returned to caller
// truncates to the field length of the DB string fields.
char *dm_tofu_cp_name(char *name) {
  if (name==NULL) {
    return NULL;
  }
  char *zn=(char *)malloc(MYSQL_STRLEN);
  int i;
  for (i=0;((i<MYSQL_STRLEN-1)&&(name[i]!='\0'));i++) {
    zn[i]=name[i];
  }
  zn[i]='\0';
  return zn; // be sure to free this later yourself
}


// kick off NS batch work
// take the host name and kick off functions to generate config
int dm_tofu_ns_batch() {
  printf("dm_tofu_ns_batch TODO\n");
}

// kick off DM batch work
int dm_tofu_dm_batch();

// check for a valid zone_status as this is an ENUM type in SQL.
// ('creating','created','offered','assigning','assigned','delegating','delegated','deleting')
// 0 = valid. -1 = not valid
int dm_tofu_is_valid_zone_status (char *zone_status);

// update db for the zone  zone_id to new zone_status
int dm_tofu_update_zone_status(MYSQL *db,int zone_id, char *zone_status) ;

// given a parent, return the name of the primary NS name. Remember to free
char *dm_tofu_get_ns(MYSQL *db,char *parent_name) {

  MYSQL_STMT *stmt;
  MYSQL_BIND bind[1];
  memset(bind, 0, sizeof(bind));
  size_t len1;
  int rc=0;  // row count

  int status;
  MYSQL_BIND bindout[1];
  memset(bindout, 0, sizeof(bindout));
  char ns_name[MYSQL_STRLEN];
  memset(ns_name,'\0',MYSQL_STRLEN);
  unsigned long length[1];
  bool is_null[1];
  bool error[1];

  if ( (parent_name==NULL) || (strlen(parent_name)<2) ) {
    printf("dm_tofu_get_ns: needs a parent name\n");
    return NULL;
  }

  stmt=mysql_stmt_init(db);
  char *stmt_str="SELECT A.name FROM infra AS A, parent AS B WHERE ( (B.parent_name=?) AND (A.infra_id = B.ns1) ); ";

  if (mysql_stmt_prepare(stmt, stmt_str, strlen(stmt_str))) {
    printf ("dm_tofu_get_ns: prepare failed. %s\n",mysql_stmt_error(stmt));
    mysql_stmt_close(stmt);
    return NULL;
  }

  bind[0].buffer_type= MYSQL_TYPE_STRING;
  bind[0].buffer= (char *)parent_name;
  bind[0].buffer_length= MYSQL_STRLEN;
  bind[0].is_null= 0;
  len1=strlen(parent_name);
  bind[0].length= &len1;

  if (mysql_stmt_bind_param(stmt, bind) ) {
    printf ("dm_tofu_get_ns: bind failed. %s\n",mysql_error(db));
    mysql_stmt_close(stmt);
    return NULL;
  }
  if (mysql_stmt_execute(stmt) ) {
    printf ("dm_tofu_get_ns: exec failed. %s\n",mysql_error(db));
    mysql_stmt_close(stmt);
    return NULL;
  }

  /* STRING COLUMN ns_name */
  bindout[0].buffer_type= MYSQL_TYPE_STRING;
  bindout[0].buffer= (char *)&ns_name;
  bindout[0].buffer_length= MYSQL_STRLEN;
  bindout[0].is_null= &is_null[0];
  bindout[0].length= &length[0];
  bindout[0].error= &error[0];

  if (mysql_stmt_bind_result(stmt, bindout)) {
    fprintf(stderr, " mysql_stmt_bind_result() failed\n");
    fprintf(stderr, " %s\n", mysql_stmt_error(stmt));
    mysql_stmt_close(stmt);
    return NULL;
  }

  // While rows to read. We only expect 1
  rc=0;  // row count
  while (1) {
    status = mysql_stmt_fetch(stmt);
    if (status == MYSQL_NO_DATA && rc==0) {
      printf ("dm_tofu_get_ns: normal. No data\n");
      break; 
    } else if (status == MYSQL_NO_DATA && rc>0) {
      break; // Last line. Normal end of read after match.
    } else if (status == 1 ) {
      printf ("dm_tofu_get_ns: Error. Can't check zone status for parent_name %s %s\n",parent_name,mysql_error(db));
      mysql_stmt_close(stmt);
      return NULL;
    } 
    // We have data to return but it is already in the buffer
    printf("rc %i ns_name %.*s \n",rc,(int)length[0],ns_name);
    rc++;
  }

  mysql_stmt_close(stmt);
  return dm_tofu_cp_name(ns_name); 

}


// given a parent, get a linked list of the secondary NS
ll_secondary_ns_t *dm_tofu_get_secondary_ns(MYSQL *db, char *parent_name) {
  ll_secondary_ns_t *ll_secondary_ns_tmp=NULL;
  ll_secondary_ns_t *ll_secondary_ns_current=NULL;
  ll_secondary_ns_t *ll_secondary_ns_head=NULL;

  int infra_id;
  char ns_name[MYSQL_STRLEN];
  MYSQL_STMT *stmt;
  MYSQL_BIND bind[1];
  memset(bind, 0, sizeof(bind));
  size_t len1;
  int rc=0;  // row count

  int status;
  MYSQL_BIND bindout[2];
  memset(bindout, 0, sizeof(bindout));
  unsigned long length[2];
  bool is_null[2];
  bool error[2];

  if ( (parent_name==NULL) || (strlen(parent_name)<2) ) {
    printf("dm_tofu_select_secondary_ns_status: needs a parent name\n");
    return NULL;
  }

  stmt=mysql_stmt_init(db);
  char *stmt_str="SELECT A.name, A.infra_id FROM infra AS A, parent AS B WHERE ( (B.parent_name=?) AND ((A.infra_id = B.ns2) OR (A.infra_id = B.ns3)) ); ";

  if (mysql_stmt_prepare(stmt, stmt_str, strlen(stmt_str))) {
    printf ("dm_tofu_select_secondary_ns_status: prepare failed. %s\n",mysql_stmt_error(stmt));
    mysql_stmt_close(stmt);
    return NULL;
  }

  bind[0].buffer_type= MYSQL_TYPE_STRING;
  bind[0].buffer= (char *)parent_name;
  bind[0].buffer_length= MYSQL_STRLEN;
  bind[0].is_null= 0;
  len1=strlen(parent_name);
  bind[0].length= &len1;

  if (mysql_stmt_bind_param(stmt, bind) ) {
    printf ("dm_tofu_select_secondary_ns_status: bind failed. %s\n",mysql_error(db));
    mysql_stmt_close(stmt);
    return NULL;
  }
  if (mysql_stmt_execute(stmt) ) {
    printf ("dm_tofu_select_secondary_ns_status: exec failed. %s\n",mysql_error(db));
    mysql_stmt_close(stmt);
    return NULL;
  }

  /* INTEGER COLUMN infra_id */
  bindout[0].buffer_type= MYSQL_TYPE_LONG;
  bindout[0].buffer= (char *)&infra_id;
  bindout[0].is_null= &is_null[0];
  bindout[0].length= &length[0];
  bindout[0].error= &error[0];
 
  /* STRING COLUMN ns_name */
  bindout[1].buffer_type= MYSQL_TYPE_STRING;
  bindout[1].buffer= (char *)&ns_name;
  bindout[1].buffer_length= MYSQL_STRLEN;
  bindout[1].is_null= &is_null[1];
  bindout[1].length= &length[1];
  bindout[1].error= &error[1];

  if (mysql_stmt_bind_result(stmt, bindout)) {
    fprintf(stderr, " mysql_stmt_bind_result() failed\n");
    fprintf(stderr, " %s\n", mysql_stmt_error(stmt));
    mysql_stmt_close(stmt);
    return NULL;
  }

  // While rows to read.
  rc=0;  // row count
  while (1) {
    status = mysql_stmt_fetch(stmt);
    if (status == MYSQL_NO_DATA && rc==0) {
      printf ("dm_tofu_select_secondary_ns_status: normal. No data\n");
      break; 
    } else if (status == MYSQL_NO_DATA && rc>0) {
      break; // Last line. Normal end of read after match.
    } else if (status == 1 ) {
      printf ("dm_tofu_select_secondary_ns_status: Error. Can't check zone status for parent_name %s %s\n",parent_name,mysql_error(db));
      mysql_stmt_close(stmt);
      return NULL;
    } 
    // We have data to return in a single linked list
    printf("rc %i ns_name %.*s id %i\n",rc,(int)length[1],ns_name,infra_id);
    ll_secondary_ns_tmp=(ll_secondary_ns_t*)malloc(sizeof(ll_secondary_ns_t));
    if (ll_secondary_ns_tmp==NULL) {
      printf("dm_tofu_select_secondary_ns_status: Error. Cannot allocate memory\n");
      exit (0);
    }
    memset(ll_secondary_ns_tmp,'\0',sizeof(ll_secondary_ns_t));
    ll_secondary_ns_tmp->next=NULL;
    // remember the head 1st time through
    if (ll_secondary_ns_head==NULL) {
      // ll_secondary_ns_head is pointer to pointer so content can be updated to this new storage
      ll_secondary_ns_head=ll_secondary_ns_tmp;
    } else {
      ll_secondary_ns_current->next=ll_secondary_ns_tmp;
    }
    ll_secondary_ns_current=ll_secondary_ns_tmp;
    ll_secondary_ns_current->infra_id=infra_id;
    strcpy(ll_secondary_ns_current->ns_name,ns_name);
    rc++;
  }

  mysql_stmt_close(stmt);
  return ll_secondary_ns_head; 

}


// create a linked list of zones under this parent with this zone_status
// returns rc or -1 on failure
int dm_tofu_select_zone_status(MYSQL *db, char *parent_name, char *zone_status, ll_zone_t **ll_zone_head) {

  ll_zone_t *ll_zone_tmp=NULL;
  ll_zone_t *ll_zone_current=NULL;

  char zone_name[MYSQL_STRLEN];
  MYSQL_STMT *stmt;
  MYSQL_BIND bind[2];
  memset(bind, 0, sizeof(bind));
  unsigned int zone_id;
  memset(bind, 0, sizeof(bind));
  size_t len1,len2;
  int rc=0;  // row count

  int status;
  MYSQL_BIND bindout[2];
  memset(bindout, 0, sizeof(bindout));
  unsigned long length[2];
  bool is_null[2];
  bool error[2];

  if ( (parent_name==NULL) || (strlen(parent_name)<2) ) {
    printf("dm_tofu_select_zone_status: needs a parent name\n");
    return -1;
  }

  stmt=mysql_stmt_init(db);
  char *stmt_str="SELECT A.zone_id, A.zone_name FROM zone AS A WHERE A.parent_name=? AND A.zone_status=?; ";

  if (mysql_stmt_prepare(stmt, stmt_str, strlen(stmt_str))) {
    printf ("dm_tofu_select_zone_status: prepare failed. %s\n",mysql_stmt_error(stmt));
    mysql_stmt_close(stmt);
    return -1;
  }

  bind[0].buffer_type= MYSQL_TYPE_STRING;
  bind[0].buffer= (char *)parent_name;
  bind[0].buffer_length= MYSQL_STRLEN;
  bind[0].is_null= 0;
  len1=strlen(parent_name);
  bind[0].length= &len1;

  bind[1].buffer_type= MYSQL_TYPE_STRING;
  bind[1].buffer= (char *)zone_status;
  bind[1].buffer_length= MYSQL_STRLEN;
  bind[1].is_null= 0;
  len2=strlen(zone_status);
  bind[1].length= &len2;

  if (mysql_stmt_bind_param(stmt, bind) ) {
    printf ("dm_tofu_select_zone_status: bind failed. %s\n",mysql_error(db));
    mysql_stmt_close(stmt);
    return -1;
  }
  if (mysql_stmt_execute(stmt) ) {
    printf ("dm_tofu_select_zone_status: exec failed. %s\n",mysql_error(db));
    mysql_stmt_close(stmt);
    return -1;
  }

  /* INTEGER COLUMN zone_id */
  bindout[0].buffer_type= MYSQL_TYPE_LONG;
  bindout[0].buffer= (char *)&zone_id;
  bindout[0].is_null= &is_null[0];
  bindout[0].length= &length[0];
  bindout[0].error= &error[0];
 
  /* STRING COLUMN zone_name */
  bindout[1].buffer_type= MYSQL_TYPE_STRING;
  bindout[1].buffer= (char *)&zone_name;
  bindout[1].buffer_length= MYSQL_STRLEN;
  bindout[1].is_null= &is_null[1];
  bindout[1].length= &length[1];
  bindout[1].error= &error[1];

  if (mysql_stmt_bind_result(stmt, bindout)) {
    fprintf(stderr, " mysql_stmt_bind_result() failed\n");
    fprintf(stderr, " %s\n", mysql_stmt_error(stmt));
    mysql_stmt_close(stmt);
    return -1;
  }

  // While rows to read.
  rc=0;  // row count
  while (1) {
    status = mysql_stmt_fetch(stmt);
    if (status == MYSQL_NO_DATA && rc==0) {
      printf ("dm_tofu_select_zone_status: normal. No data\n");
      break; 
    } else if (status == MYSQL_NO_DATA && rc>0) {
      break; // Last line. Normal end of read after match.
    } else if (status == 1 ) {
      printf ("dm_tofu_select_zone_status: Error. Can't check zone status for parent_name %s %s\n",parent_name,mysql_error(db));
      mysql_stmt_close(stmt);
      return -1;
    } 
    // We have data to return in a single linked list
    printf("rc %i zone_name %.*s id %i\n",rc,(int)length[1],zone_name,zone_id);
    ll_zone_tmp=(ll_zone_t*)malloc(sizeof(ll_zone_t));
    if (ll_zone_tmp==NULL) {
      printf("dm_tofu_select_zone_status: Error. Cannot allocate memory\n");
      exit (0);
    }
    memset(ll_zone_tmp,'\0',sizeof(ll_zone_t));
    ll_zone_tmp->next=NULL;
    // remember the head 1st time through
    if (*ll_zone_head==NULL) {
      // ll_zone_head is pointer to pointer so content can be updated to this new storage
      *ll_zone_head=ll_zone_tmp;
    } else {
      ll_zone_current->next=ll_zone_tmp;
    }
    ll_zone_current=ll_zone_tmp;
    ll_zone_current->zone_id=zone_id;
    strcpy(ll_zone_current->zone_name,zone_name);
    rc++;
  }

  mysql_stmt_close(stmt);
  return rc;

}

// Batch job to move zones from creating to created
// returns number of zones timed out or -1 for error
// ns is the name of the name server that is being configured
// (static for now but allows horizontal scaling later)
int dm_tofu_creating_to_created(char *parent_name);

// Check time out for zones stuck in created zone_status (that have not been claimed).
// Uses Innodb atomic transaction to ensure completeness.
// Marks zones for deletion, rather than directly actioning
// returns number of zones timed out or -1 for error
int timeout_created_zone(char *parent_name, time_t time_slot){ //By default this is for slot time -2
//	TODO
}

// Offer 1 zone name under parent in the db
// Uses Innodb atomic transaction to ensure uniqueness.
// Blank zone for failure (no more slots)
// The zone is then "locked" to the HNA via IP address
// This helps prevent race conditions where a zone is assigned,
// but the associated certificate has not yet been issued.
// char* offer_zone(char *parent_name, char *ip, time_t time_slot); // only one version of ip is supported. Either v4 or v6
							      //
// Check time out for zones stuck in offered zone_status (that have not transitioned to assigned).
// Uses Innodb atomic transaction to ensure completeness.
// Marks zones for deletion, rather than directly actioning
// returns number of zones timed out or -1 for error
int timeout_offered_zone(char *parent_name, time_t time_slot){ //By default this is for slot time -60
//	TODO
}

// Batch job to move zones from assigning to assigned
// returns number of zones timed out or -1 for error
int dm_tofu_assigning_to_assigned(char *parent_name){
//	TODO
}

// Check time out for zones stuck in assigned zone_status (that have not transitioned to delegated).
// Marks zones for deletion, rather than directly actioning
// returns number of zones timed out or -1 for error
int timeout_assigned_zone(char *parent_name, time_t time_slot){ //By default this is for slot time -60
//	TODO
}

// Batch job to move zones from delegating to delegated
// returns number of zones timed out or -1 for error
int dm_tofu_delegating_to_delegated(char *parent_name){
//	TODO
}

// Batch job to move zones from deleting to deleted
// returns number of zones timed out or -1 for error
int dm_tofu_deleting_to_deleted(char *parent_name){
//	TODO
}

// returns an offered zone from the pre-created list in packet format
 ldns_pkt * dm_tofu_query_ptr_response(ldns_pkt *query_pkt, char *parent_name, char *zone) { // parent_name is the owner. zone is the zone to be delegated
//	TODO
}

// function called from dm_worker to process and inbound query PTR packet
ldns_pkt * dm_worker_query_ptr(ldns_pkt *query_pkt, struct ssl_client *p_ssl_client){ // 1st arg = packet, 2nd arg=SSL client (for cert)
//	TODO
}

// Background job threads for TOFU

// function called from server create file for knotc commands
char *knot_helpers_create_file();
// function called from server exec knot helper
int knot_helpers_exec_file(char *filename);
// function called from server delete file containing knotc commands
int knot_helpers_delete_file(char *filename);

// function called from server to start backround thread for regular tasks
dm_tofu_thread_t *dm_tofu_bg_start(int thread_num) {

  dm_tofu_thread_t *ptr;
  ptr=(dm_tofu_thread_t *)malloc(sizeof(dm_tofu_thread_t));
  memset(ptr,'\0',sizeof(dm_tofu_thread_t));
  ptr->run=1;
  ptr->last_exec=0;
  ptr->last_awake=0;
  ptr->last_time_slot=0;
  ptr->thread_num=thread_num; // not used
  pthread_create(&(ptr->thread_id), NULL, dm_tofu_bg_exec, ptr);
  return ptr;
} 
  
// function called from server to execute backround thread for regular tasks
void *dm_tofu_bg_exec(void *arguments) { // a single storage element with vars for this thread
  dm_tofu_thread_t *ptr;
  ptr =(dm_tofu_thread_t *)arguments;
  while (ptr->run ==1) {
    time_t now=time(NULL);
    time_t start_time_slot=get_time_slot(now);
    printf("dm_tofu_bg_exec: woke up\n");
    // printf("now %li last_time_slot %li start_time_slot%li\n",now,ptr->last_time_slot,start_time_slot);
    // printf("next exec at %li\n",ptr->last_time_slot+DM_TOFU_SLOT_LENGTH);
    sleep(1+rand()%2);
    ptr->last_awake=now;
    if (now >= (ptr->last_time_slot + DM_TOFU_SLOT_LENGTH)) {
      printf("dm_tofu_bg_exec: Exec now %li last_time_slot %li start_time_slot%li\n",now,ptr->last_time_slot,start_time_slot);
      ptr->last_exec=now;
      ptr->last_time_slot=start_time_slot;
      printf("next awake at %li\n",ptr->last_time_slot+DM_TOFU_SLOT_LENGTH);
    }
  }
}
// function called from server to stop backround thread for regular tasks
int dm_tofu_bg_stop(dm_tofu_thread_t **my_thread) { // pointer to a threads
  dm_tofu_thread_t *ptr;
  int s;
  printf("dm_tofu_bg_stop: stopping\n");
  ptr=*my_thread;//set semaphore
  ptr->run=0;
  // wait for termination
  s = pthread_join(ptr->thread_id, NULL);
  if (s != 0) {
    printf("dm_tofu_bg_stop: Error %i", s);
    return -1;
  }
  free(ptr);
  ptr=NULL;
  return 0;
}
