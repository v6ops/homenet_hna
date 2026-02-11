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


// print a linked list of zones. Remember to set point to NULL on return.
int dm_tofu_print_ll_zone(ll_zone_t *ll_zone_head) {

  ll_zone_t *ll_zone_tmp=NULL;
  ll_zone_t *ll_zone_current=NULL;
  ll_zone_current=ll_zone_head;
  int rc=0;
  while (ll_zone_current != NULL) {
    printf("Zone_name %s zone_id %i\n",ll_zone_current->zone_name,ll_zone_current->zone_id);
    ll_zone_tmp=ll_zone_current->next;
    free(ll_zone_current);
    ll_zone_current=ll_zone_tmp;
    rc++;
  }
  return rc;
}

// print a linked list of ns. Remember to set point to NULL on return.
int dm_tofu_print_ll_ns(ll_secondary_ns_t *ll_ns_head) {

  ll_secondary_ns_t *ll_ns_tmp=NULL;
  ll_secondary_ns_t *ll_ns_current=NULL;
  ll_ns_current=ll_ns_head;
  int rc=0;
  while (ll_ns_current != NULL) {
    printf("NS %s infra_id %i\n",ll_ns_current->ns_name,ll_ns_current->infra_id);
    ll_ns_tmp=ll_ns_current->next;
    free(ll_ns_current);
    ll_ns_current=ll_ns_tmp;
    rc++;
  }
  return rc;
}

// print a linked list of parent. Remember to set point to NULL on return.
int dm_tofu_print_ll_parent(ll_parent_t *ll_parent_head) {

  ll_parent_t *ll_parent_tmp=NULL;
  ll_parent_t *ll_parent_current=NULL;
  ll_parent_current=ll_parent_head;
  int rc=0;
  while (ll_parent_current != NULL) {
    printf("parent_name %s parent_id %i\n",ll_parent_current->parent_name,ll_parent_current->parent_id);
    ll_parent_tmp=ll_parent_current->next;
    free(ll_parent_current);
    ll_parent_current=ll_parent_tmp;
    rc++;
  }
  return rc;
}

// print a linked list of cwrrparent. Remember to set point to NULL on return.
int dm_tofu_print_ll_rr(ll_rr_t *ll_rr_head) {

  ll_rr_t *ll_rr_tmp=NULL;
  ll_rr_t *ll_rr_current=NULL;
  ll_rr_current=ll_rr_head;
  int rc=0;
  while (ll_rr_current != NULL) {
    printf("rr_owner %s rr_id %i rr_ttl %i rr_type %s rr_rdata %s\n",ll_rr_current->rr_owner,ll_rr_current->rr_id,ll_rr_current->rr_ttl,ll_rr_current->rr_type,ll_rr_current->rr_rdata);
    ll_rr_tmp=ll_rr_current->next;
    free(ll_rr_current);
    ll_rr_current=ll_rr_tmp;
    rc++;
  }
  return rc;
}




// Convert an ascii encoded hex string to decimal
// Each char is 4 bits
// limited to 32 bits (8 hex chars)
uint32_t hexstr2dec(unsigned char *hex, int len) {
  int i;
  int c=0;
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
int do_EVP_SHA256(const unsigned char *message, size_t message_len, unsigned char **digest, unsigned int *digest_len) {

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

// take a message and a private key (key) and return the HMAC_SHA256(message,key) in the digest
int do_EVP_HMACSHA256(const unsigned char *message, size_t message_len, const unsigned char *key, size_t key_len, unsigned char **digest, size_t *digest_len) {
  EVP_MD_CTX* mdctx = NULL;
  EVP_PKEY *pkey = NULL;

  if(!(mdctx = EVP_MD_CTX_create())) {
    printf("do_EVP: Can't create CTX\n");
    return -1;
  }

  if(!(pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_HMAC, NULL, key, key_len))) {
    printf("do_EVP: Can't create mac key\n");
    return -1;
  }

  if(1 != EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, pkey)) {
    printf("do_EVP: Can't init CTX\n");
    return -1;
  }

  /* Call update with the message */
  if(1 != EVP_DigestSignUpdate(mdctx, message, message_len)) {
    printf("do_EVP: Can't update digest\n");
    return -1;
  }

  if(1 != EVP_DigestSignFinal(mdctx, *digest, digest_len)) {
    printf("do_EVP: Can't finalise digest\n");
    return -1;
  }
  EVP_MD_CTX_destroy(mdctx);
  EVP_PKEY_free(pkey);

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
  //printf("make_zone_name: %li %i\n",seed,nwords);

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
  size_t *digest_length;
  size_t len=EVP_MD_size(EVP_sha256());
  digest_length=&len;
  int d;        // temp decimal

  char buf[21]; // unsigned long is max 21 chars (inc \0)
  snprintf(buf, 21, "%li", seed); // is null terminated

  // create a message digest.
  // Does not have to be crypto secure but this yields
  // hard to guess zone names if people are abusive,
  // provided the seed is good.
  //do_EVP_SHA256((const unsigned char *)buf, (size_t)strlen(buf), &md, digest_length);
  char secret[]=DM_TOFU_PRIVATE_KEY;
  do_EVP_HMACSHA256((const unsigned char *)buf, (size_t)strlen(buf),(const unsigned char *)secret, (size_t)strlen(secret), &md, digest_length);

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
  // printf("make_zone_name %s\n",zn);
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


// select zone_id given a zone_name
// return -1 for no match or errors
int dm_tofu_select_zone_id(MYSQL *db, char *zone_name){
  int zone_id=0;
  MYSQL_STMT *stmt;
  MYSQL_BIND bind[1];
  memset(bind, 0, sizeof(MYSQL_BIND));
  size_t len1;
  MYSQL_BIND bindout[1];
  memset(bindout, 0, sizeof(bindout));

  int status;
  unsigned long length[1];
  bool is_null[1];
  bool error[1];
  int rc=0;

  printf("select_zone_id\n");
  // Strip any trailing dots. These are never stored in the db.
  char search_str[MYSQL_STRLEN]={'\0'};
  strcpy(search_str,zone_name);
  ldns_helpers_strip_trailing_dot(search_str);

  stmt=mysql_stmt_init(db);
  char *stmt_str="SELECT zone_id FROM zone WHERE (zone_name =?) ORDER BY zone_id LIMIT 1;";

  if (mysql_stmt_prepare(stmt, stmt_str, strlen(stmt_str))) {
    printf ("select_zone_id: prepare failed. %s\n",mysql_stmt_error(stmt));
    mysql_stmt_close(stmt);
    return -1;
  }
  // zone_name
  memset(bind, 0, sizeof(bind));
  bind[0].buffer_type= MYSQL_TYPE_STRING;
  bind[0].buffer= (char *)search_str;
  bind[0].buffer_length= MYSQL_STRLEN;
  bind[0].is_null= 0;
  len1=strlen(search_str);
  bind[0].length= &len1;

  if (mysql_stmt_bind_param(stmt, bind)) {
    printf("select_zone_id: bind failed %s\n",mysql_stmt_error(stmt));
    mysql_stmt_close(stmt);
    return -1;
  }
  if (mysql_stmt_execute(stmt)) {
    printf ("select_zone_id: exec failed. %s\n",mysql_error(db));
    mysql_stmt_close(stmt);
    return -1;
  }

  /* INTEGER COLUMN zone_id */
  bindout[0].buffer_type= MYSQL_TYPE_LONG;
  bindout[0].buffer= (char *)&zone_id;
  bindout[0].is_null= &is_null[0];
  bindout[0].length= &length[0];
  bindout[0].error= &error[0];
 
  if (mysql_stmt_bind_result(stmt, bindout)) {
    fprintf(stderr, " mysql_stmt_bind_result() failed\n");
    fprintf(stderr, " %s\n", mysql_stmt_error(stmt));
    mysql_stmt_close(stmt);
    return -1;
  }

  // While rows to read. For this query there is only 0 or 1.
  rc=0;  // row count
  while (1) {
    status = mysql_stmt_fetch(stmt);
    if (status == 1 ) {
      printf ("select_zone_id Error. Can't select zone_name %s\n",mysql_error(db));
      mysql_stmt_close(stmt);
      return -1;
    } else if (status == MYSQL_NO_DATA && rc==0) {
      printf ("select_zone_id: Info. Can't find a zone_name.\n");
      mysql_stmt_close(stmt);
      return -1;
    } else if (status == MYSQL_NO_DATA) {
      break; // last line. normal end of read
    }
    rc++;
    printf("rc %i zone_name %.*s id %i\n",rc,(int)length[0],zone_name,zone_id);
  }
  mysql_stmt_close(stmt);
  return zone_id;
}

 
// Create nzones zones under parent in the db.
// There can be collisions with existing names because the hash is truncated.
// A "unique" constraint on `name` will force this insert to fail gracefully.
void create_zones(MYSQL *db, char *parent_name, int nzones, time_t now){
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

  stmt=mysql_stmt_init(db);
  char *stmt_str="INSERT INTO zone (zone_name,parent_name,zone_status,zone_status_time) VALUES (?,?,'creating',?);";
  if (mysql_stmt_prepare(stmt, stmt_str, strlen(stmt_str))) {
    printf("create_zones: Can't prepare stmt. %s %s",stmt_str,mysql_error(db));
    exit(0);
  }

  int i=0;
  int ret=0;
  int collisions=0; // track failed inserts (asssume due to name collisions)
  while(i<nzones) {
    zn=make_zone_name(slot+i+OFFSET+collisions,4);
    ret=snprintf(buf,MYSQL_STRLEN,"%s.%s",zn,parent_name); // concat with max MYSQL_STRLEN char
    if (ret <0) { // this will never be hit if MYSQL_STRLEN has been used correctly, but prevents potential compiler warnings
      printf("create_zones: Warning. Zone name %s truncated to db field length MYSQL_STRLEN chars\n",buf);
    }
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
}

// Offer 1 zone_name under parent in the db
// Uses Innodb atomic transaction to ensure uniqueness.
// Blank zone_name for failure (no more slots)
// The zone is then "locked" to the HNA via IP address
char *offer_zone(MYSQL *db, char *parent_name, char *ipv6, time_t slot_time){
  char zone_name[MYSQL_STRLEN];
  char name[MYSQL_STRLEN]; // infra table
  char buf[MYSQL_STRLEN]; // length database name field
  memset(buf,'\0',sizeof(buf));
  time_t start_slot,end_slot,start_valid;
  MYSQL_STMT *stmt;
  MYSQL_RES *result;
  MYSQL_BIND bind[3];
  unsigned int zone_id;
  unsigned int infra_id;
  memset(bind, 0, sizeof(bind));
  size_t len1,len3;
  int rc=0;  // row count

  int status;
  MYSQL_BIND bindout[2];
  memset(bindout, 0, sizeof(bindout));
  unsigned long length[2];
  bool is_null[2];
  bool error[2];

  start_slot=(slot_time>0) ? slot_time : get_time_slot(0);
  end_slot=start_slot+60;
  start_valid=start_slot-DM_TOFU_T1+2*60; // in this version allow old zones rather than deleting them after expiry of every slot
  if (start_valid<0) { // some sytems have -ve time_t. Others don't.
    start_valid=0;
  }
  printf("Assigning zones at slot %lu\n",start_slot);

  if ( (ipv6==NULL) || (strlen(ipv6)<2) ) {
    printf("offer_zone: needs an IPv6 address\n");
    return NULL;
  }

  stmt=mysql_stmt_init(db);
  // start a transaction
  if (mysql_query(db,"BEGIN")) {
    printf ("offer_zone: Error. Can't start transaction\n");
    mysql_stmt_close(stmt);
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
    mysql_stmt_close(stmt);
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
    mysql_rollback(db);
    mysql_stmt_close(stmt);
    return NULL;
  }
  if (mysql_stmt_execute(stmt) ) {
    printf ("offer_zone: exec failed. %s\n",mysql_error(db));
    mysql_rollback(db);
    mysql_stmt_close(stmt);
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
    mysql_rollback(db);
    mysql_stmt_close(stmt);
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
    mysql_rollback(db);
    mysql_stmt_close(stmt);
    return dm_tofu_cp_name(zone_name);
  }
  mysql_stmt_close(stmt);

  // reserve one row that has not been created
  // and is in the current time slot
  // and parent matches.
  // This will lock this row for other threads until the transaction commits. Skipped locked means another thread can continue and find the next row.
  printf("Reserve zone\n");
  stmt=mysql_stmt_init(db);
  stmt_str="SELECT zone_id, zone_name FROM zone WHERE (zone_status='created' AND parent_name =? AND zone_status_time >=? AND zone_status_time <? ) ORDER BY zone_id LIMIT 1 FOR UPDATE SKIP LOCKED";

  if (mysql_stmt_prepare(stmt, stmt_str, strlen(stmt_str))) {
    printf ("Reserve zone: prepare failed. %s\n",mysql_stmt_error(stmt));
    mysql_rollback(db);
    mysql_stmt_close(stmt);
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
  // bind[1].buffer= (char *)&start_slot;
  bind[1].buffer= (char *)&start_valid; // allow older zones
  bind[1].is_null= 0;
  bind[1].length= 0;

  bind[2].buffer_type= MYSQL_TYPE_LONGLONG;
  bind[2].buffer= (char *)&end_slot;
  bind[2].is_null= 0;
  bind[2].length= 0;

  if (mysql_stmt_bind_param(stmt, bind)) {
    printf("Reserve zone: bind failed %s\n",mysql_stmt_error(stmt));
    mysql_rollback(db);
    mysql_stmt_close(stmt);
    return NULL;
  }
  if (mysql_stmt_execute(stmt)) {
    printf ("offer_zone: exec failed. %s\n",mysql_error(db));
    mysql_rollback(db);
    mysql_stmt_close(stmt);
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
    mysql_stmt_close(stmt);
    return NULL;
  }

  // While rows to read. For this query there is only 0 or 1.
  rc=0;  // row count
  while (1) {
    status = mysql_stmt_fetch(stmt);
    if (status == 1 ) {
      printf ("Offer_zone: Error. Can't reserve a zone_name %s\n",mysql_error(db));
      mysql_rollback(db);
      mysql_stmt_close(stmt);
      return NULL;
    } else if (status == MYSQL_NO_DATA && rc==0) {
      printf ("Offer_zone: Info. Can't reserve a zone_name. No slots available.\n");
      mysql_rollback(db);
      mysql_stmt_close(stmt);
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
    mysql_stmt_close(stmt);
    return NULL;
  }
  memset(buf,'\0',sizeof(buf));
  int ret=snprintf(buf,MYSQL_STRLEN,"%s%s","hna-",zone_name); // concat with max MYSQL_STRLEN char
  if (ret <0) {
    printf("Offer_zone: Warning. HNA name %s truncated to db field length MYSQL_STRLEN chars\n",buf);
  }

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
    mysql_rollback(db);
    mysql_stmt_close(stmt);
    return NULL;
  }
  if (mysql_stmt_execute(stmt)) {
    printf ("Insert HNA: exec failed. %s\n",mysql_error(db));
    mysql_rollback(db);
    mysql_stmt_close(stmt);
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
    mysql_stmt_close(stmt);
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
    mysql_rollback(db);
    mysql_stmt_close(stmt);
    return NULL;
  }
  if (mysql_stmt_execute(stmt)) {
    printf ("Select HNA: exec failed. %s\n",mysql_error(db));
    mysql_rollback(db);
    mysql_stmt_close(stmt);
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
    mysql_stmt_close(stmt);
    return NULL;
  }

  // While rows to read. For this query there is only 1.
  rc=0;  // row count
  while (1) {
    status = mysql_stmt_fetch(stmt);
    if (status == 1 || (status == MYSQL_NO_DATA && rc==0)) {
      printf ("make_zone: Error. Can't find infra id %s\n",mysql_error(db));
      mysql_rollback(db);
      mysql_stmt_close(stmt);
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
    mysql_stmt_close(stmt);
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
    mysql_rollback(db);
    mysql_stmt_close(stmt);
    return NULL;
  }
  if (mysql_stmt_execute(stmt)) {
    printf ("Select HNA: exec failed. %s\n",mysql_error(db));
    mysql_rollback(db);
    mysql_stmt_close(stmt);
    return NULL;
  }

  mysql_stmt_close(stmt);
  // commit the transaction
  mysql_commit(db);

  return dm_tofu_cp_name(zone_name);
}



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
void dm_tofu_ns_batch(MYSQL *db) {
  printf("dm_tofu_ns_batch:started\n");
  ll_parent_t *ll_parent_head=NULL;
  ll_parent_t *ll_parent_tmp=NULL;
  ll_parent_t *ll_parent_current=NULL;
  int rc= dm_tofu_select_parent_ns(db,&ll_parent_head);
  time_t slot_time=get_time_slot(0);
  // we have NS work to do on this machine
  if (rc>0) {
    ll_parent_current=ll_parent_head;
    while (ll_parent_current!=NULL) {
      // do the NS config updates
      printf("dm_tofu_ns_batch: processing %s\n",ll_parent_current->parent_name);
      dm_tofu_ns_update(db,ll_parent_current->parent_name,"creating",slot_time);
      dm_tofu_ns_update(db,ll_parent_current->parent_name,"delegating",slot_time);
      dm_tofu_ns_update(db,ll_parent_current->parent_name,"assigning",slot_time);
      dm_tofu_ns_update(db,ll_parent_current->parent_name,"deleting",slot_time);
      //dm_tofu_creating_to_created(db,ll_parent_current->parent_name,slot_time);
      //dm_tofu_assigning_to_assigned(db,ll_parent_current->parent_name,slot_time);
      //dm_tofu_delegating_to_delegated(db,ll_parent_current->parent_name,slot_time);
      //dm_tofu_deleting_to_deleted(db,ll_parent_current->parent_name,slot_time);
      ll_parent_tmp=ll_parent_current->next;
      free(ll_parent_current);
      ll_parent_current=ll_parent_tmp;
    }
  }
}

// kick off DM batch work
void dm_tofu_dm_batch(MYSQL *db) {
  printf("dm_tofu_dm_batch:started\n");
  ll_parent_t *ll_parent_head=NULL;
  ll_parent_t *ll_parent_tmp=NULL;
  ll_parent_t *ll_parent_current=NULL;

  int ret=0;
  int zone_count=0;

  int rc= dm_tofu_select_parent_dm(db,&ll_parent_head);
  time_t slot_time=get_time_slot(0);
  // we have DM work to do on this machine
  if (rc>0) {
    ll_parent_current=ll_parent_head;
    while (ll_parent_current!=NULL) {
      // do the DM timeouts
      printf("dm_tofu_dm_batch: processing %s\n",ll_parent_current->parent_name);
      dm_tofu_timeout_created_zone(db,ll_parent_current->parent_name,slot_time);
      dm_tofu_timeout_offered_zone(db,ll_parent_current->parent_name,slot_time);
      dm_tofu_timeout_assigned_zone(db,ll_parent_current->parent_name,slot_time);
      dm_tofu_timeout_delegated_zone(db,ll_parent_current->parent_name,slot_time);

      // maintain a pool of DM_TOFU_POOL_SIZE zones in creating or created status (this rate limits new zone allocation)
      zone_count=0;
      ret=dm_tofu_count_zone_status(db, ll_parent_current->parent_name, "creating");
      if (ret>0) {
        zone_count+=ret;
      }
      printf("dm_tofu_dm_batch: zone count creating %i\n",zone_count);
      ret=dm_tofu_count_zone_status(db, ll_parent_current->parent_name, "created");
      if (ret>0) {
        zone_count+=ret;
      }
      printf("dm_tofu_dm_batch: zone count created %i\n",zone_count);
      if (zone_count < DM_TOFU_POOL_SIZE) {
        printf("dm_tofu_dm_batch: creating %i new zones\n",DM_TOFU_POOL_SIZE - zone_count);
        create_zones(db, ll_parent_current->parent_name, DM_TOFU_POOL_SIZE - zone_count, slot_time);
      }

      // next parent zone
      ll_parent_tmp=ll_parent_current->next;
      free(ll_parent_current);
      ll_parent_current=ll_parent_tmp;
    }
  }
  printf("dm_tofu_dm_batch:ended\n");
}

// check for a valid zone_status as this is an ENUM type in SQL.
// ('creating','created','offered','assigning','assigned','delegating','delegated','deleting')
// 0 = valid. -1 = not valid
int dm_tofu_is_valid_zone_status (char *zone_status) {

  if ( (zone_status==NULL) || (strlen(zone_status)<7) ) {
    return -1;
  }
  if ( (strcmp(zone_status,"creating")==0) || (strcmp(zone_status,"created")==0) \
          || (strcmp(zone_status,"offered")==0) || (strcmp(zone_status,"assigning")==0) \
          || (strcmp(zone_status,"assigned")==0) || (strcmp(zone_status,"delegating")==0) \
          || (strcmp(zone_status,"delegated")==0) || (strcmp(zone_status,"deleting")==0) ) {
    return 0;
  }
  return -1;
}

// check for a valid zone_status as this is an ENUM type in SQL.
// ('creating','created','deleting')
// 0 = valid. -1 = not valid
int dm_tofu_is_valid_rr_status (char *rr_status) {

  if ( (rr_status==NULL) || (strlen(rr_status)<7) ) {
    return -1;
  }
  if ( (strcmp(rr_status,"creating")==0) || (strcmp(rr_status,"created")==0) \
          || (strcmp(rr_status,"deleting")==0) ) {
    return 0;
  }
  return -1;
}

// check for a valid rr_type as this is an ENUM type in SQL.
// (aaaa,ns,ds,txt)
// 0 = valid. -1 = not valid
int dm_tofu_is_valid_rr_type (char *rr_type) {

  if ( (strcmp(rr_type,"AAAA")==0) || (strcmp(rr_type,"NS")==0) || (strcmp(rr_type,"DS")==0) || (strcmp(rr_type,"TXT")==0) ) {
    return 0;
  }
  return -1;
}
// check for a valid l_rr_type (LDNS int coding for rr_type)
// 0 = valid. -1 = not valid
int dm_tofu_is_valid_l_rr_type (ldns_rr_type l_rr_type) {

  if ( (l_rr_type==LDNS_RR_TYPE_AAAA ) || (l_rr_type==LDNS_RR_TYPE_TXT ) || (l_rr_type==LDNS_RR_TYPE_NS ) || (l_rr_type==LDNS_RR_TYPE_DS ) ) {
    return 0;
  }
  return -1;
}




// insert db entry into zone for ONE ldns_rr
// ldns_rr typically comes from the Update/Authority field of a DNS packet
// zone comes from the Zone section/Question field
// all validity checks should have already been done before calling.
// This is for "standard" add and delete of RR. Not of the whole delgation.
// as per RFC2136
// 2.5.1 add single RR      NAME specified. TYPE specified. CLASS IN.   RDATA specified. TTL specified
// 2.2.2 Delete an RR Set   NAME specified. TYPE specified. CLASS ANY.  RDATA blank.     TTL 0
// 2.2.3 Delete all RR Sets NAME specified. TYPE ANY.       CLASS ANY.  RDATA blank.     TTL 0
// 2.2.4 Delete a single RR NAME specified. TYPE specified. CLASS NONE. RDATA specified. TTL 0
// returns are DNS error codes
int dm_tofu_insert_rr(MYSQL *db, int zone_id, ldns_rr *rr, time_t slot_time) {

  MYSQL_STMT *stmt=NULL;
  MYSQL_BIND bind[8];
  memset(bind, 0, sizeof(bind));

  if (zone_id<1) {
    printf("dm_tofu_insert_rr: needs a valid zone\n");
    return LDNS_RCODE_NOTZONE; // we don't have this zone under management
  }

  size_t len1,len2,len3,len4;
  char rr_status[MYSQL_STRLEN];
  memset(rr_status,'\0',MYSQL_STRLEN);
  char rr_owner[LDNS_MAX_DOMAINLEN];
  memset(rr_owner,'\0',LDNS_MAX_DOMAINLEN);
  char rr_rdata[LDNS_MAX_DOMAINLEN];
  memset(rr_rdata,'\0',LDNS_MAX_DOMAINLEN);
  int rr_ttl=0;
  ldns_rr_type l_rr_type;
  ldns_rr_class rr_class;
  ldns_status l_status;
  ldns_rdf_type l_rdf_type;
  ldns_rdf *l_rdf=NULL;
  ldns_buffer *buf1=NULL;
  ldns_buffer *buf2=NULL;
  char stmt_str[160]; // only used for fixed length queries defined below
  memset(stmt_str,'\0',sizeof(stmt_str));
  char *tmp=NULL;

  char *TXT="TXT";
  char *NS="NS";
  char *AAAA="AAAA";
  char *DS="DS";
  char *ANY="ANY";
  char *rr_type;
  int ignore_type=0;
  int ignore_rdata=0;

  time_t rr_status_time=(slot_time>0) ? slot_time : get_time_slot(0);

  if (rr==NULL) { 
    return LDNS_RCODE_FORMERR;
  }

  rr_class=ldns_rr_get_class(rr);
  // ignore rdata for class=any
  if ( rr_class==LDNS_RR_CLASS_ANY ) {
    ignore_rdata=1;
  }
  // check if this is an add or delete
  if ( (rr_class==LDNS_RR_CLASS_NONE) || (rr_class==LDNS_RR_CLASS_ANY) ) {
    strcpy(rr_status,"deleting");
    // ignore TTL from the rr. It must be 0 and ignored anyway.
    rr_ttl=0;
  } else if (rr_class!=LDNS_RR_CLASS_IN) { // only works for IN (Internet) Class. This is local policy thus refused.
    return LDNS_RCODE_REFUSED;
  } else {
    strcpy(rr_status,"creating");
    rr_ttl=ldns_rr_ttl(rr);
    // ignore short TTL on adds. This is not standard, but our own local policy limit.
    if (rr_ttl<600) {
      rr_ttl=600;
    }
  }

  l_rr_type=ldns_rr_get_type(rr);
  if ( (dm_tofu_is_valid_l_rr_type(l_rr_type)<0) && ( !((rr_class==LDNS_RR_CLASS_ANY)&&(l_rr_type==LDNS_RR_TYPE_ANY) ) ) ) {
    return LDNS_RCODE_REFUSED ; // we don't handle this type of RR
  }

  // Gather the data for the query params
  //
  //
  size_t i=0;
  printf("ldns_rr_rd_count %lu\n",ldns_rr_rd_count(rr));
  for (i=0;i<ldns_rr_rd_count(rr);i++) {
        l_rdf=ldns_rr_rdf(rr,i); // grab the rdf
        l_rdf_type=ldns_rdf_get_type(l_rdf);
	printf("ldns_rdf_type %li %u\n",i,l_rdf_type);
  }
  switch (l_rr_type) { // translate LDNS RR type to a text string for entry in the db
    case LDNS_RR_TYPE_TXT:
      rr_type=TXT;
      if (ignore_rdata==0) {
	if (ldns_rr_rd_count(rr)!=1) {
          return LDNS_RCODE_FORMERR;
	}
        l_rdf=ldns_rr_rdf(rr,0); // grab the first rdf. There is only one for TXT.
        l_rdf_type=ldns_rdf_get_type(l_rdf);
        if (l_rdf_type!=LDNS_RDF_TYPE_STR ) { // we should only have dname rdf in an ns rr
          return LDNS_RCODE_FORMERR;
        }
        buf1=ldns_buffer_new(LDNS_MAX_DOMAINLEN);
        ldns_rdf2buffer_str(buf1,l_rdf);
        tmp=ldns_buffer_export2str(buf1);
        strcpy(rr_rdata,tmp);
        ldns_buffer_free(buf1);
        LDNS_FREE(tmp);
      }
      printf("RDATA %s\n",rr_rdata);
      break;
    case LDNS_RR_TYPE_AAAA:
      rr_type=AAAA;
      if (ignore_rdata==0) {
	if (ldns_rr_rd_count(rr)!=1) {
          return LDNS_RCODE_FORMERR;
	}
        l_rdf=ldns_rr_rdf(rr,0); // grab the first rdf. There is only one for AAAA.
        l_rdf_type=ldns_rdf_get_type(l_rdf);
        if (l_rdf_type!=LDNS_RDF_TYPE_AAAA ) { // we should only have aaaa rdf in an aaaa rr
          return LDNS_RCODE_FORMERR;
        }
        buf1=ldns_buffer_new(LDNS_MAX_DOMAINLEN);
        ldns_rdf2buffer_str_aaaa(buf1,l_rdf);
        tmp=ldns_buffer_export2str(buf1);
        strcpy(rr_rdata,tmp);
        ldns_buffer_free(buf1);
        LDNS_FREE(tmp);
      }
      printf("RDATA %s\n",rr_rdata);
      break;
    case LDNS_RR_TYPE_DS:
      rr_type=DS;
      if (ignore_rdata==0) {
	if (ldns_rr_rd_count(rr)!=4) { // DS has 4 RDF
          return LDNS_RCODE_FORMERR;
	}
        l_rdf=ldns_rr_rdf(rr,0); // grab the first rdf.
        l_rdf_type=ldns_rdf_get_type(l_rdf);
        if (l_rdf_type!=LDNS_RDF_TYPE_INT16 ) { // key tag
          return LDNS_RCODE_FORMERR;
        }
        buf1=ldns_buffer_new(LDNS_MAX_DOMAINLEN); // potential memory leak here due to early return
        ldns_rdf2buffer_str_int16(buf1,l_rdf);
	ldns_buffer_printf(buf1,"%s"," ");
        l_rdf=ldns_rr_rdf(rr,1); // grab the second rdf.
        l_rdf_type=ldns_rdf_get_type(l_rdf);
        if (l_rdf_type!=LDNS_RDF_TYPE_ALG ) { // key algorithm number
          return LDNS_RCODE_FORMERR;
        }
        ldns_rdf2buffer_str_alg(buf1,l_rdf);
	ldns_buffer_printf(buf1,"%s"," ");
        l_rdf=ldns_rr_rdf(rr,2); // grab the third rdf.
        l_rdf_type=ldns_rdf_get_type(l_rdf);
        if (l_rdf_type!=LDNS_RDF_TYPE_INT8 ) { // digest type
          return LDNS_RCODE_FORMERR;
        }
        ldns_rdf2buffer_str_int8(buf1,l_rdf);
	ldns_buffer_printf(buf1,"%s"," ");
        l_rdf=ldns_rr_rdf(rr,3); // grab the fourth rdf.
        l_rdf_type=ldns_rdf_get_type(l_rdf);
        if (l_rdf_type!=LDNS_RDF_TYPE_HEX ) { // hex digest
          return LDNS_RCODE_FORMERR;
        }
        ldns_rdf2buffer_str_hex(buf1,l_rdf);
        tmp=ldns_buffer_export2str(buf1);
        strcpy(rr_rdata,tmp);
        ldns_buffer_free(buf1);
        LDNS_FREE(tmp);
      }
      printf("RDATA %s\n",rr_rdata);
      break;
    case LDNS_RR_TYPE_NS:
      rr_type=NS;
      if (ignore_rdata==0) {
        l_rdf=ldns_rr_rdf(rr,0); // grab the first rdf. There is only one for NS.
        l_rdf_type=ldns_rdf_get_type(l_rdf);
        if (l_rdf_type!=LDNS_RDF_TYPE_DNAME ) { // we should only have dname rdf in an ns rr
          return LDNS_RCODE_FORMERR;
        }
        buf1=ldns_buffer_new(LDNS_MAX_DOMAINLEN);
        ldns_rdf2buffer_str_dname(buf1,l_rdf);
        tmp=ldns_buffer_export2str(buf1);
        strcpy(rr_rdata,tmp);
        ldns_buffer_free(buf1);
        LDNS_FREE(tmp);
      }
      printf("RDATA %s\n",rr_rdata);
      break;
    case LDNS_RR_TYPE_ANY:
      if ((rr_class==LDNS_RR_CLASS_ANY)) { // only valid in combinaton with class = ANY
        rr_type=ANY;
	ignore_type=1;
        break;
      } else {
       return LDNS_RCODE_FORMERR; // should never be reached, but this is an illegal combo
      }
    default:
      return LDNS_RCODE_REFUSED; // should never be reached
  }  

  printf("RR Type :%s: %lu\n",rr_type,strlen(rr_type));

  if (!ldns_rr_owner(rr)) {
    return LDNS_RCODE_FORMERR;;
  }
  buf2=ldns_buffer_new(LDNS_MAX_DOMAINLEN);
  l_status = ldns_rdf2buffer_str_dname(buf2, ldns_rr_owner(rr));
  tmp=ldns_buffer_export2str(buf2);
  strcpy(rr_owner,tmp);
  ldns_buffer_free(buf2); // doesn't free buffer data
  LDNS_FREE(tmp);
  printf("RR_OWNER %s\n",rr_owner);

  if ( (l_status != LDNS_STATUS_OK) || (strlen (rr_owner)>MYSQL_STRLEN) ) { //  name too long for db or munged name
    return LDNS_RCODE_FORMERR;
  }


  if (strcmp(rr_status,"creating")==0) {
  // insert the rr for creating
  // zone_id INT DEFAULT 0,    /* link to zone */
  //   rr_owner VARCHAR(80),     /* the owner of this RR i.e. what is queried */
  //     rr_ttl INT DEFAULT 3600,  /* TTL for this RR */
  //     rr_type ENUM ('NS','DS','TXT'),
  //     rr_rdata VARCHAR(80),        /* the content associated with this owner */
  //     rr_status ENUM ('creating','created','deleting'), /* current status for state machine */
  //     rr_status_time   BIGINT SIGNED DEFAULT 0, /* time of last status change */
  //
  strcpy(stmt_str,"INSERT INTO rr (`zone_id`,`rr_owner`,`rr_ttl`,`rr_type`,`rr_rdata`,`rr_status`,`rr_status_time`) VALUES (?,?,?,?,?,?,?);");
  printf("STMT %s\n",stmt_str);
  //stmt_str="INSERT INTO rr (`zone_id`,`rr_owner`,`rr_ttl`,`rr_type`,`rr_rdata`,`rr_status`,`rr_status_time`) VALUES (?,?,?,?,?,?,?);";
  printf("VARS %i %s %i %s %s %s %lu\n",zone_id,rr_owner,rr_ttl,rr_type,rr_rdata,rr_status,rr_status_time);

  bind[0].buffer_type= MYSQL_TYPE_LONG;
  bind[0].buffer= (char *)&zone_id;
  bind[0].is_null= 0;
  bind[0].length= 0;

  bind[1].buffer_type= MYSQL_TYPE_STRING;
  bind[1].buffer= (char *)rr_owner;
  bind[1].buffer_length= MYSQL_STRLEN;
  bind[1].is_null= 0;
  len1=strlen(rr_owner);
  bind[1].length= &len1;

  bind[2].buffer_type= MYSQL_TYPE_LONG;
  bind[2].buffer= (char *)&rr_ttl;
  bind[2].is_null= 0;
  bind[2].length= 0;

  bind[3].buffer_type= MYSQL_TYPE_STRING;
  bind[3].buffer= (char *)rr_type;
  bind[3].buffer_length= MYSQL_STRLEN;
  bind[3].is_null= 0;
  len2=strlen(rr_type);
  bind[3].length= &len2;

  bind[4].buffer_type= MYSQL_TYPE_STRING;
  bind[4].buffer= (char *)rr_rdata;
  bind[4].buffer_length= MYSQL_STRLEN;
  bind[4].is_null= 0;
  len3=strlen(rr_rdata);
  bind[4].length= &len3;

  bind[5].buffer_type= MYSQL_TYPE_STRING;
  bind[5].buffer= (char *)rr_status;
  bind[5].buffer_length= MYSQL_STRLEN;
  bind[5].is_null= 0;
  len4=strlen(rr_status);
  bind[5].length= &len4;

  bind[6].buffer_type= MYSQL_TYPE_LONGLONG;
  bind[6].buffer= (char *)&rr_status_time;
  bind[6].is_null= 0;
  bind[6].length= 0;
  } else {

  // update an existing rr for deleting.
  strcpy(stmt_str,"UPDATE rr AS A SET rr_status=?, rr_status_time=? WHERE ( (`zone_id`=?) AND (`rr_owner`=?) AND ((`rr_type`=?) OR (1=?))  AND ((`rr_rdata`=?) OR (1=?)) );");
  printf("STMT %s\n",stmt_str);
  //printf("VARS %s %lu %i %s %i %s %s\n",rr_status,rr_status_time,zone_id,rr_owner,rr_ttl,rr_type,rr_rdata);
  printf("VARS %s %lu %i %s %s %i %s %i\n",rr_status,rr_status_time,zone_id,rr_owner,rr_type,ignore_type,rr_rdata,ignore_rdata);
  // similar params but different order and ttl not used
  //
  bind[0].buffer_type= MYSQL_TYPE_STRING;
  bind[0].buffer= (char *)rr_status;
  bind[0].buffer_length= MYSQL_STRLEN;
  bind[0].is_null= 0;
  len4=strlen(rr_status);
  bind[0].length= &len4;

  bind[1].buffer_type= MYSQL_TYPE_LONGLONG;
  bind[1].buffer= (char *)&rr_status_time;
  bind[1].is_null= 0;
  bind[1].length= 0;

  bind[2].buffer_type= MYSQL_TYPE_LONG;
  bind[2].buffer= (char *)&zone_id;
  bind[2].is_null= 0;
  bind[2].length= 0;

  bind[3].buffer_type= MYSQL_TYPE_STRING;
  bind[3].buffer= (char *)rr_owner;
  bind[3].buffer_length= MYSQL_STRLEN;
  bind[3].is_null= 0;
  len1=strlen(rr_owner);
  bind[3].length= &len1;

  //bind[4].buffer_type= MYSQL_TYPE_LONG;
  //bind[4].buffer= (char *)&rr_ttl;
  //bind[4].is_null= 0;
  //bind[4].length= 0;

  bind[4].buffer_type= MYSQL_TYPE_STRING;
  bind[4].buffer= (char *)rr_type;
  bind[4].buffer_length= MYSQL_STRLEN;
  bind[4].is_null= 0;
  len2=strlen(rr_type);
  bind[4].length= &len2;

  bind[5].buffer_type= MYSQL_TYPE_LONG;
  bind[5].buffer= (char *)&ignore_type;
  bind[5].is_null= 0;
  bind[5].length= 0;

  bind[6].buffer_type= MYSQL_TYPE_STRING;
  bind[6].buffer= (char *)rr_rdata;
  bind[6].buffer_length= MYSQL_STRLEN;
  bind[6].is_null= 0;
  len3=strlen(rr_rdata);
  bind[6].length= &len3;

  bind[7].buffer_type= MYSQL_TYPE_LONG;
  bind[7].buffer= (char *)&ignore_rdata;
  bind[7].is_null= 0;
  bind[7].length= 0;

  }


  stmt=mysql_stmt_init(db);
  if (mysql_stmt_prepare(stmt, stmt_str, strlen(stmt_str))) {
    printf ("Insert rr: prepare failed. %s\n",mysql_stmt_error(stmt));
    mysql_stmt_close(stmt);
    return LDNS_RCODE_SERVFAIL;
  }

  if (mysql_stmt_bind_param(stmt, bind)) {
    printf("dm_tofu_insert_rr: bind failed %s\n",mysql_stmt_error(stmt));
    mysql_stmt_close(stmt);
    return LDNS_RCODE_SERVFAIL;
  }
  if (mysql_stmt_execute(stmt)) {
    printf ("dm_tofu_insert_rr: exec failed. %s\n",mysql_error(db));
    mysql_stmt_close(stmt);
    return LDNS_RCODE_SERVFAIL;
  }

  mysql_stmt_close(stmt);

  return LDNS_RCODE_NOERROR;

}

//given an rr_rdata, return the rr id of a matching RR type or -1 for not found
int dm_tofu_select_rdata_id(MYSQL *db, char *rr_rdata, char *rr_type) {
  int rr_id=0;
  MYSQL_STMT *stmt;
  MYSQL_BIND bind[2];
  memset(bind, 0, sizeof(MYSQL_BIND));
  size_t len1,len2;
  MYSQL_BIND bindout[1];
  memset(bindout, 0, sizeof(bindout));

  int status;
  unsigned long length[1];
  bool is_null[1];
  bool error[1];
  int rc=0;

  printf("dm_tofu_select_rdata_id\n");

  if ( (rr_rdata==NULL) || (strlen(rr_rdata)<2)  ) {
    printf("dm_tofu_select_rdata_id: needs a valid rr_rdata\n");
    return -1;
  }
  if ( (rr_type==NULL) || (strlen(rr_type)<2)  ) {
    printf("dm_tofu_select_rdata_id: needs a valid rr_type\n");
    return -1;
  }

  // select an rr_id with exact match on rr_rdata and rr_type
  // Theoretically there can be more than one, but this is only currently used as a check of existence.
  stmt=mysql_stmt_init(db);
  char *stmt_str="SELECT A.rr_id FROM rr AS A WHERE ( (A.rr_rdata=?) AND (rr_type=?) AND (rr_status <>'deleting' ) ) LIMIT 1;";

  if (mysql_stmt_prepare(stmt, stmt_str, strlen(stmt_str))) {
    printf ("dm_tofu_select_rdata_id: prepare failed. %s\n",mysql_stmt_error(stmt));
    mysql_stmt_close(stmt);
    return -1;
  }

  bind[0].buffer_type= MYSQL_TYPE_STRING;
  bind[0].buffer= (char *)rr_rdata;
  bind[0].buffer_length= MYSQL_STRLEN;
  bind[0].is_null= 0;
  len1=strlen(rr_rdata);
  bind[0].length= &len1;

  bind[1].buffer_type= MYSQL_TYPE_STRING;
  bind[1].buffer= (char *)rr_type;
  bind[1].buffer_length= MYSQL_STRLEN;
  bind[1].is_null= 0;
  len2=strlen(rr_type);
  bind[1].length= &len2;

  if (mysql_stmt_bind_param(stmt, bind) ) {
    printf ("dm_tofu_select_rdata_id: bind failed. %s\n",mysql_error(db));
    mysql_stmt_close(stmt);
    return -1;
  }
  if (mysql_stmt_execute(stmt) ) {
    printf ("dm_tofu_select_rdata_id: exec failed. %s\n",mysql_error(db));
    mysql_stmt_close(stmt);
    return -1;
  }

  /* INTEGER COLUMN rr_id */
  bindout[0].buffer_type= MYSQL_TYPE_LONG;
  bindout[0].buffer= (char *)&rr_id;
  bindout[0].is_null= &is_null[0];
  bindout[0].length= &length[0];
  bindout[0].error= &error[0];
 
  if (mysql_stmt_bind_result(stmt, bindout)) {
    fprintf(stderr, " mysql_stmt_bind_result() failed\n");
    fprintf(stderr, " %s\n", mysql_stmt_error(stmt));
    mysql_stmt_close(stmt);
    return -1;
  }

  // While rows to read. For this query there is only 0 or 1.
  rc=0;  // row count
  while (1) {
    status = mysql_stmt_fetch(stmt);
    if (status == 1 ) {
      printf ("select_rdata_id Error. Can't select rr_owner %s\n",mysql_error(db));
      mysql_stmt_close(stmt);
      return -1;
    } else if (status == MYSQL_NO_DATA && rc==0) {
      printf ("select_rdata_id: Info. Can't find a rr_owner.\n");
      mysql_stmt_close(stmt);
      return -1;
    } else if (status == MYSQL_NO_DATA) {
      break; // last line. normal end of read
    }
    rc++;
    printf("rc %i rr_rdata %.*s id %i\n",rc,(int)length[0],rr_rdata,rr_id);
  }
  mysql_stmt_close(stmt);
  return rr_id;

}


// delete db entry for the rr rr_id
int dm_tofu_delete_rr(MYSQL *db, int rr_id) {

  MYSQL_STMT *stmt;
  MYSQL_BIND bind[1];
  memset(bind, 0, sizeof(bind));
  int rc=0;  // row count
  MYSQL_RES *result;

  if ( (rr_id<=0)  ) {
    printf("dm_tofu_delete_rr: needs a valid rr_id\n");
    return -1;
  }

  // delete the rr
  stmt=mysql_stmt_init(db);
  char *stmt_str="DELETE FROM rr AS A WHERE ( (A.rr_id=?) );";

  if (mysql_stmt_prepare(stmt, stmt_str, strlen(stmt_str))) {
    printf ("dm_tofu_delete_rr: prepare failed. %s\n",mysql_stmt_error(stmt));
    mysql_stmt_close(stmt);
    return -1;
  }

  bind[0].buffer_type= MYSQL_TYPE_LONG;
  bind[0].buffer= (char *)&rr_id;
  bind[0].is_null= 0;
  bind[0].length= 0;

  if (mysql_stmt_bind_param(stmt, bind) ) {
    printf ("dm_tofu_delete_rr: bind failed. %s\n",mysql_error(db));
    mysql_stmt_close(stmt);
    return -1;
  }
  if (mysql_stmt_execute(stmt) ) {
    printf ("dm_tofu_delete_rr: exec failed. %s\n",mysql_error(db));
    mysql_stmt_close(stmt);
    return -1;
  }

  result=mysql_use_result(db);
  rc=mysql_affected_rows(db);
  mysql_free_result(result);
  mysql_stmt_close(stmt);

  return rc;

}

// delete db entry for the zone zone_id
int dm_tofu_delete_zone(MYSQL *db, int zone_id) {

  MYSQL_STMT *stmt;
  MYSQL_BIND bind[1];
  memset(bind, 0, sizeof(bind));
  int rc=0;  // row count
  MYSQL_RES *result;

  if ( (zone_id<=0)  ) {
    printf("dm_tofu_delete_zone: needs a valid zone_id\n");
    return -1;
  }

  // delete any associated rr from the db. The knotc set and unset commands have already been handled.
  stmt=mysql_stmt_init(db);
  char *stmt_str2="DELETE FROM rr AS A WHERE ((A.zone_id=?) );";
  
  if (mysql_stmt_prepare(stmt, stmt_str2, strlen(stmt_str2))) {
    printf ("dm_tofu_delete_zone: prepare failed. %s\n",mysql_stmt_error(stmt));
    mysql_stmt_close(stmt);
    return -1;
  }

  bind[0].buffer_type= MYSQL_TYPE_LONG;
  bind[0].buffer= (char *)&zone_id;
  bind[0].is_null= 0;
  bind[0].length= 0;

  if (mysql_stmt_bind_param(stmt, bind) ) {
    printf ("dm_tofu_delete_zone: bind failed. %s\n",mysql_error(db));
    mysql_stmt_close(stmt);
    return -1;
  }
  if (mysql_stmt_execute(stmt) ) {
    printf ("dm_tofu_delete_zone: exec failed. %s\n",mysql_error(db));
    mysql_stmt_close(stmt);
    return -1;
  }

  result=mysql_use_result(db);
  rc=mysql_affected_rows(db);
  mysql_free_result(result);
  mysql_stmt_close(stmt);
  
  // delete any associated hna from the db. MYSQL needs to use the TEMP alias.
  stmt=mysql_stmt_init(db);
  char *stmt_str1="DELETE FROM infra WHERE infra_id IN (SELECT infra_id FROM (SELECT infra_id FROM infra AS A, zone AS B  WHERE ((B.zone_id=?) AND (B.hna=A.infra_id)) ) AS TEMP);";
  
  if (mysql_stmt_prepare(stmt, stmt_str1, strlen(stmt_str1))) {
    printf ("dm_tofu_delete_zone: prepare failed. %s\n",mysql_stmt_error(stmt));
    mysql_stmt_close(stmt);
    return -1;
  }

  bind[0].buffer_type= MYSQL_TYPE_LONG;
  bind[0].buffer= (char *)&zone_id;
  bind[0].is_null= 0;
  bind[0].length= 0;

  if (mysql_stmt_bind_param(stmt, bind) ) {
    printf ("dm_tofu_delete_zone: bind failed. %s\n",mysql_error(db));
    mysql_stmt_close(stmt);
    return -1;
  }
  if (mysql_stmt_execute(stmt) ) {
    printf ("dm_tofu_delete_zone: exec failed. %s\n",mysql_error(db));
    mysql_stmt_close(stmt);
    return -1;
  }

  result=mysql_use_result(db);
  rc=mysql_affected_rows(db);
  mysql_free_result(result);
  mysql_stmt_close(stmt);
  
  // delete the zone
  stmt=mysql_stmt_init(db);
  char *stmt_str="DELETE FROM zone AS A WHERE ( (A.zone_id=?) );";

  if (mysql_stmt_prepare(stmt, stmt_str, strlen(stmt_str))) {
    printf ("dm_tofu_delete_zone: prepare failed. %s\n",mysql_stmt_error(stmt));
    mysql_stmt_close(stmt);
    return -1;
  }

  bind[0].buffer_type= MYSQL_TYPE_LONG;
  bind[0].buffer= (char *)&zone_id;
  bind[0].is_null= 0;
  bind[0].length= 0;

  if (mysql_stmt_bind_param(stmt, bind) ) {
    printf ("dm_tofu_delete_zone: bind failed. %s\n",mysql_error(db));
    mysql_stmt_close(stmt);
    return -1;
  }
  if (mysql_stmt_execute(stmt) ) {
    printf ("dm_tofu_delete_zone: exec failed. %s\n",mysql_error(db));
    mysql_stmt_close(stmt);
    return -1;
  }

  result=mysql_use_result(db);
  rc=mysql_affected_rows(db);
  mysql_free_result(result);
  mysql_stmt_close(stmt);

  return rc;

}


// update db for the rr rr_id to new rr_status
int dm_tofu_update_rr_status(MYSQL *db, int rr_id, char *rr_status, time_t slot_time) {

  MYSQL_STMT *stmt;
  MYSQL_BIND bind[3];
  memset(bind, 0, sizeof(bind));
  size_t len1;
  int rc=0;  // row count
  MYSQL_RES *result;

  if ( (rr_status==NULL) || (dm_tofu_is_valid_rr_status(rr_status)) ) {
    printf("dm_tofu_update_rr_status: needs a valid rr status\n");
    return -1;
  }
  time_t start_slot=(slot_time>0) ? slot_time : get_time_slot(0);

  stmt=mysql_stmt_init(db);
  char *stmt_str="UPDATE rr AS A SET rr_status=?, rr_status_time=? WHERE ( (A.rr_id=?) );";

  if (mysql_stmt_prepare(stmt, stmt_str, strlen(stmt_str))) {
    printf ("dm_tofu_update_rr_status: prepare failed. %s\n",mysql_stmt_error(stmt));
    mysql_stmt_close(stmt);
    return -1;
  }

  bind[0].buffer_type= MYSQL_TYPE_STRING;
  bind[0].buffer= (char *)rr_status;
  bind[0].buffer_length= MYSQL_STRLEN;
  bind[0].is_null= 0;
  len1=strlen(rr_status);
  bind[0].length= &len1;
  bind[1].buffer_type= MYSQL_TYPE_LONGLONG;
  bind[1].buffer= (char *)&start_slot;
  bind[1].is_null= 0;
  bind[1].length= 0;
  bind[2].buffer_type= MYSQL_TYPE_LONG;
  bind[2].buffer= (char *)&rr_id;
  bind[2].is_null= 0;
  bind[2].length= 0;

  if (mysql_stmt_bind_param(stmt, bind) ) {
    printf ("dm_tofu_update_rr_status: bind failed. %s\n",mysql_error(db));
    mysql_stmt_close(stmt);
    return -1;
  }
  if (mysql_stmt_execute(stmt) ) {
    printf ("dm_tofu_update_rr_status: exec failed. %s\n",mysql_error(db));
    mysql_stmt_close(stmt);
    return -1;
  }

  result=mysql_use_result(db);
  rc=mysql_affected_rows(db);
  mysql_free_result(result);
  mysql_stmt_close(stmt);

  return rc;

}

// update db for the zone zone_id to new zone_status
int dm_tofu_update_zone_status(MYSQL *db, int zone_id, char *zone_status, time_t slot_time) {

  MYSQL_STMT *stmt;
  MYSQL_BIND bind[3];
  memset(bind, 0, sizeof(bind));
  size_t len1;
  int rc=0;  // row count
  MYSQL_RES *result;

  if ( (zone_status==NULL) || (dm_tofu_is_valid_zone_status(zone_status)) ) {
    printf("dm_tofu_update_zone_status: needs a valid zone status\n");
    return -1;
  }
  time_t start_slot=(slot_time>0) ? slot_time : get_time_slot(0);

  stmt=mysql_stmt_init(db);
  char *stmt_str="UPDATE zone AS A SET zone_status=?, zone_status_time=? WHERE ( (A.zone_id=?) );";

  if (mysql_stmt_prepare(stmt, stmt_str, strlen(stmt_str))) {
    printf ("dm_tofu_update_zone_status: prepare failed. %s\n",mysql_stmt_error(stmt));
    mysql_stmt_close(stmt);
    return -1;
  }

  bind[0].buffer_type= MYSQL_TYPE_STRING;
  bind[0].buffer= (char *)zone_status;
  bind[0].buffer_length= MYSQL_STRLEN;
  bind[0].is_null= 0;
  len1=strlen(zone_status);
  bind[0].length= &len1;
  bind[1].buffer_type= MYSQL_TYPE_LONGLONG;
  bind[1].buffer= (char *)&start_slot;
  bind[1].is_null= 0;
  bind[1].length= 0;
  bind[2].buffer_type= MYSQL_TYPE_LONG;
  bind[2].buffer= (char *)&zone_id;
  bind[2].is_null= 0;
  bind[2].length= 0;

  if (mysql_stmt_bind_param(stmt, bind) ) {
    printf ("dm_tofu_update_zone_status: bind failed. %s\n",mysql_error(db));
    mysql_stmt_close(stmt);
    return -1;
  }
  if (mysql_stmt_execute(stmt) ) {
    printf ("dm_tofu_update_zone_status: exec failed. %s\n",mysql_error(db));
    mysql_stmt_close(stmt);
    return -1;
  }

  result=mysql_use_result(db);
  rc=mysql_affected_rows(db);
  mysql_free_result(result);
  mysql_stmt_close(stmt);

  return rc;

}


// given a parent, return the name of the primary NS name. Remember to free the string.
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
  char *stmt_str="SELECT A.infra_id, A.name FROM infra AS A, parent AS B WHERE ( (B.parent_name=?) AND ((A.infra_id = B.ns2) OR (A.infra_id = B.ns3)) ); ";

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
    ldns_helpers_add_trailing_dot(ll_secondary_ns_current->ns_name);
    rc++;
  }

  mysql_stmt_close(stmt);
  return ll_secondary_ns_head; 

} 

/*
 * interface to knotc doesn't work this way.... you set one line per item
 *
// given a parent, return the notify list in knot format  of the secondary NS names. Remember to free the string.
char *dm_tofu_get_notify_list(MYSQL *db,char *parent_name) {
  // get the secondary NS for this parent
  ll_secondary_ns_t *ll_secondary_ns_head=dm_tofu_get_secondary_ns(db, parent_name); 
  ll_secondary_ns_t *ll_secondary_ns_tmp=NULL;
  ll_secondary_ns_t *ll_secondary_ns_current=NULL;

  // create a knotc notify list of secondary NS
  //char notify_list[MYSQL_STRLEN];
  size_t notify_list_len=MYSQL_STRLEN*3+8;
  char *notify_list=(char *)malloc(notify_list_len); // big enough for 3 very long NS names plus commas
  if (notify_list==NULL) {
    printf("dm_tofu_get_notify_list: Error. Couldn't allocate memory\n");
    exit(0);
  }
  memset(notify_list,'\0',notify_list_len);
  ll_secondary_ns_current=ll_secondary_ns_head;
  strcat(notify_list,"[ ");
  while (ll_secondary_ns_current!=NULL) {
    if (strlen(notify_list)+3+strlen(ll_secondary_ns_current->ns_name)>=notify_list_len) {
      printf("dm_tofu_get_notify_list: Warning. NS skipped to avoid buffer overflow %s\n",ll_secondary_ns_current->ns_name);
      continue;
    }
    strcat(notify_list,ll_secondary_ns_current->ns_name);
    strcat(notify_list,", "); // always add a comma.
    ll_secondary_ns_tmp=ll_secondary_ns_current->next;
    free (ll_secondary_ns_current);
    ll_secondary_ns_current=ll_secondary_ns_tmp;
  }
  // strip off last comma and replace with list closure ' ]'
  if (strlen(notify_list)>2) {
    notify_list[ (strlen(notify_list)-2) ]=' ';
    notify_list[ (strlen(notify_list)-1) ]=']';
  }
  //printf("notify list %s\n",notify_list);
  return notify_list;
}
*
* */



// create a linked list of parent where this hostname acts as primary NS
// returns rc or -1 on failure
int dm_tofu_select_parent_ns(MYSQL *db, ll_parent_t **ll_parent_head) {
  return dm_tofu_select_parent_func(db, ll_parent_head,"ns");
}

// create a linked list of parent where this hostname acts as primary dm
// returns rc or -1 on failure
int dm_tofu_select_parent_dm(MYSQL *db, ll_parent_t **ll_parent_head) {
  return dm_tofu_select_parent_func(db, ll_parent_head,"dm");
}

// create a linked list of parent where this hostname acts as func
// funs id literal dm or ns
// returns rc or -1 on failure
int dm_tofu_select_parent_func(MYSQL *db, ll_parent_t **ll_parent_head,char *type) {

  ll_parent_t *ll_parent_tmp=NULL;
  ll_parent_t *ll_parent_current=NULL;

  char hostname[MYSQL_STRLEN];
  memset(hostname, '\0', MYSQL_STRLEN);
  char parent_name[MYSQL_STRLEN];
  memset(parent_name, '\0', MYSQL_STRLEN);
  MYSQL_STMT *stmt;
  MYSQL_BIND bind[1];
  memset(bind, 0, sizeof(bind));
  unsigned int parent_id;
  size_t len1;
  int rc=0;  // row count

  int status;
  MYSQL_BIND bindout[2];
  memset(bindout, 0, sizeof(bindout));
  unsigned long length[2];
  bool is_null[2];
  bool error[2];
  char *stmt_str;

  if (gethostname(hostname, MYSQL_STRLEN)|| (strlen(hostname)<2)) {
    printf("dm_tofu_select_parent_func: can't get hostname\n");
    return -1;
  }

  stmt=mysql_stmt_init(db);
  if (type==NULL) {
    return -1;
  }
  if (strcmp(type,"ns")==0) {
    stmt_str="SELECT DISTINCT A.parent_id, A.parent_name FROM parent AS A, infra AS B WHERE ((A.ns1=B.infra_id) AND (B.hostname=?)) ; ";
  } else if(strcmp(type,"dm")==0) {
    stmt_str="SELECT DISTINCT A.parent_id, A.parent_name FROM parent AS A, infra AS B WHERE ( ((A.dm1=B.infra_id) || (A.dm2=B.infra_id)) AND (B.hostname=?)) ; ";
  } else {
     printf("dm_tofu_select_parent_func: unknown function %s\n",type);
    return -1;
  }

  if (mysql_stmt_prepare(stmt, stmt_str, strlen(stmt_str))) {
    printf ("dm_tofu_select_parent_func: prepare failed. %s\n",mysql_stmt_error(stmt));
    mysql_stmt_close(stmt);
    return -1;
  }

  bind[0].buffer_type= MYSQL_TYPE_STRING;
  bind[0].buffer= (char *)hostname;
  bind[0].buffer_length= MYSQL_STRLEN;
  bind[0].is_null= 0;
  len1=strlen(hostname);
  bind[0].length= &len1;

  if (mysql_stmt_bind_param(stmt, bind) ) {
    printf ("dm_tofu_select_parent_func: bind failed. %s\n",mysql_error(db));
    mysql_stmt_close(stmt);
    return -1;
  }
  if (mysql_stmt_execute(stmt) ) {
    printf ("dm_tofu_select_parent_func: exec failed. %s\n",mysql_error(db));
    mysql_stmt_close(stmt);
    return -1;
  }

  /* INTEGER COLUMN parent_id */
  bindout[0].buffer_type= MYSQL_TYPE_LONG;
  bindout[0].buffer= (char *)&parent_id;
  bindout[0].is_null= &is_null[0];
  bindout[0].length= &length[0];
  bindout[0].error= &error[0];
 
  /* STRING COLUMN parent_name */
  bindout[1].buffer_type= MYSQL_TYPE_STRING;
  bindout[1].buffer= (char *)&parent_name;
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
      printf ("dm_tofu_select_parent_func: normal. No data\n");
      break; 
    } else if (status == MYSQL_NO_DATA && rc>0) {
      break; // Last line. Normal end of read after match.
    } else if (status == 1 ) {
      printf ("dm_tofu_select_parent_func: Error. Can't get parent names hostname %s %s\n",hostname,mysql_error(db));
      mysql_stmt_close(stmt);
      return -1;
    } 
    // We have data to return in a single linked list
    printf("rc %i parent_name %.*s id %i\n",rc,(int)length[1],parent_name,parent_id);
    ll_parent_tmp=(ll_parent_t*)malloc(sizeof(ll_parent_t));
    if (ll_parent_tmp==NULL) {
      printf("dm_tofu_select_parent_func: Error. Cannot allocate memory\n");
      exit (0);
    }
    memset(ll_parent_tmp,'\0',sizeof(ll_parent_t));
    ll_parent_tmp->next=NULL;
    // remember the head 1st time through
    if (*ll_parent_head==NULL) {
      // ll_parent_head is pointer to pointer so content can be updated to this new storage
      *ll_parent_head=ll_parent_tmp;
    } else {
      ll_parent_current->next=ll_parent_tmp;
    }
    ll_parent_current=ll_parent_tmp;
    ll_parent_current->parent_id=parent_id;
    strcpy(ll_parent_current->parent_name,parent_name);
    rc++;
  }

  mysql_stmt_close(stmt);
  return rc;
}


// given a rr_owner, return the longest match from the zone table
// returns zone_name or NULL on failure or no match
// trailing odts are striopped before searching
// remember to free
char *dm_tofu_get_zone(MYSQL *db, char *rr_owner) {
  MYSQL_STMT *stmt;
  MYSQL_BIND bind[1];
  memset(bind, 0, sizeof(bind));
  size_t len1;
  int rc=0;  // row count
  char zone_name[MYSQL_STRLEN];
  memset(zone_name, '\0', MYSQL_STRLEN);

  int status;
  MYSQL_BIND bindout[1];
  memset(bindout, 0, sizeof(bindout));
  unsigned long length[1];
  bool is_null[1];
  bool error[1];

  if ( (rr_owner==NULL) || (strlen(rr_owner)<2) ) {
    printf("dm_tofu_get_zone: needs a rr name\n");
    return NULL;
  }
  // Strip any trailing dots. These are never stored in the db.
  char search_str[MYSQL_STRLEN]={'\0'};
  strcpy(search_str,rr_owner);
  ldns_helpers_strip_trailing_dot(search_str);

  stmt=mysql_stmt_init(db);
  // regexp (literal dot)<rr_owner with dots escaped><anchored to end of string>
  // results sorted by length, longest first, take only the first entry
  // first \ escape is for C string, then a second for SQL string parsing
  char *stmt_str="SELECT zone_name FROM zone AS A WHERE ? REGEXP concat('\\\\.',REPLACE(A.zone_name,'.','\\\\.'),'$') ORDER BY length(A.zone_name) DESC LIMIT 1;";
  //printf ("stmt_str :%s:\n",stmt_str);

  if (mysql_stmt_prepare(stmt, stmt_str, strlen(stmt_str))) {
    printf ("dm_tofu_get_zone: prepare failed. %s\n",mysql_stmt_error(stmt));
    mysql_stmt_close(stmt);
    return NULL;
  }

  bind[0].buffer_type= MYSQL_TYPE_STRING;
  bind[0].buffer= (char *)search_str;
  bind[0].buffer_length= MYSQL_STRLEN;
  bind[0].is_null= 0;
  len1=strlen(search_str);
  bind[0].length= &len1;

  if (mysql_stmt_bind_param(stmt, bind) ) {
    printf ("dm_tofu_get_zone: bind failed. %s\n",mysql_error(db));
    mysql_stmt_close(stmt);
    return NULL;
  }
  if (mysql_stmt_execute(stmt) ) {
    printf ("dm_tofu_get_zone: exec failed. %s\n",mysql_error(db));
    mysql_stmt_close(stmt);
    return NULL;
  }

  /* STRING COLUMN zone_name */
  bindout[0].buffer_type= MYSQL_TYPE_STRING;
  bindout[0].buffer= (char *)&zone_name;
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

  // While rows to read.
  rc=0;  // row count. should always be 0 or 1
  while (1) {
    status = mysql_stmt_fetch(stmt);
    if (status == MYSQL_NO_DATA && rc==0) {
      // printf ("dm_tofu_get_zone: No match\n");
      mysql_stmt_close(stmt);
      return NULL;
    } else if (status == MYSQL_NO_DATA && rc>0) {
      // printf ("dm_tofu_get_zone: normal end \n");
      break; // Last line. Normal end of read after match.
    } else if (status == 1 ) {
      printf ("dm_tofu_get_zone: Error. Can't check zone name for zone_name %s %s\n",search_str,mysql_error(db));
      mysql_stmt_close(stmt);
      return NULL;
    } 
    // We have data to return
    // printf("rc %i rr_name %s zone_name %s\n",rc,rr_name,zone_name);
    rc++;
  }

  mysql_stmt_close(stmt);
  // printf("returning %s\n",zone_name);
  return dm_tofu_cp_name(zone_name);
}

// Given a zone_name, return the count of exact  match from the parent table
// -1 for error
int dm_tofu_count_parent(MYSQL *db, char *zone_name) {
  MYSQL_STMT *stmt;
  MYSQL_BIND bind[1];
  memset(bind, 0, sizeof(bind));
  size_t len1;
  int rc=0;  // row count
  int count;

  int status;
  MYSQL_BIND bindout[1];
  memset(bindout, 0, sizeof(bindout));
  unsigned long length[1];
  bool is_null[1];
  bool error[1];

  if ( (zone_name==NULL) || (strlen(zone_name)<2) ) {
    printf("dm_tofu_count_parent: needs a zone name\n");
    return -1;
  }

  stmt=mysql_stmt_init(db);
  // regexp (literal dot)<parent_name with dots escaped><anchored to end of string>
  // results sorted by length, longest first, take only the first entry
  // first \ escape is for C string, then a second for SQL string parsing
  // ignore trailing dots
  char *stmt_str="SELECT COUNT(parent_name) FROM parent AS A WHERE ? REGEXP CONCAT('^',A.parent_name,'\\\\.?$') ;";
  printf ("stmt_str :%s:\n",stmt_str);
  printf ("zone_name :%s:\n",zone_name);

  if (mysql_stmt_prepare(stmt, stmt_str, strlen(stmt_str))) {
    printf ("dm_tofu_count_parent: prepare failed. %s\n",mysql_stmt_error(stmt));
    mysql_stmt_close(stmt);
    return -1;
  }

  bind[0].buffer_type= MYSQL_TYPE_STRING;
  bind[0].buffer= (char *)zone_name;
  bind[0].buffer_length= MYSQL_STRLEN;
  bind[0].is_null= 0;
  len1=strlen(zone_name);
  bind[0].length= &len1;

  if (mysql_stmt_bind_param(stmt, bind) ) {
    printf ("dm_tofu_count_parent: bind failed. %s\n",mysql_error(db));
    mysql_stmt_close(stmt);
    return -1;
  }
  if (mysql_stmt_execute(stmt) ) {
    printf ("dm_tofu_count_parent: exec failed. %s\n",mysql_error(db));
    mysql_stmt_close(stmt);
    return -1;
  }

  /* INTEGER COLUMN infra_id */
  bindout[0].buffer_type= MYSQL_TYPE_LONG;
  bindout[0].buffer= (char *)&count;
  bindout[0].is_null= &is_null[0];
  bindout[0].length= &length[0];
  bindout[0].error= &error[0];
 
  if (mysql_stmt_bind_result(stmt, bindout)) {
    fprintf(stderr, " mysql_stmt_bind_result() failed\n");
    fprintf(stderr, " %s\n", mysql_stmt_error(stmt));
    mysql_stmt_close(stmt);
    return -1;
  }

  // While rows to read.
  rc=0;  // row count. should always be 0 or 1
  while (1) {
    status = mysql_stmt_fetch(stmt);
    if (status == MYSQL_NO_DATA && rc==0) {
      // printf ("dm_tofu_count_parent: No count\n");
      mysql_stmt_close(stmt);
      return -1;
    } else if (status == MYSQL_NO_DATA && rc>0) {
      // printf ("dm_tofu_count_parent: normal end \n");
      break; // Last line. Normal end of read after match.
    } else if (status == 1 ) {
      printf ("dm_tofu_count_parent: Error. Can't check zone name for parent_name %s %s\n",zone_name,mysql_error(db));
      mysql_stmt_close(stmt);
      return -1;
    } 
    // We have data to return
    // printf("rc %i zone_count %i\n",rc,count);
    rc++;
  }

  mysql_stmt_close(stmt);
  printf("returning %i\n",count);
  return count;
}

// Given a zone_name, return the longest match from the parent table
// returns parent_name or NULL on failure or no match.
// Exact matches are NOT returned.
// remember to free
char *dm_tofu_get_parent(MYSQL *db, char *zone_name) {
  MYSQL_STMT *stmt;
  MYSQL_BIND bind[1];
  memset(bind, 0, sizeof(bind));
  size_t len1;
  int rc=0;  // row count
  char parent_name[MYSQL_STRLEN];
  memset(parent_name, '\0', MYSQL_STRLEN);

  int status;
  MYSQL_BIND bindout[1];
  memset(bindout, 0, sizeof(bindout));
  unsigned long length[1];
  bool is_null[1];
  bool error[1];

  if ( (zone_name==NULL) || (strlen(zone_name)<2) ) {
    printf("dm_tofu_get_parent: needs a zone name\n");
    return NULL;
  }

  stmt=mysql_stmt_init(db);
  // regexp (literal dot)<parent_name with dots escaped><anchored to end of string>
  // results sorted by length, longest first, take only the first entry
  // first \ escape is for C string, then a second for SQL string parsing
  // trailing dots are not ignored
  char *stmt_str="SELECT parent_name FROM parent AS A WHERE ? REGEXP concat('\\\\.',REPLACE(A.parent_name,'.','\\\\.'),'$') ORDER BY length(A.parent_name) DESC LIMIT 1;";
  //printf ("stmt_str :%s:\n",stmt_str);

  if (mysql_stmt_prepare(stmt, stmt_str, strlen(stmt_str))) {
    printf ("dm_tofu_get_parent: prepare failed. %s\n",mysql_stmt_error(stmt));
    mysql_stmt_close(stmt);
    return NULL;
  }

  bind[0].buffer_type= MYSQL_TYPE_STRING;
  bind[0].buffer= (char *)zone_name;
  bind[0].buffer_length= MYSQL_STRLEN;
  bind[0].is_null= 0;
  len1=strlen(zone_name);
  bind[0].length= &len1;

  if (mysql_stmt_bind_param(stmt, bind) ) {
    printf ("dm_tofu_get_parent: bind failed. %s\n",mysql_error(db));
    mysql_stmt_close(stmt);
    return NULL;
  }
  if (mysql_stmt_execute(stmt) ) {
    printf ("dm_tofu_get_parent: exec failed. %s\n",mysql_error(db));
    mysql_stmt_close(stmt);
    return NULL;
  }

  /* STRING COLUMN parent_name */
  bindout[0].buffer_type= MYSQL_TYPE_STRING;
  bindout[0].buffer= (char *)&parent_name;
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

  // While rows to read.
  rc=0;  // row count. should always be 0 or 1
  while (1) {
    status = mysql_stmt_fetch(stmt);
    if (status == MYSQL_NO_DATA && rc==0) {
      // printf ("dm_tofu_get_parent: No match\n");
      mysql_stmt_close(stmt);
      return NULL;
    } else if (status == MYSQL_NO_DATA && rc>0) {
      // printf ("dm_tofu_get_parent: normal end \n");
      break; // Last line. Normal end of read after match.
    } else if (status == 1 ) {
      printf ("dm_tofu_get_parent: Error. Can't check zone name for parent_name %s %s\n",zone_name,mysql_error(db));
      mysql_stmt_close(stmt);
      return NULL;
    } 
    // We have data to return
    // printf("rc %i zone_name %s parent_name %s\n",rc,zone_name,parent_name);
    rc++;
  }

  mysql_stmt_close(stmt);
  // printf("returning %s\n",parent_name);
  return dm_tofu_cp_name(parent_name);
}


// count zones under this parent with this zone_status
// returns rc or -1 on failure
int dm_tofu_count_zone_status(MYSQL *db, char *parent_name, char *zone_status) {

  MYSQL_STMT *stmt;
  MYSQL_BIND bind[2];
  memset(bind, 0, sizeof(bind));
  size_t len1,len2;
  int rc=0;  // row count
  int zone_count=0;
  int count=0;

  int status;
  MYSQL_BIND bindout[1];
  memset(bindout, 0, sizeof(bindout));
  unsigned long length[1];
  bool is_null[1];
  bool error[1];

  if ( (parent_name==NULL) || (strlen(parent_name)<2) ) {
    printf("dm_tofu_count_zone_status: needs a parent name\n");
    return -1;
  }

  stmt=mysql_stmt_init(db);
  char *stmt_str="SELECT COUNT(*) FROM `zone` WHERE ( (`parent_name`=?) AND (`zone_status`=?) );";

  if (mysql_stmt_prepare(stmt, stmt_str, strlen(stmt_str))) {
    printf ("dm_tofu_count_zone_status: prepare failed. %s\n",mysql_stmt_error(stmt));
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
    printf ("dm_tofu_count_zone_status: bind failed. %s\n",mysql_error(db));
    mysql_stmt_close(stmt);
    return -1;
  }
  if (mysql_stmt_execute(stmt) ) {
    printf ("dm_tofu_count_zone_status: exec failed. %s\n",mysql_error(db));
    mysql_stmt_close(stmt);
    return -1;
  }

  /* INTEGER COLUMN count */
  bindout[0].buffer_type= MYSQL_TYPE_LONG;
  bindout[0].buffer= (char *)&count;
  bindout[0].is_null= &is_null[0];
  bindout[0].length= &length[0];
  bindout[0].error= &error[0];
 
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
      printf ("dm_tofu_count_zone_status: Error. No count data\n");
      mysql_stmt_close(stmt);
      return -1;
    } else if (status == MYSQL_NO_DATA && rc>0) {
      break; // Last line. Normal end of read after match.
    } else if (status == 1 ) {
      printf ("dm_tofu_count_zone_status: Error. Can't check zone count for parent_name %s %s\n",parent_name,mysql_error(db));
      mysql_stmt_close(stmt);
      return -1;
    } 
    // We have data to return
    printf("rc %i count %i\n",rc,count);
    zone_count+=count;
    rc++;
  }

  mysql_stmt_close(stmt);
  return count;
}

// select zone status given zone name
// returns NULL on no match or error
char *dm_tofu_select_zone_status(MYSQL *db, char *zone_name) {

  char zone_status[MYSQL_STRLEN]={'\0'};
  MYSQL_STMT *stmt;
  MYSQL_BIND bind[1];
  memset(bind, 0, sizeof(bind));
  size_t len1;
  int rc=0;  // row count

  int status;
  MYSQL_BIND bindout[1];
  memset(bindout, 0, sizeof(bindout));
  unsigned long length[1];
  bool is_null[1];
  bool error[1];

  if ( (zone_name==NULL) || (strlen(zone_name)<2) ) {
    printf("dm_tofu_select_zone_status: needs a zone name\n");
    return NULL;
  }

  stmt=mysql_stmt_init(db);
  char *stmt_str="SELECT A.zone_status FROM zone AS A WHERE A.zone_name=?; ";

  if (mysql_stmt_prepare(stmt, stmt_str, strlen(stmt_str))) {
    printf ("dm_tofu_select_zone_status: prepare failed. %s\n",mysql_stmt_error(stmt));
    mysql_stmt_close(stmt);
    return NULL;
  }

  bind[0].buffer_type= MYSQL_TYPE_STRING;
  bind[0].buffer= (char *)zone_name;
  bind[0].buffer_length= MYSQL_STRLEN;
  bind[0].is_null= 0;
  len1=strlen(zone_name);
  bind[0].length= &len1;

  if (mysql_stmt_bind_param(stmt, bind) ) {
    printf ("dm_tofu_select_zone_status: bind failed. %s\n",mysql_error(db));
    mysql_stmt_close(stmt);
    return NULL;
  }
  if (mysql_stmt_execute(stmt) ) {
    printf ("dm_tofu_select_zone_status: exec failed. %s\n",mysql_error(db));
    mysql_stmt_close(stmt);
    return NULL;
  }

  /* STRING COLUMN zone_status */
  bindout[0].buffer_type= MYSQL_TYPE_STRING;
  bindout[0].buffer= (char *)&zone_status;
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
      printf ("dm_tofu_select_zone_status: Error. Can't select zone status for zone_name %s %s\n",zone_name,mysql_error(db));
      mysql_stmt_close(stmt);
      return NULL;
    } 
    // We have data to return in a single element. Copied to result after all read.
    rc++;
  }
  mysql_stmt_close(stmt);
  if ( (strlen(zone_status)<2) ) { // zone status is an enum and is always quite long
    return NULL;
  }
  return dm_tofu_cp_name(zone_status);
}

// create a linked list of zones under this parent with this zone_status
// returns rc or -1 on failure
int dm_tofu_select_zone_with_status(MYSQL *db, char *parent_name, char *zone_status, ll_zone_t **ll_zone_head) {

  ll_zone_t *ll_zone_tmp=NULL;
  ll_zone_t *ll_zone_current=NULL;

  char zone_name[MYSQL_STRLEN];
  MYSQL_STMT *stmt;
  MYSQL_BIND bind[2];
  memset(bind, 0, sizeof(bind));
  unsigned int zone_id;
  size_t len1,len2;
  int rc=0;  // row count

  int status;
  MYSQL_BIND bindout[2];
  memset(bindout, 0, sizeof(bindout));
  unsigned long length[2];
  bool is_null[2];
  bool error[2];

  if ( (parent_name==NULL) || (strlen(parent_name)<2) ) {
    printf("dm_tofu_select_zone_with_status: needs a parent name\n");
    return -1;
  }

  stmt=mysql_stmt_init(db);
  char *stmt_str="SELECT A.zone_id, A.zone_name FROM zone AS A WHERE A.parent_name=? AND A.zone_status=?; ";

  if (mysql_stmt_prepare(stmt, stmt_str, strlen(stmt_str))) {
    printf ("dm_tofu_select_zone_with_status: prepare failed. %s\n",mysql_stmt_error(stmt));
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
    printf ("dm_tofu_select_zone_with_status: bind failed. %s\n",mysql_error(db));
    mysql_stmt_close(stmt);
    return -1;
  }
  if (mysql_stmt_execute(stmt) ) {
    printf ("dm_tofu_select_zone_with_status: exec failed. %s\n",mysql_error(db));
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
      printf ("dm_tofu_select_zone_with_status: normal. No data\n");
      break; 
    } else if (status == MYSQL_NO_DATA && rc>0) {
      break; // Last line. Normal end of read after match.
    } else if (status == 1 ) {
      printf ("dm_tofu_select_zone_with_status: Error. Can't check zone status for parent_name %s %s\n",parent_name,mysql_error(db));
      mysql_stmt_close(stmt);
      return -1;
    } 
    // We have data to return in a single linked list
    printf("rc %i zone_name %.*s id %i\n",rc,(int)length[1],zone_name,zone_id);
    ll_zone_tmp=(ll_zone_t*)malloc(sizeof(ll_zone_t));
    if (ll_zone_tmp==NULL) {
      printf("dm_tofu_select_zone_with_status: Error. Cannot allocate memory\n");
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
    ldns_helpers_add_trailing_dot(ll_zone_current->zone_name);
    rc++;
  }

  mysql_stmt_close(stmt);
  return rc;

}

// Batch job to move zones from creating to created
// returns number of zones timed out or -1 for error
int dm_tofu_creating_to_created(MYSQL *db, char *parent_name, time_t slot_time) {
  return dm_tofu_ns_update(db, parent_name, "creating", slot_time);
}
// Batch job to move zones from assigning to assigned
// returns number of zones timed out or -1 for error
int dm_tofu_assigning_to_assigned(MYSQL *db, char *parent_name, time_t slot_time){
  return dm_tofu_ns_update(db, parent_name, "assigning", slot_time);
}
// Batch job to move zones from delegating to delegated
// returns number of zones timed out or -1 for error
int dm_tofu_delegating_to_delegated(MYSQL *db, char *parent_name, time_t slot_time){
  return dm_tofu_ns_update(db, parent_name, "delegating", slot_time);
}
// Batch job to move zones from deleting to deleted
// returns number of zones timed out or -1 for error
int dm_tofu_deleting_to_deleted(MYSQL *db, char *parent_name, time_t slot_time){
  return dm_tofu_ns_update(db, parent_name, "deleting", slot_time);
}

// maintain a list of RR updates to be done in the DB after the knot config has been updated
// DB update only done after knotc has execed to minimise risk of out of synch
// unfortunately too complex to do a proper transaction and roll back
void push_rr_update(ll_rr_update_t **ll_rr_update_head, ll_rr_update_t **ll_rr_update_current, int rr_id, char *rr_status) {
  ll_rr_update_t *ll_rr_update_tmp=NULL;

    ll_rr_update_tmp=(ll_rr_update_t*)malloc(sizeof(ll_rr_t));
    if (ll_rr_update_tmp==NULL) {
      printf("push_rr_update: Error. Cannot allocate memory\n");
      exit (0);
    }
    memset(ll_rr_update_tmp,'\0',sizeof(ll_rr_update_t));
    ll_rr_update_tmp->next=NULL;
    // remember the head 1st time through
    if (*ll_rr_update_head==NULL) {
      // ll_rr_update_head is pointer to pointer so content can be updated to this new storage
      *ll_rr_update_head=ll_rr_update_tmp;
    } else {
      (*ll_rr_update_current)->next=ll_rr_update_tmp;
    }
    *ll_rr_update_current=ll_rr_update_tmp;
    (*ll_rr_update_current)->rr_id=rr_id;
    strcpy((*ll_rr_update_current)->rr_status,rr_status);
}

// Batch job to move zones from zone_status to new_zone_status
// trade off between having one complex routine or lots of repeated code.
// We chose for one complex routine because the work per transition is relatively small.
int dm_tofu_ns_update(MYSQL *db, char *parent_name, char *zone_status, time_t slot_time) {
  ll_zone_t *ll_zone_head=NULL; // linked list of zones under this parent in this status
  ll_zone_t *ll_zone_tmp=NULL;
  ll_zone_t *ll_zone_current=NULL;

  ll_rr_t *ll_rr_head=NULL;     // linked list of rr under this zone
  ll_rr_t *ll_rr_tmp=NULL;
  ll_rr_t *ll_rr_current=NULL;

  ll_rr_update_t *ll_rr_update_head=NULL; // remember rr_id and rr_status for db updates
  ll_rr_update_t *ll_rr_update_current=NULL;
  ll_rr_update_t *ll_rr_update_tmp=NULL;

  ll_secondary_ns_t *ll_secondary_ns_head; // list of secondary NS (for notify)
  ll_secondary_ns_t *ll_secondary_ns_tmp=NULL;
  ll_secondary_ns_t *ll_secondary_ns_current=NULL;

  if ( (zone_status==NULL) || (dm_tofu_is_valid_zone_status(zone_status)) ) {
    printf("dm_tofu_ns_update: needs a valid zone status, Got %s\n",zone_status);
    return -1;
  }

  char new_zone_status[MYSQL_STRLEN]="";

  if (strcmp(zone_status,"creating")==0) {
    strcpy(new_zone_status,"created");
  } else if (strcmp(zone_status,"deleting")==0) {
    strcpy(new_zone_status,"deleted"); 
  } else if (strcmp(zone_status,"delegating")==0) {
    strcpy(new_zone_status,"delegated"); 
  } else if (strcmp(zone_status,"assigning")==0) {
    strcpy(new_zone_status,"assigned"); 
  } else {
    printf("dm_tofu_ns_update: unsupported zone status %s\n",zone_status);
    return -1;
  }

  int rc,rc2,rc3;

  char *fn_knotc_config;
  FILE *fd_knotc_config;
  char *fn_knotc_zone;
  FILE *fd_knotc_zone;

  char *raw_ns_name;
  char ns_name[MYSQL_STRLEN+1]; // allow trailing dot as this goes in knotc config rather that the db

  time_t start_slot=(slot_time>0) ? slot_time : get_time_slot(0);
  int status=0;
  printf("dm_tofu_ns_update: started\n");

  // get the list of zones in this parent in this status
  rc=dm_tofu_select_zone_with_status(db, parent_name, zone_status, &ll_zone_head);

  if (rc==0) {
    printf("dm_tofu_ns_update: nothing to do.\n");
    return rc;
  }
  if (rc<0) {
    printf("dm_tofu_ns_update: Error in dm_tofu_select_zone_with_status. Nothing to do.\n");
    return rc;
  }

  // we have zones to process (rc>0)
  ll_zone_current=ll_zone_head;
  int first_pass=1;

  // get the primary NS for this parent
  raw_ns_name=dm_tofu_get_ns(db,parent_name); // ns_name is guaranteed to be null terminated
  strcpy(ns_name,raw_ns_name);
  ldns_helpers_add_trailing_dot(ns_name);
  // clean up
  if (raw_ns_name != NULL) {
   free(raw_ns_name);
  }

  //
  // get the secondary NS for this parent
  // notify_list=dm_tofu_get_notify_list(db,parent_name);
  ll_secondary_ns_head=dm_tofu_get_secondary_ns(db, parent_name); 

  while (ll_zone_current!=NULL) {
    printf("dm_tofu_ns_update: processing zone %s\n",ll_zone_current->zone_name);

    if (first_pass==1) {
      first_pass=0;

      // Create temp files for knotc config and zone commands for the parent zone
      fn_knotc_config=knot_helpers_create_file();
      fn_knotc_zone=knot_helpers_create_file();
      if ((fn_knotc_config==NULL) || (fn_knotc_zone)==NULL) {
        printf("dm_tofu_ns_update: Error. Can't create temp files.\n");
        break;
      }

      // open the temp files
      fd_knotc_config=fopen(fn_knotc_config,"w+");
      fd_knotc_zone=fopen(fn_knotc_zone,"w+");
      if ((fd_knotc_config==NULL) || (fd_knotc_zone)==NULL) {
        printf("dm_tofu_ns_update: Error. Can't open temp files.\n");
        break;
      }

      // start knotc transactions
      fprintf(fd_knotc_config,"conf-begin\n");
      if (strcmp(zone_status,"assigning")!=0) { // for everything except assigning, the updates are all in the parent zone
        fprintf(fd_knotc_zone,"zone-freeze %s\n",parent_name);
        fprintf(fd_knotc_zone,"zone-begin %s\n",parent_name);
      }
    }

    if (strcmp(zone_status,"creating")==0) {
      // create zones and config a zone file
      fprintf(fd_knotc_config,"conf-set zone[\'%s\']\n",ll_zone_current->zone_name);
      char knotd_home[]=KNOTD_HOME;
      fprintf(fd_knotc_config,"conf-set zone[\'%s\'].file \'%s/zones/%szone\'\n",ll_zone_current->zone_name,knotd_home,ll_zone_current->zone_name); // zone already has a trailing dot
      fprintf(fd_knotc_config,"conf-set zone[\'%s\'].dnssec-signing off \n",ll_zone_current->zone_name); // signing is done by the HNA
      // we only add the primary later once ACME completes

      // add config for notifies for secondaries and secondary NS rr to parent zone
      //fprintf(fd_knotc_config,"conf-set zone[\'%s\'].notify %s \n",ll_zone_current->zone_name,notify_list);
      ll_secondary_ns_current=ll_secondary_ns_head;
      while (ll_secondary_ns_current!=NULL) {
        fprintf(fd_knotc_config,"conf-set zone[\'%s\'].notify %s \n",ll_zone_current->zone_name,ll_secondary_ns_current->ns_name);
	// add NS to parent for secondaries
        fprintf(fd_knotc_zone,"zone-set %s %s 3600 NS %s\n",parent_name,ll_zone_current->zone_name,ll_secondary_ns_current->ns_name);
        ll_secondary_ns_tmp=ll_secondary_ns_current->next;
        ll_secondary_ns_current=ll_secondary_ns_tmp;
      }

      // add the primary NS delegation to the parent
      fprintf(fd_knotc_zone,"zone-set %s %s 3600 NS %s\n",parent_name,ll_zone_current->zone_name,ns_name);

      // add a soa to the new zone. knotc allows nested zone config
      fprintf(fd_knotc_zone,"zone-begin %s\n",ll_zone_current->zone_name);
      fprintf(fd_knotc_zone,"zone-set %s @ 3600 SOA %s admin 1 86400 900 691200 3600\n",ll_zone_current->zone_name,ns_name);
      fprintf(fd_knotc_zone,"zone-commit %s\n",ll_zone_current->zone_name);
      // commit
      // There can't be any additional rr in creating state at this time. Nothing to do.

    } else if (strcmp(zone_status,"deleting")==0) {
      // unset the zone. This also unsets any TXT SOA and other RR within the zone
      fprintf(fd_knotc_config,"conf-unset zone[\'%s\']\n",ll_zone_current->zone_name);

      // unset the NS delegation in the parent
      fprintf(fd_knotc_zone,"zone-unset %s %s 3600 NS %s\n",parent_name,ll_zone_current->zone_name,ns_name);

      // get the list of DS rr in this zone in created status and unset them in the parent zone
      // DB entries are all deleted with the zone.
      rc2=dm_tofu_select_rr_status(db, ll_zone_current->zone_id, "created", &ll_rr_head);
      if( rc2>0) {
        ll_rr_current=ll_rr_head;
        while (ll_rr_current!=NULL) {
          if ( (strcmp(ll_rr_current->rr_type,"DS")==0) ) {
            printf("dm_tofu_ns_update: deleting rr %s\n",ll_rr_current->rr_owner);
            fprintf(fd_knotc_zone,"zone-unset %s %s %i %s %s\n",parent_name,ll_rr_current->rr_owner,ll_rr_current->rr_ttl,ll_rr_current->rr_type,ll_rr_current->rr_rdata);
          }
          // get next rr
          ll_rr_tmp=ll_rr_current->next;
          free(ll_rr_current);
          ll_rr_current=ll_rr_tmp;
        }
      } // end rc>2 (we have RR to delete)
      ll_rr_head=NULL;
    } else if (strcmp(zone_status,"assigning")==0) {
      // start a transaction for this zone
      fprintf(fd_knotc_zone,"zone-begin %s\n",ll_zone_current->zone_name);
      // get the list of TXT rr in this zone in deleting status and unset them in the delegated zone
      rc2=dm_tofu_select_rr_status(db, ll_zone_current->zone_id, "deleting", &ll_rr_head);
      if( rc2>0) {
        ll_rr_current=ll_rr_head;
        while (ll_rr_current!=NULL) {
          if ( (strcmp(ll_rr_current->rr_type,"TXT")==0) ) { // only add TXT types in creating status
            printf("dm_tofu_ns_update: unassigning rr %s\n",ll_rr_current->rr_owner);
            fprintf(fd_knotc_zone,"zone-unset %s %s %i %s %s\n",ll_zone_current->zone_name,ll_rr_current->rr_owner,ll_rr_current->rr_ttl,ll_rr_current->rr_type,ll_rr_current->rr_rdata);
            push_rr_update(&ll_rr_update_head,&ll_rr_update_current,ll_rr_current->rr_id,"deleted"); // remember rr_id for db status update after exec command file
          }
          // get next rr
          ll_rr_tmp=ll_rr_current->next;
          free(ll_rr_current);
          ll_rr_current=ll_rr_tmp;
        }
      } // end rc>2 (we have TXT RR to delete)
      ll_rr_head=NULL;
      // get the list of TXT rr in this zone in creating status and set them in the delegated zone
      rc3=dm_tofu_select_rr_status(db, ll_zone_current->zone_id, "creating", &ll_rr_head);
      if( rc3>0) {
        ll_rr_current=ll_rr_head;
        while (ll_rr_current!=NULL) {
          if ( (strcmp(ll_rr_current->rr_type,"TXT")==0) ) { // only add TXT types in creating status
            printf("dm_tofu_ns_update: assigning rr %s\n",ll_rr_current->rr_owner);
            fprintf(fd_knotc_zone,"zone-set %s %s %i %s %s\n",ll_zone_current->zone_name,ll_rr_current->rr_owner,ll_rr_current->rr_ttl,ll_rr_current->rr_type,ll_rr_current->rr_rdata);
            push_rr_update(&ll_rr_update_head,&ll_rr_update_current,ll_rr_current->rr_id,"created"); // remember rr_id for db status update after exec command file
          }
          // get next rr
          ll_rr_tmp=ll_rr_current->next;
          free(ll_rr_current);
          ll_rr_current=ll_rr_tmp;
        }
      } // end rc3>2 (we have TXT RR to create)
      ll_rr_head=NULL;
      if ( (rc2>0) || (rc3>0) ) { // we've updated something, so bump the SOA
        fprintf(fd_knotc_zone,"zone-serial-set %s +1\n",ll_zone_current->zone_name);
      }
      // close this zone transaction for assigning
      fprintf(fd_knotc_zone,"zone-commit %s\n",ll_zone_current->zone_name);
    } else if (strcmp(zone_status,"delegating")==0) {
      // get the list of rr deleting status and unset them in the parent zone or remove the config
      // delete before create because some objects need to delete the entire object rather than just the sub-item.
      // e.g. if you just unset the remote[id].address then you get an error on conf-commit as id without address
      rc2=dm_tofu_select_rr_status(db, ll_zone_current->zone_id, "deleting", &ll_rr_head);
      if( rc2>0) {
        ll_rr_current=ll_rr_head;
        while (ll_rr_current!=NULL) {
          if ( (strcmp(ll_rr_current->rr_type,"DS")==0) ) { // only delete DS types in deleting status
            printf("dm_tofu_ns_update: deleting rr %s\n",ll_rr_current->rr_owner);
            fprintf(fd_knotc_zone,"zone-unset %s %s %i %s %s\n",parent_name,ll_rr_current->rr_owner,ll_rr_current->rr_ttl,ll_rr_current->rr_type,ll_rr_current->rr_rdata);
            push_rr_update(&ll_rr_update_head,&ll_rr_update_current,ll_rr_current->rr_id,"deleted"); // remember rr_id for db status update after exec command file
          } else if ( (strcmp(ll_rr_current->rr_type,"NS")==0) ) { // NS has to be done first
            printf("dm_tofu_ns_update: deleting rr %s\n",ll_rr_current->rr_owner);
            fprintf(fd_knotc_config,"conf-unset zone[\'%s\'].master\n",ll_zone_current->zone_name); // unset master
            push_rr_update(&ll_rr_update_head,&ll_rr_update_current,ll_rr_current->rr_id,"deleted"); // remember rr_id for db status update after exec command file
          } else if ( (strcmp(ll_rr_current->rr_type,"AAAA")==0) ) { 
            printf("dm_tofu_ns_update: deleting rr %s\n",ll_rr_current->rr_owner);
            fprintf(fd_knotc_config,"conf-unset remote[\'%s\']\n",ll_rr_current->rr_owner); // remove remote and all addresses
            push_rr_update(&ll_rr_update_head,&ll_rr_update_current,ll_rr_current->rr_id,"deleted"); // remember rr_id for db status update after exec command file
          }
          // get next rr
          ll_rr_tmp=ll_rr_current->next;
          free(ll_rr_current);
          ll_rr_current=ll_rr_tmp;
        }
      } // end rc>2 (we have RR to delete)
      ll_rr_head=NULL;
      // get the list of rr in this zone in creating status and set them in the parent zone
      rc3=dm_tofu_select_rr_status(db, ll_zone_current->zone_id, "creating", &ll_rr_head);
      if( rc3>0) {
        ll_rr_current=ll_rr_head;
        while (ll_rr_current!=NULL) {
          if ( (strcmp(ll_rr_current->rr_type,"DS")==0) ) { // add DS types in creating status
            printf("dm_tofu_ns_update: assigning rr %s\n",ll_rr_current->rr_owner);
            fprintf(fd_knotc_zone,"zone-set %s %s %i %s %s\n",parent_name,ll_rr_current->rr_owner,ll_rr_current->rr_ttl,ll_rr_current->rr_type,ll_rr_current->rr_rdata);
            push_rr_update(&ll_rr_update_head,&ll_rr_update_current,ll_rr_current->rr_id,"created"); // remember rr_id for db status update after exec command file
          } else if ( (strcmp(ll_rr_current->rr_type,"AAAA")==0) ) { // AAAA has to be done first otherwise knotc commplains
            printf("dm_tofu_ns_update: setting rr %s\n",ll_rr_current->rr_owner);
            fprintf(fd_knotc_config,"conf-set remote[\'%s\']\n",ll_rr_current->rr_owner); // create id for remote
            fprintf(fd_knotc_config,"conf-set remote[\'%s\'].address \'%s\'\n",ll_rr_current->rr_owner,ll_rr_current->rr_rdata); // set address for remote
            push_rr_update(&ll_rr_update_head,&ll_rr_update_current,ll_rr_current->rr_id,"created"); // remember rr_id for db status update after exec command file
          } else if ( (strcmp(ll_rr_current->rr_type,"NS")==0) ) { 
            printf("dm_tofu_ns_update: setting rr %s\n",ll_rr_current->rr_owner);
            fprintf(fd_knotc_config,"conf-set zone[\'%s\'].master \'%s\'\n",ll_zone_current->zone_name,ll_rr_current->rr_rdata); // set master
            push_rr_update(&ll_rr_update_head,&ll_rr_update_current,ll_rr_current->rr_id,"created"); // remember rr_id for db status update after exec command file
          }
          // get next rr
          ll_rr_tmp=ll_rr_current->next;
          free(ll_rr_current);
          ll_rr_current=ll_rr_tmp;
        }
      } // end rc>3 (we have RR to create)
      ll_rr_head=NULL;
    } // end if delegating

    // get next zone
    ll_zone_tmp=ll_zone_current->next;

    if (ll_zone_tmp==NULL) { // last time through?
      // end knotc transactions
      fprintf(fd_knotc_config,"conf-commit\n");
      if (strcmp(zone_status,"assigning")!=0) { // for everything except assigning, the updates are all in the parent zone
        fprintf(fd_knotc_zone,"zone-commit %s\n",parent_name);
        fprintf(fd_knotc_zone,"zone-thaw %s\n",parent_name);
        fprintf(fd_knotc_zone,"zone-sign %s\n",parent_name);
      }

      // close the temp files
      fclose(fd_knotc_config); 
      fclose(fd_knotc_zone); 

      // execute the commands via knotc. TODO improve status checking for failed command files.
      printf("dm_tofu_ns_update: executing zone %s\n",parent_name);
      status=0;
      status=knot_helpers_exec_file(fn_knotc_config);
      if (status!=0) {
        printf("dm_tofu_ns_update: warning. Error executing zone config %s\n",parent_name);
      }
      status=knot_helpers_exec_file(fn_knotc_zone);
      if (status!=0) {
        printf("dm_tofu_ns_update: warning. Error executing zone content %s\n",parent_name);
      }

      // remove the temp files
      status=knot_helpers_delete_file(fn_knotc_config);
      if (status!=0) {
        printf("dm_tofu_ns_update: warning. Error deleting temp config file %s\n",fn_knotc_config);
      }
      status=knot_helpers_delete_file(fn_knotc_zone);
      if (status!=0) {
        printf("dm_tofu_ns_update: warning. Error deleting temp zone content file %s\n",fn_knotc_zone);
      }
    } // end if last time through
    ll_zone_current=ll_zone_tmp;
  } // end WHILE ll_zone_current
  // all zones are done
    
  // this pass to free the secondary NS linked list.
  ll_secondary_ns_current=ll_secondary_ns_head;
  while (ll_secondary_ns_current!=NULL) {
    ll_secondary_ns_tmp=ll_secondary_ns_current->next;
    free(ll_secondary_ns_current);
    ll_secondary_ns_current=ll_secondary_ns_tmp;
  }
 
  // this pass to update the rr status in the db and free the linked list. This covers all zones under this parent in one go.
  ll_rr_update_current=ll_rr_update_head;
  while (ll_rr_update_current!=NULL) {
    printf("dm_tofu_ns_update: updating rr %i %li\n",ll_rr_update_current->rr_id,start_slot);
    if (strcmp(ll_rr_update_current->rr_status,"created")==0) {
      dm_tofu_update_rr_status(db, ll_rr_update_current->rr_id, ll_rr_update_current->rr_status, start_slot);
    } else if (strcmp(ll_rr_update_current->rr_status,"deleted")==0) {
      dm_tofu_delete_rr(db, ll_rr_update_current->rr_id);
    }
    ll_rr_update_tmp=ll_rr_update_current->next;
    free(ll_rr_update_current);
    ll_rr_update_current=ll_rr_update_tmp;
  } // end WHILE ll_rr_update_current
  ll_rr_update_head=NULL;

  // this pass to update the zone status in the db and free the linked list
  ll_zone_current=ll_zone_head;
  while (ll_zone_current!=NULL) {
    printf("dm_tofu_ns_update: updating zone %s %li\n",ll_zone_current->zone_name,start_slot);
    if ( (strcmp(new_zone_status,"created")==0) || (strcmp(new_zone_status,"assigned")==0) || (strcmp(new_zone_status,"delegated")==0) ) {
      dm_tofu_update_zone_status(db, ll_zone_current->zone_id, new_zone_status, start_slot);
    } else if (strcmp(new_zone_status,"deleted")==0) {
      dm_tofu_delete_zone(db, ll_zone_current->zone_id);
    }
    ll_zone_tmp=ll_zone_current->next;
    free(ll_zone_current);
    ll_zone_current=ll_zone_tmp;
  } // end WHILE ll_zone_current

  //if (notify_list != NULL) {
  // free(notify_list);
  // }
   
  printf("dm_tofu_ns_update: ended.\n");
  return rc;
}

// Check time out for zones stuck in zone_status.
// Uses Innodb atomic transaction to ensure completeness.
// Marks zones for deletion, rather than directly actioning
// returns number of zones timed out or -1 for error
int dm_tofu_timeout_zone(MYSQL *db, char *parent_name, char *zone_status, time_t slot_time, time_t timeout) { 

  MYSQL_STMT *stmt;
  MYSQL_BIND bind[2];
  memset(bind, 0, sizeof(bind));
  size_t len1;
  int rc=0;  // row count
  MYSQL_RES *result;

  time_t start_slot=(slot_time>0) ? slot_time : get_time_slot(0);
  time_t offset=(timeout>0) ? timeout : 0;
  offset+=2*DM_TOFU_SLOT_LENGTH; // add 2 slots to timeout value to avoid race condition
  time_t last_valid_time=start_slot-offset;

  if ( (parent_name==NULL) || (strlen(parent_name)<2) ) {
    printf("dm_tofu_timeout_zone: needs a parent name\n");
    return -1;
  }
  if ( (zone_status==NULL) || (dm_tofu_is_valid_zone_status(zone_status)) ) {
    printf("dm_tofu_timeout_zone: needs a valid zone status\n");
    return -1;
  }

  stmt=mysql_stmt_init(db);
  char *stmt_str="UPDATE zone AS A SET zone_status='deleting' WHERE ( (A.zone_status=?) AND (A.zone_status_time<=?) );"; 

  if (mysql_stmt_prepare(stmt, stmt_str, strlen(stmt_str))) {
    printf ("dm_tofu_timeout_zone: prepare failed. %s\n",mysql_stmt_error(stmt));
    mysql_stmt_close(stmt);
    return -1;
  }

  bind[0].buffer_type= MYSQL_TYPE_STRING;
  bind[0].buffer= (char *)zone_status;
  bind[0].buffer_length= MYSQL_STRLEN;
  bind[0].is_null= 0;
  len1=strlen(zone_status);
  bind[0].length= &len1;
  bind[1].buffer_type= MYSQL_TYPE_LONG;
  bind[1].buffer= (char *)&last_valid_time;
  bind[1].is_null= 0;
  bind[1].length= 0;
  if (mysql_stmt_bind_param(stmt, bind) ) {
    printf ("dm_tofu_timeout_zone: bind failed. %s\n",mysql_error(db));
    mysql_stmt_close(stmt);
    return -1;
  }
  if (mysql_stmt_execute(stmt) ) {
    printf ("dm_tofu_timeout_zone: exec failed. %s\n",mysql_error(db));
    mysql_stmt_close(stmt);
    return -1;
  }

  result=mysql_use_result(db);
  rc=mysql_affected_rows(db);
  mysql_free_result(result);
  mysql_stmt_close(stmt);

  return rc;

}


// Check time out for zones stuck in created zone_status (that have not been claimed).
// Uses Innodb atomic transaction to ensure completeness.
// Marks zones for deletion, rather than directly actioning
// returns number of zones timed out or -1 for error
int dm_tofu_timeout_created_zone(MYSQL *db, char *parent_name, time_t slot_time){
  return dm_tofu_timeout_zone(db, parent_name, "created", slot_time, DM_TOFU_T1) ;
}

// Check time out for zones stuck in offered zone_status (that have not transitioned to assigned).
// Uses Innodb atomic transaction to ensure completeness.
// Marks zones for deletion, rather than directly actioning
// returns number of zones timed out or -1 for error
int dm_tofu_timeout_offered_zone(MYSQL *db, char *parent_name, time_t slot_time){
  return dm_tofu_timeout_zone(db, parent_name, "offered", slot_time, DM_TOFU_T2) ;
}

// Check time out for zones stuck in assigned zone_status (that have not transitioned to delegated).
// Marks zones for deletion, rather than directly actioning
// returns number of zones timed out or -1 for error
int dm_tofu_timeout_assigned_zone(MYSQL *db, char *parent_name, time_t slot_time){
  return dm_tofu_timeout_zone(db, parent_name, "assigned", slot_time, DM_TOFU_T3) ;
}


// Check time out for zones stuck in delegated zone_status (that have not had any updates using certificates, probably due to HNA no longer in use).
// Marks zones for deletion, rather than directly actioning
// returns number of zones timed out or -1 for error
int dm_tofu_timeout_delegated_zone(MYSQL *db, char *parent_name, time_t slot_time){
  return dm_tofu_timeout_zone(db, parent_name, "delegated", slot_time, DM_TOFU_T4) ;
}


// create a linked list of rr under this zone with this rr_status
// returns rc or -1 on failure
// order depending on deleting or adding
int dm_tofu_select_rr_status(MYSQL *db, int zone_id, char *rr_status, ll_rr_t **ll_rr_head) {

  ll_rr_t *ll_rr_tmp=NULL;
  ll_rr_t *ll_rr_current=NULL;

  char rr_owner[MYSQL_STRLEN];
  int rr_ttl;
  char rr_type[MYSQL_STRLEN];
  char rr_rdata[MYSQL_STRLEN];
  MYSQL_STMT *stmt;
  MYSQL_BIND bind[2];
  memset(bind, 0, sizeof(bind));
  unsigned int rr_id;
  size_t len1;
  int rc=0;  // row count

  int status;
  MYSQL_BIND bindout[5];
  memset(bindout, 0, sizeof(bindout));
  unsigned long length[5];
  bool is_null[5];
  bool error[5];

  if ( zone_id<=0 ) {
    printf("dm_tofu_select_rr_status: needs a zone id\n");
    return -1;
  }

  stmt=mysql_stmt_init(db);
  char stmt_str[160];
  memset(stmt_str,'\0',sizeof(stmt_str));
  if (strcmp(rr_status,"creating")==0) { // for creating we want aaaa (high rr_type) before ns (low rr_type). It's a bit of a kludge but it works.
    strcpy(stmt_str,"SELECT A.rr_id, A.rr_owner, A.rr_ttl, A.rr_type, A.rr_rdata FROM rr AS A WHERE A.zone_id=? AND A.rr_status=? ORDER BY A.zone_id, A.rr_type DESC;");
  } else {
    strcpy(stmt_str,"SELECT A.rr_id, A.rr_owner, A.rr_ttl, A.rr_type, A.rr_rdata FROM rr AS A WHERE A.zone_id=? AND A.rr_status=? ORDER BY A.zone_id, A.rr_type;");
  }

  if (mysql_stmt_prepare(stmt, stmt_str, strlen(stmt_str))) {
    printf ("dm_tofu_select_rr_status: prepare failed. %s\n",mysql_stmt_error(stmt));
    mysql_stmt_close(stmt);
    return -1;
  }

  bind[0].buffer_type= MYSQL_TYPE_LONG;
  bind[0].buffer= (char *)&zone_id;
  bind[0].is_null= 0;
  bind[0].length= 0;

  bind[1].buffer_type= MYSQL_TYPE_STRING;
  bind[1].buffer= (char *)rr_status;
  bind[1].buffer_length= MYSQL_STRLEN;
  bind[1].is_null= 0;
  len1=strlen(rr_status);
  bind[1].length= &len1;

  if (mysql_stmt_bind_param(stmt, bind) ) {
    printf ("dm_tofu_select_rr_status: bind failed. %s\n",mysql_error(db));
    mysql_stmt_close(stmt);
    return -1;
  }
  if (mysql_stmt_execute(stmt) ) {
    printf ("dm_tofu_select_rr_status: exec failed. %s\n",mysql_error(db));
    mysql_stmt_close(stmt);
    return -1;
  }

  /* INTEGER COLUMN rr_id */
  bindout[0].buffer_type= MYSQL_TYPE_LONG;
  bindout[0].buffer= (char *)&rr_id;
  bindout[0].is_null= &is_null[0];
  bindout[0].length= &length[0];
  bindout[0].error= &error[0];

  /* STRING COLUMN rr_owner */
  bindout[1].buffer_type= MYSQL_TYPE_STRING;
  bindout[1].buffer= (char *)&rr_owner;
  bindout[1].buffer_length= MYSQL_STRLEN;
  bindout[1].is_null= &is_null[1];
  bindout[1].length= &length[1];
  bindout[1].error= &error[1];

  /* INTEGER COLUMN rr_ttl */
  bindout[2].buffer_type= MYSQL_TYPE_LONG;
  bindout[2].buffer= (char *)&rr_ttl;
  bindout[2].is_null= &is_null[2];
  bindout[2].length= &length[2];
  bindout[2].error= &error[2];

  /* STRING COLUMN rr_type */
  bindout[3].buffer_type= MYSQL_TYPE_STRING;
  bindout[3].buffer= (char *)&rr_type;
  bindout[3].buffer_length= MYSQL_STRLEN;
  bindout[3].is_null= &is_null[3];
  bindout[3].length= &length[3];
  bindout[3].error= &error[3];

  /* STRING COLUMN rr_rdata */
  bindout[4].buffer_type= MYSQL_TYPE_STRING;
  bindout[4].buffer= (char *)&rr_rdata;
  bindout[4].buffer_length= MYSQL_STRLEN;
  bindout[4].is_null= &is_null[4];
  bindout[4].length= &length[4];
  bindout[4].error= &error[4];

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
      printf ("dm_tofu_select_rr_status: normal. No data\n");
      break; 
    } else if (status == MYSQL_NO_DATA && rc>0) {
      break; // Last line. Normal end of read after match.
    } else if (status == 1 ) {
      printf ("dm_tofu_select_rr_status: Error. Can't check rr status for zone_id %i %s\n",zone_id,mysql_error(db));
      mysql_stmt_close(stmt);
      return -1;
    } 
    // We have data to return in a single linked list
    printf("rc %i rr_owner %.*s id %i\n",rc,(int)length[1],rr_owner,rr_id);
    ll_rr_tmp=(ll_rr_t*)malloc(sizeof(ll_rr_t));
    if (ll_rr_tmp==NULL) {
      printf("dm_tofu_select_rr_status: Error. Cannot allocate memory\n");
      exit (0);
    }
    memset(ll_rr_tmp,'\0',sizeof(ll_rr_t));
    ll_rr_tmp->next=NULL;
    // remember the head 1st time through
    if (*ll_rr_head==NULL) {
      // ll_rr_head is pointer to pointer so content can be updated to this new storage
      *ll_rr_head=ll_rr_tmp;
    } else {
      ll_rr_current->next=ll_rr_tmp;
    }
    ll_rr_current=ll_rr_tmp;
    ll_rr_current->rr_id=rr_id;
    strcpy(ll_rr_current->rr_owner,rr_owner);
    ll_rr_current->rr_ttl=rr_ttl;
    strcpy(ll_rr_current->rr_type,rr_type);
    strcpy(ll_rr_current->rr_rdata,rr_rdata);
    rc++;
  }

  mysql_stmt_close(stmt);
  return rc;
}


// function called from dm_worker to process and inbound query PTR packet
// a PTR Query is a solicit for a child domain from the HNA to the DM.
// The reply from the DM is an offer and MAY contain zero, one, or more than one answers.
//
// The PTR query SHOULD contain exactly one question.
// QTYPE MUST be PTR. QCLASS MUST be IN.
// NAME field MAY be blank. DM is free to offer any child domain name.
// NAME field MAY be a delegated IPv6 prefix as per RFC8501 2.3.3. in IP6.ARPA format (RFC3152)
// Address MAY be used as a hint by the DM to assign a child domain name. Address to child domain name mapping MUST be sufficiently opaque to prevent guessing.
// NAME field MAY be a parent. DM SHOULD use this as a hint to offer a child domain from this parent domain. Non-existent parent= name error/NXDOMAIN.
// NAME field MAY be a FQDN of a child domain. DM SHOULD check whether this name is available for use by this HNA. Non-existent = Name error/NXDOMAIN. Not allowed for this HHA = REFUSED.
//
ldns_pkt * dm_worker_query_ptr(ldns_pkt *query_pkt, struct ssl_client *p_ssl_client){ // 1st arg = packet, 2nd arg=SSL client (for cert)
  ldns_rr *query_question_rr=NULL;
  ldns_pkt *response_pkt=NULL;
  ldns_rr_list *response_qr=NULL;
  ldns_rr_list *response_an=NULL;
  char buf[160+MYSQL_STRLEN]={'\0'};
  ldns_pkt_rcode rcode=LDNS_RCODE_NOERROR;
  char query_name[MYSQL_STRLEN]={'\0'};
  char parent_name[MYSQL_STRLEN]={'\0'};
  char child_rr_str[80+MYSQL_STRLEN]={'\0'};
      
  // some sanity checking
  if (!query_pkt) {
    sprintf(buf, "Blank packet passed to dm_tofu_query_ptr_response\n");
    printf("%s",buf);
    return NULL;
  }
  sprintf(buf, "incoming PTR query\n");
  printf("%s",buf);

  // generate a blank response packet
  response_pkt = ldns_pkt_new();
  ldns_pkt_set_qr(response_pkt, 1); //response
  ldns_pkt_set_aa(response_pkt, 1); //authoratative
  ldns_pkt_set_id(response_pkt, ldns_pkt_id(query_pkt));

  query_question_rr = ldns_rr_list_rr(ldns_pkt_question(query_pkt), 0); // get the first RR of the question
  if (query_question_rr!=NULL) {
    response_qr = ldns_rr_list_new();
  //query_question_rr = ldns_rr_clone(ldns_rr_list_rr(ldns_pkt_question(query_pkt), 0)); // get the first RR of the question and clone it
    ldns_rr_list_push_rr(response_qr, ldns_rr_clone(query_question_rr));
    //printf("response_qr: %s\n",ldns_rr_list2str(response_qr));
  }

  // Checks
  if (p_ssl_client->db == NULL) {
    sprintf(buf, "dm_tofu_query_ptr_response: No DB connection\n");
    printf("%s",buf);
    rcode=LDNS_RCODE_SERVFAIL;
    goto return_response;
  }

  char *ipv6_client=p_ssl_client->client_addr;
  if ( (ipv6_client==NULL) || (strlen(ipv6_client)<2) ) {
    printf ("dm_tofu_query_ptr_response: ipv6_client is NULL\n");
    rcode=LDNS_RCODE_SERVFAIL;
    goto return_response;
  }
  size_t q_count=ldns_rr_list_rr_count(ldns_pkt_question(query_pkt));
  if (q_count !=1) { // no question or too many questions
    sprintf(buf, "dm_tofu_query_ptr_response: invalid number of questions, %zu.\n",q_count);
    printf("%s",buf);
    rcode=LDNS_RCODE_FORMERR;
    goto return_response;
  }

  if (ldns_rr_get_class(query_question_rr)!=LDNS_RR_CLASS_IN ) { // not asking for Internet
    sprintf(buf, "dm_tofu_query_ptr_response: Not asking for class INin \n");
    printf("%s",buf);
    rcode=LDNS_RCODE_FORMERR;
    goto return_response;
  }
  if (ldns_rr_get_type(query_question_rr)!=LDNS_RR_TYPE_PTR) { // not asking for a pointer
    sprintf(buf, "dm_tofu_query_ptr_response: Not asking for a PTR in \n");
    printf("%s",buf);
    rcode=LDNS_RCODE_FORMERR;
    goto return_response;
  }
  ldns_dname_2str(query_name, ldns_rr_owner(query_question_rr)); // get the NAME field from the query
  sprintf(buf, "incoming PTR query for %s\n",query_name);
  printf("%s",buf);

  // get a list of parent zones where we are the DM
  // we ignore the question for now (!)
  // TODO add in ipv6 hints or parent name hints
  ll_parent_t *ll_parent_head=NULL;
  ll_parent_t *ll_parent_tmp=NULL;
  ll_parent_t *ll_parent_current=NULL;
  int answer=0;
  int rc= dm_tofu_select_parent_dm(p_ssl_client->db,&ll_parent_head);
  if (rc<1) {
    sprintf(buf, "dm_tofu_query_ptr_response: Couldn't find parent zones\n");
    printf("%s",buf);
    rcode=LDNS_RCODE_SERVFAIL;
    goto return_response;
  }
  // step through the parents
  ll_parent_current=ll_parent_head;
  char *child=NULL;
  while (ll_parent_current != NULL) {
    // attempt to offer a single zone per parent
    child=offer_zone(p_ssl_client->db, ll_parent_current->parent_name, ipv6_client, 0);
    if  (child !=NULL)  {
      if ( strlen(child)>2) {
        answer++; // we have found a child zone to offer
        // create a new rr and push onto the answer
        ldns_rr *an_rr=NULL;
        ldns_rdf *prev=NULL;
        ldns_status l_status;
        ldns_rdf *origin = NULL;
        child_rr_str[0]='\0';
        // TTL: MAY be used to indicate timeout available for TOFU to complete T2+T3
        snprintf(child_rr_str, sizeof child_rr_str, "%s     %d    IN      PTR       %s", parent_name,DM_TOFU_T2+DM_TOFU_T3,child);
        l_status = ldns_rr_new_frm_str(&an_rr,child_rr_str,DM_TOFU_T2+DM_TOFU_T3,origin,&prev);
        if (prev!=NULL) {
          ldns_rdf_deep_free(prev);
          prev=NULL;
        }
        if (LDNS_STATUS_OK==l_status) {
          if (answer ==1) { // first answer so create the answer list
            response_an = ldns_rr_list_new();
            ldns_pkt_set_ancount(response_pkt,0);
          }
          // push the new an_rr onto the answer rr list
          ldns_rr_list_push_rr(response_an,an_rr);
        } else {
          sprintf(buf, "dm_tofu_query_ptr_response: Couldn't create RR for %s.\n",child_rr_str);
          printf("%s",buf);
	}
      }
      free(child);
    }
    // get next parent
    ll_parent_tmp=ll_parent_current->next;
    free(ll_parent_current);
    ll_parent_current=ll_parent_tmp;
  } // end while parent

  if ( (answer==0) ) { // couldn't offer anything = temporary failure 
    sprintf(buf, "dm_tofu_query_ptr_response: Couldn't offer a zone.\n");
    printf("%s",buf);
    rcode=LDNS_RCODE_SERVFAIL;
    goto return_response;
  }

   // set the response code and push the answer (if any) into the packet
   return_response:
   ldns_pkt_set_rcode(response_pkt,rcode);
   if (response_an!=NULL) { // ldns_new_pkt also creates rr list storage so free, clone, free
     ldns_rr_list_deep_free(response_pkt->_answer);
     response_pkt->_answer = ldns_rr_list_clone(response_an);
     ldns_pkt_set_ancount(response_pkt,ldns_rr_list_rr_count(response_an));
     ldns_rr_list_deep_free(response_an);
   }
   if (response_qr!=NULL) {
     ldns_rr_list_deep_free(response_pkt->_question);
     response_pkt->_question = ldns_rr_list_clone(response_qr);
     ldns_pkt_set_qdcount(response_pkt,ldns_rr_list_rr_count(response_qr));
     ldns_rr_list_deep_free(response_qr);
   }
   return response_pkt; // note: no timestamp set yet (done in caller)
}


char *dm_tofu_select_zone_ip(MYSQL *db, char *zone_name) {
  MYSQL_STMT *stmt;
  MYSQL_BIND bind[1];
  memset(bind, 0, sizeof(MYSQL_BIND));
  size_t len1;
  MYSQL_BIND bindout[1];
  memset(bindout, 0, sizeof(bindout));

  int status;
  unsigned long length[1];
  bool is_null[1];
  bool error[1];
  int rc=0;

  char ipv6[INET6_ADDRSTRLEN]={'\0'};

  // select the ipv6 address from the db (if there is one)

  stmt=mysql_stmt_init(db);
  char *stmt_str="SELECT A.ipv6 FROM infra AS A, zone AS B  WHERE ( (B.hna = A.infra_id) AND (B.zone_name=?) ) LIMIT 1;"; 

  if (mysql_stmt_prepare(stmt, stmt_str, strlen(stmt_str))) {
    printf ("dm_tofu_select_zone_ip: prepare failed. %s\n",mysql_stmt_error(stmt));
    mysql_stmt_close(stmt);
    return NULL;
  }
  // zone_name
  memset(bind, 0, sizeof(bind));
  bind[0].buffer_type= MYSQL_TYPE_STRING;
  bind[0].buffer= (char *)zone_name;
  bind[0].buffer_length= MYSQL_STRLEN;
  bind[0].is_null= 0;
  len1=strlen(zone_name);
  bind[0].length= &len1;

  if (mysql_stmt_bind_param(stmt, bind)) {
    printf("dm_tofu_select_zone_ip: bind failed %s\n",mysql_stmt_error(stmt));
    mysql_stmt_close(stmt);
    return NULL;
  }
  if (mysql_stmt_execute(stmt)) {
    printf ("dm_tofu_select_zone_ip: exec failed. %s\n",mysql_error(db));
    mysql_stmt_close(stmt);
    return NULL;
  }

  /* STRING COLUMN ipv6 */
  bindout[0].buffer_type= MYSQL_TYPE_STRING;
  bindout[0].buffer= (char *)&ipv6;
  bindout[0].buffer_length= MYSQL_STRLEN;
  bindout[0].is_null= &is_null[1];
  bindout[0].length= &length[1];
  bindout[0].error= &error[1];

  if (mysql_stmt_bind_result(stmt, bindout)) {
    fprintf(stderr, " mysql_stmt_bind_result() failed\n");
    fprintf(stderr, " %s\n", mysql_stmt_error(stmt));
    mysql_stmt_close(stmt);
    return NULL;
  }

  // While rows to read. For this query there is only 0 or 1.
  rc=0;  // row count
  while (1) {
    status = mysql_stmt_fetch(stmt);
    if (status == 1 ) {
      printf ("dm_tofu_select_zone_ip Error. Can't select ip %s\n",mysql_error(db));
      mysql_stmt_close(stmt);
      return NULL;
    } else if (status == MYSQL_NO_DATA && rc==0) {
      printf ("dm_tofu_select_zone_ip: Info. Can't find an ip.\n");
      mysql_stmt_close(stmt);
      return NULL;
    } else if (status == MYSQL_NO_DATA) {
      break; // last line. normal end of read
    }
    rc++;
    printf("rc %i len %i zone_name %s ipv6 %s\n",rc,(int)length[0],zone_name,ipv6);
  }
  mysql_stmt_close(stmt);
  if ( (strlen(ipv6)<2) ) {
    return NULL;
  }
  return dm_tofu_cp_name(ipv6);
}


// Check the trust on first use before entering a TXT RR into the parent
// checks the lock on source IP address of the TXT update compared to the offer query
// 0 for OK -1 for fail
int dm_tofu_check_txt_tofu(char *acme_challenge, struct ssl_client *p_ssl_client) { // 1st arg the TXT challenge RR owner. 2nd = SSL client (for IP)
  int result=-1;
  char *ipv6_client=p_ssl_client->client_addr;

  if ( (ipv6_client==NULL) || (strlen(ipv6_client)<2) ) {
    printf ("ipv6_client is NULL\n");
    return -1; // no client ip
  }
  if (strlen(acme_challenge)>MYSQL_STRLEN) {
    return -1; // name too long
  }
  char *zone_name=dm_tofu_get_zone(p_ssl_client->db, acme_challenge); // find the zone associated with this RR

  if ( (zone_name!=NULL) ) {
    // check the db for a hna ipv6 for this zone
    char *ipv6_db=NULL;
    ipv6_db=dm_tofu_select_zone_ip(p_ssl_client->db,zone_name);
    free(zone_name);
    zone_name=NULL;

    if ( (ipv6_db!=NULL) ) {
      int cmp=strcmp(ipv6_db,ipv6_client); // ipv6 in the db should match the ipv6 of the client
      if (cmp!=0) {
        result=-1;
      } else {
        result=0;
      }
      printf ("ipv6_db %s ipv6_client %s\n",ipv6_db,ipv6_client);
      free(ipv6_db);
      ipv6_db=NULL;
    } else {
      printf ("ipv6_db is NULL\n");
    }  
  } else {
    printf ("zone_name is NULL\n");
  }
  return result;
}

// Background job threads for TOFU

// function called from server create file for knotc commands
char *knot_helpers_create_file() {
   char filename_template[] = "/tmp/KnotcCommandsXXXXXX"; // must contain 6*X which are substitued by mkstemp.
   char *filename=(char*)malloc(sizeof(filename_template));
   memset(filename,'\0',sizeof(filename_template));

   if (filename == NULL) {
     printf("knot_helpers_create_file: can't allocate memory\n");
     return NULL;
   }
   strcpy(filename,filename_template); // gets overwritten by std function so use own storage.

   int fd = mkstemp(filename);
   if (fd < 0) {
     printf("knot_helpers_create_file: can't create temporary file\n");
     return NULL;
   }
   close(fd);

   return filename;
}

// function called from server delete file containing knotc commands
int knot_helpers_delete_file(char *filename) {
  char filename_template[] = "/tmp/KnotcCommands"; // must match prefix in the template above
  size_t i=0;
  int cmp=0;
  int dotcount=0;
  int ret=0;

  if ((filename==NULL)) {
    printf("knot_helpers_delete_file: needs a filename\n");
    return -1;
  }
  // poor man's parser sanity check for non-alphanumeric and curious filenames
  for (i=0;i<strlen(filename);i++) {
    // allow forward slashes and single dots but not next to each other
    if ( (filename[i]=='/') || (filename[i]=='.')) {
      dotcount++;
      if (dotcount>1) {
        cmp=-1;
        break;
      } else {
        continue;
      }
    }
    if (isalnum(filename[i])==0) {
      cmp=-1;
      break;
    } else {
      dotcount=0;
    }
  }
  if (cmp) {
    printf("knot_helpers_delete_file: filename is too complex %s\n",filename);
    return cmp;
  }

  if (strlen(filename)<=strlen(filename_template)) {
    printf("knot_helpers_delete_file: filename is too short %s\n",filename);
    return -1;
  }
  // sanity check that the prefix is as expected
  for (i=0;i<strlen(filename_template);i++) {
    if (filename_template[i]!=filename[i]) {
      printf("knot_helpers_delete_file: filename does not match prefix %s\n",filename);
      return -1;
    }
  }

  printf("unlink(%s)\n",filename);
  //ret=unlink(filename);
  if (filename!=NULL) {
    free(filename);
    filename=NULL;
  }
  return ret;
}


// function called from server to start backround thread for regular tasks
dm_tofu_thread_t *dm_tofu_bg_start(int thread_num) {

  dm_tofu_thread_t *ptr;
  ptr=(dm_tofu_thread_t *)malloc(sizeof(dm_tofu_thread_t));
  memset(ptr,'\0',sizeof(dm_tofu_thread_t));
  MYSQL *db;

  db=db_init();
  db_connect(db,DB_SERVER, DB_USER, DB_PASSWORD, DB_DATABASE);

  ptr->run=1;
  ptr->last_exec=0;
  ptr->last_awake=0;
  ptr->last_time_slot=0;
  ptr->db=db;
  ptr->thread_num=thread_num; // not used
  pthread_create(&(ptr->thread_id), NULL, dm_tofu_bg_exec, ptr);
  return ptr;
} 
  
// function called from server to execute backround thread for regular tasks
void *dm_tofu_bg_exec(void *arguments) { // a single storage element with vars for this thread
  dm_tofu_thread_t *ptr;
  ptr =(dm_tofu_thread_t *)arguments;
  int *ret=NULL;
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
      // do DM batch work
      dm_tofu_dm_batch(ptr->db);
      // do NS batch work
      dm_tofu_ns_batch(ptr->db);
      ptr->last_exec=now;
      ptr->last_time_slot=start_time_slot;
      printf("next awake at %li\n",ptr->last_time_slot+DM_TOFU_SLOT_LENGTH);
    }
  }
  return (void*)ret; // keep pthread and the compiler happy
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
  if (ptr->db !=NULL) {
    db_close(ptr->db);
    ptr->db=NULL;
  }
  free(ptr);
  ptr=NULL;
  return 0;
}
