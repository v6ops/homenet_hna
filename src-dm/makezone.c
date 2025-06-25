/*
 * functions to make a preprovisioned zone name
 * (C) Ray.Hunter@globis.net net June 2024
 */
#include "makezone.h"

// Convert an ascii encoded hex string to decimal
// Each char is 4 bits
// limited to 32 bits (8 hex chars)
uint32_t hexstr2dec(unsigned char *hex, int len) {
  uint32_t dec = 0;
  int i = 0;
  int todo=len;
  if (todo>8) { // only take the first 8 chars
    todo=8;
  }
  while (i<todo) {
    // get current char then increment
    char byte = hex[i]; 
    i++;
    // transform hex char to the 4 bit decimal, using ascii codes
    if (byte >= '0' && byte <= '9') byte = byte - '0';
    else if (byte >= 'a' && byte <='f') byte = byte - 'a' + 10;
    else if (byte >= 'A' && byte <='F') byte = byte - 'A' + 10;    
    // shift 4 bits for next char, and add the 4 bits of the new char 
    dec = (dec << 4) | (byte & 0xF);
  }
  return dec;
}

// take a string buffer and return the sha256 message digest
// md must be SHA256_DIGEST_LENGTH (32) char long
void do_sha256(char *buf, size_t buf_len, unsigned char *md) {
  SHA256_CTX ctx;
  size_t len;
  size_t todo;
  todo=buf_len;
  size_t pos;
  pos=0;
  len=0;
  // initialise the sha256 context
  SHA256_Init(&ctx);
  // add chunks of data
  do {
    if (todo >= BUFSIZ) {
      len=BUFSIZ;
    } else {
      len=todo;
    }
    SHA256_Update(&ctx, buf+pos, len);
    pos+=len;
    todo-=len;
  } while (pos < buf_len);
  // place the result in buffer
  SHA256_Final(md, &ctx);
  // output the result
  for (len = 0; len < SHA256_DIGEST_LENGTH; ++len)
    printf("%02x", md[len]);
  putchar('\n');
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
  return i;
}

// create an invariant opaque pass phrase zone name like dog.cat.zoo.here
// remember to free once used
char *make_zone_name (unsigned long seed, int nwords) {

  if (nwords>16) { nwords=16; } // md is 32 chars with 2 chars per word

  // create sufficient storage for zone name, including dots and null.
  // assumes each word max 7 chars plus \0
  char *zn=calloc(nwords*8,sizeof(char));
  if (zn == NULL) {
    printf("make_zone_name: Cannot allocate memory\n");
    exit(-1);
  }

  size_t pos=0; // position in the output
  unsigned char md[32]={'\0'}; // message digest
  int d;        // temp decimal
  char buf[21]; // unsigned long is max 21 chars (inc \0)
  snprintf(buf, 21, "%li", seed); // is null terminated

  // create a message digest.
  // Does not have to be crypto secure but this yields
  // hard to guess zone names if people are abusive,
  // provided the seed is good.
  do_sha256(buf,strlen(buf),md);

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
  return zn;
}

// return the current time slot
uint64_t get_time_slot(){
  uint64_t slot;
  slot=(uint64_t)time(NULL); // local time since 1970
  slot=slot/60*60;           // time slot ot the nearest minute
  return slot;
}

 
// Create nzones zones under parent in the db.
// There can be collisions with existing names because the hash is truncated.
// A "unique" constraint on `name` will force this insert to fail gracefully.
void create_zone_names(char *parent, int nzones){
  MYSQL *db;
  char *zn;
  char buf[MYSQL_STRLEN]; // length database name field
  memset(buf,'\0',sizeof(buf));
  uint64_t slot;
  MYSQL_STMT *stmt;
  MYSQL_BIND bind[3];
  memset(bind, 0, sizeof(bind));
  size_t len1,len2;

  slot=get_time_slot();
  printf("Creating zones at slot %lu\n",slot);

  db=db_init(); 
  db_connect(db, DB_SERVER, DB_USER, DB_PASSWORD, DB_DATABASE);

  stmt=mysql_stmt_init(db);
  char *stmt_str="INSERT INTO zone (name,parent,created) VALUES (?,?,?);";
  mysql_stmt_prepare(stmt, stmt_str, strlen(stmt_str));

  int i=0;
  int collisions=0; // track failed inserts (asssum due to name collissions)
  while(i<nzones) {
    i++;
    zn=make_zone_name(slot+i+OFFSET,4);
    snprintf(buf,MYSQL_STRLEN,"%s.%s",zn,parent); // concat with max MYSQL_STRLEN char
    free(zn);

    bind[0].buffer_type= MYSQL_TYPE_STRING;
    bind[0].buffer= (char *)buf;
    bind[0].buffer_length= MYSQL_STRLEN;
    bind[0].is_null= 0;
    len1=strlen(buf);
    bind[0].length= &len1;

    bind[1].buffer_type= MYSQL_TYPE_STRING;
    bind[1].buffer= (char *)parent;
    bind[1].buffer_length= MYSQL_STRLEN;
    bind[1].is_null= 0;
    len2=strlen(parent);
    bind[1].length= &len2;
    
    bind[2].buffer_type= MYSQL_TYPE_LONGLONG;
    bind[2].buffer= (char *)&slot;
    bind[2].is_null= 0;
    bind[2].length= 0;

    mysql_stmt_bind_param(stmt, bind);
    if (mysql_stmt_execute(stmt)) {
      fprintf(stderr, " mysql_stmt_execute(), 1 failed\n");
      fprintf(stderr, " %s\n", mysql_stmt_error(stmt));
      exit(0);
    }
    uint64_t affected_rows;
    affected_rows= mysql_stmt_affected_rows(stmt);

    if (affected_rows != 1) { /* expect 1  affected row per insert*/
      collisions++;
      if (collisions >100) {
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

// Assign 1 zone name under parent in the db
// Uses Innodb atomic transaction to ensure uniqueness.
// Blank zone for failure (no more slots)
// The zone is then "locked" to the HNA via IP address
char* assign_zone_name(char *parent, char *ipv4, char *ipv6){
  MYSQL *db;
  int ret;
  char name[MYSQL_STRLEN];
  char buf[MYSQL_STRLEN]; // length database name field
  memset(buf,'\0',sizeof(buf));
  uint64_t start_slot,end_slot;
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

  start_slot=get_time_slot();
  end_slot=start_slot+60;
  printf("Assigning zones at slot %lu\n",start_slot);

  db=db_init(); 
  db_connect(db, DB_SERVER, DB_USER, DB_PASSWORD, DB_DATABASE);

  stmt=mysql_stmt_init(db);
  // start a transaction
  if (mysql_query(db,"BEGIN")) {
    printf ("make_zone: Error. Can't start transaction\n");
    return NULL;
  }
  result=mysql_use_result(db);
  mysql_free_result(result);

  // Check if there's already a reservation from this IPv4 or IPv6
  // that is awaiting delegation. If there is repeat the reply.
  // This to prevent resource exhaustion from a single HNA.
  // This will lock for other threads until the transaction commits
  printf("Check for existing reservation.\n");
  char *stmt_str="SELECT A.zone_id, A.name FROM zone AS A,infra AS B WHERE A.assigned > 0 AND A.created >0 AND A.parent =? AND A.delegated =0 AND B.infra_id = A.hna AND ((LENGTH(B.ipv4)>0 AND B.ipv4 = ?) OR (LENGTH(B.ipv6)>0 AND B.ipv6 = ?)) FOR UPDATE";

  if (mysql_stmt_prepare(stmt, stmt_str, strlen(stmt_str))) {
    printf ("make_zone: prepare failed. %s\n",mysql_error(db));
  }

  bind[0].buffer_type= MYSQL_TYPE_STRING;
  bind[0].buffer= (char *)parent;
  bind[0].buffer_length= MYSQL_STRLEN;
  bind[0].is_null= 0;
  len1=strlen(parent);
  bind[0].length= &len1;

  bind[1].buffer_type= MYSQL_TYPE_STRING;
  bind[1].buffer= (char *)ipv4;
  bind[1].buffer_length= 15;
  bind[1].is_null= 0;
  len2=strlen(ipv4);
  bind[1].length= &len2;

  bind[2].buffer_type= MYSQL_TYPE_STRING;
  bind[2].buffer= (char *)ipv6;
  bind[2].buffer_length= 39;
  bind[2].is_null= 0;
  len3=strlen(ipv6);
  bind[2].length= &len3;

  if (mysql_stmt_bind_param(stmt, bind) ) {
    printf ("make_zone: bind failed. %s\n",mysql_error(db));
  }
  if (mysql_stmt_execute(stmt) ) {
    printf ("make_zone: exec failed. %s\n",mysql_error(db));
  }

  /* INTEGER COLUMN zone_id */
  bindout[0].buffer_type= MYSQL_TYPE_LONG;
  bindout[0].buffer= (char *)&zone_id;
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

  // While rows to read.
  rc=0;  // row count
  while (1) {
    status = mysql_stmt_fetch(stmt);
    if (status == MYSQL_NO_DATA && rc==0) {
      printf ("make_zone: normal. No existing name. Continuing\n");
      break; 
    } else if (status == MYSQL_NO_DATA && rc>0) {
      break; // Last line. Normal end of read after match.
    } else if (status == 1 ) {
      printf ("make_zone: Error. Can't check current status for request from %s %s %s\n",ipv4,ipv6,mysql_error(db));
    mysql_rollback(db);
    return NULL;
    } 
    // We have a match on existing request.
    // Could break here on 1st match.
    rc++;
    printf("rc %i name %.*s id %i\n",rc,(int)length[1],name,zone_id);
  }

  if (rc>0) { // repeat the last response
    printf("Existing reservation found rc %i name %.*s id %i\n",rc,(int)length[1],name,zone_id);
    mysql_rollback(db);
    return "OK";
  }

  // reserve one row that has not been assigned
  // and is in the current time slot
  // and parent matches.
  // This will lock for other threads until the transaction commits
  printf("Reserve zone\n");
  stmt_str="SELECT zone_id, name FROM zone WHERE assigned = 0 AND parent =? AND created >=? AND created <? LIMIT 1 FOR UPDATE";

  mysql_stmt_prepare(stmt, stmt_str, strlen(stmt_str));
  if(stmt == NULL) {
    printf ("make_zone: prepare failed. %s\n",mysql_error(db));
    mysql_rollback(db);
    return NULL;
  }

  bind[0].buffer_type= MYSQL_TYPE_STRING;
  bind[0].buffer= (char *)parent;
  bind[0].buffer_length= MYSQL_STRLEN;
  bind[0].is_null= 0;
  len1=strlen(parent);
  bind[0].length= &len1;

  bind[1].buffer_type= MYSQL_TYPE_LONGLONG;
  bind[1].buffer= (char *)&start_slot;
  bind[1].is_null= 0;
  bind[1].length= 0;

  bind[2].buffer_type= MYSQL_TYPE_LONGLONG;
  bind[2].buffer= (char *)&end_slot;
  bind[2].is_null= 0;
  bind[2].length= 0;

  mysql_stmt_bind_param(stmt, bind);
  mysql_stmt_execute(stmt);

  // re-use bindout
  memset(bindout, 0, sizeof(bindout));

  /* INTEGER COLUMN zone_id */
  bindout[0].buffer_type= MYSQL_TYPE_LONG;
  bindout[0].buffer= (char *)&zone_id;
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
      printf ("make_zone: Error. Can't reserve a zone name %s\n",mysql_error(db));
      mysql_rollback(db);
      return NULL;
    } else if (status == MYSQL_NO_DATA) {
      break; // last line. normal end of read
    }
    rc++;
    printf("rc %i name %.*s id %i\n",rc,(int)length[1],name,zone_id);
  }
  mysql_stmt_free_result(stmt);

  // create an HNA entry in infra
  printf("Create HNA\n");
  stmt=mysql_stmt_init(db);
  stmt_str="INSERT INTO infra (name,created,assigned,ipv4,ipv6,function) VALUES (?,?,?,?,?,'hna')";
  mysql_stmt_prepare(stmt, stmt_str, strlen(stmt_str));
  memset(buf,'\0',sizeof(buf));
  snprintf(buf,MYSQL_STRLEN,"%s%s","hna-",name); // concat with max MYSQL_STRLEN char

  MYSQL_BIND bind_infra[5];
  memset(bind_infra, 0, sizeof(bind_infra));
  printf("Error %s\n",mysql_error(db));

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

  bind_infra[4].buffer_type= MYSQL_TYPE_STRING;
  bind_infra[4].buffer= (char *)ipv6;
  bind_infra[4].buffer_length= 39;
  bind_infra[4].is_null= 0;
  len3=strlen(ipv6);
  bind_infra[4].length= &len3;

  mysql_stmt_bind_param(stmt, bind_infra);
  mysql_stmt_execute(stmt);
  mysql_stmt_free_result(stmt);

  // get the newly created HNA entry infra_id back
  printf("Get HNA\n");
  stmt=mysql_stmt_init(db);
  stmt_str="SELECT infra_id, name FROM infra WHERE name =? AND created =? AND assigned =? ORDER BY infra_id DESC LIMIT 1";

  mysql_stmt_prepare(stmt, stmt_str, strlen(stmt_str));
  printf("Error prepare %s\n",mysql_error(db));
  // similar to previous so re-use bind
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

  bind[2].buffer_type= MYSQL_TYPE_LONGLONG;
  bind[2].buffer= (char *)&start_slot;
  bind[2].is_null= 0;
  bind[2].length= 0;

  mysql_stmt_bind_param(stmt, bind);
  mysql_stmt_execute(stmt);

  // similar to previous so re-use bindout
  /* INTEGER COLUMN infra_id */
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
  mysql_stmt_free_result(stmt);

  // update the reservation
  printf("UPDATE zone\n");
  stmt=mysql_stmt_init(db);
  stmt_str="UPDATE zone SET hna=? , assigned=? WHERE zone_id =?";
  printf("UPDATE zone SET hna=%i,assigned= %li WHERE zone_id=%i\n",infra_id,start_slot,zone_id);

  mysql_stmt_prepare(stmt, stmt_str, strlen(stmt_str));
  printf("Error prepare %s\n",mysql_error(db));
  // similar to previous so re-use bind
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

  mysql_stmt_bind_param(stmt, bind);
  printf("Error bind %s\n",mysql_error(db));
  mysql_stmt_execute(stmt);
  printf("Error exec %s\n",mysql_error(db));
  mysql_stmt_free_result(stmt);
  printf("Error free %s\n",mysql_error(db));

  // commit the transaction
  mysql_commit(db);

  db_close(db);
  return "OK";
/*


  char *stmt_str="INSERT INTO zone (name,parent,created) VALUES (?,?,?);";
  mysql_stmt_prepare(stmt, stmt_str, strlen(stmt_str));

  int i=0;
  while(i<nzones) {
    i++;
    zn=make_zone_name(slot+i+OFFSET,4);
    snprintf(buf,MYSQL_STRLEN,"%s.%s",zn,parent); // concat with max MYSQL_STRLEN char
    free(zn);

    bind[0].buffer_type= MYSQL_TYPE_STRING;
    bind[0].buffer= (char *)buf;
    bind[0].buffer_length= MYSQL_STRLEN;
    bind[0].is_null= 0;
    len1=strlen(buf);
    bind[0].length= &len1;

    bind[1].buffer_type= MYSQL_TYPE_STRING;
    bind[1].buffer= (char *)parent;
    bind[1].buffer_length= MYSQL_STRLEN;
    bind[1].is_null= 0;
    len2=strlen(parent);
    bind[1].length= &len2;
    
    bind[2].buffer_type= MYSQL_TYPE_LONGLONG;
    bind[2].buffer= (char *)&slot;
    bind[2].is_null= 0;
    bind[2].length= 0;

    mysql_stmt_bind_param(stmt, bind);
    mysql_stmt_execute(stmt);
  }
  db_close(db);
  */
}




int main (void) {
  unsigned char buf[SHA256_DIGEST_LENGTH]; // the output
  unsigned char *buffer;
  buffer=(unsigned char *)&buf;
  printf("Starting\n");
  printf("following test vectors have been checked against\n");
  printf("https://emn178.github.io/online-tools/sha256.html\n");
  do_sha256("a",1,buffer);
  printf("ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb\n");
  do_sha256("abcdefghijklm",13,buffer);
  printf("ff10304f1af23606ede1e2d8abcdc94c229047a61458d809d8bbd53ede1f6598\n");
  do_sha256("0123456789",10,buffer);
  printf("84d89877f0d4041efb6bf91a16f0248f2fd573e6af05c19f96bedb9f882f7882\n");
  do_sha256("0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789",130,buffer);
  printf("426f26da928927a3520b61ade620dc7c69ed4d315425929fa04d9a993a22a0f3\n");
  do_sha256("0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789abcdefghijklmnopqrstuvwxyz",156,buffer);
  printf("0275e32522a6de59f7e8df16c53b2d39dbf940c5e07940f4ad4c5e9406d4a8f3\n");
  // output the result
  int len;
  for (len = 0; len < SHA256_DIGEST_LENGTH; ++len)
  printf("%02x", buf[len]);
  putchar('\n');
  printf("1234 %i\n",hexstr2dec("1234",4));
  printf("0000 %i\n",hexstr2dec("0000",4));
  printf("0100 %i\n",hexstr2dec("0100",4));
  printf("00fE %i\n",hexstr2dec("00fE",4));
  printf("00fE %i\n",hexstr2dec("00fE",3));
  size_t l;
  int i;
  for (i=0;i<1024;i++) {
  char buffer[8]="";
  l=dec2word(i,buffer);
  //printf("ret %li %s\n",l,buffer);
  }
  char *zn;
  zn=make_zone_name(0,4);
  printf("zn %s\n",zn);
  printf("start db\n");
  create_zone_names("homenetdns.com",10);
  assign_zone_name("homenetdns.com","1.2.3.9","2001:abcd::1");
  assign_zone_name("homenetdns.com","1.2.3.9","2001:abcd::1");
  assign_zone_name("homenetdns.com","1.2.3.9","2001:abcd::2");
  assign_zone_name("homenetdns.com","1.2.3.8","2001:abcd::2");
  assign_zone_name("homenetdns.com","","2001:abcd::3");
  assign_zone_name("homenetdns.com","","2001:abcd::3");
  assign_zone_name("homenetdns.com","","2001:abcd::4");
  assign_zone_name("homenetdns.com","1.2.3.10","");
  assign_zone_name("homenetdns.com","1.2.3.11","");
  printf("end db\n");
  exit(0);

}
