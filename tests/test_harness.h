/**
 *  common functions for testing
 *
 *  Copyright (c) 2025 Ray Hunter
 */

#ifndef TEST_HARNESS
#define TEST_HARNESS

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

#include <mysql/mysql.h>

#define TESTDB_SERVER "localhost"
#define TESTDB_USER "knottest"
#define TESTDB_PASSWORD "Kn0ttestpassword!"
#define TESTDB_DATABASE "test"


void testdb_close(MYSQL *con) {
  mysql_close(con);
}

void fatal_testdb_error(MYSQL *con)
{
  fprintf(stderr, "DM: Fatal DB error %s\n", mysql_error(con));
  db_close(con);
  exit(1);
}

/* init database */
MYSQL *testdb_init() {
  MYSQL *con;
  con = mysql_init(NULL);
  if (con == NULL) {
    fprintf(stderr, "%s\n", mysql_error(con));
    exit(1);
  }
  return con;
}

/* Connect to the database */
void testdb_connect(MYSQL *con, char *db_server, char *db_user, char *db_password, char *db_database) {
  if (!mysql_real_connect(con, db_server, db_user, db_password, db_database, 0, NULL, 0))
    fatal_testdb_error(con);
}


// compare 2 arrays. 0 = identical
int cmp_array(char *a, char *b, size_t len) {
  int ret=0;
  int i;
  for (i=0;i<len;i++) {
    if (a[i]!=b[i]) {
     ret++;
    }
  }
  return ret;
}

#endif
