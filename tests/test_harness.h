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
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <mysql/mysql.h>

#define TESTDB_SERVER "localhost"
#define TESTDB_USER "knottest"
#define TESTDB_PASSWORD "Kn0ttestpassword!"
#define TESTDB_DATABASE "test"

#define MYSQL_BIN  "/usr/bin/mysql"
//#define MYSQL_BIN  "/usr/bin/echo"


int reset_testdb (char *filename);

void testdb_close(MYSQL *con) ;

void fatal_testdb_error(MYSQL *con);

MYSQL *testdb_init() ;

/* Connect to the database */
void testdb_connect(MYSQL *con, char *db_server, char *db_user, char *db_password, char *db_database) ;


// compare 2 arrays. 0 = identical
int cmp_array(char *a, char *b, size_t len) ;

#endif
