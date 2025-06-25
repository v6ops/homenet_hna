/** Routines to shim between the DM and a MySQL DB
 *
 * We may want to change to another DB in the future so use neutral names
 *
 *     (c) Ray Hunter <v6ops@globis.net> June 2024
 * 
 */
#include "db.h"

void db_close(MYSQL *con) {
  mysql_close(con);
}

void fatal_db_error(MYSQL *con)
{
  fprintf(stderr, "DM: Fatal DB error %s\n", mysql_error(con));
  db_close(con);
  exit(1);        
}

/* init database */
MYSQL *db_init() {
  MYSQL *con;
  con = mysql_init(NULL);
  if (con == NULL) {
    fprintf(stderr, "%s\n", mysql_error(con));
    exit(1);
  }
  return con;
}

/* Connect to the database */
void db_connect(MYSQL *con, char *db_server, char *db_user, char *db_password, char *db_database) {
  if (!mysql_real_connect(con, db_server, db_user, db_password, db_database, 0, NULL, 0))
    fatal_db_error(con);
}

