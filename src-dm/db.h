#ifndef DM_DB
#define DM_DB

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

#include <mysql/mysql.h>

#define DB_SERVER "localhost"
#define DB_USER "knot"
#define DB_PASSWORD "Kn0tpassword!"
#define DB_DATABASE "dm"

/* fatal error */
void fatal_db_error(MYSQL *con);

/* db init */
MYSQL *db_init();

/* Connect to database */
void db_connect(MYSQL *con, char *db_server, char *db_user, char *db_password, char *db_database);

/* close */
void db_close(MYSQL *con);

#endif //DM_DB
