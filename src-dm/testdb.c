/* simple routines to test the db */
#include "db.h"

/**
 *  Main function for demonstrating the db server.
 */
int main(int argc, char *argv[]) {
  MYSQL *con;

  con=db_init();
  db_connect(con,DB_SERVER, DB_USER, DB_PASSWORD, DB_DATABASE);
  db_close(con);

}

