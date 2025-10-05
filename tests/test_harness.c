/**
 *  common functions for testing
 *
 *  Copyright (c) 2025 Ray Hunter
 */


#include "test_harness.h"


int reset_testdb (char *filename) {
pid_t  pid;
   int status;
   int fd;
   char fn[80];
   memset(fn,'\0',80);

   if ((filename !=NULL) && (strlen(filename)>0)) {
     strcpy(fn,filename);
   } else {
     strcpy(fn,"./testdata/reset_testdb.sql");
   }


    printf("resetting testdb\n");
    fd = open(fn, O_RDONLY);
    if (fd < 0) {
        perror("open");
        return EXIT_FAILURE;
    }

   pid = fork();
   if (pid == -1){
      printf("can't fork, error occured\n");
      exit(EXIT_FAILURE);
   }
   else if (pid == 0){

      // point the sql to stdin
      printf("exec mysql\n");
      dup2(fd, STDIN_FILENO);
      close(fd);

      char passwd_opt[60];
      memset(passwd_opt,'\0',60);
      strcat(passwd_opt,"--password=");
      strcat(passwd_opt,TESTDB_PASSWORD);

      char user_opt[60];
      memset(user_opt,'\0',60);
      strcat(user_opt,"-u");
      //strcat(user_opt,TESTDB_PASSWORD);

      char *argv_list[5] = {NULL};
      argv_list[0] = MYSQL_BIN;
      argv_list[1] = user_opt;
      argv_list[2] = TESTDB_USER;
      argv_list[3] = passwd_opt;
      argv_list[4] = NULL;

      execv(MYSQL_BIN,argv_list);
      exit(0);
   }
   else {
        if (waitpid(pid, &status, 0) > 0) {
            if (WIFEXITED(status) && !WEXITSTATUS(status)) {
              // printf("program execution successful\n");
	      return 0;
	    } else if (WIFEXITED(status) && WEXITSTATUS(status)) {
                if (WEXITSTATUS(status) == 127) {
                    // execv failed
                     printf("execv failed\n");
                } else {
                     printf("program terminated normally,"
                       " but returned a non-zero status\n");
		}
            } else
                printf("program didn't terminate normally\n");
        }  else {
           // waitpid() failed
            printf("waitpid() failed\n");
        }
      printf("fork returned\n");
      exit(0);
   }
}



void testdb_close(MYSQL *con) {
  mysql_close(con);
}

void fatal_testdb_error(MYSQL *con)
{
  fprintf(stderr, "DM: Fatal DB error %s\n", mysql_error(con));
  testdb_close(con);
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

