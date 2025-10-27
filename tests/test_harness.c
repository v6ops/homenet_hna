/**
 *  common functions for testing
 *
 *  Copyright (c) 2025 Ray Hunter
 */


#include "test_harness.h"

// take the sha256b hash of a file given the file name
int f_sha256(unsigned char* dest, char* filename){
  FILE* file;
  int read;
  int BUFFER_LENGTH = 1024;
  char buffer[BUFFER_LENGTH];
  EVP_MD_CTX *mdctx;
  const EVP_MD *md;
  unsigned int length;
  file = fopen(filename, "r");
  if(file <= 0){
    printf("%s\n", filename);
    perror("No file");
    return -1;
  }
  mdctx = EVP_MD_CTX_create();
  length = 0;
  OpenSSL_add_all_digests();
  md = EVP_get_digestbyname("sha256");
  EVP_DigestInit_ex(mdctx, md, NULL);
  while((read = fread((void*)buffer, 1, BUFFER_LENGTH, file)) != 0){
    EVP_DigestUpdate(mdctx, buffer, read);
    length += read;
    if(read < BUFFER_LENGTH){
      break;
    }
  }
  EVP_DigestFinal_ex(mdctx, dest, &length);
  EVP_MD_CTX_destroy(mdctx);
  EVP_cleanup();
  return 0;
}


// set db to known state
int set_testdb (char *filename) {
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

// get test db to file
int get_testdb (char *filename) {
pid_t  pid;
   int status;
   int fd;
   char fn[80];
   memset(fn,'\0',80);

   if ((filename !=NULL) && (strlen(filename)>0 && (strlen(filename)<80))) {
     strcpy(fn,filename);
   } else {
     strcpy(fn,"./testdata/get_testdb.sql");
   }

   printf("getting testdb\n");

   pid = fork();
   if (pid == -1){
      printf("can't fork, error occured\n");
      exit(EXIT_FAILURE);
   }
   else if (pid == 0){

      // mysqldump -u root -p --result-file=./testdata/get_testdb.sql --no-create-info --no-create-db --compact test infra zone rr parent
      // compact sets the following
      // --skip-add-drop-table
      // --skip-add-locks
      // --skip-comments
      // --skip-disable-keys
      // --skip-set-charset
      
      char passwd_opt[60];
      memset(passwd_opt,'\0',60);
      strcat(passwd_opt,"--password=");
      strcat(passwd_opt,TESTDB_PASSWORD);

      char user_opt[60];
      memset(user_opt,'\0',60);
      strcat(user_opt,"-u");
      //strcat(user_opt,TESTDB_PASSWORD);
      
      char output_opt[100];
      memset(output_opt,'\0',100);
      strcat(output_opt,"--result-file="); // dump to file
      strcat(output_opt,filename);

      char nocreate1_opt[20];
      memset(nocreate1_opt,'\0',20);
      strcat(nocreate1_opt,"--no-create-info"); // skip the table creates

      char nocreate2_opt[20];
      memset(nocreate2_opt,'\0',20);
      strcat(nocreate2_opt,"--no-create-db"); // skip the db create

      char compact_opt[10];
      memset(compact_opt,'\0',10);
      strcat(compact_opt,"--compact"); // skip table locking, comments etc.

      char db_opt[10];
      memset(db_opt,'\0',10);
      strcat(db_opt,"test"); // dump only the test db

      char t1_opt[10];
      memset(t1_opt,'\0',10);
      strcat(t1_opt,"infra"); // dump the infra table

      char t2_opt[10];
      memset(t2_opt,'\0',10);
      strcat(t2_opt,"zone"); // dump the zone table

      char t3_opt[10];
      memset(t3_opt,'\0',10);
      strcat(t3_opt,"rr"); // dump the rr table

      char t4_opt[10];
      memset(t4_opt,'\0',10);
      strcat(t4_opt,"parent"); // dump the parent table

      char *argv_list[14] = {NULL};
      argv_list[0] = MYSQLDUMP_BIN;
      argv_list[1] = user_opt;
      argv_list[2] = TESTDB_USER;
      argv_list[3] = passwd_opt;
      argv_list[4] = output_opt;
      argv_list[5] = nocreate1_opt;
      argv_list[6] = nocreate2_opt;
      argv_list[7] = compact_opt;
      argv_list[8] = db_opt;
      argv_list[9] = t1_opt;
      argv_list[10] = t2_opt;
      argv_list[11] = t3_opt;
      argv_list[12] = t4_opt;
      argv_list[13] = NULL;

      execv(MYSQLDUMP_BIN,argv_list);
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


// exec a bash script
int exec_bash (char *filename) {
pid_t  pid;
   int status;
   int fd;
   char fn[80];
   memset(fn,'\0',80);

   if ((filename !=NULL) && (strlen(filename)>0 && (strlen(filename)<80))) {
     strcpy(fn,filename);
   } else {
     strcpy(fn,"./testdata/reset_knot.bash");
   }

   printf("Exec bash script %s\n",fn);

   pid = fork();
   if (pid == -1){
      printf("can't fork, error occured\n");
      exit(EXIT_FAILURE);
   }
   else if (pid == 0){

      char *argv_list[3] = {NULL};
      argv_list[0] = BASH_BIN;
      argv_list[1] = fn;
      argv_list[2] = NULL;

      execv(BASH_BIN,argv_list);
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
void testdb_connect(MYSQL *con) {
  if (!mysql_real_connect(con,TESTDB_SERVER,TESTDB_USER,TESTDB_PASSWORD,TESTDB_DATABASE, 0, NULL, 0))
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

// compare 2 files via hashing. 0 = identical
int cmp_file(char *fn_a, char *fn_b) {
 unsigned char a[SHA256_LENGTH]={'\0'};
 unsigned char b[SHA256_LENGTH]={'\0'};
 int i;
 f_sha256(a,fn_a);
 /*
 printf("a: ");
 for (i=0;i<SHA256_LENGTH;i++) {
   printf("%02x ",(unsigned int)a[i]);
 }
 printf("\nb: ");
 */
 f_sha256(b,fn_b);
 /*for (i=0;i<SHA256_LENGTH;i++) {
   printf("%02x ",(unsigned int)b[i]);
 }
printf ("\n");
*/
 return cmp_array(a,b,SHA256_LENGTH);
}
