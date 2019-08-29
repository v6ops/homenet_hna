/* homenet_hna knot_helpers

* Copyright (c) 2019 Ray Hunter

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
#include "knot_helpers.h"



int fork_make_knot_config(const char *zone, const char *dm_notify, const char *dm_acl) {
pid_t  pid; 
   int status; 
   fprintf(stderr,"knot_helpers_make_knot_config %s %s %s\n",zone,dm_notify,dm_acl);
   pid = fork(); 
   if (pid == -1){ 
      printf("can't fork, error occured\n"); 
      exit(EXIT_FAILURE); 
   } 
   else if (pid == 0){ 
      printf("child process, pid = %u\n",getpid()); 
  
      static const char* argv_list[] = {MAKE_KNOT_CONFIG,zone,dm_notify,dm_acl,NULL}; 
  
      execv(MAKE_KNOT_CONFIG,const_cast<char **>(argv_list)); 
      exit(0); 
   } 
   else{ 
      printf("parent process, pid = %u\n",getppid()); 
        if (waitpid(pid, &status, 0) > 0) { 
            if (WIFEXITED(status) && !WEXITSTATUS(status)) {
              printf("program execution successful\n"); 
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
      exit(0); 
   } 
} 


int fork_make_knot_ds(const char *zone,const char *ds_filename) {
pid_t  pid; 
   int status; 
   fprintf(stderr,"knot_helpers_make_knot_ds %s\n",zone);

   pid = fork(); 
   if (pid == -1){ 
      printf("can't fork, error occured\n"); 
      exit(EXIT_FAILURE); 
   } 
   else if (pid == 0){ 
      printf("child process, pid = %u\n",getpid()); 
  
      static const char* argv_list[] = {MAKE_KNOT_DS,zone,ds_filename,NULL}; 
  
      execv(MAKE_KNOT_DS,const_cast<char **>(argv_list)); 
      exit(0); 
   } 
   else{ 
      printf("parent process, pid = %u\n",getppid()); 
        if (waitpid(pid, &status, 0) > 0) { 
            if (WIFEXITED(status) && !WEXITSTATUS(status)) {
              printf("program execution successful\n"); 
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
      exit(0); 
   } 
} 

// take a text DS RR and place in the DM comfig
int fork_make_knot_dm_ds(const char *ds_rr) {
pid_t  pid; 
   int status; 
   fprintf(stderr,"knot_helpers_make_knot_dm_ds %s\n",ds_rr);

   pid = fork(); 
   if (pid == -1){ 
      printf("can't fork, error occured\n"); 
      exit(EXIT_FAILURE); 
   } 
   else if (pid == 0){ 
      printf("child process, pid = %u\n",getpid()); 
  
      static const char* argv_list[] = {MAKE_KNOT_DM_DS,ds_rr,NULL}; 
  
      execv(MAKE_KNOT_DM_DS,const_cast<char **>(argv_list)); 
      exit(0); 
   } 
   else{ 
      printf("parent process, pid = %u\n",getppid()); 
        if (waitpid(pid, &status, 0) > 0) { 
            if (WIFEXITED(status) && !WEXITSTATUS(status)) {
              printf("program execution successful\n"); 
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
      exit(0); 
   } 
} 

int fork_make_knot_dm_config(const char *zone, const char *dm_remote) {
pid_t  pid; 
   int status; 
   fprintf(stderr,"knot_helpers_make_dm_knot_config %s %s\n",zone,dm_remote);
   pid = fork(); 
   if (pid == -1){ 
      printf("can't fork, error occured\n"); 
      exit(EXIT_FAILURE); 
   } 
   else if (pid == 0){ 
      printf("child process, pid = %u\n",getpid()); 
  
      static const char* argv_list[] = {MAKE_KNOT_DM_CONFIG,zone,dm_remote,NULL}; 
  
      execv(MAKE_KNOT_DM_CONFIG,const_cast<char **>(argv_list)); 
      exit(0); 
   } 
   else{ 
      printf("parent process, pid = %u\n",getppid()); 
        if (waitpid(pid, &status, 0) > 0) { 
            if (WIFEXITED(status) && !WEXITSTATUS(status)) {
              printf("program execution successful\n"); 
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
      exit(0); 
   } 
} 


