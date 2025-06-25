#include "./get_cli_opt.h"

int get_cli_opt(int argc, char **argv, CLI_OPT* cli_opt){

//defaults
cli_opt->domain_only=0;

int opt;
int error_code=0;

    while (1)
    {
      if (error_code!=0) // we've hit an error (e.g. unexpected option)
	   break;

      int option_index = 0;
      static struct option long_options[] =
        {
          {"domain-only",  no_argument,  0, 'D'},
          {"add",     no_argument,       0, 'a'},
          {"append",  no_argument,       0, 'b'},
          {"create",  required_argument, 0, 'c'},
          {"delete",  required_argument, 0, 'd'},
          {"file",    required_argument, 0, 'f'},
          {0, 0, 0, 0}
        };

      opt = getopt_long(argc, argv, "Dabc:d:f:", long_options, &option_index);
      if (opt == -1) // last option, return
	    break;
      switch (opt)
      {
        case 'D':
          printf ("option -D\n");
	  cli_opt->domain_only=1;

          break;

        case 'a':
          puts ("option -a\n");
          break;

        case 'b':
          puts ("option -b\n");
          break;

        case 'c':
          printf ("option -c with value `%s'\n", optarg);
          break;

        case 'd':
          printf ("option -d with value `%s'\n", optarg);
          break;

        case 'f':
          printf ("option -f with value `%s'\n", optarg);
          break;

        default:  /* '?' */
          // fprintf(stderr, "Usage: %s [-t nsecs] [-n] name\n", argv[0]);
	  error_code=1;
          break;
      }
    }


return error_code;
}
