#ifndef CLI_OPT_INCLUDED
#define CLI_OPT_INCLUDED
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
typedef struct {
    int domain_only;
    int a;
    int b;
} CLI_OPT;

#endif

int get_cli_opt(int argc, char **argv, CLI_OPT* cli_opt);
