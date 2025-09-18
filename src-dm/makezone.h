#ifndef MAKE_ZONE_INCLUDED
#define MAKE_ZONE_INCLUDED

#include <openssl/sha.h>
#include <openssl/evp.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
// dictionary of words to use as tokens
#include "dict.h"
#include "db.h"
#define MYSQL_STRLEN 80

#define OFFSET 1890284230853075345
// A large random int used to make zone names harder to guess.
// Change this if you want. There's no dependency.

uint32_t hexstr2dec(unsigned char *hex, int len) ;
void do_sha256(char *buf, size_t buf_len, unsigned char *md) ;
size_t dec2word(int dec, char *buf) ;
char *make_zone_name (unsigned long seed, int nwords) ;
#endif // MAKE_ZONE_INCLUDED
