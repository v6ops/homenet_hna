#ifndef PROGRAM_MAIN_INCLUDED
#define PROGRAM_MAIN_INCLUDED

#include <iostream>
#include <fstream>
#include <unistd.h>
#include <string.h>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

#include "../lib/ssl_session.h"
#include "../lib/ldns_helpers.h"
#include "../lib/knot_helpers.h"
#include "../lib/ssl_helpers.h"

#define DEFAULT_DM_CTRL "dm.homenetdns.com"
#define DEFAULT_DM_PORT "433"
#define DEFAULT_DM_ACL "::1/64"
#define DEFAULT_DM_NOTIFY "::1"
#define DEFAULT_ZONE "sub.homenetdns.com"
#define DEFAULT_HNA_LISTEN ""
#define DEFAULT_HNA_CERTIFICATE ""
#define DEFAULT_HNA_KEY ""


#endif

