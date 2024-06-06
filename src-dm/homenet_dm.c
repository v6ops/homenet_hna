/* switch on the additional SSL code in libevent-cb.h */
#ifndef WITH_SSL
#define WITH_SSL
#endif // WITH_SSL
/* switch on the IPv6 code in libevent-cb.h */
#ifndef WITH_IPv6
#define WITH_IPv6
#endif // WITH_IPv6

#include "libevent-cb.h"
#include "workqueue.h"
/**
 *  Main function for demonstrating the echo server.
 *  You can remove this and simply call runServer() from your application. 
 */
int main(int argc, char *argv[]) {
    int port = (argc > 1 && atoi(argv[1]) > 0) ? atoi(argv[1]) : DEFULT_SERVER_PORT;
#ifdef WITH_SSL
    printf("Running with SSL support.\n");
#endif // WITH_SSL

    return runServer(port);
}