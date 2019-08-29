/* homenet_hna homenet_dm

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
#include <stdio.h>
#include <iostream>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "../lib/ssl_session.h"



int main_old(int argc, char **argv)
{
    std::cout << "Main Starting\n" << std::flush;
    int sock;
    SSL_CTX *ctx;

    init_openssl();
    ctx = create_server_context();

    configure_server_context(ctx);

    char ipv6_address[40]="2001:470:1f15:62e:21c::2";
    sock = create_ssl_socket(4433,ipv6_address);

    /* Handle connections */
    while(1) {
        std::cout << "Handling Connection\n" << std::flush;
        struct sockaddr_in sin6;
        uint len = sizeof(sin6);
        SSL *ssl;
        const char reply[] = "HTTP/1.1 200 OK\nServer: Apache/1.3.29 (Unix) PHP/4.3.4\nContent-Type: text/plain\n\ntest\n\n";

        int client = accept(sock, (struct sockaddr*)&sin6, &len);
        if (client < 0) {
            perror("Unable to accept");
            exit(EXIT_FAILURE);
        }

        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client);

        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
        }
        else {
        std::cout << "SSL Accepted\n" << std::flush;
	// perror("trying to write");
	// exit(EXIT_FAILURE);
	std::cout << sslRead(ssl) << std::flush;
            SSL_write(ssl, reply, strlen(reply));
        }

        SSL_free(ssl);
        close(client);
    }

    close(sock);
    SSL_CTX_free(ctx);
    cleanup_openssl();
}

int main(int argc, char **argv)
{
    std::cout << "Main Starting\n" << std::flush;
    SSL_CTX *ctx;

    init_openssl();
    ctx = create_server_context();

    configure_server_context(ctx);

    //char ipv6_address[40]="2001:470:1f15:62e:21c::2";
    //sock = create_ssl_socket(4433,ipv6_address);
    //
  BIO *sbio, *bbio, *acpt, *out;
  int len;
  char tmpbuf[1024];
  SSL *ssl;


 out = BIO_new_fp(stdout, BIO_NOCLOSE);

  /* New SSL BIO setup as server */
 sbio=BIO_new_ssl(ctx,0);

 BIO_get_ssl(sbio, &ssl);

 if(!ssl) {
   fprintf(stderr, "Can't locate SSL pointer\n");
   /* whatever ... */
 }

 /* Don't want any retries */
 SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

 /* Create the buffering BIO */
 bbio = BIO_new(BIO_f_buffer());

 /* Add to chain */
 sbio = BIO_push(bbio, sbio);
 char host_port[40]="[2001:470:1f15:62e:21c::2]:4433";

 acpt=BIO_new_accept(host_port);

 /* By doing this when a new connection is established
  * we automatically have sbio inserted into it. The
  * BIO chain is now 'swallowed' by the accept BIO and
  * will be freed when the accept BIO is freed.
  */

 BIO_set_accept_bios(acpt,sbio);

 BIO_puts(out, "Accepting Connectionr\n");

 /* Setup accept BIO */
 if(BIO_do_accept(acpt) <= 0) {
        fprintf(stderr, "Error setting up accept BIO\n");
        ERR_print_errors_fp(stderr);
        return 0;
 }
 BIO_puts(out, "Waiting for Connectionr\n");

 /* Now wait for incoming connection */
 if(BIO_do_accept(acpt) <= 0) {
        fprintf(stderr, "Error in connection\n");
        ERR_print_errors_fp(stderr);
        return 0;
 }

 /* We only want one connection so remove and free
  * accept BIO
  */

 sbio = BIO_pop(acpt);

 BIO_free_all(acpt);

 if(BIO_do_handshake(sbio) <= 0) {
        fprintf(stderr, "Error in SSL handshake\n");
        ERR_print_errors_fp(stderr);
        return 0;
 }

 BIO_puts(out, "Established Connectionr\n");
    /* Handle connections */
    while(1) {
	len = BIO_gets(sbio, tmpbuf, 1024);
        if(len <= 0) break;
        BIO_write(sbio, tmpbuf, len);
        BIO_write(out, tmpbuf, len);
        /* Look for blank line signifying end of headers*/
        if((tmpbuf[0] == '\r') || (tmpbuf[0] == '\n')) break;
    }

   BIO_puts(sbio, "--------------------------------------------------\r\n");
   BIO_puts(sbio, "\r\n");

   /* Since there is a buffering BIO present we had better flush it */
   BIO_flush(sbio);
   BIO_free_all(sbio);

    SSL_CTX_free(ctx);
    cleanup_openssl();
}
