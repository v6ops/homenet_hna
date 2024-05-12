#ifndef SSL_SESSION_H_INCLUDED
#define SSL_SESSION_H_INCLUDED
//#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <stdio.h>
#include <string.h>


const unsigned char alpn_protocols[] = {
 //    2, 'h', '2',   // RFC7540 HTTP/2 over TLS
     8, 'h', 't', 't', 'p', '/', '1', '.', '1' // RFC7230 HTTP/1.1
 };
unsigned int alpn_len = sizeof(alpn_protocols);

int server_protos_advertised_cb(SSL *ssl, const unsigned char  **out, unsigned int *outlen, void *arg);

int alpn_select_proto_cb(
                SSL *ssl,
                const unsigned char **out,
                unsigned char *outlen,
                const unsigned char *in,
                unsigned int inlen,
                void *arg
                                );

int create_ssl_socket(int port, const char *ipv6_address);

void init_openssl(void);

SSL_CTX *create_client_context(void);
void configure_client_context(SSL_CTX *ctx);

SSL_CTX *create_server_context(void);
void configure_server_context(SSL_CTX *ctx);

void cleanup_openssl(void);

int  ssl_session_set_cert_from_config(SSL_CTX *ctx, const char *one_line_cert) ;
int  ssl_session_set_key_from_config(SSL_CTX *ctx, const char *one_line_key) ;

char *sslRead (SSL *ssl);

int ssl_session_verify_callback(int preverify, X509_STORE_CTX* x509_ctx);
void print_san_name(const char* label, X509* const cert);
void print_cn_name(const char* label, X509_NAME* const name);

#endif /* SSL_SESSION_H_INCLUDED */
