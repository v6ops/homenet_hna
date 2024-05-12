/* ssl_session

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
#include "ssl_session.h"

/* start only used for ALPN negotiation (DNS over HTTPS) */



int server_protos_advertised_cb(SSL *ssl, const unsigned char  **out, unsigned int *outlen, void *arg){
  *out=alpn_protocols;
  *outlen = (unsigned int)alpn_len;
  //std::cerr << "server_protos_advertised_cb" << std::endl;
  fprintf(stderr,"server_protos_advertised_cb\n");
  return SSL_TLSEXT_ERR_OK;
}

int alpn_select_proto_cb(
                SSL *ssl,
                const unsigned char **out, // is used for the result of the negotiation
                unsigned char *outlen,
                const unsigned char *in,   // is set to what the client has requested
                unsigned int inlen,
                void *arg
                                ) {
  int status = -1;

  status=SSL_select_next_proto((unsigned char **)out,outlen,alpn_protocols,alpn_len,in,inlen);

  if (status != OPENSSL_NPN_NEGOTIATED ) {
    return SSL_TLSEXT_ERR_NOACK;
  }
  return SSL_TLSEXT_ERR_OK;
}
/* end only used for ALPN negotiation (DNS over HTTPS) */

void init_openssl(void)
{
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms(); // synonym for SSL_library_init()
}

void cleanup_openssl(void)
{
    EVP_cleanup();
}

SSL_CTX *create_client_context(void)
{
  const SSL_METHOD* method_client = SSLv23_method();
  SSL_CTX *ctx;
  if(!(NULL != method_client)) {
        perror("Unable to create SSL method");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
  ctx = SSL_CTX_new(method_client);
  if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
  }

  return ctx;
}

SSL_CTX *create_server_context(void)
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = SSLv23_server_method(); // flexible server method that negotiates the right protocol

    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

int alpn_negotiated=0;

void configure_client_context(SSL_CTX *ctx)
{
	// SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, ssl_session_verify_callback);
  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

  /* Cannot fail ??? */
  SSL_CTX_set_verify_depth(ctx, 4);

  /* Cannot fail ??? */
  const long flags = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION;
  SSL_CTX_set_options(ctx, flags);

  long res=1;
  //res = SSL_CTX_load_verify_locations(ctx, "../tests/testdata/fullchain.pem", NULL);
  //res = SSL_CTX_load_verify_locations(ctx, "../tests/testdata/cabundle.pem", NULL);
    res = SSL_CTX_load_verify_locations(ctx, "../tests/dm/homenetdnsCA.pem",NULL);

  if(!(1 == res))
    {
        fprintf(stderr, "Cannot load certificate chain\n");
        abort();
    }

  /* certs are now taken from the config file
  // use client certificate
  // todo add password for key file
  if ( SSL_CTX_use_certificate_file(ctx, "../tests/dm/sub.homenetdns.com.pem", SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    // set the private key from KeyFile (may be the same as CertFile)
    if ( SSL_CTX_use_PrivateKey_file(ctx, "../tests/dm/sub.homenetdns.com.key", SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    if ( !SSL_CTX_check_private_key(ctx) )
    {
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    }
    */
}

// use client certificate from json config
int  ssl_session_set_cert_from_config(SSL_CTX *ctx, const char *one_line_cert) {
	char pemCertString[100000]="\0"; // max cert chain size;
	size_t i;
	size_t j=0;
	int ret = 0;

	// restore newlines into one-line-cert
	for (i=0;i<strlen(one_line_cert);i++) {
		if (one_line_cert[i] == '\\' && one_line_cert[i+1] == 'n') {
			pemCertString[j]='\n';
			j++;
			i++;
		} else {
			pemCertString[j]=one_line_cert[i];
			j++;
		}
	}
	pemCertString[j]='\0';
	printf ("cert %s",pemCertString);

	size_t certLen = strlen(pemCertString);

        BIO* certBio = BIO_new(BIO_s_mem());
        BIO_write(certBio, pemCertString, certLen);
	X509* certX509 = PEM_read_bio_X509(certBio, NULL, NULL, NULL);
	if (!certX509) {
    		printf("unable to parse certificate in memory\n");
		SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_FILE, ERR_R_PEM_LIB);
    		goto end;
	}
	ret = SSL_CTX_use_certificate(ctx, certX509);
	end:
	BIO_free(certBio);
	X509_free(certX509);
	return ret;
}

// use client private key from json config
int  ssl_session_set_key_from_config(SSL_CTX *ctx, const char *one_line_key) {
	char pemKeyString[100000]="\0"; // max key size;
	size_t i;
	size_t j=0;
	int ret = 0;
	EVP_PKEY *pkey = NULL;

	// restore newlines into one-line-key
	for (i=0;i<strlen(one_line_key);i++) {
		if (one_line_key[i] == '\\' && one_line_key[i+1] == 'n') {
			pemKeyString[j]='\n';
			j++;
			i++;
		} else {
			pemKeyString[j]=one_line_key[i];
			j++;
		}
	}
	pemKeyString[j]='\0';
	printf ("key %s",pemKeyString);

	size_t keyLen = strlen(pemKeyString);

        BIO* certBio = BIO_new(BIO_s_mem());
        BIO_write(certBio, pemKeyString, keyLen);
	pkey = PEM_read_bio_PrivateKey(certBio, NULL, NULL, NULL);
	if (pkey == NULL) {
    		printf("unable to parse private key in memory\n");
		SSLerr(SSL_F_SSL_CTX_USE_PRIVATEKEY_FILE, ERR_R_PEM_LIB);
    		goto end;
	}
	ret = SSL_CTX_use_PrivateKey(ctx, pkey);
	EVP_PKEY_free(pkey);
	end:
	BIO_free(certBio);
	return ret;
}



void configure_server_context(SSL_CTX *ctx)
{
    SSL_CTX_set_ecdh_auto(ctx, 1);  // always choose the most appropriate curve for a client

    SSL_CTX_set_min_proto_version(ctx,TLS1_2_VERSION); // minimum of TLS v1.2 i.e. weak SSLv3 etc. are disabled
    SSL_CTX_set_max_proto_version(ctx,TLS1_3_VERSION); // maximum of TLS v1.3

    /* Set the key and cert */
    //if (SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0) {
    //    ERR_print_errors_fp(stderr);
//      exit(EXIT_FAILURE);
 //   }
    //if (SSL_CTX_use_certificate_chain_file(ctx, "../tests/testdata/fullchain.pem") <= 0) {
    if (SSL_CTX_use_certificate_chain_file(ctx, "../tests/dm/fullchain.pem") <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    //if (SSL_CTX_use_PrivateKey_file(ctx, "../tests/testdata/key.pem", SSL_FILETYPE_PEM) <= 0 ) {
    if (SSL_CTX_use_PrivateKey_file(ctx, "../tests/dm/key.pem", SSL_FILETYPE_PEM) <= 0 ) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    //
    // Set up client verification
    //SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, ssl_session_verify_callback);
    //SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    //SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    //SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    // debugging no blocking on no client cert
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER|SSL_VERIFY_CLIENT_ONCE, NULL);
    // below line drops the session if no client cert is sent
    //SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT|SSL_VERIFY_CLIENT_ONCE, NULL);

    // Other CA locations (DM root CA cert)
    if ( SSL_CTX_load_verify_locations(ctx, "../tests/dm/homenetdnsCA.pem",NULL) <=0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    SSL_CTX_set_verify_depth(ctx, 5);

    STACK_OF(X509_NAME)  *list;

    list=SSL_load_client_CA_file("../tests/dm/homenetdnsCA.pem");
    if (list == NULL) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    SSL_CTX_set_client_CA_list(ctx,list);

    SSL_CTX_set_next_protos_advertised_cb(ctx, server_protos_advertised_cb, NULL);

    SSL_CTX_set_alpn_select_cb(ctx, alpn_select_proto_cb, &alpn_negotiated);

}


int create_ssl_socket(int port, const char *ipv6_address)
{
    int s;
    struct sockaddr_in6 sin6;

    sin6.sin6_family = AF_INET6;
    sin6.sin6_flowinfo = 0;
    sin6.sin6_port = htons(port);
    //inet_pton(AF_INET6, "::1", &sin6.sin6_addr);
    inet_pton(AF_INET6, ipv6_address, &sin6.sin6_addr);
    // sin6.sin6_addr = in6addr_any;

    s = socket(PF_INET6, SOCK_STREAM, 0);
    if (s < 0) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    if (bind(s, (struct sockaddr*)&sin6, sizeof(sin6)) < 0) {
        perror("Unable to bind");
        exit(EXIT_FAILURE);
    }

    if (listen(s, 1) < 0) {
        perror("Unable to listen");
        exit(EXIT_FAILURE);
    }

    return s;
}

char *sslRead (SSL *ssl) //Remy Lebeau https://stackoverflow.com/questions/31171396/openssl-non-blocking-socket-ssl-read-unpredictable
{
    const int readSize = 1024;
    char *rc = NULL;
    int received, count = 0;
    int TotalReceived = 0;
    fd_set fds;
    struct timeval timeout;
    char buffer[1024];

    if (ssl)
    {
        while (1)
        {
            received = SSL_read (ssl, buffer, readSize);
            if (received > 0)
            {
                TotalReceived += received;
                printf("Buffsize - %i - %.*s \n", received, received, buffer);
            }
            else
            {
                count++;

                printf(" received equal to or less than 0\n");
                int err = SSL_get_error(ssl, received);
                switch (err)
                {
                    case SSL_ERROR_NONE:
                    {
                        // no real error, just try again...
                        printf("SSL_ERROR_NONE %i\n", count);
			continue;
                    }

                    case SSL_ERROR_ZERO_RETURN:
                    {
                        // peer disconnected...
                        printf("SSL_ERROR_ZERO_RETURN %i\n", count);
                        break;
                    }

                    case SSL_ERROR_WANT_READ:
                    {
                        // no data available right now, wait a few seconds in case new data arrives...
                        printf("SSL_ERROR_WANT_READ %i\n", count);

                        int sock = SSL_get_rfd(ssl);
                        FD_ZERO(&fds);
                        FD_SET(sock, &fds);

                        timeout.tv_sec = 1;
                        //timeout.tv_nsec = 0;

                        err = select(sock+1, &fds, NULL, NULL, &timeout);
                        if (err > 0)
                            continue; // more data to read...

                        if (err == 0) {
                            // timeout....
                        } else {
                            // error...
                        }
 break;
                    }

                    case SSL_ERROR_WANT_WRITE:
                    {
                        // socket not writable right now, wait a few seconds and try again...
                        printf("SSL_ERROR_WANT_WRITE %i\n", count);

                        int sock = SSL_get_wfd(ssl);
                        FD_ZERO(&fds);
                        FD_SET(sock, &fds);

                        timeout.tv_sec = 5;
                        //timeout.tv_nsec = 0;

                        err = select(sock+1, NULL, &fds, NULL, &timeout);
                        if (err > 0)
                            continue; // can write more data now...

                        if (err == 0) {
                            // timeout....
                        } else {
                            // error...
                        }

                        break;
                    }

                    default:
                    {
                        printf("error %i:%i\n", received, err);
                        break;
			}
                }

                break;
            }
        }
    }

    return rc;
}

/* Warning: only use for debugging only, as ssl_session_verify_callback always eturns preverify */
int ssl_session_verify_callback(int preverify, X509_STORE_CTX* x509_ctx)
{
    int depth = X509_STORE_CTX_get_error_depth(x509_ctx);
    int err = X509_STORE_CTX_get_error(x509_ctx);
    
    X509* cert = X509_STORE_CTX_get_current_cert(x509_ctx);
    X509_NAME* iname = cert ? X509_get_issuer_name(cert) : NULL;
    X509_NAME* sname = cert ? X509_get_subject_name(cert) : NULL;
    
    fprintf(stderr,"ssl_session_verify_callback with preverify=%i",preverify);
    print_cn_name("Issuer (cn)", iname);
    print_cn_name("Subject (cn)", sname);
    
    if(depth == 0) {
        /* If depth is 0, its the server's certificate. Print the SANs too */
        print_san_name("Subject (san)", cert);
    }

    return preverify;
}


/* Warning: only use for debugging only */
/* copied from https://github.com/palixthepalalix/NetworkSecProj2/blob/master/testserver.c */
void print_cn_name(const char* label, X509_NAME* const name)
{
    int idx = -1, success = 0;
    unsigned char *utf8 = NULL;

    do
    {
        if(!name) break; /* failed */

        idx = X509_NAME_get_index_by_NID(name, NID_commonName, -1);
        if(!(idx > -1))  break; /* failed */

        X509_NAME_ENTRY* entry = X509_NAME_get_entry(name, idx);
        if(!entry) break; /* failed */

        ASN1_STRING* data = X509_NAME_ENTRY_get_data(entry);
        if(!data) break; /* failed */

        int length = ASN1_STRING_to_UTF8(&utf8, data);
        if(!utf8 || !(length > 0))  break; /* failed */

        fprintf(stdout, "  %s: %s\n", label, utf8);
        success = 1;

    } while (0);

    if(utf8)
        OPENSSL_free(utf8);

    if(!success)
        fprintf(stdout, "  %s: <not available>\n", label);
}

/* Warning: only use for debugging only */
/* copied from https://github.com/palixthepalalix/NetworkSecProj2/blob/master/testserver.c */
void print_san_name(const char* label, X509* const cert)
{
    int success = 0;
    //GENERAL_NAMES* names = NULL;
    STACK_OF(GENERAL_NAME) *names = NULL;
    unsigned char* utf8 = NULL;

    do
    {
        if(!cert) break; /* failed */

        //names = (stack_st_GENERAL_NAME*) X509_get_ext_d2i((X509 *) cert, NID_subject_alt_name, NULL, NULL);

        names = X509_get_ext_d2i(cert, NID_subject_alt_name, 0, 0 );
        if(!names) break;

        int i = 0, count = sk_GENERAL_NAME_num(names);
        if(!count) break; /* failed */

        for( i = 0; i < count; ++i )
        {
            GENERAL_NAME* entry = sk_GENERAL_NAME_value(names, i);
            if(!entry) continue;

            if(GEN_DNS == entry->type)
            {
                int len1 = 0, len2 = -1;

                len1 = ASN1_STRING_to_UTF8(&utf8, entry->d.dNSName);
                if(utf8) {
                    len2 = (int)strlen((const char*)utf8);
                }

                if(len1 != len2) {
                    fprintf(stderr, "  Strlen and ASN1_STRING size do not match (embedded null?): %d vs %d\n", len2, len1);
                }

                /* If there's a problem with string lengths, then     */
                /* we skip the candidate and move on to the next.     */
                /* Another policy would be to fails since it probably */
                /* indicates the client is under attack.              */
                if(utf8 && len1 && len2 && (len1 == len2)) {
                    fprintf(stdout, "  %s: %s\n", label, utf8);
                    success = 1;
                }

                if(utf8) {
                    OPENSSL_free(utf8), utf8 = NULL;
                }
            }
            else
            {
                fprintf(stderr, "  Unknown GENERAL_NAME type: %d\n", entry->type);
            }
        }

    } while (0);

    if(names)
        GENERAL_NAMES_free(names);

    if(utf8)
        OPENSSL_free(utf8);

    if(!success)
        fprintf(stdout, "  %s: <not available>\n", label);

}
