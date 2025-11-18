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
#include "homenet_hna.h"

// json config file
//#include <nlohmann/json.hpp>
//using json = nlohmann::json;
#include <jansson.h>
// reading CLI options
#include "./get_cli_opt.h"

void handleFailure(void) {
	ERR_print_errors_fp(stderr);
	exit(1);
}

int main(int argc, char** argv)
{

  // read CLI options
  CLI_OPT cli_opt;
  int opt_error=0;
  opt_error=get_cli_opt(argc,argv,&cli_opt);
  if (opt_error !=0)
  {
	  printf("usage %s -a -b -c 1 -d 4 -e 5 -f\n",argv[0]);
	  exit(EXIT_FAILURE);
  }

  // ssl session
  SSL_CTX* ctx = NULL;
  BIO *web = NULL, *out = NULL;
  SSL *ssl = NULL;
  long res = 1;
  printf("Main Starting\n");

  // config
  json_t *config_hna_client;
  json_t *config_hna_server;
  json_error_t json_error;
  char *tmp_buf;

  config_hna_server=json_load_file("./homenet_hna_server_config.json",0,&json_error);
  if(!config_hna_server) {
    fprintf(stderr,"%s",json_error.text);
  }

  //tmp_buf=json_dumps(config_hna_server,0);
  //printf("Read server config: %s\n",tmp_buf);
  //free(tmp_buf);

  config_hna_client=json_load_file("./homenet_hna_client_config.json",0,&json_error);
  if(!config_hna_client) {
    fprintf(stderr,"%s",json_error.text);
  }
  //tmp_buf=json_dumps(config_hna_client,0);
  //printf("Read client config: %s\n",tmp_buf);
  //free(tmp_buf);

  /* obj is a JSON object */
  char *key;
  json_t *value;
  char *dm_ctrl=DEFAULT_DM_CTRL;
  char *dm_notify=DEFAULT_DM_NOTIFY; // casting is bad but avoids warnings.
  char *dm_acl=DEFAULT_DM_ACL;
  char *dm_port=DEFAULT_DM_PORT;
  char *zone=DEFAULT_ZONE;
  char *hna_listen=DEFAULT_HNA_LISTEN;
  char *hna_certificate=DEFAULT_HNA_CERTIFICATE;
  char *hna_key=DEFAULT_HNA_KEY;

  json_object_foreach(config_hna_client, key, value) {
  // set up the hna client to DM connection via SSL
    if(strcmp(key,"dm_ctrl")==0)        dm_ctrl=(char *)json_string_value(value);
    if(strcmp(key,"dm_port")==0)        dm_port=(char *)json_string_value(value);
    if(strcmp(key,"zone")==0)           zone=(char *)json_string_value(value);
    if(strcmp(key,"dm_acl")==0)         dm_acl=(char *)json_string_value(value);
    if(strcmp(key,"dm_notify")==0)      dm_notify=(char *)json_string_value(value);
    if(strcmp(key,"hna_certificate")==0)hna_certificate=(char *)json_string_value(value);
    if(strcmp(key,"hna_key")==0)        hna_key=(char *)json_string_value(value);
  // end read config
  }

  // ldns and wire packets
  ldns_pkt *notify;
  ldns_pkt *axfr_pkt;
  ldns_pkt *ns_pkt;
  ldns_pkt *ptr_pkt;
  ldns_pkt *response_pkt;
  ldns_zone *z;
  char buf[80];

  // start config ssl
  init_openssl();
  ctx = create_client_context();
  configure_client_context(ctx);

  ssl_session_set_cert_from_config(ctx, hna_certificate);
  ssl_session_set_key_from_config(ctx, hna_key);
  if ( !SSL_CTX_check_private_key(ctx) )
    {
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    }

  web = BIO_new_ssl_connect(ctx);
  if(!(web != NULL)) handleFailure();

  char connection_string[80]; //unsafe
  strcat(connection_string,dm_ctrl);
  strcat(connection_string,":");
  strcat(connection_string,dm_port);
  printf("Connecting to:%s\n",connection_string);

  res = BIO_set_conn_hostname(web, connection_string);
  if(!(1 == res)) handleFailure();

  BIO_get_ssl(web, &ssl);
  if(!(ssl != NULL)) handleFailure();

  const char* const PREFERRED_CIPHERS = "HIGH:!aNULL:!kRSA:!PSK:!SRP:!MD5:!RC4";
  res = SSL_set_cipher_list(ssl, PREFERRED_CIPHERS);
  if(!(1 == res)) handleFailure();

  res = SSL_set_tlsext_host_name(ssl, dm_ctrl);
  if(!(1 == res)) handleFailure();

  out = BIO_new_fp(stdout, BIO_NOCLOSE);
  if(!(NULL != out)) handleFailure();
  // end config ssl
  //
  // start connect ssl
  printf("Do Connect.\n");

  res = BIO_do_connect(web); // do_connect also actually does the full handshake
  if(!(1 == res)) handleFailure();

  printf("Do Handshake.\n");
  res = BIO_do_handshake(web); // but behaviour may change between versions
  if(!(1 == res)) handleFailure();

  /* Step 1: verify a server certificate was presented during the negotiation */
  printf("Get Peer cert:");
  X509* cert = SSL_get_peer_certificate(ssl);
  X509_print_fp(stdout,cert);   // print the cert for debug
  printf("\n");
  if(cert == NULL) handleFailure();
  if(cert) { X509_free(cert); } /* Free immediately */

  /* Step 2: verify the result of chain verification */
  /* Verification performed according to RFC 4158    */
  res = SSL_get_verify_result(ssl);
  if(!(X509_V_OK == res)) handleFailure();

  /* Step 3: hostname verification */
  /* An exercise left to the reader */

  // end connect ssl
  //
  //
  //
  /* start Query PTR */
  if (cli_opt.domain_only ==1) // get a new domain, print it and exit
  {
    BIO_puts(out,"Creating PTR\n");
    ptr_pkt=ldns_helpers_ptr_query("_domain-s._tcp._solicit.homenetdns.com");
    BIO_puts(out,"Created PTR\n");
    ldns_pkt_print(stdout,ptr_pkt);
    BIO_puts(out,"Printed PTR\n");
    ssl_helpers_pkt2bio(ptr_pkt,web);
    ldns_helpers_pkt_free(ptr_pkt);

    BIO_puts(out,"Waiting PTR response\n");

    if ( (response_pkt=ssl_helpers_bio2pkt(web)) ) {
      ldns_pkt_print(stdout, response_pkt);
      ldns_helpers_pkt_free(response_pkt);
    }

    exit(EXIT_SUCCESS);
  }

  /* end Query PTR */




  // fetch soa for our zone from the DM
  /* start AXFR */
  BIO_puts(out,"Creating AXFR\n");
  axfr_pkt=ldns_helpers_axfr_query_new(zone);
  BIO_puts(out,"Created AXFR\n");
  ldns_pkt_print(stdout,axfr_pkt);
  BIO_puts(out,"Printed AXFR\n");
  ssl_helpers_pkt2bio(axfr_pkt,web);
  ldns_helpers_pkt_free(axfr_pkt);

  BIO_puts(out,"Waiting AXFR reply\n");

  if ( (response_pkt=ssl_helpers_bio2pkt(web)) ) {
      sprintf(buf, "Converting AXFR to zone\n");
      BIO_puts(out, buf);
      // Convert to a zone
      z=ldns_helpers_axfr_pkt2zone(response_pkt);
      sprintf(buf, "Printing zone\n");
      BIO_puts(out, buf);
      ldns_helpers_zone_to_configfile(z,NULL);

    // print to file
    char *outputfile_name = NULL;
    FILE *outputfile;
    if (!outputfile_name) {
      outputfile_name = LDNS_XMALLOC(char, LDNS_MAX_FILENAME_LEN);
      snprintf(outputfile_name, LDNS_MAX_FILENAME_LEN, "%s.config", zone);
    }
    if (z) {
      if (strncmp(outputfile_name, "-", 2) == 0) {
        ldns_zone_print(stdout,z);
      } else {
        outputfile = fopen(outputfile_name, "w");
        if (!outputfile) {
          fprintf(stderr, "Unable to open %s for writing: %s\n",
          outputfile_name, strerror(errno));
        } else {
          ldns_zone_print(outputfile,z);
          fclose(outputfile);
          fork_make_knot_config(zone,dm_notify,dm_acl);
        }
      }

      sprintf(buf, "freeing zone\n");
      BIO_puts(out, buf);
      ldns_zone_free(z);
    }
    sprintf(buf, "freeing response pkt\n");
    BIO_puts(out, buf);
    ldns_helpers_pkt_free(response_pkt);
  }
  sprintf(buf, "Done AXFR\n");
  BIO_puts(out, buf);

  /* end AXFR */

  /* start update ns */
  ldns_pkt *update_ns_pkt;
  BIO_puts(out,"Creating NS UPDATE\n");
  update_ns_pkt=ldns_helpers_ns_update_new(zone,"homenetdns.com",hna_listen);
  BIO_puts(out,"Created NS UPDATE\n");
  ldns_pkt_print(stdout,update_ns_pkt);
  BIO_puts(out,"Printed NS UPDATE\n");
  ssl_helpers_pkt2bio(update_ns_pkt,web);
  ldns_helpers_pkt_free(update_ns_pkt);
  BIO_puts(out,"Sent NS\n");
  /* end update ns */

  /* start update ds */
  ldns_pkt *update_ds_pkt;
  BIO_puts(out,"Creating DS UPDATE\n");
  update_ds_pkt=ldns_helpers_ds_update_new(zone,"homenetdns.com");
  if (update_ds_pkt) {
    BIO_puts(out,"Created DS UPDATE\n");
    ldns_pkt_print(stdout,update_ds_pkt);
    BIO_puts(out,"Printed DS UPDATE\n");
    ssl_helpers_pkt2bio(update_ds_pkt,web);
    ldns_helpers_pkt_free(update_ds_pkt);
    BIO_puts(out,"Sent DS\n");
  } else {
    BIO_puts(out,"Failed to create DS\n");
  }
  /* end update ds */


  /* start NOTIFY */

  notify=ldns_helpers_notify_new("sub.homenetdns.com");
  ssl_helpers_pkt2bio(notify,web);
  ldns_helpers_pkt_free(notify); 

  /* end NOTIFY */


  /* start Query NS */
  BIO_puts(out,"Creating NS\n");
  ns_pkt=ldns_helpers_ns_query_new("homenetdns.com");
  BIO_puts(out,"Created NS\n");
  ldns_pkt_print(stdout,ns_pkt);
  BIO_puts(out,"Printed NS\n");
  ssl_helpers_pkt2bio(ns_pkt,web);
  ldns_helpers_pkt_free(ns_pkt);

  BIO_puts(out,"Waiting NS response\n");

  if ( (response_pkt=ssl_helpers_bio2pkt(web)) ) {
    ldns_pkt_print(stdout, response_pkt);
    ldns_helpers_pkt_free(response_pkt);
  }

  /* end Query NS */



  /* loop and print replies
int len = 0;
do
{
  char buff[1536] = {};
  len = BIO_read(web, buff, sizeof(buff));

  if(len > 0)
    BIO_write(out, buff, len);

} while (len > 0 || BIO_should_retry(web));

*/

  if(out)
    BIO_free(out);

  if(web != NULL)
  BIO_free_all(web);

  if(ctx != NULL) {
    SSL_CTX_free(ctx);
    cleanup_openssl();
  }
}
