/* dm_tofu.h handles the Trust on First Use self-registration

* Copyright (c) 2024-2025 Ray Hunter

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
#ifndef DM_TOFU_INCLUDED
#define DM_TOFU_INCLUDED


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// for background thread
#include <pthread.h>
#include <unistd.h>

// for isalnum
#include <ctype.h>

#include "db.h"
#include <ldns/ldns.h>
#include "../lib/ldns_helpers.h"
#include "../lib/knot_helpers.h"
#include "../lib/ssl_helpers.h"
#include "../lib/workqueue.h"
#include "ssl_client.h"

// sha256_Final function is decprecated in openssl, so use EVP instead.
// #include <openssl/sha.h>
#include <openssl/evp.h>

// TOFU works by pre-provisioning a fixed number of zones to be claimed during a timeslot
// this limits the maximum work on the server and mitigates DoS attacks or resource exhaustion
//
//
/* zone state lifecycle DM perspective */
/*******************************************************************************
*                                                                              *
*  not exist ----> creating  zone names are in DB                              * 
*    |                |                                                        *
*    |             created   zones are created as primary asynch in a batch.   *
*    |             /  |      NS and AAAA glue in parent. No DNSSEC on child.   *
*    |            /   |                                                        *
*    | batch   T1/    |      solicit PTR query received and PTR answer sent    *
*    |          /     v                                                        *
*  deleting <----- offered   one or more zones are sent to the HNA by DM(s)    *
*    ^         T2     |                                                        *
*    |                |      client requests cert from CA via ACME DNS         *
*    |                |                                                        *
*    |                |      client receives ACME DNS challenge from CA        *
*    |                |                                                        *
*    |                v      TXT update challenge received and answered        *
*    |                |                                                        *
*    |             assigning                                                   *
*    |                |      potentially batch                                 *
*    ^         T3     v                                                        *
*    | <----<----- assigned  Glue TXT RR inserted in zone for ACME             *
*    ^                |                                                        *
*    |   any          |      client & CA complete cert asynch via ACME DNS     *
*    |   NS RR        |                                                        *
*    |   left?        |      DS or NS update add received using cert           *
*    |  n    y        v                                                        *
*    |<---------> delegating NS + Glue DS AAAA noted for add or delete         *
*    ^    |           |                                                        *
*    |    ^ NS or     |      batch to add DS to parent and resign or           *
*    |    | DS Update |      zone changed to secondary and primary NS added    *
*    |    |           v                                                        *
*    L--<----<--- delegated  fully delegated zone with AXFR & glue in place    *
*       T4                                                                     *
*                                                                              *
*                  any ->                                                      *
*                   ^    |   AXFR received and reply sent                      *
*                   |    |                                                     *
*                    <---                                                      *
*                                                                              *
*                                                                              *
*******************************************************************************/

/*******************************************************************************
*                                                                              *
*               Time slots related to scheduled activities                     *
*                                                                              *
*  --------------------------------------------------------------------------  *
* |       |          |         |      |        |         |           |       | *
* | not   | deleting |  avoid  |  open for     |  avoid  | creating  | not   | *
* | exist |          |  race   |  assigning    |  race   |           | exist | *
* |       |          |         |      |        |(created)|           |       | *
*  --------------------------------------------------------------------------  *
*       T1-2       T1-1        T1     0       +1        +2          +3         *
* ---------------------------------time slot---------------------------------> *
*                                                                              *
*                                       ^                                      *
*                                      now                                     *
*                                                                              *
* Avoid race is to cope with situations where assigments have been accepted    *
* but not yet executed in the DB and the slot rolls over. Zone creation is     *
* also not instantaneous, so slots are created for slot +2 at time "now" so    *
* that they are all ready for assignment when the slot rolls over.             *
*                                                                              *
* Acceptance of an inbound event packet is limited to the timeout.             *
* Delete events in batcj mode are timed at timeout-2 slots.                    *
* So there's a period of ±2 timeslots where a zone exists in a state           *
* that cannot change as it waits to be deleted.                                *
*******************************************************************************/

// dictionary of words to use as tokens. Feel free to alter these words e.g. to your own language. more words = more bits per word. 1024=10 bits
#include "dict.h"
#define MYSQL_STRLEN 80

// number of zones to maintain in creating or created status (rate limits how many new zones can be offered in a slot)
#define DM_TOFU_POOL_SIZE 20

// home directory of the knotd user. Must have double quotes and no trailing slash
#define KNOTD_HOME "/home/knot"

// How long to wait between time slots.
// longer means more open db entries and pending actions which could lead to timeouts in cert operations
// Shorter = more load on the DNS server to create records and resign zones
#define DM_TOFU_SLOT_LENGTH 60 // slot length in seconds. default 1 minute.
// timeouts
#define DM_TOFU_T1 31*24*60*DM_TOFU_SLOT_LENGTH // should be at least 1 * slot length in seconds. May be much longer.
					  // Zone is open for offer from Now+1 until T1. Timeout to deleting @T1-2
#define DM_TOFU_T2 30*DM_TOFU_SLOT_LENGTH // arbitrary n >= 2 * slot length in seconds
					  // (2 to allow for assigning -> assigned transition) and n to allow ACME challenge TXT RR to be received.
					  // Theoretically possible to transition back to created state, but we don't know what the related CA state is.
					  // Safe option is therefore to delete and start over with a new offer.
#define DM_TOFU_T3 60*DM_TOFU_SLOT_LENGTH // arbitrary n * slot length to allow ACME challenge to completed and certificate to be received and used.
#define DM_TOFU_T4 366*24*60*DM_TOFU_SLOT_LENGTH // arbitrary n * slot length to detect deceased clients who never issue an ACME challenge.
			       
#define MAX_NS_SECONDARY 2                // maximum number of secodnary NS per parent

// A large random int used to make zone names harder to guess by subtracting it from current time (doEVPSHA256).
// Change this if you want. There's no dependency.
// Note: guessing a zone name from a random IP address is only possible in the created state.
// Once offered they are locked by source IP.
// Once assigned they are locked by certificate before moving to delegating/delegated.
// Should be < 17556722000 to avoid making time negative to 1 jan 1970 (unsigned 64 int in DB)
#define OFFSET 15902842308
#define DM_TOFU_PRIVATE_KEY "private key123"

// crude round robin on NS names
// not sensible except for multiple parents running in one infra
void round_robin_ns(char *parent_name, int *ns1_id, int *ns2_id, int *ns3_id );

// Convert an ascii encoded hex string to decimal
// Each char is 4 bits
// limited to 32 bits (8 hex chars)
uint32_t hexstr2dec(unsigned char *hex, int len) ;

// take a string buffer and return the sha256 message digest
// md must be SHA256_DIGEST_LENGTH (32) char long
//void do_sha256(char *buf, size_t buf_len, unsigned char *md) ;
//void do_EVP(const unsigned char *message, size_t message_len, unsigned char *digest);
int do_EVP_SHA256(const unsigned char *message, size_t message_len, unsigned char **digest, unsigned int *digest_len);
// HMAC version
int do_EVP_HMACSHA256(const unsigned char *message, size_t message_len, const unsigned char *key, size_t key_len, unsigned char **digest, size_t *digest_len);

// Convert a decimal to a word token
// Each token represents 10 bits of information (1024 words in the dictionary)
// Returns the length of the word added to the buffer.
// The buffer must be large enough and is not checked.
size_t dec2word(int dec, char *buf) ;

// create an invariant opaque pass phrase zone name like horse.dog.cat.zoo.here
// remember to free once used
char *make_zone_name (unsigned long seed, int nwords) ;

// return the current time slot
// can be called with 0 to use current time
time_t get_time_slot(time_t time);

// Create nzones zones under parent in the db.
// There can be collisions with existing names because the hash is truncated.
// A "unique" constraint on `name` will force this insert to fail gracefully.
// nzones is how many additional zones should be created
void create_zones(MYSQL *db, char *parent_name, int nzones ,time_t time_slot);

// copy from temporary storage to something more permanent that can be returned to caller
 char *dm_tofu_cp_name(char *name);

// linked list needed for dm_tofu_ns_batch
typedef struct ll_parent {
  char parent_name[MYSQL_STRLEN];
  int parent_id;
  struct ll_parent *next;
} ll_parent_t;

// create a linked list of parent under this hostname for DM or NS
int dm_tofu_select_parent_func(MYSQL *db, ll_parent_t **ll_parent_head,char *type);

// create a linked list of parent under this hostname for NS
// returns rc or -1 on failure
int dm_tofu_select_parent_ns(MYSQL *db, ll_parent_t **ll_parent_head);

// create a linked list of parent under this hostname for DM
// returns rc or -1 on failure
int dm_tofu_select_parent_dm(MYSQL *db, ll_parent_t **ll_parent_head);

// kick off NS batch work
// take the host name and kick off functions to generate config
void dm_tofu_ns_batch(MYSQL *db);

// kick off DM batch work
void dm_tofu_dm_batch(MYSQL *db);

// check for a valid zone_status as this is an ENUM type in SQL.
// ('creating','created','offered','assigning','assigned','delegating','delegated','deleting')
// 0 = valid. -1 = not valid
int dm_tofu_is_valid_zone_status (char *zone_status);

// delete db entry for zone with this zone_id
int dm_tofu_delete_zone(MYSQL *db, int zone_id);

// update db for the zone  zone_id to new zone_status
int dm_tofu_update_zone_status(MYSQL *db,int zone_id, char *zone_status, time_t slot_time) ;

// given a parent, return the name of the primary NS name. Remember to free
char *dm_tofu_get_ns(MYSQL *db,char *parent_name) ;

// given a parent, return the notify list (in knot format) of the secondary NS names. Remember to free
char *dm_tofu_get_notify_list(MYSQL *db,char *parent_name);

// linked list needed for dm_tofu_get_secondary_ns
typedef struct ll_secondary_ns {
  char ns_name[MYSQL_STRLEN];
  int infra_id;
  struct ll_secondary_ns *next;
} ll_secondary_ns_t;

// given a parent_name, get a linked list of the secondary NS
ll_secondary_ns_t *dm_tofu_get_secondary_ns(MYSQL *db, char *parent_name) ;

// linked list needed for dm_tofu_creating_to_created and dm_tofu_select_zone_status
typedef struct ll_zone {
  char zone_name[MYSQL_STRLEN];
  int zone_id;
  struct ll_zone *next;
} ll_zone_t;

int dm_tofu_print_ll_zone(ll_zone_t *ll_zone_head);
int dm_tofu_print_ll_ns(ll_secondary_ns_t *ll_secondary_ns_head);
int dm_tofu_print_ll_parent(ll_parent_t *ll_parent_head);

// count zones under this parent_name with this zone_status
int dm_tofu_count_zone_status(MYSQL *db, char *parent_name, char *zone_status);

// // create a linked list of zones under this parent_name with this zone_status
// returns rc or -1 on failure
int dm_tofu_select_zone_status(MYSQL *db, char *parent_name, char *zone_status, ll_zone_t **ll_zone_head);


// Batch job to move zones from zone_status to new zone_status e.g. creating to created
// returns number of zones timed out or -1 for error
int dm_tofu_ns_update(MYSQL *db, char *parent_name, char *zone_status, time_t slot_time);

// Batch job to move zones from creating to created
// returns number of zones timed out or -1 for error
int dm_tofu_creating_to_created(MYSQL *db, char *parent_name, time_t time_slot);

// Check time out for zones stuck in zone_status.
// Marks zones for deletion, rather than directly actioning
// returns number of zones timed out or -1 for error
int dm_tofu_timeout_zone(MYSQL *db, char *parent_name, char * zone_status, time_t time_slot, time_t timeout); //By default this is for current slot time +timeout +2*DM_TOFU_SLOT_LENGTH

// Check time out for zones stuck in created zone_status (that have not been claimed).
// Uses Innodb atomic transaction to ensure completeness.
// Marks zones for deletion, rather than directly actioning
// returns number of zones timed out or -1 for error
int dm_tofu_timeout_created_zone(MYSQL *db, char *parent_name, time_t time_slot);

// Offer 1 zone name under parent_name in the db
// Uses Innodb atomic transaction to ensure uniqueness.
// Blank zone for failure (no more slots)
// The zone is then "locked" to the HNA via IP address
// This helps prevent race conditions where a zone is assigned,
// but the associated certificate has not yet been issued.
char* offer_zone(MYSQL *db, char *parent_name, char *ip, time_t time_slot); // only one version of ip is supported. Either v4 or v6

// Check time out for zones stuck in offered zone_status (that have not transitioned to assigned).
// Uses Innodb atomic transaction to ensure completeness.
// Marks zones for deletion, rather than directly actioning
// returns number of zones timed out or -1 for error
int dm_tofu_timeout_offered_zone(MYSQL *db, char *parent_name, time_t time_slot);

// Batch job to move zones from assigning to assigned
// returns number of zones timed out or -1 for error
int dm_tofu_assigning_to_assigned(MYSQL *db, char *parent_name, time_t time_slot);

// Check time out for zones stuck in assigned zone_status (that have not transitioned to delegated).
// Marks zones for deletion, rather than directly actioning
// returns number of zones timed out or -1 for error
int dm_tofu_timeout_assigned_zone(MYSQL *db, char *parent_name, time_t time_slot);

// Batch job to move zones from delegating to delegated
// returns number of zones timed out or -1 for error
int dm_tofu_delegating_to_delegated(MYSQL *db, char *parent_name, time_t time_slot);

// Check time out for zones stuck in delegated zone_status (that have not had any updates using certificates, probably due to HNA no longer in use).
// Marks zones for deletion, rather than directly actioning
// returns number of zones timed out or -1 for error
int dm_tofu_timeout_delegated_zone(MYSQL *db, char *parent_name, time_t time_slot);

// Batch job to move zones from deleting to deleted
// returns number of zones timed out or -1 for error
int dm_tofu_deleting_to_deleted(MYSQL *db, char *parent_name, time_t time_slot);

// returns an offered zone from the pre-created list in packet format
 ldns_pkt * dm_tofu_query_ptr_response(ldns_pkt *query_pkt, char *parent_name, char *zone) ; // parent_name is the owner. zone is the zone to be delegated

// function called from dm_worker to process and inbound query PTR packet
ldns_pkt * dm_worker_query_ptr(ldns_pkt *query_pkt, struct ssl_client *p_ssl_client); // 1st arg = packet, 2nd arg=SSL client (for cert)

// Background job threads for TOFU

// args storage to pass to thread
typedef struct {
           pthread_t thread_id;        /* ID returned by pthread_create() */
	   int       run;              /* semaphore. 1 = continure running */
	   time_t    last_exec;        /* last time this thread payload was executed */
	   time_t    last_awake;       /* last time this thread was awake */
	   time_t    last_time_slot;   /* last time slot this thread was processed.  time_t but written to DB. Is likely a 2038 problem */
	   MYSQL     *db;              /* db handle specific ot this thread */
           int       thread_num;       /* Application-defined thread # */
} dm_tofu_thread_t;

// function called from server create file for knotc commands
char *knot_helpers_create_file();
// function called from server delete file containing knotc commands
int knot_helpers_delete_file(char *filename);

// function called from server to start backround thread for regular tasks
dm_tofu_thread_t *dm_tofu_bg_start(int thread_num);
// function called from server to execute backround thread for regular tasks
void *dm_tofu_bg_exec(void *arguments); // a single storage element with vars for this thread
// function called from server to stop backround thread for regular tasks
int dm_tofu_bg_stop(dm_tofu_thread_t **my_thread); // pointer to a threads

#endif // DM_TOFU_INCLUDED
