/**
 *  function for testing do_EVP_HMACSHA256
 *  Copyright (c) 2025 Ray Hunter
 */

#include <CUnit/CUnit.h>
#include "../src-dm/dm_tofu.h"
#include "./test_harness.h"

int do_EVP_HMACSHA256_test(void){
  CU_ASSERT(0 == 0);

  MYSQL *db;

  db=db_init();
  db_connect(db,DB_SERVER, DB_USER, DB_PASSWORD, DB_DATABASE);

int res=0;

size_t len=32;
unsigned char *digest=(unsigned char*)malloc(len);
size_t *digest_len=&len;

// test vector 1. Checked against https://www.devglan.com/online-tools/hmac-sha256-online
// b8b027eac82b0e466fd84d1214419748909f8943146b171b8aab6453d9a3e5de
char message1[]="test message 22";
size_t message_len1=strlen(message1);
char key1[]="privatekey";
size_t key_len1=strlen(key1);
unsigned char expected_digest1[]={0xb8, 0xb0, 0x27, 0xea, 0xc8, 0x2b, 0x0e, 0x46, 0x6f, 0xd8, 0x4d, 0x12, 0x14, 0x41, 0x97, 0x48, 0x90, 0x9f, 0x89, 0x43, 0x14, 0x6b, 0x17, 0x1b, 0x8a, 0xab, 0x64, 0x53, 0xd9, 0xa3, 0xe5, 0xde};
memset(digest,'\0',len);

res=do_EVP_HMACSHA256((const unsigned char *)message1, message_len1, (const unsigned char *)key1, key_len1, &digest, digest_len);

CU_ASSERT(digest!=NULL);
CU_ASSERT(res==0);
CU_ASSERT(len==32);
CU_ASSERT(sizeof(expected_digest1)==32);
//Now assert byte-by-byte equality
CU_ASSERT(cmp_array(digest,expected_digest1,len)==0);

// test vector 2. RFC4231
char message2[]="what do ya want for nothing?";
size_t message_len2=strlen(message2);
char key2[]="Jefe";
size_t key_len2=strlen(key2);
unsigned char expected_digest2[]={0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e, 0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75, 0xc7, 0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83, 0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43};
memset(digest,'\0',len);

res=do_EVP_HMACSHA256((const unsigned char *)message2, message_len2, (const unsigned char *)key2, key_len2, &digest, digest_len);

CU_ASSERT(digest!=NULL);
CU_ASSERT(res==0);
CU_ASSERT(len==32);
CU_ASSERT(sizeof(expected_digest2)==32);
//Now assert byte-by-byte equality
CU_ASSERT(cmp_array(digest,expected_digest2,len)==0);

// test vector 7. RFC4231
char message3[]="This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.";
size_t message_len3=strlen(message3);
size_t key_len3=131; // have to be careful here. The compiler can apparently do odd things on hex string literals.
char *key3=(char *)malloc(key_len3);
memset(key3,0xaa,key_len3);
unsigned char expected_digest3[]={0x9b, 0x09, 0xff, 0xa7, 0x1b, 0x94, 0x2f, 0xcb, 0x27, 0x63, 0x5f, 0xbc, 0xd5, 0xb0, 0xe9, 0x44, 0xbf, 0xdc, 0x63, 0x64, 0x4f, 0x07, 0x13, 0x93, 0x8a, 0x7f, 0x51, 0x53, 0x5c, 0x3a, 0x35, 0xe2};
memset(digest,'\0',len);

res=do_EVP_HMACSHA256((const unsigned char *)message3, message_len3, (const unsigned char *)key3, key_len3, &digest, digest_len);

CU_ASSERT(digest!=NULL);
CU_ASSERT(res==0);
CU_ASSERT(len==32);
CU_ASSERT(sizeof(expected_digest3)==32);
//Now assert byte-by-byte equality
CU_ASSERT(cmp_array(digest,expected_digest3,len)==0);
/*
  // output the result for debug
  for (size_t i = 0; i < *digest_len; i++) {
    printf("0x%02x, ", digest[i]);
  }
  putchar('\n');
 */

  free(digest);
  free(key3);

  db_close(db);

}

