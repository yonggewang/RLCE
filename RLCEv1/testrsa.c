#include <stdio.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <string.h>

/* gcc -o rsa testrsa.c -lssl -lcrypto
 */

 
 
int main(int argc, char* argv[]) {
  /*
  112        2048
 128        3072
 192        7680
 256       15360
  */
    
  int numT = 100;
  int  i= 0;
  RSA             *r = NULL;
  BIGNUM          *bne = NULL;
  BIO             *bp_public = NULL, *bp_private = NULL;
  int             bits = 15360;
  unsigned long   e = RSA_F4;

  clock_t start, finish;
  double seconds;
  
  /* 1. generate rsa key */
  /*
  start = clock();
  for (i=0; i<numT; i++) {
    bne = BN_new();
    BN_set_word(bne,e);
    r = RSA_new();
    RSA_generate_key_ex(r, bits, bne, NULL);
    RSA_free(r);
    BN_free(bne);
  }
  finish = clock();
  seconds = ((double)(finish - start))/CLOCKS_PER_SEC;
  printf("takes %f seconds\n", seconds);
  */
  
  bne = BN_new();
  BN_set_word(bne,e);
  r = RSA_new();
  RSA_generate_key_ex(r, bits, bne, NULL);
    
  /* 2. save public key*/
  bp_public = BIO_new_file("public.pem", "w+");
  PEM_write_bio_RSAPublicKey(bp_public, r);

  /*
  
    BIO_free_all(bp_public);
    BIO_free_all(bp_private);
    RSA_free(r);
    BN_free(bne);
  */
    
  char plainText[2048/8] = "Hello this is RLCE";
  int padding = RSA_PKCS1_PADDING;
  int data_len = 64;
  unsigned char data[64];
  unsigned char encrypted[4098];
  unsigned char decrypted[4098];
  int eLen=0,dLen=0;
  /*
  start = clock();
  for (i=0; i<numT; i++)
    eLen=RSA_public_encrypt(strlen(plainText),(const unsigned char*)plainText,encrypted,r,padding);
  finish = clock();
  seconds = ((double)(finish - start))/CLOCKS_PER_SEC;
  printf("takes %f seconds\n", seconds);
  printf("eLen=%d\n", eLen);
  */
  

  eLen=RSA_public_encrypt(strlen(plainText),(const unsigned char*)plainText,encrypted,r,padding);
  start = clock();
  for (i=0; i<numT; i++)
    dLen=RSA_private_decrypt(eLen,encrypted,decrypted,r,padding);
  finish = clock();
  seconds = ((double)(finish - start))/CLOCKS_PER_SEC;
  printf("takes %f seconds\n", seconds);
  /* 
  printf("dLen=%d\n", dLen);
  printf("%s\n", decrypted);
  */
  
  RSA_free(r);
  BN_free(bne);
  return 0;
}
