#include "rlce.h"
#include <string.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/sha.h>

aeskey_t aeskey_init(unsigned short kappa) {
  if ((kappa!=128)&&(kappa!=192)&&(kappa!=256)){
    return NULL;
  }
  aeskey_t out;
  out = (aeskey_t) malloc(sizeof(struct AESkey));
  out->keylen= kappa/8;
  out->key = (unsigned char *) calloc(kappa/8, sizeof(unsigned char));
  return out;
}

void aeskey_free(aeskey_t key) {
  free(key->key);
  free(key);
  return;
}

void handleErrors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

void AES_Encrypt(unsigned char plain[], unsigned char cipher[], aeskey_t key) {
  EVP_CIPHER_CTX *ctx;
  int len;
  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();
  switch (key->keylen) {
    case 16:
       if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key->key, NULL)) handleErrors();
       break;
     case 24: 
      if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_192_ecb(), NULL, key->key, NULL)) handleErrors();
      break;
     case 32: 
       if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key->key, NULL)) handleErrors();
     default:
       return;
  }    
  if(1 != EVP_EncryptUpdate(ctx, cipher, &len, plain, 16)) handleErrors();
  EVP_CIPHER_CTX_free(ctx);
}

void sha1_MD(unsigned char message[], int size, unsigned int hash[5]) {
  SHA_CTX ctx;
  SHA1_Init(&ctx); 
  SHA1_Update(&ctx, (const void*) message, (size_t) size);
  SHA1_Final((unsigned char*) hash, &ctx);
}

void sha256_MD(unsigned char message[], int size, unsigned int hash[8]) {
  SHA256_CTX ctx;
  SHA256_Init(&ctx);
  SHA256_Update(&ctx, (const void *) message, (size_t) size);
  SHA256_Final((unsigned char *)hash, &ctx);
}

void sha512_MD(unsigned char message[], int size, unsigned long hash[8]) {
  SHA512_CTX ctx;
  SHA512_Init(&ctx);
  SHA512_Update(&ctx, (const void *) message, (size_t) size);
  SHA512_Final((unsigned char *)hash, &ctx);
}
    