/* encrypt.c
 * https://bench.cr.yp.to/call-encrypt.html 
 * http://csrc.nist.gov/groups/ST/post-quantum-crypto/documents/example-files/api-notes.pdf
 */
#include "api.h"
#include "rlce.h"

void randombytes(unsigned char *x,unsigned long long xlen) {
  unsigned char r[]={0xae,0x7e,0xbe,0x06,0x29,0x71,0xf5,0xeb,0x32,0xe5,0xb2,0x14,0x44,0x75,0x07,0x85,
		     0xde,0x81,0x65,0x95,0xad,0x2c,0xbe,0x80,0xa2,0x09,0xc8,0xf8,0xab,0x04,0xb5,0x46,
		     0x67,0x56,0x27,0xef,0x86,0xaa,0x2e,0x7d,0x70,0x29,0xa1,0x52,0xb8,0x00,0x07,0x2f};
  memcpy(x, r, xlen);
  return;
}

int crypto_kem_keygenerate(unsigned char *pk, unsigned char *sk) {
  unsigned char seed[CRYPTO_RANDOMBYTES];
  randombytes(seed, CRYPTO_RANDOMBYTES);
  return crypto_kem_keygenerate_KAT(pk,sk, (const unsigned char *) seed);
}

int crypto_kem_keygenerate_KAT(unsigned char *pk, unsigned char *sk, const unsigned char *randomness) {
  int ret;
  unsigned int para[PARASIZE];
  ret=getRLCEparameters(para,CRYPTO_SCHEME,CRYPTO_PADDING);
  if (ret<0) return ret;
  RLCE_private_key_t RLCEsk=RLCE_private_key_init(para);
  RLCE_public_key_t RLCEpk=RLCE_public_key_init(para);
  unsigned char nonce[]={0x5e,0x7d,0x69,0xe1,0x87,0x57,0x7b,0x04,0x33,0xee,0xe8,0xea,0xb9,0xf7,0x77,0x31};
  ret=RLCE_key_setup((unsigned char *)randomness, CRYPTO_RANDOMBYTES, nonce, 16, RLCEpk, RLCEsk);
  if (ret<0) return ret;
  unsigned int sklen=CRYPTO_SECRETKEYBYTES;
  unsigned int pklen=CRYPTO_PUBLICKEYBYTES;
  ret=pk2B(RLCEpk,pk,&pklen);
  ret=sk2B(RLCEsk,sk,&sklen);
  return ret;
}

int crypto_kem_encapsulate(unsigned char *ct,unsigned char *ss,const unsigned char *pk) {
  unsigned char seed[CRYPTO_RANDOMBYTES];
  randombytes(seed, CRYPTO_RANDOMBYTES);
  return crypto_kem_encapsulate_KAT(ct,ss,pk,(const unsigned char*)seed);
}

int crypto_kem_encapsulate_KAT(unsigned char *ct,unsigned char *ss,
			       const unsigned char *pk,const unsigned char *randomness) {
  int ret;
  RLCE_public_key_t RLCEpk=B2pk(pk, CRYPTO_PUBLICKEYBYTES);
  if (RLCEpk==NULL) return -1;
  unsigned long long RLCEmlen=RLCEpk->para[6];
  unsigned char *message=calloc(RLCEmlen, sizeof(unsigned char)); 
  memcpy(message, ss, CRYPTO_BYTES);
  unsigned long long ctlen=CRYPTO_CIPHERTEXTBYTES;
  unsigned char nonce[1];
  ret=RLCE_encrypt(message,RLCEmlen,(unsigned char *)randomness,CRYPTO_RANDOMBYTES,nonce,0,RLCEpk,ct,&ctlen);
  free(message);
  return ret;
}

int crypto_kem_decapsulate(unsigned char *ss,const unsigned char *ct,const unsigned char *sk) {
  int ret;
  RLCE_private_key_t RLCEsk=B2sk(sk, CRYPTO_SECRETKEYBYTES);
  if (RLCEsk==NULL) return -1;
  unsigned char message[RLCEsk->para[6]];
  unsigned long long mlen=RLCEsk->para[6];
  ret=RLCE_decrypt((unsigned char *)ct,CRYPTO_CIPHERTEXTBYTES,RLCEsk,message,&mlen);
  if (ret<0) return ret;
  memcpy(ss, message, CRYPTO_BYTES);
  return ret;
}
  
