/* encrypt.c
 * https://bench.cr.yp.to/call-encrypt.html 
 * http://csrc.nist.gov/groups/ST/post-quantum-crypto/documents/example-files/api-notes.pdf
 */
#include "api.h"
#include "rlce.h"

void randombytes(unsigned char *x,unsigned long long xlen) {
  char hexstring[]="10509641332a4d72a3c5936512c37cb9ab9874693902ee4c76e963675627ef86aa2e7d7029a152b800072fc53eeb6b41d12f481cde99b467dac3486836f6e146e9a79d3fb90d9b26f213ddbfac590ca083ed83fde4924395d25b645b96a6983e65fd662cae66112ebfa990f09b86b01270b7f0ef35f183eb01ffcbd7d5ec6adc4839cf3814dac858e013c6d79528ef273dd83724ccdc82b73dc63698fcf8ef0924f27b6a49d6d38f0ce261aa5a0a88779e47a413c29e1d7d20e4ab914bbabd5e6e0241cf53263a8efa321b4a632eb062b255c0ce5a0833114161dd073dd037967a1f03daf2dd7e927b801b40e62f26c0872ea100132807650232126aa8f29d70";
  hex2char(hexstring, x, xlen);
  return;
}

int crypto_encrypt_keypair (unsigned char *pk, unsigned char *sk) {
  unsigned char seed[CRYPTO_RANDOMBYTES];
  randombytes(seed, CRYPTO_RANDOMBYTES);
  return crypto_encrypt_keypair_KAT(pk,sk, seed);
}

int crypto_encrypt_keypair_KAT(unsigned char *pk, unsigned char *sk, unsigned char *randomness) {
  int ret;
  unsigned int para[PARASIZE];
  ret=getRLCEparameters(para,CRYPTO_SCHEME,CRYPTO_PADDING);
  if (ret<0) return ret;
  RLCE_private_key_t RLCEsk=RLCE_private_key_init(para);
  if (RLCEsk==NULL) return -1;
  RLCE_public_key_t RLCEpk=RLCE_public_key_init(para);
  if (RLCEpk==NULL) return -1;
  char noncehex[] = "5e7d69e187577b0433eee8eab9f77731";
  unsigned char nonce[16];
  hex2char(noncehex, nonce, 16);
  ret=RLCE_key_setup(randomness, CRYPTO_RANDOMBYTES, nonce, 16, RLCEpk, RLCEsk);
  if (ret<0) return ret;
  unsigned int sklen=CRYPTO_SECRETKEYBYTES;
  unsigned int pklen=CRYPTO_PUBLICKEYBYTES;
  ret=pk2B(RLCEpk,pk,&pklen);
  ret=sk2B(RLCEsk,sk,&sklen);
  return ret;
}

int crypto_encrypt(unsigned char *c, unsigned long long *clen,
		   const unsigned char *m, unsigned long long mlen,
		   const unsigned char *pk) {
  unsigned char seed[CRYPTO_RANDOMBYTES];
  randombytes(seed, CRYPTO_RANDOMBYTES);
  return crypto_encrypt_KAT(c, clen,m, mlen,pk,seed);
}

int crypto_encrypt_KAT(unsigned char *c, unsigned long long *clen,
		       const unsigned char *m, unsigned long long mlen,
		       const unsigned char *pk, unsigned char *randomness) {
  int ret;
  RLCE_public_key_t RLCEpk=B2pk(pk, CRYPTO_PUBLICKEYBYTES);
  if (RLCEpk==NULL) return -1;
  unsigned long long RLCEmlen=RLCEpk->para[6];
  if (mlen >RLCEmlen-4) return -1;
  unsigned char *message=calloc(RLCEmlen, sizeof(unsigned char));
  memcpy(message, m, mlen);
  message[mlen]=0x01;
  message[mlen+1]=0x00;
  unsigned char S[2];
  I2BS((unsigned int)mlen, S,2);
  memcpy(&(message[mlen+2]), S,2);
  unsigned char nonce[1];
  int noncelen=0;
  clen[0]=RLCEpk->para[16];
  ret=RLCE_encrypt(message,RLCEmlen,randomness,CRYPTO_RANDOMBYTES,nonce,noncelen,RLCEpk,c,clen);
  free(message);
  return ret;
}


int crypto_encrypt_open(unsigned char *m, unsigned long long *mlen,
			const unsigned char *c, unsigned long long clen,
			const unsigned char *sk) {
  int ret;
  RLCE_private_key_t RLCEsk=B2sk(sk, CRYPTO_SECRETKEYBYTES);
  if (RLCEsk==NULL) return -1;
  if (clen !=RLCEsk->para[16]) return -1;
  unsigned char *message=calloc(RLCEsk->para[6], sizeof(unsigned char));
  mlen[0]=RLCEsk->para[6];
  ret=RLCE_decrypt((unsigned char *)c, clen,RLCEsk,message,mlen);
  if (ret<0) return ret;
  int i=0,done=0;
  mlen[0]=RLCEsk->para[6]-5;
  while (done==0) {
    if ((message[i+1]==0x01) && (message[i+2]==0x00)) {
      if (i+1==BS2I(&(message[i+3]),2)) {
	done=1;
      } else {
	if (i==mlen[0]) done=1;
	i++;
      }
    } else {
      if (i==mlen[0]) done=1;
      i++;
    }
  }
  mlen[0]=i+1;
  memcpy(m,message,i+1);		
  free(message);
  return 0;
}



