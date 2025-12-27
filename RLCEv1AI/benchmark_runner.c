#include "rlce.h"
#include <stdio.h>
#include <time.h>

// Re-using logic from test.c for benchmarking

void run_drbg_benchmark() {
  printf("Benchmarking DRBG (SHA-256, SHA-512)...\n");
  clock_t start, finish;
  double seconds;
  int nRB = 10000;
  int i;
  unsigned char randomBytes[nRB];

  unsigned char pers[] = "PostQuantumCryptoRLCEversion2017";
  int perlen = sizeof(pers) - 1;
  unsigned char addS[] = "GRSbasedPostQuantumENCSchemeRLCE";
  int addlen = sizeof(addS) - 1;
  char noncehex[] = "5e7d69e187577b0433eee8eab9f77731";
  unsigned char nonce[16];
  hex2char(noncehex, nonce, 16);
  int noncelen = 16;
  char entropyhex[] =
      "5c7d69e187577b0433ece8eab9f778325c7d69e187577b0433ece8eab9f778325c7d69e1"
      "87577b0433ece8eab9f778325c7d69e187577b0433ece8eab9f77832";
  unsigned char entropy[64];
  hex2char(entropyhex, entropy, 64);
  int entropylen = 64;
  hash_drbg_state_t drbgState;
  drbg_Input_t drbgInput;

  start = clock();
  for (i = 0; i < 1000; i++) { // Reduced iterations for quick benchmark
    drbgState = drbgstate_init(1);
    drbgInput = drbgInput_init(entropy, entropylen, nonce, noncelen, pers,
                               perlen, addS, addlen);
    hash_DRBG(drbgState, drbgInput, randomBytes, nRB);
    free_drbg_state(drbgState);
    free_drbg_input(drbgInput);
  }
  finish = clock();
  seconds = ((double)(finish - start)) / CLOCKS_PER_SEC;
  printf("SHA-256 DRBG (1000 iters): %f seconds\n", seconds);

  start = clock();
  for (i = 0; i < 1000; i++) {
    drbgState = drbgstate_init(2);
    drbgInput = drbgInput_init(entropy, entropylen, nonce, noncelen, pers,
                               perlen, addS, addlen);
    hash_DRBG(drbgState, drbgInput, randomBytes, nRB);
    free_drbg_state(drbgState);
    free_drbg_input(drbgInput);
  }
  finish = clock();
  seconds = ((double)(finish - start)) / CLOCKS_PER_SEC;
  printf("SHA-512 DRBG (1000 iters): %f seconds\n", seconds);
}

int getSKPK_bench(RLCE_public_key_t pk, RLCE_private_key_t sk) {
  int ret;
  unsigned char entropy[] = {
      0x11, 0x4f, 0x5c, 0x01, 0x0c, 0x52, 0x17, 0xe9, 0xf0, 0xcd, 0x2a, 0xce,
      0x99, 0x92, 0xd9, 0x4d, 0x4b, 0xdb, 0x34, 0x02, 0xf3, 0xe3, 0x8c, 0xc2,
      0xfd, 0xc1, 0x84, 0x2a, 0xd9, 0x2d, 0x3e, 0x98, 0x09, 0x1f, 0xaf, 0x54,
      0x71, 0x6f, 0x1c, 0x16, 0x6a, 0xc8, 0xed, 0x77, 0xe6, 0xbb, 0x22, 0x36};
  unsigned char nonce[] = {0x5e, 0x7d, 0x69, 0xe1, 0x87, 0x57, 0x7b, 0x04,
                           0x33, 0xee, 0xe8, 0xea, 0xb9, 0xf7, 0x77, 0x31};
  ret = RLCE_key_setup(entropy, sk->para[19], nonce, 16, pk, sk);
  return ret;
}

int getOneCipher_bench(RLCE_public_key_t pk, unsigned char *cipher,
                       unsigned long long *clen) {
  int ret;
  unsigned long long mlen = pk->para[6];
  unsigned char entropy[] = {
      0x11, 0x4f, 0x5c, 0x01, 0x0c, 0x52, 0x17, 0xe9, 0xf0, 0xcd, 0x2a, 0xce,
      0x99, 0x92, 0xd9, 0x4d, 0x4b, 0xdb, 0x34, 0x02, 0xf3, 0xe3, 0x8c, 0xc2,
      0xfd, 0xc1, 0x84, 0x2a, 0xd9, 0x2d, 0x3e, 0x98, 0x09, 0x1f, 0xaf, 0x54,
      0x71, 0x6f, 0x1c, 0x16, 0x6a, 0xc8, 0xed, 0x77, 0xe6, 0xbb, 0x22, 0x36};

  unsigned char sslong[] = {
      0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11,
      0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x20, 0x21, 0x22,
      0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x30, 0x31, 0x32, 0x33,
      0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x40, 0x41, 0x42, 0x43, 0x44,
      0x45, 0x46, 0x47, 0x48, 0x49, 0x50, 0x52, 0x52, 0x53, 0x54, 0x55,
      0x56, 0x57, 0x58, 0x59, 0x60, 0x61, 0x62, 0x63, 0x64};
  unsigned char *message = calloc(mlen, sizeof(unsigned char));
  memcpy(message, sslong, 64);
  unsigned char nonce[1];
  ret = RLCE_encrypt(message, mlen, entropy, pk->para[19], nonce, 0, pk, cipher,
                     clen);
  free(message);
  return ret;
}

void run_rlce_benchmark() {
  printf("Benchmarking RLCE scheme 0 padding 0...\n");
  clock_t start, finish;
  double seconds;
  int scheme = 0;
  int padding = 0;
  unsigned int para[PARASIZE];
  int ret = getRLCEparameters(para, scheme, padding);
  if (ret < 0) {
    printf("Error getting parameters\n");
    return;
  }

  RLCE_private_key_t sk = RLCE_private_key_init(para);
  RLCE_public_key_t pk = RLCE_public_key_init(para);
  getSKPK_bench(pk, sk);

  unsigned long long mlen = pk->para[6];
  unsigned long long clen = pk->para[16];
  unsigned char *cipher = calloc(clen, sizeof(unsigned char));
  unsigned char *msg = calloc(mlen, sizeof(unsigned char));

  int numE = 100;
  start = clock();
  for (int i = 0; i < numE; i++) {
    getOneCipher_bench(pk, cipher, &clen);
  }
  finish = clock();
  seconds = ((double)(finish - start)) / CLOCKS_PER_SEC;
  printf("RLCE Encrypt (100 iters): %f seconds\n", seconds);

  int numD = 100;
  start = clock();
  for (int i = 0; i < numD; i++) {
    RLCE_decrypt(cipher, clen, sk, msg, &mlen);
  }
  finish = clock();
  seconds = ((double)(finish - start)) / CLOCKS_PER_SEC;
  printf("RLCE Decrypt (100 iters): %f seconds\n", seconds);

  free(cipher);
  free(msg);
  RLCE_free_sk(sk);
  RLCE_free_pk(pk);
}

int main() {
  run_drbg_benchmark();
  run_rlce_benchmark();
  return 0;
}
