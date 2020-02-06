/* sha.c
 * Yongge Wang 
 *
 * Code was written: November 12, 2016-November 26, 2016
 *
 * sha.c implements SHA-1 (SHA-160), SHA256, and SHA512 for RLCE
 *
 * This code is for prototype purpose only and is not optimized
 *
 * Copyright (C) 2016 Yongge Wang
 * 
 * Yongge Wang
 * Department of Software and Information Systems
 * UNC Charlotte
 * Charlotte, NC 28223
 * yonwang@uncc.edu
 *
 */

#include "rlce.h"

#define ROTL(a,b) (((a) << (b)) | ((a) >> (32-(b))))
#define ROTR(a,b) (((a) >> (b)) | ((a) << (32-(b))))
#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define Sigma0(x) (ROTR(x,2) ^ ROTR(x,13) ^ ROTR(x,22))
#define Sigma1(x) (ROTR(x,6) ^ ROTR(x,11) ^ ROTR(x,25))
#define sigma0(x) (ROTR(x,7) ^ ROTR(x,18) ^ ((x) >> 3))
#define sigma1(x) (ROTR(x,17) ^ ROTR(x,19) ^ ((x) >> 10))

#define ROTL512(a,b) (((a) << (b)) | ((a) >> (64-(b))))
#define ROTR512(a,b) (((a) >> (b)) | ((a) << (64-(b))))
#define sigma5120(x) (ROTR512(x,1) ^ ROTR512(x,8) ^ ((x) >> 7))
#define sigma5121(x) (ROTR512(x,19) ^ ROTR512(x,61) ^ ((x) >> 6))
#define Sigma5120(x) (ROTR512(x,28) ^ ROTR512(x,34) ^ ROTR512(x,39))
#define Sigma5121(x) (ROTR512(x,14) ^ ROTR512(x,18) ^ ROTR512(x,41))

void sha1_process(unsigned int[], unsigned char[]);
void sha256_process(unsigned int[], unsigned char[]);
void sha512_process(unsigned long [], unsigned char []);

void sha_msg_pad(unsigned char message[], int size, unsigned int bitlen,
		 unsigned char paddedmsg[]) {
  int i;
  for (i=0; i<size; i++) {
    paddedmsg[i]=message[i];
  }
  paddedmsg[size]= 0x80;
  for (i=size+1; i<64; i++) {
    paddedmsg[i]=0x00;
  }
  paddedmsg[63] = bitlen;
  paddedmsg[62] = bitlen >> 8;
  paddedmsg[61] = bitlen >> 16;
  paddedmsg[60] = bitlen >> 24;
  return;
}

void sha_msg_pad0(unsigned int bitlen, unsigned char paddedmsg[]) {
  int i;
  for (i=0; i<64; i++) {
    paddedmsg[i]=0x00;
  }
  paddedmsg[63] = bitlen;
  paddedmsg[62] = bitlen >> 8;
  paddedmsg[61] = bitlen >> 16;
  paddedmsg[60] = bitlen >> 24;
  return;
}

void sha1_md(unsigned char message[], int size, unsigned int hash[5]) {
  unsigned int bitlen = 8*size;
  hash[0] = 0x67452301;
  hash[1] = 0xEFCDAB89;
  hash[2] = 0x98BADCFE;
  hash[3] = 0x10325476;
  hash[4] = 0xC3D2E1F0;
  int i;

  unsigned char msgTBH[64]; /* 64 BYTE msg to be hashed */
  unsigned char paddedMessage[64]; /* last msg block to be hashed*/

  int Q= size/64;
  int R= size%64;
  unsigned char msg[R];
  memcpy(msg, &message[64*Q], R * sizeof(unsigned char));
  
  for (i=0; i<Q; i++) {
    memcpy(msgTBH, &message[64*i], 64 * sizeof(unsigned char));
    sha1_process(hash, msgTBH);
  }
  if (R>55) {
    memcpy(msgTBH, msg, R * sizeof(unsigned char));
    msgTBH[R]=0x80;
    for (i=R+1; i<64; i++) {
      msgTBH[i]=0x00;
    } 
    sha1_process(hash, msgTBH);
    sha_msg_pad0(bitlen,paddedMessage);
  } else {
    sha_msg_pad(msg, R, bitlen, paddedMessage);
  }
  sha1_process(hash, paddedMessage);
  return;
}

void sha1_process(unsigned int hash[], unsigned char msg[]) {
  const unsigned int K[4] = {0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6};
  unsigned int W[80];
  unsigned int A, B, C, D, E, T;
  int i;
  for(i = 0; i < 16; i++) {
    W[i] = (((unsigned) msg[i * 4]) << 24) +
      (((unsigned) msg[i * 4 + 1]) << 16) +
      (((unsigned) msg[i * 4 + 2]) << 8) +
      (((unsigned) msg[i * 4 + 3]));
  }
  for(i = 16; i < 80; i++) {
    W[i] = W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16];
    W[i] = ROTL(W[i],1);
  }

  A = hash[0];
  B = hash[1];
  C = hash[2];
  D = hash[3];
  E = hash[4];

  for(i = 0; i < 20; i++) {
    T = ROTL(A,5) + ((B & C) ^ ((~B) & D)) + E + W[i] + K[0];
    E = D;
    D = C;
    C = ROTL(B, 30);
    B = A;
    A = T;
  }
  for(i = 20; i < 40; i++) {
    T = ROTL(A,5) + (B^C^D) + E + W[i] + K[1];
    E = D;
    D = C;
    C = ROTL(B, 30);
    B = A;
    A = T;
  }
  for(i = 40; i < 60; i++) {
    T = ROTL(A,5) + ((B & C) ^ (B & D) ^ (C & D)) + E + W[i] + K[2];
    E = D;
    D = C;
    C = ROTL(B, 30);
    B = A;
    A = T;
  }
  for(i = 60; i < 80; i++) {
    T = ROTL(A,5) + (B ^ C ^ D) + E + W[i] + K[3];
    E = D;
    D = C;
    C = ROTL(B, 30);
    B = A;
    A = T;
    /* printf("%d: %x %x %x %x %x\n",i, A, B, C, D, E); */
  }

  hash[0] +=  A;
  hash[1] +=  B;
  hash[2] +=  C;
  hash[3] +=  D;
  hash[4] +=  E;
  return;
}

void sha256_md(unsigned char message[], int size, unsigned int hash[8]) {
  unsigned int bitlen = 8*size;
  hash[0] = 0x6A09E667;  
  hash[1] = 0xBB67AE85;
  hash[2] = 0x3C6EF372;  
  hash[3] = 0xA54FF53A;  
  hash[4] = 0x510E527F;
  hash[5] = 0x9B05688C;
  hash[6] = 0x1F83D9AB;
  hash[7] = 0x5BE0CD19;
  
  unsigned char msgTBH[64]; /* 64 BYTE msg to be hashed */
  unsigned char paddedMessage[64]; /* last msg block to be hashed*/
  int i;
  int Q= size/64;
  int R= size%64;
  unsigned char msg[R];
  memcpy(msg, &message[64*Q], R * sizeof(unsigned char));
  
  for (i=0; i<Q; i++) {
    memcpy(msgTBH, &message[64*i], 64 * sizeof(unsigned char));
    sha256_process(hash, msgTBH);
  }
  if (R>55) {
    memcpy(msgTBH, msg, R * sizeof(unsigned char));
    msgTBH[R]=0x80;
    for (i=R+1; i<64; i++) {
      msgTBH[i]=0x00;
    }
    sha256_process(hash, msgTBH);
    sha_msg_pad0(bitlen,paddedMessage);
  } else {
    sha_msg_pad(msg, R, bitlen, paddedMessage);
  }
 
  sha256_process(hash, paddedMessage);
  return;
}

void sha256_process(unsigned int hash[], unsigned char msg[]) {
  const unsigned int K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,
    0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
    0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,
    0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,
    0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
    0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,
    0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,
    0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
    0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
  unsigned int W[64];
  int i;
  unsigned int A, B, C, D, E, F, G, H, T1, T2;
  for(i = 0; i < 16; i++) {
    W[i] = (((unsigned) msg[i * 4]) << 24) |
      (((unsigned) msg[i * 4 + 1]) << 16) |
      (((unsigned) msg[i * 4 + 2]) << 8) | 
      (((unsigned) msg[i * 4 + 3]));
  }
  for(i = 16; i < 64; i++) {
    W[i] = sigma1(W[i-2])+W[i-7]+sigma0(W[i-15])+ W[i-16];
  }
  A = hash[0];
  B = hash[1];
  C = hash[2];
  D = hash[3];
  E = hash[4];
  F = hash[5];
  G = hash[6];
  H = hash[7];

  for (i = 0; i < 64; ++i) {
    T1 = H + Sigma1(E) + CH(E,F,G) + K[i] + W[i];
    T2 = Sigma0(A) + MAJ(A,B,C);
    H = G;
    G = F;
    F = E;
    E = D + T1;
    D = C;
    C = B;
    B = A;
    A = T1 + T2;
  }
  
  hash[0] +=A;
  hash[1] +=B;
  hash[2] +=C;
  hash[3] +=D;
  hash[4] +=E;
  hash[5] +=F;
  hash[6] +=G;
  hash[7] +=H;
  return;
}


void sha512_msg_pad(unsigned char message[], int size, unsigned int bitlen, unsigned char paddedmsg[]) {
  int i;
  for (i=0; i<size; i++) {
    paddedmsg[i]=message[i];
  }
  paddedmsg[size]= 0x80;
  for (i=size+1; i<128; i++) {
    paddedmsg[i]=0x00;
  }
  paddedmsg[127] = bitlen;
  paddedmsg[126] = bitlen >> 8;
  paddedmsg[125] = bitlen >> 16;
  paddedmsg[124] = bitlen >> 24;
  return;
}

void sha512_msg_pad0(unsigned int bitlen, unsigned char paddedmsg[]) {
  int i;
  for (i=0; i<128; i++) {
    paddedmsg[i]=0x00;
  }
  paddedmsg[127] = bitlen;
  paddedmsg[126] = bitlen >> 8;
  paddedmsg[125] = bitlen >> 16;
  paddedmsg[124] = bitlen >> 24;
  return;
}


void sha512_md(unsigned char message[], int size, unsigned long hash[8]) {
  unsigned int bitlen = 8*size;
  hash[0] = 0x6a09e667f3bcc908;
  hash[1] = 0xbb67ae8584caa73b;
  hash[2] = 0x3c6ef372fe94f82b;
  hash[3] = 0xa54ff53a5f1d36f1;
  hash[4] = 0x510e527fade682d1;
  hash[5] = 0x9b05688c2b3e6c1f;
  hash[6] = 0x1f83d9abfb41bd6b;
  hash[7] = 0x5be0cd19137e2179;
  
  unsigned char msgTBH[128]; /* 128 BYTE msg to be hashed */
  unsigned char paddedMessage[128]; /* last msg block to be hashed*/
  
  int Q= size/128;
  int R= size%128;
  unsigned char msg[R];
  memcpy(msg, &message[128*Q], R * sizeof(unsigned char));
  int i;
  for (i=0; i<Q; i++) {
    memcpy(msgTBH, &message[128*i], 128 * sizeof(unsigned char));
    sha512_process(hash, msgTBH);
  }
  if (R>111) {
    memcpy(msgTBH, msg, R * sizeof(unsigned char));
    msgTBH[R]=0x80;
    for (i=R+1; i<128; i++) {
      msgTBH[i]=0x00;
    }
    sha512_process(hash, msgTBH);
    sha512_msg_pad0(bitlen,paddedMessage);
  } else {
    sha512_msg_pad(msg, R, bitlen, paddedMessage);
  }
 
  sha512_process(hash, paddedMessage);
  return;
}

void sha512_process(unsigned long hash[], unsigned char msg[]) {
  const unsigned long K[80] = {
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817};
  int i;
  unsigned long W[80];
  unsigned long A, B, C, D, E, F, G, H, T1, T2;
  for(i = 0; i < 16; i++) {
    W[i] = (((unsigned long) msg[i * 8])<< 56) |
      (((unsigned long) msg[i * 8 + 1]) << 48) |
      (((unsigned long) msg[i * 8 + 2]) << 40) | 
      (((unsigned long) msg[i * 8 + 3]) << 32) |
      (((unsigned long) msg[i * 8 + 4]) << 24) |
      (((unsigned long) msg[i * 8 + 5]) << 16) | 
      (((unsigned long) msg[i * 8 + 6]) << 8)  |
      (((unsigned long) msg[i * 8 + 7]));
  }
  for(i = 16; i < 80; i++) {
    W[i] = sigma5121(W[i-2])+W[i-7]+sigma5120(W[i-15])+ W[i-16];
  }
  A = hash[0];
  B = hash[1];
  C = hash[2];
  D = hash[3];
  E = hash[4];
  F = hash[5];
  G = hash[6];
  H = hash[7];

  for (i = 0; i < 80; ++i) {
    T1 = H + Sigma5121(E) + CH(E,F,G) + K[i] + W[i];
    T2 = Sigma5120(A) + MAJ(A,B,C);
    H = G;
    G = F;
    F = E;
    E = D + T1;
    D = C;
    C = B;
    B = A;
    A = T1 + T2;
  }
  
  hash[0] +=A;
  hash[1] +=B;
  hash[2] +=C;
  hash[3] +=D;
  hash[4] +=E;
  hash[5] +=F;
  hash[6] +=G;
  hash[7] +=H;
  return;
}


