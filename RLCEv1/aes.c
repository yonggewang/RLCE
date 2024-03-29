/* aes.c
 * Code was written: June 7, 2017
 *
 * aes.c implements AES-128, AES-192, and AES-256 for RLCE
 * AES decryption is not required for RLCE, so not optimized
 * Copyright (C) 2017 Yongge Wang
 * 
 * Yongge Wang
 * Department of Software and Information Systems
 * UNC Charlotte
 * Charlotte, NC 28223
 * yonwang@uncc.edu
 *
 */

#include "rlce.h"
#define TABLE4MIXCOLUMN 1

static const uint8_t sbox[256] ={
  0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
  0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
  0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
  0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
  0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
  0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
  0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
  0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
  0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
  0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
  0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
  0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
  0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
  0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
  0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
  0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static const uint8_t Invsbox[256] ={
  0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
  0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
  0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
  0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
  0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
  0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
  0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
  0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
  0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
  0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
  0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
  0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
  0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
  0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
  0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
  0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
};


static const uint8_t times2[256] ={
  0x00,0x02,0x04,0x06,0x08,0x0a,0x0c,0x0e,0x10,0x12,0x14,0x16,0x18,0x1a,0x1c,0x1e,
  0x20,0x22,0x24,0x26,0x28,0x2a,0x2c,0x2e,0x30,0x32,0x34,0x36,0x38,0x3a,0x3c,0x3e,
  0x40,0x42,0x44,0x46,0x48,0x4a,0x4c,0x4e,0x50,0x52,0x54,0x56,0x58,0x5a,0x5c,0x5e,
  0x60,0x62,0x64,0x66,0x68,0x6a,0x6c,0x6e,0x70,0x72,0x74,0x76,0x78,0x7a,0x7c,0x7e,
  0x80,0x82,0x84,0x86,0x88,0x8a,0x8c,0x8e,0x90,0x92,0x94,0x96,0x98,0x9a,0x9c,0x9e,
  0xa0,0xa2,0xa4,0xa6,0xa8,0xaa,0xac,0xae,0xb0,0xb2,0xb4,0xb6,0xb8,0xba,0xbc,0xbe,
  0xc0,0xc2,0xc4,0xc6,0xc8,0xca,0xcc,0xce,0xd0,0xd2,0xd4,0xd6,0xd8,0xda,0xdc,0xde,
  0xe0,0xe2,0xe4,0xe6,0xe8,0xea,0xec,0xee,0xf0,0xf2,0xf4,0xf6,0xf8,0xfa,0xfc,0xfe,
  0x1b,0x19,0x1f,0x1d,0x13,0x11,0x17,0x15,0x0b,0x09,0x0f,0x0d,0x03,0x01,0x07,0x05,
  0x3b,0x39,0x3f,0x3d,0x33,0x31,0x37,0x35,0x2b,0x29,0x2f,0x2d,0x23,0x21,0x27,0x25,
  0x5b,0x59,0x5f,0x5d,0x53,0x51,0x57,0x55,0x4b,0x49,0x4f,0x4d,0x43,0x41,0x47,0x45,
  0x7b,0x79,0x7f,0x7d,0x73,0x71,0x77,0x75,0x6b,0x69,0x6f,0x6d,0x63,0x61,0x67,0x65,
  0x9b,0x99,0x9f,0x9d,0x93,0x91,0x97,0x95,0x8b,0x89,0x8f,0x8d,0x83,0x81,0x87,0x85,
  0xbb,0xb9,0xbf,0xbd,0xb3,0xb1,0xb7,0xb5,0xab,0xa9,0xaf,0xad,0xa3,0xa1,0xa7,0xa5,
  0xdb,0xd9,0xdf,0xdd,0xd3,0xd1,0xd7,0xd5,0xcb,0xc9,0xcf,0xcd,0xc3,0xc1,0xc7,0xc5,
  0xfb,0xf9,0xff,0xfd,0xf3,0xf1,0xf7,0xf5,0xeb,0xe9,0xef,0xed,0xe3,0xe1,0xe7,0xe5
};

static const uint8_t times3[256] ={
  0x00,0x03,0x06,0x05,0x0c,0x0f,0x0a,0x09,0x18,0x1b,0x1e,0x1d,0x14,0x17,0x12,0x11,
  0x30,0x33,0x36,0x35,0x3c,0x3f,0x3a,0x39,0x28,0x2b,0x2e,0x2d,0x24,0x27,0x22,0x21,
  0x60,0x63,0x66,0x65,0x6c,0x6f,0x6a,0x69,0x78,0x7b,0x7e,0x7d,0x74,0x77,0x72,0x71,
  0x50,0x53,0x56,0x55,0x5c,0x5f,0x5a,0x59,0x48,0x4b,0x4e,0x4d,0x44,0x47,0x42,0x41,
  0xc0,0xc3,0xc6,0xc5,0xcc,0xcf,0xca,0xc9,0xd8,0xdb,0xde,0xdd,0xd4,0xd7,0xd2,0xd1,
  0xf0,0xf3,0xf6,0xf5,0xfc,0xff,0xfa,0xf9,0xe8,0xeb,0xee,0xed,0xe4,0xe7,0xe2,0xe1,
  0xa0,0xa3,0xa6,0xa5,0xac,0xaf,0xaa,0xa9,0xb8,0xbb,0xbe,0xbd,0xb4,0xb7,0xb2,0xb1,
  0x90,0x93,0x96,0x95,0x9c,0x9f,0x9a,0x99,0x88,0x8b,0x8e,0x8d,0x84,0x87,0x82,0x81,
  0x9b,0x98,0x9d,0x9e,0x97,0x94,0x91,0x92,0x83,0x80,0x85,0x86,0x8f,0x8c,0x89,0x8a,
  0xab,0xa8,0xad,0xae,0xa7,0xa4,0xa1,0xa2,0xb3,0xb0,0xb5,0xb6,0xbf,0xbc,0xb9,0xba,
  0xfb,0xf8,0xfd,0xfe,0xf7,0xf4,0xf1,0xf2,0xe3,0xe0,0xe5,0xe6,0xef,0xec,0xe9,0xea,
  0xcb,0xc8,0xcd,0xce,0xc7,0xc4,0xc1,0xc2,0xd3,0xd0,0xd5,0xd6,0xdf,0xdc,0xd9,0xda,
  0x5b,0x58,0x5d,0x5e,0x57,0x54,0x51,0x52,0x43,0x40,0x45,0x46,0x4f,0x4c,0x49,0x4a,
  0x6b,0x68,0x6d,0x6e,0x67,0x64,0x61,0x62,0x73,0x70,0x75,0x76,0x7f,0x7c,0x79,0x7a,
  0x3b,0x38,0x3d,0x3e,0x37,0x34,0x31,0x32,0x23,0x20,0x25,0x26,0x2f,0x2c,0x29,0x2a,
  0x0b,0x08,0x0d,0x0e,0x07,0x04,0x01,0x02,0x13,0x10,0x15,0x16,0x1f,0x1c,0x19,0x1a
};

static const uint8_t Rcon[11] = {0x8d,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36};

aeskey_t aeskey_init(unsigned short kappa) {
  if ((kappa!=128)&&(kappa!=192)&&(kappa!=256)){
    return NULL;
  }
  aeskey_t out;
  out = (aeskey_t) malloc(sizeof(struct AESkey));
  out->keylen= kappa/8;
  out->Nk = kappa/32;
  switch(out->Nk) {
  case 4:
    out->Nr=10;
    out->wLen = 176; 
    break;
  case 6:
    out->Nr=12;
    out->wLen = 208;
    break;
  case 8:
    out->Nr=14;
    out->wLen = 240;
    break;
  default:
    return NULL;
  }
  out->key = (uint8_t *) calloc(kappa/8, sizeof(uint8_t));
  return out;
}

void aeskey_free(aeskey_t key) {
  free(key->key);
  free(key);
  return;
}


int KeyExpansion128(aeskey_t key, uint8_t w[]){
  uint8_t temp[4];
  memcpy(w, key->key, 16*sizeof(uint8_t)); 
  uint32_t *temp32 = (uint32_t *)temp;
  uint32_t *w32= (uint32_t *) w;
  temp[0]=sbox[w[13]]^Rcon[1];
  temp[1]=sbox[w[14]];
  temp[2]=sbox[w[15]];
  temp[3]=sbox[w[12]];  
  w32[4] = w32[0]^temp32[0];
  w32[5] = w32[1]^w32[4];
  w32[6] = w32[2]^w32[5];
  w32[7] = w32[3]^w32[6];
  temp[0]=sbox[w[29]]^ Rcon[2];
  temp[1]=sbox[w[30]];
  temp[2]=sbox[w[31]];
  temp[3]=sbox[w[28]];
  w32[8] = w32[4]^temp32[0];
  w32[9] = w32[5]^w32[8];
  w32[10] = w32[6]^w32[9];
  w32[11] = w32[7]^w32[10];
  temp[0]=sbox[w[45]]^Rcon[3];
  temp[1]=sbox[w[46]];
  temp[2]=sbox[w[47]];
  temp[3]=sbox[w[44]];
  w32[12] = w32[8]^temp32[0];
  w32[13] = w32[9]^w32[12];
  w32[14] = w32[10]^w32[13];
  w32[15] = w32[11]^w32[14];
  temp[0]=sbox[w[61]]^Rcon[4];
  temp[1]=sbox[w[62]];
  temp[2]=sbox[w[63]];
  temp[3]=sbox[w[60]];
  w32[16] = w32[12]^temp32[0];
  w32[17] = w32[13]^w32[16];
  w32[18] = w32[14]^w32[17];
  w32[19] = w32[15]^w32[18];
  temp[0]=sbox[w[77]]^Rcon[5];
  temp[1]=sbox[w[78]];
  temp[2]=sbox[w[79]];
  temp[3]=sbox[w[76]];
  w32[20] = w32[16]^temp32[0];
  w32[21] = w32[17]^w32[20];
  w32[22] = w32[18]^w32[21];
  w32[23] = w32[19]^w32[22];
  temp[0]=sbox[w[93]]^Rcon[6];
  temp[1]=sbox[w[94]];
  temp[2]=sbox[w[95]];
  temp[3]=sbox[w[92]];
  w32[24] = w32[20]^temp32[0];
  w32[25] = w32[21]^w32[24];
  w32[26] = w32[22]^w32[25];
  w32[27] = w32[23]^w32[26];
  temp[0]=sbox[w[109]]^Rcon[7];
  temp[1]=sbox[w[110]];
  temp[2]=sbox[w[111]];
  temp[3]=sbox[w[108]];
  w32[28] = w32[24]^temp32[0];    
  w32[29] = w32[25]^w32[28];
  w32[30] = w32[26]^w32[29];
  w32[31] = w32[27]^w32[30];
  temp[0]=sbox[w[125]]^Rcon[8];
  temp[1]=sbox[w[126]];
  temp[2]=sbox[w[127]];
  temp[3]=sbox[w[124]];
  w32[32] = w32[28]^temp32[0];    
  w32[33] = w32[29]^w32[32];
  w32[34] = w32[30]^w32[33];
  w32[35] = w32[31]^w32[34];
  temp[0]=sbox[w[141]]^Rcon[9];
  temp[1]=sbox[w[142]];
  temp[2]=sbox[w[143]];
  temp[3]=sbox[w[140]];
  w32[36] = w32[32]^temp32[0];    
  w32[37] = w32[33]^w32[36];
  w32[38] = w32[34]^w32[37];
  w32[39] = w32[35]^w32[38];
  temp[0]=sbox[w[157]]^Rcon[10];;
  temp[1]=sbox[w[158]];
  temp[2]=sbox[w[159]];
  temp[3]=sbox[w[156]];
  w32[40] = w32[36]^temp32[0];
  w32[41] = w32[37]^w32[40];
  w32[42] = w32[38]^w32[41];
  w32[43] = w32[39]^w32[42];
  return 0;
}

int KeyExpansion192(aeskey_t key, uint8_t w[]){
  uint8_t temp[4];
  memcpy(w, key->key, 24*sizeof(uint8_t)); 
  uint32_t *temp32 = (uint32_t *)temp;
  uint32_t *w32= (uint32_t *) w;

  temp[0]=sbox[w[21]]^ Rcon[1];
  temp[1]=sbox[w[22]];
  temp[2]=sbox[w[23]];
  temp[3]=sbox[w[20]];
  w32[6] = w32[0]^temp32[0];  
  w32[7] = w32[1]^w32[6];
  w32[8] = w32[2]^w32[7];
  w32[9] = w32[3]^w32[8];
  w32[10] = w32[4]^w32[9];
  w32[11] = w32[5]^w32[10];
  temp[0]=sbox[w[45]]^ Rcon[2];
  temp[1]=sbox[w[46]];
  temp[2]=sbox[w[47]];
  temp[3]=sbox[w[44]];
  w32[12] = w32[6]^temp32[0];
  w32[13] = w32[7]^w32[12];
  w32[14] = w32[8]^w32[13];
  w32[15] = w32[9]^w32[14];
  w32[16] = w32[10]^w32[15];
  w32[17] = w32[11]^w32[16];
  temp[0]=sbox[w[69]]^ Rcon[3];
  temp[1]=sbox[w[70]];
  temp[2]=sbox[w[71]];
  temp[3]=sbox[w[68]];
  w32[18] = w32[12]^temp32[0];
  w32[19] = w32[13]^w32[18];
  w32[20] = w32[14]^w32[19];
  w32[21] = w32[15]^w32[20];
  w32[22] = w32[16]^w32[21];
  w32[23] = w32[17]^w32[22];
  temp[0]=sbox[w[93]]^ Rcon[4];
  temp[1]=sbox[w[94]];
  temp[2]=sbox[w[95]];
  temp[3]=sbox[w[92]];
  w32[24] = w32[18]^temp32[0];
  w32[25] = w32[19]^w32[24];
  w32[26] = w32[20]^w32[25];
  w32[27] = w32[21]^w32[26];
  w32[28] = w32[22]^w32[27];
  w32[29] = w32[23]^w32[28];
  temp[0]=sbox[w[117]]^ Rcon[5];
  temp[1]=sbox[w[118]];
  temp[2]=sbox[w[119]];
  temp[3]=sbox[w[116]];
  w32[30] = w32[24]^temp32[0];
  w32[31] = w32[25]^w32[30];
  w32[32] = w32[26]^w32[31];
  w32[33] = w32[27]^w32[32];
  w32[34] = w32[28]^w32[33];
  w32[35] = w32[29]^w32[34];
  temp[0]=sbox[w[141]]^ Rcon[6];
  temp[1]=sbox[w[142]];
  temp[2]=sbox[w[143]];
  temp[3]=sbox[w[140]];
  w32[36] = w32[30]^temp32[0];
  w32[37] = w32[31]^w32[36];
  w32[38] = w32[32]^w32[37];
  w32[39] = w32[33]^w32[38];
  w32[40] = w32[34]^w32[39];
  w32[41] = w32[35]^w32[40];
  temp[0]=sbox[w[165]]^ Rcon[7];
  temp[1]=sbox[w[166]];
  temp[2]=sbox[w[167]];
  temp[3]=sbox[w[164]];
  w32[42] = w32[36]^temp32[0];
  w32[43] = w32[37]^w32[42];
  w32[44] = w32[38]^w32[43];
  w32[45] = w32[39]^w32[44];
  w32[46] = w32[40]^w32[45];
  w32[47] = w32[41]^w32[46];
  temp[0]=sbox[w[189]]^ Rcon[8];
  temp[1]=sbox[w[190]];
  temp[2]=sbox[w[191]];
  temp[3]=sbox[w[188]];
  w32[48] = w32[42]^temp32[0];
  w32[49] = w32[43]^w32[48];
  w32[50] = w32[44]^w32[49];
  w32[51] = w32[45]^w32[50]; 
  return 0;
}

int KeyExpansion256(aeskey_t key, uint8_t w[]){
  uint8_t temp[4];
  memcpy(w, key->key, 32*sizeof(uint8_t)); 
  uint32_t *temp32 = (uint32_t *)temp;
  uint32_t *w32= (uint32_t *) w;

  temp[0]=sbox[w[29]]^ Rcon[1];
  temp[1]=sbox[w[30]];
  temp[2]=sbox[w[31]];
  temp[3]=sbox[w[28]];
  w32[8] = w32[0]^temp32[0];  
  w32[9] = w32[1]^w32[8];
  w32[10] = w32[2]^w32[9];
  w32[11] = w32[3]^w32[10];
  temp[0]=sbox[w[44]];
  temp[1]=sbox[w[45]];
  temp[2]=sbox[w[46]];
  temp[3]=sbox[w[47]];  
  w32[12] = w32[4]^temp32[0]; 
  w32[13] = w32[5]^w32[12];
  w32[14] = w32[6]^w32[13];
  w32[15] = w32[7]^w32[14];
  temp[0]=sbox[w[61]]^ Rcon[2];
  temp[1]=sbox[w[62]];
  temp[2]=sbox[w[63]];
  temp[3]=sbox[w[60]];
  w32[16] = w32[8]^temp32[0];  
  w32[17] = w32[9]^w32[16];
  w32[18] = w32[10]^w32[17];
  w32[19] = w32[11]^w32[18];
  temp[0]=sbox[w[76]];
  temp[1]=sbox[w[77]];
  temp[2]=sbox[w[78]];
  temp[3]=sbox[w[79]];
  w32[20] = w32[12]^temp32[0]; 
  w32[21] = w32[13]^w32[20];
  w32[22] = w32[14]^w32[21];
  w32[23] = w32[15]^w32[22];
  temp[0]=sbox[w[93]]^ Rcon[3];
  temp[1]=sbox[w[94]];
  temp[2]=sbox[w[95]];
  temp[3]=sbox[w[92]];
  w32[24] = w32[16]^temp32[0];  
  w32[25] = w32[17]^w32[24];
  w32[26] = w32[18]^w32[25];
  w32[27] = w32[19]^w32[26];
  temp[0]=sbox[w[108]];
  temp[1]=sbox[w[109]];
  temp[2]=sbox[w[110]];
  temp[3]=sbox[w[111]];
  w32[28] = w32[20]^temp32[0]; 
  w32[29] = w32[21]^w32[28];
  w32[30] = w32[22]^w32[29];
  w32[31] = w32[23]^w32[30];
  temp[0]=sbox[w[125]]^ Rcon[4];
  temp[1]=sbox[w[126]];
  temp[2]=sbox[w[127]];
  temp[3]=sbox[w[124]];
  w32[32] = w32[24]^temp32[0];  
  w32[33] = w32[25]^w32[32];
  w32[34] = w32[26]^w32[33];
  w32[35] = w32[27]^w32[34];
  temp[0]=sbox[w[140]];
  temp[1]=sbox[w[141]];
  temp[2]=sbox[w[142]];
  temp[3]=sbox[w[143]];
  w32[36] = w32[28]^temp32[0]; 
  w32[37] = w32[29]^w32[36];
  w32[38] = w32[30]^w32[37];
  w32[39] = w32[31]^w32[38];
  temp[0]=sbox[w[157]]^ Rcon[5];
  temp[1]=sbox[w[158]];
  temp[2]=sbox[w[159]];
  temp[3]=sbox[w[156]];
  w32[40] = w32[32]^temp32[0];  
  w32[41] = w32[33]^w32[40];
  w32[42] = w32[34]^w32[41];
  w32[43] = w32[35]^w32[42];
  temp[0]=sbox[w[172]];
  temp[1]=sbox[w[173]];
  temp[2]=sbox[w[174]];
  temp[3]=sbox[w[175]];
  w32[44] = w32[36]^temp32[0]; 
  w32[45] = w32[37]^w32[44];
  w32[46] = w32[38]^w32[45];
  w32[47] = w32[39]^w32[46];
  temp[0]=sbox[w[189]]^ Rcon[6];
  temp[1]=sbox[w[190]];
  temp[2]=sbox[w[191]];
  temp[3]=sbox[w[188]];
  w32[48] = w32[40]^temp32[0];
  w32[49] = w32[41]^w32[48];
  w32[50] = w32[42]^w32[49];
  w32[51] = w32[43]^w32[50];
  temp[0]=sbox[w[204]];
  temp[1]=sbox[w[205]];
  temp[2]=sbox[w[206]];
  temp[3]=sbox[w[207]];
  w32[52] = w32[44]^temp32[0]; 
  w32[53] = w32[45]^w32[52];
  w32[54] = w32[46]^w32[53];
  w32[55] = w32[47]^w32[54];
  temp[0]=sbox[w[221]]^ Rcon[7];
  temp[1]=sbox[w[222]];
  temp[2]=sbox[w[223]];
  temp[3]=sbox[w[220]];
  w32[56] = w32[48]^temp32[0];
  w32[57] = w32[49]^w32[56];
  w32[58] = w32[50]^w32[57];
  w32[59] = w32[51]^w32[58];
 
  return 0;
}

int KeyExpansion(aeskey_t key, uint8_t w[]){
  int i;
  uint8_t temp[4];
  uint8_t tmp;
  unsigned short Nk = key->Nk;
  unsigned short Nr= key->Nr;
  memcpy(w, key->key, 4*Nk*sizeof(uint8_t));
  uint32_t *temp32 = (uint32_t *)temp;
  uint32_t *w32= (uint32_t *) w; 
  for (i=Nk; i<4*(Nr+1); i++){
    temp32[0]=w32[i-1];    
    if ((i % Nk) == 0) {
      tmp = temp[0];
      temp[0]=sbox[temp[1]];
      temp[1]=sbox[temp[2]];
      temp[2]=sbox[temp[3]];
      temp[3]=sbox[tmp];
      temp[0] ^= Rcon[i/Nk];
    } else if ((Nk==8) && ((i%Nk)==4)) {
      temp[0]= sbox[temp[0]];
      temp[1]= sbox[temp[1]];
      temp[2]= sbox[temp[2]];
      temp[3]= sbox[temp[3]];
    }
    w32[i] = w32[i-Nk]^temp32[0];
  }
  return 0;
}

void AES_encrypt(uint8_t plain[], uint8_t cipher[], aeskey_t key) {
  int k;
  uint8_t *w;
  w=calloc(key->wLen, sizeof(uint8_t));
  /* KeyExpansion(key, w);*/
  if ((key->Nk) ==4) {
    KeyExpansion128(key, w);
  } else if ((key->Nk) ==6) {
    KeyExpansion192(key, w);
  } else if ((key->Nk) ==8) {
    KeyExpansion256(key, w);
  } else {
    KeyExpansion(key, w);
  }
  uint64_t * rkey = (uint64_t *) w;
  memcpy(cipher, plain, 16*sizeof(uint8_t));
  uint64_t *state= (uint64_t *) cipher;
  state[0] ^= rkey[0];
  state[1] ^= rkey[1];
  uint8_t a[16];
  for (k=1; k<key->Nr; k++) {
    a[0]=sbox[cipher[0]];
    a[1]=sbox[cipher[4]];
    a[2]=sbox[cipher[8]];
    a[3]=sbox[cipher[12]];
    a[4]=sbox[cipher[5]];
    a[5]=sbox[cipher[9]];
    a[6]=sbox[cipher[13]];
    a[7]=sbox[cipher[1]];
    a[8]=sbox[cipher[10]];
    a[9]=sbox[cipher[14]];
    a[10]=sbox[cipher[2]];
    a[11]=sbox[cipher[6]];
    a[12]=sbox[cipher[15]];
    a[13]=sbox[cipher[3]];
    a[14]=sbox[cipher[7]];
    a[15]=sbox[cipher[11]];
    /*
    for (i=0; i<4; i++) {
      for(j=0;j<4;j++) {
	b[j]= ((a[4*j+i]<<1) ^ (0x1B & (uint8_t)((signed char) a[4*j+i] >> 7)));
      }
      cipher[4*i] = b[0] ^ a[12+i] ^ a[8+i] ^ b[1] ^ a[4+i];
      cipher[4*i+1] = b[1] ^ a[i] ^ a[12+i] ^ b[2] ^ a[8+i];
      cipher[4*i+2] = b[2] ^ a[4+i] ^ a[i] ^ b[3] ^ a[12+i];
      cipher[4*i+3] = b[3] ^ a[8+i] ^ a[4+i] ^ b[0] ^ a[i];
    }
    */
    cipher[0] = times2[a[0]] ^ a[12] ^ a[8] ^ times3[a[4]];
    cipher[1] = times2[a[4]] ^ a[0] ^ a[12] ^ times3[a[8]];
    cipher[2] = times2[a[8]] ^ a[4] ^ a[0] ^ times3[a[12]];
    cipher[3] = times2[a[12]] ^ a[8] ^ a[4] ^ times3[a[0]];
    cipher[4] = times2[a[1]] ^ a[13] ^ a[9] ^ times3[a[5]];
    cipher[5] = times2[a[5]] ^ a[1] ^ a[13] ^ times3[a[9]];
    cipher[6] = times2[a[9]] ^ a[5] ^ a[1] ^ times3[a[13]];
    cipher[7] = times2[a[13]] ^ a[9] ^ a[5] ^ times3[a[1]];	
    cipher[8] = times2[a[2]] ^ a[14] ^ a[10] ^ times3[a[6]];
    cipher[9] = times2[a[6]] ^ a[2] ^ a[14] ^ times3[a[10]];
    cipher[10] = times2[a[10]] ^ a[6] ^ a[2] ^ times3[a[14]];
    cipher[11] = times2[a[14]] ^ a[10] ^ a[6] ^ times3[a[2]];
    cipher[12] = times2[a[3]] ^ a[15] ^ a[11] ^ times3[a[7]];
    cipher[13] = times2[a[7]] ^ a[3] ^ a[15] ^ times3[a[11]];
    cipher[14] = times2[a[11]] ^ a[7] ^ a[3] ^ times3[a[15]];
    cipher[15] = times2[a[15]] ^ a[11] ^ a[7] ^ times3[a[3]];
    state[0] ^= rkey[2*k];
    state[1] ^= rkey[2*k+1];
  }
  uint8_t tmp;
  cipher[0]=sbox[cipher[0]];
  cipher[4]=sbox[cipher[4]];
  cipher[8]=sbox[cipher[8]];
  cipher[12]=sbox[cipher[12]];
  tmp=cipher[1];
  cipher[1]=sbox[cipher[5]];
  cipher[5]=sbox[cipher[9]];
  cipher[9]=sbox[cipher[13]];
  cipher[13]=sbox[tmp];
  tmp = cipher[2];
  cipher[2]=sbox[cipher[10]];
  cipher[10]=sbox[tmp];
  tmp = cipher[6];
  cipher[6]=sbox[cipher[14]];
  cipher[14]=sbox[tmp];
  tmp=cipher[15];
  cipher[15]=sbox[cipher[11]];
  cipher[11]=sbox[cipher[7]];
  cipher[7]=sbox[cipher[3]];
  cipher[3]=sbox[tmp];
  state[0] ^= rkey[2*(key->Nr)];
  state[1] ^= rkey[2*(key->Nr)+1];
  free(w);
  return;
}

void AES_encryptV1(uint8_t plain[], uint8_t cipher[], aeskey_t key) {
  int i,j,k;
  uint8_t *w;
  w=calloc(key->wLen, sizeof(uint8_t));
  KeyExpansion(key, w);
  uint64_t * rkey = (uint64_t *) w;
  memcpy(cipher, plain, 16*sizeof(uint8_t));
  uint64_t *state= (uint64_t *) cipher;
  state[0] ^= rkey[0];
  state[1] ^= rkey[1];
  uint8_t a[4][4];
  uint8_t b[4];
  for (k=1; k<key->Nr; k++) {
    a[0][0]=sbox[cipher[0]];
    a[0][1]=sbox[cipher[4]];
    a[0][2]=sbox[cipher[8]];
    a[0][3]=sbox[cipher[12]];
    a[1][0]=sbox[cipher[5]];
    a[1][1]=sbox[cipher[9]];
    a[1][2]=sbox[cipher[13]];
    a[1][3]=sbox[cipher[1]];
    a[2][0]=sbox[cipher[10]];
    a[2][1]=sbox[cipher[14]];
    a[2][2]=sbox[cipher[2]];
    a[2][3]=sbox[cipher[6]];
    a[3][0]=sbox[cipher[15]];
    a[3][1]=sbox[cipher[3]];
    a[3][2]=sbox[cipher[7]];
    a[3][3]=sbox[cipher[11]];
    if (TABLE4MIXCOLUMN ==0){
      for (i=0; i<4; i++) {
	for(j=0;j<4;j++) {
	  b[j]= ((a[j][i]<<1) ^ (0x1B & (uint8_t)((signed char) a[j][i] >> 7)));
	}
	cipher[4*i] = b[0] ^ a[3][i] ^ a[2][i] ^ b[1] ^ a[1][i];
	cipher[4*i+1] = b[1] ^ a[0][i] ^ a[3][i] ^ b[2] ^ a[2][i];
	cipher[4*i+2] = b[2] ^ a[1][i] ^ a[0][i] ^ b[3] ^ a[3][i];
	cipher[4*i+3] = b[3] ^ a[2][i] ^ a[1][i] ^ b[0] ^ a[0][i];
      }
    } else {
      for (i=0; i<4; i++) {
	cipher[4*i]   = times2[a[0][i]] ^ a[3][i] ^ a[2][i] ^ times3[a[1][i]];
	cipher[4*i+1] = times2[a[1][i]] ^ a[0][i] ^ a[3][i] ^ times3[a[2][i]];
	cipher[4*i+2] = times2[a[2][i]] ^ a[1][i] ^ a[0][i] ^ times3[a[3][i]];
	cipher[4*i+3] = times2[a[3][i]] ^ a[2][i] ^ a[1][i] ^ times3[a[0][i]];
      }
    }
    state[0] ^= rkey[2*k];
    state[1] ^= rkey[2*k+1];
  }
  uint8_t tmp;
  cipher[0]=sbox[cipher[0]];
  cipher[4]=sbox[cipher[4]];
  cipher[8]=sbox[cipher[8]];
  cipher[12]=sbox[cipher[12]];
  tmp=cipher[1];
  cipher[1]=sbox[cipher[5]];
  cipher[5]=sbox[cipher[9]];
  cipher[9]=sbox[cipher[13]];
  cipher[13]=sbox[tmp];
  tmp = cipher[2];
  cipher[2]=sbox[cipher[10]];
  cipher[10]=sbox[tmp];
  tmp = cipher[6];
  cipher[6]=sbox[cipher[14]];
  cipher[14]=sbox[tmp];
  tmp=cipher[15];
  cipher[15]=sbox[cipher[11]];
  cipher[11]=sbox[cipher[7]];
  cipher[7]=sbox[cipher[3]];
  cipher[3]=sbox[tmp];
  state[0] ^= rkey[2*(key->Nr)];
  state[1] ^= rkey[2*(key->Nr)+1];
  free(w);
  return;
}

static void InvShiftRows(uint8_t plain[]) {
  uint8_t tmp;
  plain[0]=Invsbox[plain[0]];
  plain[4]=Invsbox[plain[4]];
  plain[8]=Invsbox[plain[8]];
  plain[12]=Invsbox[plain[12]];
  /* row 1 */
  tmp=plain[13];
  plain[13]=Invsbox[plain[9]];
  plain[9]=Invsbox[plain[5]];
  plain[5]=Invsbox[plain[1]];
  plain[1]=Invsbox[tmp];
   /* row 2 */
  tmp = plain[2];
  plain[2]=Invsbox[plain[10]];
  plain[10]=Invsbox[tmp];
  tmp = plain[6];
  plain[6]=Invsbox[plain[14]];
  plain[14]=Invsbox[tmp];
  /* row 3 */
  tmp=plain[3];
  plain[3]=Invsbox[plain[7]];
  plain[7]=Invsbox[plain[11]];
  plain[11]=Invsbox[plain[15]];
  plain[15]=Invsbox[tmp];
}

static uint8_t f256times2(uint8_t a) {
  return ((a<<1) ^ (0x1B & (uint8_t)((signed char) a >> 7)));
}

static uint8_t f256mul(uint8_t b, uint8_t a) {
  switch(b) {
  case 0x09:
    return f256times2(f256times2(f256times2(a))) ^ a;
  case 0x0b:
    return f256times2(a^f256times2(f256times2(a))) ^a;
  case 0x0d:
    return f256times2(f256times2(a^f256times2(a))) ^a;
  case 0x0e:
    return f256times2(a^f256times2(a^f256times2(a)));
  }
  return '\0';
}


static void InvMixColumns(uint8_t plain[]) {
  int i;
  uint8_t a[4];    
  for (i=0; i<4; i++) {
    memcpy(a, plain+4*i, 4*sizeof(uint8_t));
    plain[4*i]   = f256mul(0x0e,a[0])^f256mul(0x0b,a[1])^f256mul(0x0d,a[2])^f256mul(0x09,a[3]);
    plain[4*i+1] = f256mul(0x09,a[0])^f256mul(0x0e,a[1])^f256mul(0x0b,a[2])^f256mul(0x0d,a[3]); 
    plain[4*i+2] = f256mul(0x0d,a[0])^f256mul(0x09,a[1])^f256mul(0x0e,a[2])^f256mul(0x0b,a[3]);
    plain[4*i+3] = f256mul(0x0b,a[0])^f256mul(0x0d,a[1])^f256mul(0x09,a[2])^f256mul(0x0e,a[3]);
  }
}


void AES_decrypt(uint8_t cipher[], uint8_t plain[], aeskey_t key) {
  int i;
  uint8_t *w;
  w=calloc(key->wLen, sizeof(uint8_t));
  if ((key->Nk) ==4) {
    KeyExpansion128(key, w);
  } else if ((key->Nk) ==6) {
    KeyExpansion192(key, w);
  } else if ((key->Nk) ==8) {
    KeyExpansion256(key, w);
  } else {
    KeyExpansion(key, w);
  }
  /* KeyExpansion(key, w);*/
  uint64_t * rkey = (uint64_t *) w;
  memcpy(plain, cipher, 16*sizeof(uint8_t));
  uint64_t *state= (uint64_t *) plain;
  state[0] ^= rkey[2*(key->Nr)];
  state[1] ^= rkey[2*(key->Nr)+1];
  InvShiftRows(plain);
  for(i=key->Nr-1;i>0;i--)  {
    state[0] ^= rkey[2*i];
    state[1] ^= rkey[2*i+1];
    InvMixColumns(plain);
    InvShiftRows(plain);
  }
  state[0] ^= rkey[0];
  state[1] ^= rkey[1];
  free(w);
  return;
}
