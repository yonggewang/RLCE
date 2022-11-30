/* drbg.c
 *
 * Code was written: January 21, 2017-January 25, 2017 
 *
 * drbg.c implements Hash_DRBG and CTR_DRBG for RLCE
 * http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-90Ar1.pdf
 *
 * This code is for prototype purpose only and is not optimized
 *
 * Copyright (C) 2017 Yongge Wang
 * 
 * Yongge Wang
 * Department of Software and Information Systems
 * UNC Charlotte
 * Charlotte, NC 28223
 * yonwang@uncc.edu
 *
 * For Hash_DRBG, max_number_of_bits_per_request is:
 * 2^19 bits = 2^16 Bytes = 64KB
 * 
 * Maximum number of requests between reseeds (reseed_interval) is:
 * 2^48. In orhter words, for each seed, Hash_DBRG can 
 * generate 2^48*2^16 bytes =2^54 KB = 2^44 MB = 2^34 GB
 * for this prototype implementation, we do not expect
 * more than 2^34 GB random bits needed, so no reseeding 
 * process is implemented. For product version, the user
 * may choose to implement full version of NIST DRBG.
 * outlen = 160; for SHA1 
 * outlen = 256; for SHA-256
 * outlen = 512; for SHA-512 
 * 
 * seedlen for Hash_DRBG:
 * seedlen = 440 (SHA1), 440 (SHA256), 888 (SHA512)
 *
 * Maximum entropy input length (max_ length):
 * 2^35 bits = 2^32 bytes=2^22 KB = 2^12 MB = 4GB
 * max_personalization_string_length=2^35
 * max_additional_input_length=2^35
 *
 * for CTR_DRBG, we only implemented AES-128,192,256 based CTR_DRBG.
 * CTR_DRBG has the following requirements:
 * 1. 4<= ctr_len <= blocklen (=128 for AES)
 * 2. seedlen = outlen+keylen: 256 (32) (AES-128), 320 (40) (AES-192), 384 (48) (AES-256)
 *    that is, seedlen=block_length + key length. For AES, blocklen=16byte
 * 3. minimum entropy length: seedlen
 * 4. max_number_of_bits_per_request is: min(B, 2^19)
 *    where B = (2^ctr_len -4)*128. 
 * 5. Maximum number of requests between reseeds is: 2^48
 * 6. DF is optional for CTR_DRBG (which is mandatory for Hash_DRBG).
 * 7. when DF is not used, the only needed strings are: entropy and personal string.
 *    both of them should be seedlen bytes
 * 8. when DF is used, the input could contain: entropy, personal string, and nonce
 * 9. For reseed, both (w/DF or wo/DF) requires: entropy/additionalinput: seedlen/0 long
 *    difference: wo/DF, both seedlen/0 bytes. w/DF, arbitrary long
 * 10. each time when generate random bits, one could provide additioanal string
 *    where it must be seedlen (or zero) for wo/DF and arbitrary for w/DF.
 * 
 */

#include "rlce.h"

/* num1: a big integer
 * num2: a big integer
 * require: num1len >= num2len
 * return: num1=num1+num2
 * all numbers are in interpreted as: num[0] most significant bits
 */
void big_add(uint8_t num1[], int num1len,
	     uint8_t num2[], int num2len) {
  unsigned short carry=0;
  unsigned short d=num1len-num2len;    
  int i=0;
  for (i=num2len-1; i>=0; i--){
    carry +=num1[i+d]+num2[i];
    num1[i+d]=carry & 0xFF;
    carry = (carry>>8); 
  }
  for (i=d-1; i>=0; i--){
    if (carry==0) {
      return;
    } else {
      carry=num1[i]+1;
      num1[i]=carry & 0xFF;
      carry=(carry>>8); 
    }
  }
  return;
}

void hashTObytes(uint8_t bytes[], int bSize, size_t hash[]) {
  int i=0;
  for (i=0; i<bSize; i++) bytes[i] = (hash[i/4]>>(24-(i%4)*8)) & 0xFF;
}

void hash512TObytes(uint8_t bytes[], int bSize, unsigned long hash512[]) {
  int i = 0;
  for (i=0; i<bSize; i++) bytes[i] = (hash512[i/8]>>(56-(i%8)*8)) & 0xFF;  
}


void free_drbg_state(hash_drbg_state_t drbgState) {
  free(drbgState->V);
  free(drbgState->C);
  free(drbgState);
  return;
}

hash_drbg_state_t drbgstate_init(int shatype) {
  hash_drbg_state_t drbgstate;
  drbgstate = (hash_drbg_state_t) malloc(sizeof (struct hash_drbg_state));
  drbgstate->hashSize=0;
  drbgstate->shatype = shatype;  
  if (shatype == 0) {
    drbgstate->seedlen = 55; 
    drbgstate->security_strength=112;
    drbgstate->hashSize=5;
  } else if (shatype == 1) {
    drbgstate->seedlen = 55;
    drbgstate->security_strength=128;
    drbgstate->hashSize=8;
  } else if (shatype == 2) {
    drbgstate->seedlen = 111; 
    drbgstate->security_strength=256;
    drbgstate->hashSize=8;
  }
  drbgstate->pf_flag = 0;
  drbgstate->reseed_interval = (1ul << 48);
  drbgstate->max_B_per_req = 65536;
  drbgstate->reseed_counter=0;
  drbgstate->V = (uint8_t*) calloc(drbgstate->seedlen, sizeof(uint8_t));
  drbgstate->C = (uint8_t*) calloc(drbgstate->seedlen, sizeof(uint8_t));
  return drbgstate;
}


drbg_Input_t drbgInput_init(uint8_t entropy[],int entropylen,
			    uint8_t nonce[],int noncelen,
			    uint8_t personalization_string[],int perslen,
			    uint8_t additional_input[], int addlen) {
  drbg_Input_t drbgInput;
  drbgInput = (drbg_Input_t) malloc(sizeof (struct drbg_Input));
  drbgInput->entropylen = entropylen;
  drbgInput->noncelen = noncelen;
  drbgInput->perslen = perslen;
  drbgInput->addlen = addlen;
  
  drbgInput->entropy=entropy;
  drbgInput->nonce=nonce;
  drbgInput->personalization_string =personalization_string;
  drbgInput->additional_input=additional_input;
  
  return drbgInput;
}

void free_drbg_input(drbg_Input_t drbgInput) {
  free(drbgInput);
  return;
}


int drbg_hash_df(int shatype,uint8_t input[],int inputlen,
		  uint8_t output[], int outputlen){
  /* implements NIST.SP800-90Ar1 Section 10.3.1 Hash_df */

  uint8_t seed[inputlen+5];
  memcpy(&seed[5], input, inputlen);
  size_t outputlenBits = 8*outputlen;

  seed[4]=0xFF & outputlenBits;
  seed[3]=0xFF & (outputlenBits>>8);
  seed[2]=0xFF & (outputlenBits>>16);
  seed[1]=0xFF & (outputlenBits>>24);
  seed[0]=0x01;
  int hashSize=0;
  void (*sha)(uint8_t[], int, size_t[]);
  if (shatype ==0) {
    hashSize = 5;
    sha = sha1_md;
  } else if (shatype == 1) {
    hashSize = 8;
    sha = sha256_md;
  } else if (shatype == 2) {
    hashSize = 8;
  } else {
    return SHATYPENOTSUPPORTED;
  }
  size_t hash[hashSize];
  int ctr = 0;
  int i;
   
  if  ((shatype==0) || (shatype==1)) {
    ctr =  4 * hashSize;
    for (i=0; i<outputlen; i++) {
      if (ctr== 4 * hashSize) {
	(*sha)(seed, inputlen+5, hash);
	seed[0]++;
	ctr=0;
      }
      output[i] = (hash[ctr/4]>>(24-(ctr%4)*8)) & 0xFF;
      ctr++;
    }
  } else if (shatype ==2 ) {
    ctr =  8 * hashSize;
    unsigned long hash512[hashSize];
    for (i=0; i<outputlen; i++) {
      if (ctr== 8 * hashSize) {
	sha512_md(seed, inputlen+5, hash512);
	seed[0]++;
	ctr=0;
      }
      output[i] = (hash512[ctr/8]>>(56-(ctr%8)*8)) & 0xFF;
      ctr++;
    }   
  }
  
  return 0;  
}

int hash_DRBG_Instantiate(hash_drbg_state_t drbgState, drbg_Input_t drbgInput){
  int ret = 0;
  int seed_material_len=drbgInput->entropylen+drbgInput->noncelen+drbgInput->perslen;
  uint8_t seed_material[seed_material_len];
  memcpy(seed_material,drbgInput->entropy, drbgInput->entropylen);
  memcpy(&(seed_material[drbgInput->entropylen]),drbgInput->nonce, drbgInput->noncelen);
  if (!(drbgInput->perslen == 0)) {
    memcpy(&(seed_material[drbgInput->entropylen+drbgInput->noncelen]),
	   drbgInput->personalization_string, drbgInput->perslen);
  }
  ret = drbg_hash_df(drbgState->shatype, seed_material, seed_material_len, drbgState->V, drbgState->seedlen);
  if (ret<0) return ret;
  uint8_t seedC[drbgState->seedlen+1];
  seedC[0]=0x00;
  memcpy(&(seedC[1]),drbgState->V, drbgState->seedlen);
  ret = drbg_hash_df(drbgState->shatype, seedC, drbgState->seedlen+1, drbgState->C, drbgState->seedlen);
  drbgState->reseed_counter=1;
  return ret;
}


/* implement "Hash_DRBG_Generate Process" in NIST SP800-90Ar1 Section 10.1.1.4 */
int hash_DRBG_Generate(hash_drbg_state_t drbgState,drbg_Input_t drbgInput,
		       uint8_t returned_bytes[],
		       long unsigned req_no_of_bytes) {
  int i,j,ret = 0;
  if (drbgState->reseed_counter > drbgState->reseed_interval){
    return DRBGRESEEDREQUIRED;
  }
  void (*sha)(uint8_t[], int, size_t[]);
  sha = 0;
  if (drbgState->shatype == 0) {
    sha = sha1_md;
  } else if (drbgState->shatype == 1) {
    sha = sha256_md;
  }

  int hashSize = drbgState->hashSize;
  uint8_t wseed[1+drbgState->seedlen+drbgInput->addlen];
  size_t w[hashSize];
  uint8_t wBytes[4*(drbgState->hashSize)];
  unsigned long w512[hashSize];
  uint8_t w512Bytes[8*hashSize];
  if (drbgInput->addlen> 0) {
    wseed[0]= 0x02;
    memcpy(&(wseed[1]), drbgState->V, drbgState->seedlen);
    memcpy(&(wseed[1+drbgState->seedlen]), drbgInput->additional_input, drbgInput->addlen);
    if  ((drbgState->shatype==0) || (drbgState->shatype==1)) {
      (*sha)(wseed, drbgState->seedlen+1+drbgInput->addlen, w);
      hashTObytes(wBytes, 4*hashSize, w);
      big_add(drbgState->V, drbgState->seedlen, wBytes, 4*hashSize);
      /* V = V+w mod 2^seedlen */
    } else if (drbgState->shatype ==2 ) {
      sha512_md(wseed, drbgState->seedlen+1+drbgInput->addlen, w512);
      for (i=0; i<64; i++) w512Bytes[i] = (w512[i/8]>>(56-(i%8)*8)) & 0xFF;
      big_add(drbgState->V, drbgState->seedlen, w512Bytes, 8*hashSize);
      /*  V = V+w512 mod 2^seedlen */
    }
  }
  
  /* the following implements Hashgen Process: for 
   *(returned_bits) = Hashgen (requested_number_of_bits, V). 
   */
  if (req_no_of_bytes>drbgState->max_B_per_req) {
    return DRBGREQ2MANYB;
  }
  uint8_t data[drbgState->seedlen];
  memcpy(data, drbgState->V, drbgState->seedlen);
  
  int m = 0;
  uint8_t one[1]={0x01};
  int remainedBytes = 0;
  uint8_t tmp[8*(drbgState->hashSize)];
  if  ((drbgState->shatype==0) || (drbgState->shatype==1)) {
    m = (req_no_of_bytes/(4*(drbgState->hashSize)));
    for (i=0; i<m;i++){
      (*sha)(data, drbgState->seedlen, w);
      big_add(data, drbgState->seedlen, (uint8_t *)&one, 1);
      hashTObytes(&(returned_bytes[i*4*(drbgState->hashSize)]), 4*(drbgState->hashSize), w);
    }
    remainedBytes=req_no_of_bytes%(4*(drbgState->hashSize));
    if (remainedBytes>0) {
      (*sha)(data, drbgState->seedlen, w);
      hashTObytes(tmp, 4*(drbgState->hashSize), w);
      memcpy(&(returned_bytes[m*4*(drbgState->hashSize)]), tmp, remainedBytes);
    }
    
  } else if (drbgState->shatype ==2 ) {
    m=(req_no_of_bytes/(8*(drbgState->hashSize)));
    for (i=0; i<m;i++){
      sha512_md(data, drbgState->seedlen, w512);
      big_add(data, drbgState->seedlen, (uint8_t *)&one, 1);
      for (j=0;j<64;j++) returned_bytes[i*64+j]=(w512[j/8]>>(56-(j%8)*8))&0xFF;
    }
    remainedBytes=req_no_of_bytes%(8*(drbgState->hashSize));
    if (remainedBytes>0) {
      sha512_md(data, drbgState->seedlen, w512);
      for (i=0; i<64; i++) tmp[i] = (w512[i/8]>>(56-(i%8)*8)) & 0xFF;  
      memcpy(&(returned_bytes[m*8*(drbgState->hashSize)]), tmp, remainedBytes);
    }
  }  
  /* end of Hashgen */
  

  uint8_t hseed[1+drbgState->seedlen];
  size_t h[drbgState->hashSize];
  uint8_t hBytes[4*(drbgState->hashSize)];
  unsigned long h512[drbgState->hashSize];
  uint8_t h512Bytes[8*(drbgState->hashSize)];
  uint8_t reseedByte[4];
  reseedByte[0]=((drbgState->reseed_counter) >>24) & 0xFF;
  reseedByte[1]=((drbgState->reseed_counter) >>16) & 0xFF;
  reseedByte[2]=((drbgState->reseed_counter) >>8) & 0xFF;
  reseedByte[3]=(drbgState->reseed_counter) & 0xFF;
  hseed[0]= 0x03;
  memcpy(&(hseed[1]), drbgState->V, drbgState->seedlen);
  if  ((drbgState->shatype==0) || (drbgState->shatype==1)) {
    (*sha)(hseed, drbgState->seedlen+1, h);
    hashTObytes(hBytes, 4*(drbgState->hashSize), h);    
    big_add(drbgState->V, drbgState->seedlen, hBytes, 4*(drbgState->hashSize));
    big_add(drbgState->V, drbgState->seedlen, drbgState->C, drbgState->seedlen);
    big_add(drbgState->V, drbgState->seedlen, reseedByte, 4);
    /* V = V+C+reseed_counter+H mod 2^seedlen */
  } else if (drbgState->shatype ==2 ) {
    sha512_md(hseed, drbgState->seedlen+1, h512);
    for (i=0; i<64; i++)h512Bytes[i] = (h512[i/8]>>(56-(i%8)*8)) & 0xFF; 
    big_add(drbgState->V, drbgState->seedlen, h512Bytes, 8*(drbgState->hashSize));
    big_add(drbgState->V, drbgState->seedlen, drbgState->C, drbgState->seedlen);
    big_add(drbgState->V, drbgState->seedlen, reseedByte, 4);
    /*  V = V+C+reseed_counter+H512 mod 2^seedlen */
  }  
  (drbgState->reseed_counter)++;
  return ret;
}


/* implements NIST SP800-90 Section 10.1.1.3: Hash_DRBG Reseed Process */
int hash_DRBG_Reseed(hash_drbg_state_t drbgState, drbg_Input_t drbgInput){
  int ret=0;
  int seed_material_len=1+drbgState->seedlen+drbgInput->entropylen+drbgInput->addlen;
  uint8_t seed_material[seed_material_len];
  seed_material[0]=0x01;
  memcpy(&(seed_material[1]),drbgState->V, drbgState->seedlen);
  memcpy(&(seed_material[1+drbgState->seedlen]),drbgInput->entropy, drbgInput->entropylen);
  if (drbgInput->addlen >0) {
    memcpy(&(seed_material[1+drbgState->seedlen+drbgInput->entropylen]),
	   drbgInput->additional_input, drbgInput->addlen);
  }
  
  uint8_t seed[drbgState->seedlen];
  ret = drbg_hash_df(drbgState->shatype, seed_material, seed_material_len, seed, drbgState->seedlen);
  if (ret<0) {
    return ret;
  }
  memcpy(drbgState->V,seed, drbgState->seedlen);
  uint8_t seedC[drbgState->seedlen+1];
  seedC[0]=0x00;
  memcpy(&(seedC[1]),drbgState->V, drbgState->seedlen);  
  ret = drbg_hash_df(drbgState->shatype, seedC, drbgState->seedlen+1,
		     drbgState->C, drbgState->seedlen);
  drbgState->reseed_counter=1;
  return ret;
}


int hash_DRBG(hash_drbg_state_t drbgState, drbg_Input_t drbgInput,
	      uint8_t output[], unsigned long outlen){
  int ret = 0;
  int i = 0;

  /* 10.1.1.2 Instantiation of Hash_DRBG */
  ret= hash_DRBG_Instantiate(drbgState, drbgInput);  
  if (ret<0) return ret;
  int loop = outlen/(drbgState->max_B_per_req);
  int rem= outlen%(drbgState->max_B_per_req);
  
  uint8_t returned_bytes[drbgState->max_B_per_req];  
  for (i=0; i<loop; i++) {
    ret=hash_DRBG_Generate(drbgState, drbgInput, &(output[i*(drbgState->max_B_per_req)]),drbgState->max_B_per_req);
    if (ret<0) return ret;
  }
  
  if (rem >0) {
    ret=hash_DRBG_Generate(drbgState, drbgInput,returned_bytes, rem);
    if (ret<0) return ret;
    memcpy(&(output[loop*(drbgState->max_B_per_req)]), returned_bytes, rem);
  }
  return ret;
}



/* the following is for CTR_DRBG implementation */
/************************************************/
ctr_drbg_state_t ctr_drbgstate_init(unsigned short aestype) {
  ctr_drbg_state_t ctr_drbgstate;
  ctr_drbgstate = (ctr_drbg_state_t) malloc(sizeof (struct ctr_drbg_state));
  ctr_drbgstate->aestype = aestype;  
  if (aestype == 128) {
    ctr_drbgstate->seedlen = 32; /* 256/8: this is for non-DF, in DF function, will be reduced*/ 
    ctr_drbgstate->security_strength=128;
  } else if (aestype == 192) {
    ctr_drbgstate->seedlen = 40; /* 320/8 */
    ctr_drbgstate->security_strength=192;
  } else if (aestype == 256) {
    ctr_drbgstate->seedlen = 48; /* 384/8 */
    ctr_drbgstate->security_strength=256;
  }
  ctr_drbgstate->ctr_len=16;
  ctr_drbgstate->reseed_interval = (1ul << 48);
  ctr_drbgstate->max_B_per_req = 65536;
  ctr_drbgstate->pf_flag = 0;
  ctr_drbgstate->reseed_counter=0;
  ctr_drbgstate->V = (uint8_t*) calloc(16, sizeof(uint8_t));
  ctr_drbgstate->Key = (uint8_t*) calloc(aestype/8, sizeof(uint8_t));
  return ctr_drbgstate;
}

void free_ctr_drbg_state(ctr_drbg_state_t ctr_drbgState) {
  free(ctr_drbgState->V);
  free(ctr_drbgState->Key);
  free(ctr_drbgState);
  return;
}

int BCC(aeskey_t key, uint8_t data[], size_t datalen, uint8_t output[]) {
  if (datalen%16 !=0) {
    return -500;
  }
  memset(output, 0, 16*sizeof(uint8_t));/* output used for chaining_value in 10.3.3 */
  int n = datalen/16;
  int i;
  uint8_t input_block[16];
  unsigned long long * output_long = (unsigned long long*) output;
  unsigned long long * data_long = (unsigned long long*) data;
  unsigned long long * input_long = (unsigned long long*) input_block;
  for (i=0; i<n; i++) {
    input_long[0] = output_long[0] ^ data_long[2*i];
    input_long[1] = output_long[1] ^ data_long[2*i+1];
    AES_encrypt(input_block, output, key);
  }
  return 0;
}
int block_cipher_df(int aestype,uint8_t input[], uint32_t inputlen,
		    uint8_t output[], uint32_t outputlen){
  /* implements NIST.SP800-90Ar1 Section 10.3.2 Block_Cipher_df */

  if (outputlen > 64) {
    return OUTPUTLENTOOLONG;
  }
  int sLen = 9+inputlen;
  if ((sLen%16)>0) {
    sLen = sLen + 16-(sLen%16);
  }
  uint8_t S[sLen];
  memset(S, 0, sLen*sizeof(uint8_t));
  S[0]=(inputlen>>24) & 0xFF;
  S[1]=(inputlen>>16) & 0xFF;
  S[2]=(inputlen>>8) & 0xFF;
  S[3]=inputlen & 0xFF;
  S[4]=(outputlen>>24) & 0xFF;
  S[5]=(outputlen>>16) & 0xFF;
  S[6]=(outputlen>>8) & 0xFF;
  S[7]=outputlen & 0xFF;
  memcpy(&(S[8]), input, inputlen*sizeof(uint8_t));
  S[8+inputlen]=0x80;
  aeskey_t key = aeskey_init(aestype);
  uint8_t temp[key->keylen+24];
  long unsigned tempLen =0;
  uint8_t IV[16+sLen];
  memset(IV, 0, 16*sizeof(uint8_t));
  uint32_t i=0;
  const uint8_t *Kf =(uint8_t *)"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f";
  memcpy(key->key, Kf, (key->keylen)*sizeof(uint8_t));
  memcpy(&(IV[16]), S, sLen*sizeof(uint8_t));
  while (tempLen < key->keylen+16) {
    IV[0]=(i>>24) & 0xFF;
    IV[1]=(i>>16) & 0xFF;
    IV[2]=(i>>8) & 0xFF;
    IV[3]=i & 0xFF;
    BCC(key, IV, 16+sLen, &temp[tempLen]);
    tempLen += 16;
    i++;
  }
  memcpy(key->key, temp, (key->keylen)*sizeof(uint8_t));
  uint8_t X[16];
  memcpy(X, &(temp[key->keylen]), 16*sizeof(uint8_t));

  uint8_t newtemp[outputlen+16];
  memset(newtemp, 0, (outputlen+16)*sizeof(uint8_t));
  size_t newtempLen=0;
  while (newtempLen<outputlen) {
    AES_encrypt(X, &(newtemp[newtempLen]), key);
    memcpy(X, &(newtemp[newtempLen]), 16*sizeof(uint8_t));
    newtempLen += 16;
  }
  aeskey_free(key);
  memcpy(output, newtemp, outputlen*sizeof(uint8_t));
  return 0;
}

/* implements 10.2.1.2 The Update Function (CTR_DRBG_Update) 
 * this will update the values of V and key */
int ctr_DRBG_Update (uint8_t provided_data[], unsigned short dataLen, ctr_drbg_state_t drbgState) {
  int i;
  if (dataLen != drbgState->seedlen) {
    return CTRDRBGSEEDLENWRONG;
  }
  uint8_t temp[dataLen+16];
  int templen=0;
  uint8_t one[1];
  one[0]=0x01;
  uint8_t inc[drbgState->ctr_len];
  aeskey_t key=aeskey_init(drbgState->aestype);
  memcpy(key->key,drbgState->Key,((drbgState->aestype)/8)*sizeof(uint8_t) );
  while (templen<drbgState->seedlen) {
    if (drbgState->ctr_len < 16) {
      memcpy(inc, &(drbgState->V[16-drbgState->ctr_len]), (drbgState->ctr_len)*sizeof(uint8_t));
      big_add(inc, drbgState->ctr_len, one, 1);
      memcpy(&(drbgState->V[16-drbgState->ctr_len]), inc, (drbgState->ctr_len)*sizeof(uint8_t));
    } else {
      big_add(drbgState->V, 16, one, 1);/* V = V+1 mod 2^{128} */
    }
    AES_encrypt(drbgState->V, &(temp[templen]),key);
    templen += 16;
  }
  aeskey_free(key);
  unsigned long long * templong =(unsigned long long*) temp;
  unsigned long long * provided = (unsigned long long*) provided_data;
  for (i=0; i<dataLen/sizeof(unsigned long long); i++) {
    templong[i] ^=provided[i];
  }
  memcpy(drbgState->Key, temp, ((drbgState->aestype)/8)*sizeof(uint8_t));
  memcpy(drbgState->V, &(temp[(drbgState->aestype)/8]), 16*sizeof(uint8_t));
  return 0;
}


/* 10.2.1.3.1 Instantiation When a Derivation Function is Not Used */
int ctr_DRBG_Instantiate_algorithm(ctr_drbg_state_t drbgState, drbg_Input_t drbgInput){
  long unsigned i;
  if (drbgInput->entropylen < drbgState->seedlen) {
    printf("drbgInput->entropylen=%d,drbgState->seedlen=%d \n", drbgInput->entropylen, drbgState->seedlen);
    return ENTROPYLENTOOSHORT;
  }
  int seedlen=drbgState->seedlen;
  uint8_t seed[seedlen];
  uint8_t personString[seedlen];
  unsigned long long * seedlong =(unsigned long long*) seed;
  unsigned long long * entropylong =(unsigned long long*) drbgInput->entropy;
  unsigned long long * perlong =(unsigned long long*) personString;
  memset(personString, 0, seedlen*sizeof(uint8_t));
  if (drbgInput->perslen >0) {
    int len=0;
    if (seedlen > drbgInput->perslen) {
      len = drbgInput->perslen;
    } else {
      len = drbgState->seedlen;
    }
    memcpy(personString,  drbgInput->personalization_string, len*sizeof(uint8_t));
  }
  for (i=0; i<seedlen/sizeof(unsigned long long); i++) {
    seedlong[i] = entropylong[i] ^ perlong[i];
  }
  memset(drbgState->V, 0,16*sizeof(uint8_t));
  memset(drbgState->Key, 0,((drbgState->aestype)/8)*sizeof(uint8_t));
  ctr_DRBG_Update (seed, seedlen, drbgState);
  drbgState->reseed_counter = 1;
  return 0; 
}


/* 10.2.1.3.2 Instantiation When a Derivation Function is Used */
/* nonce is requird */
int ctr_DRBG_Instantiate_algorithm_DF(ctr_drbg_state_t drbgState, drbg_Input_t drbgInput){
  int ret = 0;
  int entropylen = drbgInput->entropylen;
  int noncelen = drbgInput->noncelen;
  int perslen = drbgInput->perslen;
  int seed_material_len=entropylen+noncelen+perslen;
  uint8_t seed_material[seed_material_len];
  memcpy(seed_material,drbgInput->entropy, entropylen);
  memcpy(&(seed_material[entropylen]),drbgInput->nonce,noncelen);
  if (drbgInput->perslen != 0) {
    memcpy(&(seed_material[entropylen+noncelen]),
	   drbgInput->personalization_string, perslen);
  }
  uint8_t seed[drbgState->seedlen];
  ret = block_cipher_df(drbgState->aestype, seed_material, seed_material_len, seed,drbgState->seedlen);
  if (ret<0) {
    return ret;
  }
  memset(drbgState->V, 0,16*sizeof(uint8_t));
  memset(drbgState->Key, 0,((drbgState->aestype)/8)*sizeof(uint8_t));
  ctr_DRBG_Update(seed, drbgState->seedlen, drbgState);
  drbgState->reseed_counter = 1;
  return ret;
}

/* implements NIST SP800-90Ar1 Section 10.2.1.4.1 Reseeding When a Derivation Function is Not Used */
int ctr_DRBG_Reseed(ctr_drbg_state_t drbgState, drbg_Input_t drbgInput){
  int i;
  uint8_t add[drbgState->seedlen];
  memset(add, 0, (drbgState->seedlen)*sizeof(uint8_t));
  memcpy(add, drbgInput->additional_input, (drbgInput->addlen)*sizeof(uint8_t));
  unsigned long long * addlong =(unsigned long long*) add;
  unsigned long long * entropylong =(unsigned long long*) drbgInput->entropy;
  for (i=0; i<((drbgState->seedlen)/8); i++) {
    addlong[i] ^= entropylong[i];
  }
  ctr_DRBG_Update(add, drbgState->seedlen, drbgState);
  drbgState->reseed_counter = 1;
  return 0;
}

/* implements NIST SP800-90Ar1 Section 10.2.1.4.2 Reseeding When a Derivation Function is Used */
int ctr_DRBG_Reseed_DF(ctr_drbg_state_t drbgState, drbg_Input_t drbgInput){
  int ret;
  unsigned short seed_material_len=drbgInput->entropylen+drbgInput->addlen;
  uint8_t seed_material[seed_material_len];
  uint8_t seed[drbgState->seedlen];
  memcpy(seed_material, drbgInput->entropy,(drbgInput->entropylen)*sizeof(uint8_t));
  memcpy(&seed_material[drbgInput->entropylen], drbgInput->additional_input,(drbgInput->addlen)*sizeof(uint8_t));
  ret = block_cipher_df(drbgState->aestype, seed_material, seed_material_len, seed,drbgState->seedlen);
  if (ret<0) {
    return ret;
  }
  ctr_DRBG_Update(seed, drbgState->seedlen, drbgState);
  drbgState->reseed_counter = 1;
  return 0;
}

/* implement 10.2.1.5.1 Generating Pseudorandom Bits When a Derivation Function is Not Used */
int ctr_DRBG_Generate(ctr_drbg_state_t drbgState, drbg_Input_t drbgInput,
		      uint8_t returned_bytes[],
		      unsigned long req_no_of_bytes) {
  if (drbgState->reseed_counter > drbgState->reseed_interval){
    return DRBGRESEEDREQUIRED;
  }
  uint8_t add[drbgState->seedlen];
  memset(add, 0, (drbgState->seedlen)*sizeof(uint8_t));
  if (drbgInput->addlen >0) {
    memcpy(add, drbgInput->additional_input, (drbgInput->addlen)*sizeof(uint8_t));
    ctr_DRBG_Update(add, drbgState->seedlen, drbgState);
  }
  uint8_t temp[16];
  uint8_t one[1];
  one[0]=0x01;
  int ctr_len=drbgState->ctr_len;
  uint8_t inc[ctr_len];
  aeskey_t key=aeskey_init(drbgState->aestype);
  memcpy(key->key,drbgState->Key,((drbgState->aestype)/8)*sizeof(uint8_t) );
  int loop = req_no_of_bytes / 16;
  int rem= req_no_of_bytes % 16;
  int i;
  for (i=0; i<loop; i++) {
    if (ctr_len < 16) {
      memcpy(inc, &(drbgState->V[16-ctr_len]), ctr_len*sizeof(uint8_t));
      big_add(inc, ctr_len, one, 1);
      memcpy(&(drbgState->V[16-ctr_len]), inc, ctr_len*sizeof(uint8_t));
    } else {
      big_add(drbgState->V, 16, one, 1);
    }
    AES_encrypt(drbgState->V, &(returned_bytes[16*i]), key);
  }
  if (rem>0) {
    if (ctr_len < 16) {
      memcpy(inc, &(drbgState->V[16-ctr_len]), ctr_len*sizeof(uint8_t));
      big_add(inc, ctr_len, one, 1);
      memcpy(&(drbgState->V[16-ctr_len]), inc, ctr_len*sizeof(uint8_t));
    } else {
      big_add(drbgState->V, 16, one, 1);
    }
    AES_encrypt(drbgState->V, temp, key);
    memcpy(returned_bytes+16*loop, temp, rem*sizeof(uint8_t));
  }
  aeskey_free(key);
  ctr_DRBG_Update(add, drbgState->seedlen, drbgState);
  (drbgState->reseed_counter)++;
  return 0;
}


/* implement 10.2.1.5.2 Generating Pseudorandom Bits When a Derivation Function is Used */
int ctr_DRBG_Generate_DF(ctr_drbg_state_t drbgState, drbg_Input_t drbgInput,
			 uint8_t returned_bytes[],
			 unsigned long req_no_of_bytes) {
  int ret;
  if (drbgState->reseed_counter > drbgState->reseed_interval){
    return DRBGRESEEDREQUIRED;
  }
  uint8_t add[drbgState->seedlen];
  memset(add, 0, (drbgState->seedlen)*sizeof(uint8_t));
  if (drbgInput->addlen >0) {
    ret = block_cipher_df(drbgState->aestype, drbgInput->additional_input, drbgInput->addlen,add,drbgState->seedlen);
    if (ret<0)return ret;
    ctr_DRBG_Update(add, drbgState->seedlen, drbgState);
  }  
  uint8_t temp[16];
  uint8_t one[1];
  one[0]=0x01;
  int ctr_len=drbgState->ctr_len;
  uint8_t inc[ctr_len];
  aeskey_t key=aeskey_init(drbgState->aestype);
  memcpy(key->key,drbgState->Key,((drbgState->aestype)/8)*sizeof(uint8_t) );
  int loop = req_no_of_bytes / 16;
  int rem= req_no_of_bytes % 16;
  int i;
  for (i=0; i<loop; i++) {
    if (ctr_len < 16) {
      memcpy(inc, &(drbgState->V[16-ctr_len]), ctr_len*sizeof(uint8_t));
      big_add(inc, ctr_len, one, 1);
      memcpy(&(drbgState->V[16-ctr_len]), inc, ctr_len*sizeof(uint8_t));
    } else {
      big_add(drbgState->V, 16, one, 1);
    }
    AES_encrypt(drbgState->V, &(returned_bytes[16*i]), key);
  }
  if (rem>0) {
    if (ctr_len < 16) {
      memcpy(inc, &(drbgState->V[16-ctr_len]), ctr_len*sizeof(uint8_t));
      big_add(inc, ctr_len, one, 1);
      memcpy(&(drbgState->V[16-ctr_len]), inc, ctr_len*sizeof(uint8_t));
    } else {
      big_add(drbgState->V, 16, one, 1);
    }
    AES_encrypt(drbgState->V, temp, key);
    memcpy(returned_bytes+16*loop, temp, rem*sizeof(uint8_t));
  }
 
  aeskey_free(key);
  ctr_DRBG_Update(add, drbgState->seedlen, drbgState);
  (drbgState->reseed_counter)++;
  return 0;
}


int ctr_DRBG(ctr_drbg_state_t drbgState, drbg_Input_t drbgInput,
	     uint8_t output[], unsigned long outlen){
  int ret = 0;
  int i = 0;
  ret=  ctr_DRBG_Instantiate_algorithm(drbgState, drbgInput);
  if (ret<0) return ret;
  int loop = outlen/(drbgState->max_B_per_req);
  int rem= outlen%(drbgState->max_B_per_req);
  uint8_t returned_bytes[drbgState->max_B_per_req];
  for (i=0; i<loop; i++) {
    ret=ctr_DRBG_Generate(drbgState,drbgInput,&(output[i*(drbgState->max_B_per_req)]),drbgState->max_B_per_req);
    if (ret<0) return ret;
  }
  if (rem >0) {
    ret=ctr_DRBG_Generate(drbgState,drbgInput,returned_bytes,rem);
    if (ret<0) return ret;
    memcpy(&(output[loop*(drbgState->max_B_per_req)]), returned_bytes, rem);
  }
  return ret;
}


int ctr_DRBG_DF(ctr_drbg_state_t drbgState, drbg_Input_t drbgInput,
		uint8_t output[], unsigned long outlen){
  int ret = 0;
  int i = 0;

  ret=  ctr_DRBG_Instantiate_algorithm_DF(drbgState, drbgInput);
  if (ret<0) return ret;
  int loop = outlen/(drbgState->max_B_per_req);
  int rem= outlen%(drbgState->max_B_per_req);
  uint8_t returned_bytes[drbgState->max_B_per_req];  
  for (i=0; i<loop; i++) {
    ret=ctr_DRBG_Generate_DF(drbgState,drbgInput,&(output[i*(drbgState->max_B_per_req)]),drbgState->max_B_per_req);
    if (ret<0) return ret;
  }
  
  if (rem >0) {
    ret=ctr_DRBG_Generate_DF(drbgState,drbgInput,returned_bytes,rem);
    if (ret<0) return ret;
    memcpy(&(output[loop*(drbgState->max_B_per_req)]), returned_bytes, rem);
  }
  return ret;
}
