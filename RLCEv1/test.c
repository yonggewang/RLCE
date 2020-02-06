/* test.c
 * Yongge Wang 
 *
 * Code was written: November 17, 2016-February 8, 2017
 * Copyright (C) 2016 Yongge Wang
 * 
 * Yongge Wang
 * Department of Software and Information Systems
 * UNC Charlotte
 * Charlotte, NC 28223
 * yonwang@uncc.edu
 */

#include "rlce.h"
#define NUMOFSCHEME 6
int getMSG(unsigned char msg[], unsigned short msglen);
void hex2char(char * pos, unsigned char hexChar[], int charlen);

uint64_t rdtsc(){
    unsigned int lo,hi;
    __asm__ __volatile__ ("rdtsc" : "=a" (lo), "=d" (hi));
    return ((uint64_t)hi << 32) | lo;
}

void printCPUinfo(void) {
  volatile uint32_t i=0x01234567;
  int littleendian= ((*((uint8_t*)(&i))) == 0x67);
  if (littleendian==0) {
    printf("the machine is big endian\n");
  } else printf("the machine is little endian\n");
  printf("sizeof(field_t)=%ld, sizeof(int)=%ld, sizeof(long)=%ld\n",
	 sizeof(field_t),sizeof(int),sizeof(long));
}

int getSKPK(RLCE_public_key_t pk,RLCE_private_key_t sk) {
  int ret;
  unsigned char entropy[]={0xae,0x7e,0xbe,0x06,0x29,0x71,0xf5,0xeb,0x32,0xe5,0xb2,0x14,0x44,0x75,0x07,0x85,
			0xde,0x81,0x65,0x95,0xad,0x2c,0xbe,0x80,0xa2,0x09,0xc8,0xf8,0xab,0x04,0xb5,0x46,
			0x67,0x56,0x27,0xef,0x86,0xaa,0x2e,0x7d,0x70,0x29,0xa1,0x52,0xb8,0x00,0x07,0x2f};
  unsigned char nonce[]={0x5e,0x7d,0x69,0xe1,0x87,0x57,0x7b,0x04,0x33,0xee,0xe8,0xea,0xb9,0xf7,0x77,0x31};
  ret=RLCE_key_setup(entropy,sk->para[19], nonce, 16, pk, sk);
  return ret;
}

int getOneCipher(RLCE_public_key_t pk, unsigned char* cipher, unsigned long long *clen){
  int ret;
  unsigned long long mlen=pk->para[6];
  unsigned char entropy[]={0xae,0x7e,0xbe,0x06,0x29,0x71,0xf5,0xeb,0x32,0xe5,0xb2,0x14,0x44,0x75,0x07,0x85,
			0xde,0x81,0x65,0x95,0xad,0x2c,0xbe,0x80,0xa2,0x09,0xc8,0xf8,0xab,0x04,0xb5,0x46,
			0x67,0x56,0x27,0xef,0x86,0xaa,0x2e,0x7d,0x70,0x29,0xa1,0x52,0xb8,0x00,0x07,0x2f};

  unsigned char sslong[]={0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x10,0x11,0x12,0x13,0x14,0x15,0x16,
			  0x17,0x18,0x19,0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x30,0x31,0x32,
			  0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,
			  0x49,0x50,0x52,0x52,0x53,0x54,0x55,0x56,0x57,0x58,0x59,0x60,0x61,0x62,0x63,0x64};  
  unsigned char *message=calloc(mlen, sizeof(unsigned char));
  memcpy(message, sslong, 64);
  /*
  char m[]="This is the first message encrypted by RLCE reference implementation!";
  unsigned int actualmlen=sizeof(m)-1;
  memcpy(message, sslong,  actualmlen);
  message[actualmlen]=0x01;
  message[actualmlen+1]=0x00;
  unsigned char S[2];
  I2BS((unsigned int)actualmlen, S,2);
  memcpy(&(message[actualmlen+2]), S,2);
  */
  unsigned char nonce[1];
  ret=RLCE_encrypt(message,mlen,entropy,pk->para[19],nonce,0,pk,cipher,clen);
  free(message);
  return ret;
}

void tRAM(int testRAM,int scheme,int padding) {
  RLCE_private_key_t sk;
  RLCE_public_key_t pk;
  if (testRAM==1) {
    unsigned int para[PARASIZE];
    getRLCEparameters(para,scheme,padding);
    sk=RLCE_private_key_init(para);
    pk=RLCE_public_key_init(para);
    getSKPK(pk,sk);
    writeSK("sk.bin", sk,0);
    writePK("pk.bin", pk,0);
    RLCE_free_sk(sk);
    RLCE_free_pk(pk);
    return;
  }

  if (testRAM==2) {
    pk=readPK("pk.bin",0);
    unsigned long long clen=pk->para[16];
    unsigned char *cipher=calloc(clen,sizeof(unsigned char));
    getOneCipher(pk, cipher,(unsigned long long *) &clen);
    rlceWriteFile("cipher.bin", cipher, clen,0);
    printf("clen=%llu",clen);
    free(cipher);
    RLCE_free_pk(pk);
    return;
  }

  if (testRAM==3) {
    sk=readSK("sk.bin",0);
    unsigned long long clen=sk->para[16];
    unsigned char *cipher=rlceReadFile("cipher.bin", &clen, 0);
    unsigned long long mlen=sk->para[6];
    unsigned char *msg=calloc(mlen,sizeof(unsigned char));
    RLCE_decrypt(cipher, clen,sk, msg, &mlen);
    free(cipher);
    free(msg);
    RLCE_free_sk(sk);
    return;
  }
  return;
}


void test_per(void){
  clock_t start, finish;
  double seconds;

  start = clock();
  finish = clock();
  seconds = ((double)(finish - start))/CLOCKS_PER_SEC;
  printf("takes %f seconds\n", seconds);
  return;
}


void testpolyEvalPer(void){
  clock_t start, finish;
  double seconds;

  int t[6]={80,78,118,114,280,230};
  int i,j;
  poly_t p;
  int m=10;

  for (i=0; i<6; i++) {
    p=poly_init(t[i]+1);    
    p->deg=t[i];
    for (j=0; j<t[i]+1; j++) p->coeff[j]=j+i+1;    
    
    start = clock();
    for (j=0; j<10000; j++)  poly_eval(p, 0x012A, m);
    finish = clock();
    seconds = ((double)(finish - start))/CLOCKS_PER_SEC;
    printf("scheme[%d], t=%d standard takes %f seconds\n", i, t[i], seconds);

    start = clock();
    for (j=0; j<10000; j++)  poly_evalopt(p, 0x012A, m);
    finish = clock();
    seconds = ((double)(finish - start))/CLOCKS_PER_SEC;
    printf("scheme[%d], t=%d NEW takes %f seconds\n", i, t[i], seconds);

    poly_free(p);
    
  }
}

  

int testReedSolomonper(void) {
  clock_t start, finish;
  double seconds;
  unsigned int para[PARASIZE];
  int ret=0,i, j,scheme;
  poly_t codeword, corruptedCodeword, decodedWord, message, generator;
  int random;
  time_t tim;  
  for (scheme=0; scheme<6; scheme++) {
    ret=getRLCEparameters(para, scheme, 0);
    if (ret<0)  return ret;
    int GFsize=para[3];
    int codeLen = (1u<< GFsize) -1;
    int zeroLen = codeLen - para[0];
    int codeDim = para[1]+zeroLen;
 
  
    generator=initialize_RS (codeLen, codeDim, GFsize);
    message =  poly_init(codeLen);
    poly_zero(message);
    for (i=0; i<codeDim; i++) {
      message->coeff[i]='Y';
    }
    message->deg=codeDim-1;
    
    codeword =  poly_init(codeLen);
    corruptedCodeword  =  poly_init(codeLen);
    ret=rs_encode (generator, message, codeword, GFsize);
    poly_free(generator);
    poly_free(message);
    if (ret<0) return ret;
    poly_copy(codeword, corruptedCodeword);

    srand((unsigned) time(&tim));
    for (i=0; i< (codeLen-codeDim)/2; i++) {
      random = rand()%codeLen;
      corruptedCodeword->coeff[random]=10;
    }
    poly_deg(corruptedCodeword);

    int numErrors=0;
    for (i=0; i<codeLen; i++) {
      if (codeword->coeff[i] != corruptedCodeword->coeff[i]) {
	numErrors++;
      }
    }
    field_t eLocation[codeLen-codeDim];
    start = clock();
    for (j=0; j<10000; j++) {
      decodedWord=rs_decode(0, corruptedCodeword, codeLen, codeDim, eLocation, GFsize);
    }
    finish = clock();
    seconds = ((double)(finish - start))/CLOCKS_PER_SEC;
    printf("Scheme %d BM-decoder takes %f seconds\n", scheme, seconds);

    start = clock();
    for (j=0; j<10000; j++) {
      decodedWord=rs_decode(1, corruptedCodeword, codeLen, codeDim, eLocation, GFsize);
    }
    finish = clock();
    seconds = ((double)(finish - start))/CLOCKS_PER_SEC;
    printf("Scheme %d Euclidean-decoder takes %f seconds\n", scheme, seconds);

    poly_free(decodedWord);
    poly_free(corruptedCodeword);
    poly_free(codeword);
  }
  return 0;
}


int matrix_inv_standard(matrix_t A,matrix_t C, int m);
int matrix_inv_strassen(matrix_t A,matrix_t C, int m);
int matrix_mul_strassen(matrix_t A,matrix_t B,matrix_t C, int m);
int matrix_mul_winograd(matrix_t A,matrix_t B,matrix_t C, int m);

void test_matper_per(int num){
  int i,j,jj,m=10,ctr=0;
  clock_t start, finish;
  double seconds;
  int n[6]={376,470,618,700,764,800};
  int nRB = 800*800+10;
  int ret;
  

  unsigned char pers[] ="PostQuantumCryptoRLCEversion2017";
  int perlen = sizeof(pers)-1;
  unsigned char addS[]="GRSbasedPostQuantumENCSchemeRLCE";
  int addlen = sizeof(addS)-1;
  char noncehex[] = "5e7d69e187577b0433eee8eab9f77731";
  unsigned char nonce[16];
  hex2char(noncehex, nonce, 16);
  int noncelen=16;
  char entropyhex[] = "5c7d69e187577b0433ece8eab9f778325c7d69e187577b0433ece8eab9f778325c7d69e187577b0433ece8eab9f778325c7d69e187577b0433ece8eab9f77832";
  unsigned char entropy[64];
  hex2char(entropyhex, entropy, 64);
  int entropylen=64;
  hash_drbg_state_t drbgState;
  drbg_Input_t drbgInput;

  unsigned char *randomBytes;
  randomBytes=calloc(nRB,sizeof(unsigned char));
  drbgState=drbgstate_init(2);
  drbgInput=drbgInput_init(entropy,entropylen,nonce,noncelen,pers,perlen,addS,addlen);
  ret=hash_DRBG(drbgState,drbgInput,randomBytes, nRB);
  free_drbg_state(drbgState);
  free_drbg_input(drbgInput);
    
  matrix_t A,B,C,dest1,dest2;
  for (i=0; i<6; i++) {  
    A = matrix_init(n[i],n[i]);
    B = matrix_init(n[i],n[i]);
    C = matrix_init(n[i],n[i]);
    dest1 = matrix_init(n[i],n[i]);
    dest2 = matrix_init(n[i],n[i]);
    ctr=0;
    for (j=0;j<A->numR; j++) {
      for (jj=0; jj<A->numC; jj++) {
	A->data[j][jj]=GF_exp(((randomBytes[ctr] <<2) ^ (randomBytes[ctr+1] >>6))%(fieldSize(m)-1), m);
	B->data[j][jj]=randomBytes[ctr];
	ctr++;
      }
    }
  
    start = clock();
    for (j=0; j<num; j++) matrix_mul_strassen(A,B,C,m);
    finish = clock();
    seconds = ((double)(finish - start))/CLOCKS_PER_SEC;
    printf("Strassen %dx%d Mul takes %f seconds\n", n[i],n[i],seconds);

    start = clock();
    for (j=0; j<num; j++)  matrix_mul_winograd(A, B,dest2,m);
    finish = clock();
    seconds = ((double)(finish - start))/CLOCKS_PER_SEC;
    printf("Winograd %dx%d Mul takes %f seconds\n", n[i],n[i],seconds);

    start = clock();
    for (j=0; j<num; j++) matrix_standard_mul(A,B,dest1,m);
    finish = clock();
    seconds = ((double)(finish - start))/CLOCKS_PER_SEC;
    printf("standard %dx%d Mul takes %f seconds\n", n[i],n[i],seconds);

    int winograd=0;
    int strassen=0;
    for (jj=0; jj<C->numR; jj++) {
      for (j=0; j<C->numC; j++) {
	if (dest1->data[jj][j] != C->data[jj][j]) strassen++;
	if (dest2->data[jj][j] != dest1->data[jj][j])  winograd++;
      }
    }  
    if (strassen >0) {
      printf("strassen multiplication is incorrect with %d errors\n", strassen);
    } else printf("strassen multiplication is correct\n");
    if (winograd>0) {
      printf("winograd multiplication is incorrect with %d errors\n", winograd);
    } else printf("winograd multiplication is correct\n");
    
    start = clock();
    for (j=0; j<num; j++) ret=matrix_inv_standard(A,C, m);
    if (ret<0) printf("return %d\n", ret);
    finish = clock();
    seconds = ((double)(finish - start))/CLOCKS_PER_SEC;
    printf("standard %dx%d inverse takes %f seconds\n", n[i],n[i],seconds);

    start = clock();
    for (j=0; j<num; j++) matrix_inv_strassen(A,dest1,m);
    if (ret<0) printf("return %d\n", ret);
    finish = clock();
    seconds = ((double)(finish - start))/CLOCKS_PER_SEC;
    printf("Strassen %dx%d inverse takes %f seconds\n", n[i],n[i],seconds);

    strassen=0;
    for (jj=0; jj<C->numR; jj++)
      for (j=0; j<C->numC; j++) if (C->data[jj][j] != dest1->data[jj][j]) strassen++;
    if (strassen >0) {
      printf("strassen inverse is incorrect with %d errors\n", strassen);
    } else  printf("strassen inverse is correct\n");
    
    matrix_free(A);
    matrix_free(B);
    matrix_free(C);
    matrix_free(dest1);
    matrix_free(dest2);
  }
  free(randomBytes);
 
  return;
}

void test_polymul_per(void){
  clock_t start, finish;
  double seconds;

  int t[6]={80,78,118,114,280,230};
  int i,j;
  poly_t p,q,r;
  int m=10;

  for (i=0; i<6; i++) {
    p=poly_init(t[i]+1);    
    p->deg=t[i];
    for (j=0; j<t[i]+1; j++) {
      p->coeff[j]=j+i+1;
    }
    q=poly_init(2*t[i]+1);
    q->deg=2*t[i];
    for (j=0; j<2*t[i]+1; j++) {
      q->coeff[j]=j+i+1;
    }
    r=poly_init(3*t[i]+1);
    
    start = clock();
    for (j=0; j<10000; j++) {
      poly_mul_standard(p, q, r, m);
    }
    finish = clock();
    seconds = ((double)(finish - start))/CLOCKS_PER_SEC;
    printf("scheme[%d], t=%d standard takes %f seconds\n", i, t[i], seconds);

    start = clock();
    for (j=0; j<10000; j++) {
      poly_mul_karatsuba(p, q, r, m);
    }
    finish = clock();
    seconds = ((double)(finish - start))/CLOCKS_PER_SEC;
    printf("scheme[%d], t=%d karatsuba takes %f seconds\n", i, t[i], seconds);

    start = clock();
    for (j=0; j<10000; j++) {
      poly_mul_FFT(p, q, r, m);
    }
    finish = clock();
    seconds = ((double)(finish - start))/CLOCKS_PER_SEC;
    printf("scheme[%d], t=%d FFT takes %f seconds\n", i, t[i], seconds);
    poly_free(p);
    poly_free(q);
    poly_free(r);
  }
    
  
  start = clock();
  finish = clock();
  seconds = ((double)(finish - start))/CLOCKS_PER_SEC;
  printf("takes %f seconds\n", seconds);
  return;
}

void test_roots_per(void){
  clock_t start, finish;
  double seconds;

  //int t[6]={4,6,8,10,14,18};
  int t[6]={78,80,114,118,230,280};
  int i,j;
  poly_t p;
  field_t *roots;
  field_t *eLocation;
  int m=10;
  
  for (i=0; i<6; i++) {
    roots =calloc(t[i], sizeof(field_t));
    eLocation =calloc(2*t[i], sizeof(field_t));
    p=poly_init(t[i]+1);    
    p->deg=t[i];
    for (j=0; j<t[i]+1; j++) {
      p->coeff[j]=j+i+1;
    }
    start = clock();
    for (j=0; j<10000; j++) {
      find_roots_Chien(p, roots, eLocation, m);
    }
    finish = clock();
    seconds = ((double)(finish - start))/CLOCKS_PER_SEC;
    printf("scheme[%d], t=%d Chien takes %f seconds\n", i, t[i], seconds);

    start = clock();
    for (j=0; j<10000; j++) {
      find_roots_exhaustive(p, roots, m);
    }
    finish = clock();
    seconds = ((double)(finish - start))/CLOCKS_PER_SEC;
    printf("scheme[%d], t=%d Exhaustive takes %f seconds\n", i, t[i], seconds);

    start = clock();
    for (j=0; j<10000; j++) {
      find_roots_BTA(p, roots, m);
    }
    finish = clock();
    seconds = ((double)(finish - start))/CLOCKS_PER_SEC;
    printf("scheme[%d], t=%d BTA takes %f seconds\n", i, t[i], seconds);

    start = clock();
    for (j=0; j<10000; j++) {
      find_roots_FFT(p, roots, m);
    }
    finish = clock();
    seconds = ((double)(finish - start))/CLOCKS_PER_SEC;
    printf("scheme[%d], t=%d FFT takes %f seconds\n", i, t[i], seconds);
    
    free(eLocation);
    free(roots);
    poly_free(p);
  }
 
  return;
}

void test_DRBBG_per(void) {
  clock_t start, finish;
  double seconds;
  int nRB = 10000;
  int i;
  unsigned char randomBytes[nRB];

  unsigned char pers[] ="PostQuantumCryptoRLCEversion2017";
  int perlen = sizeof(pers)-1;
  unsigned char addS[]="GRSbasedPostQuantumENCSchemeRLCE";
  int addlen = sizeof(addS)-1;
  char noncehex[] = "5e7d69e187577b0433eee8eab9f77731";
  unsigned char nonce[16];
  hex2char(noncehex, nonce, 16);
  int noncelen=16;
  char entropyhex[] = "5c7d69e187577b0433ece8eab9f778325c7d69e187577b0433ece8eab9f778325c7d69e187577b0433ece8eab9f778325c7d69e187577b0433ece8eab9f77832";
  unsigned char entropy[64];
  hex2char(entropyhex, entropy, 64);
  int entropylen=64;
  hash_drbg_state_t drbgState;
  drbg_Input_t drbgInput;
  ctr_drbg_state_t aesdrbgState;
  
  start = clock();
  for (i=0; i<10000; i++) {   
    drbgState=drbgstate_init(1);   
    drbgInput=drbgInput_init(entropy,entropylen,nonce,noncelen,pers,perlen,addS,addlen);
    hash_DRBG(drbgState,drbgInput,randomBytes, nRB);
    free_drbg_state(drbgState);
    free_drbg_input(drbgInput);
  }
  finish = clock();
  seconds = ((double)(finish - start))/CLOCKS_PER_SEC;
  printf("takes SHA-256 %f seconds\n", seconds);

  start = clock();
  for (i=0; i<10000; i++) {   
    drbgState=drbgstate_init(2);   
    drbgInput=drbgInput_init(entropy,entropylen,nonce,noncelen,pers,perlen,addS,addlen);
    hash_DRBG(drbgState,drbgInput,randomBytes, nRB);
    free_drbg_state(drbgState);
    free_drbg_input(drbgInput);
  }
  finish = clock();
  seconds = ((double)(finish - start))/CLOCKS_PER_SEC;
  printf("takes SHA-512 %f seconds\n", seconds);
  
  start = clock();
  for (i=0; i<10000; i++) {  
    aesdrbgState=ctr_drbgstate_init(128);
    drbgInput=drbgInput_init(entropy,entropylen,nonce,0,pers,perlen,addS,addlen);
    ctr_DRBG(aesdrbgState,drbgInput,randomBytes, nRB);
    free_ctr_drbg_state(aesdrbgState);
    free_drbg_input(drbgInput);
  }
  finish = clock();
  seconds = ((double)(finish - start))/CLOCKS_PER_SEC;
  printf("takes AES-128 %f seconds\n", seconds);


  start = clock();
  for (i=0; i<10000; i++) {  
    aesdrbgState=ctr_drbgstate_init(192);
    drbgInput=drbgInput_init(entropy,entropylen,nonce,0,pers,perlen,addS,addlen);
    ctr_DRBG(aesdrbgState,drbgInput,randomBytes, nRB);
    free_ctr_drbg_state(aesdrbgState);
    free_drbg_input(drbgInput);
  }
  finish = clock();
  seconds = ((double)(finish - start))/CLOCKS_PER_SEC;
  printf("takes AES-192 %f seconds\n", seconds);

  start = clock();
  for (i=0; i<10000; i++) {  
    aesdrbgState=ctr_drbgstate_init(256);
    drbgInput=drbgInput_init(entropy,entropylen,nonce,0,pers,perlen,addS,addlen);
    ctr_DRBG(aesdrbgState,drbgInput,randomBytes, nRB);
    free_ctr_drbg_state(aesdrbgState);
    free_drbg_input(drbgInput);
  }
  finish = clock();
  seconds = ((double)(finish - start))/CLOCKS_PER_SEC;
  printf("takes AES-256 %f seconds\n", seconds);

  
  return;  
}


int testFE2B2FE (int scheme, int padding) {
  unsigned int para[PARASIZE];
  int ret,i;
  ret=getRLCEparameters(para, scheme, padding);
  if (ret<0) return ret;
  int nLen=para[0];

  vector_t FE;
  int FEsize = (nLen*8)/9;
  FE=vec_init(FEsize);

  unsigned char test[nLen];
  for (i=0; i<nLen; i++) {
    test[i]=0xFF;
  }
 
  unsigned char testResult[nLen];

  ret=B2FE9 (test, nLen, FE);
  if (ret<0) {
    return ret;
  }
  ret=FE2B9 (FE, testResult, nLen);
  if (ret<0) {
    return ret;
  }
  for (i=0; i<nLen-1; i++) {
    if (testResult[i] != 0xFF) {
      printf("testB2FE9 failed.\n");
    }
  }
  vector_free(FE);
  
  /* BEGIN test B2FE10 and FE2B10 */
  vector_t FE10;
  int FEsize10 = (nLen*8)/10;
  FE10=vec_init(FEsize10);

  ret=B2FE10 (test, nLen, FE10);
  if (ret<0) {
    return ret;
  }
  ret=FE2B10 (FE10, testResult, nLen);
  if (ret<0) {
    return ret;
  }
  for (i=0; i<nLen-1; i++) {
    if (testResult[i] != 0xFF) {
      printf("testB2FE10 failed.\n");
    }
  }
  vector_free(FE10);
  /*END test B2FE10 and FE2B10 */

  /* BEGIN test B2FE11 and FE2B11 */
  vector_t FE11;
  int FEsize11 = (nLen*8)/11;
  FE11=vec_init(FEsize11);

  ret=B2FE11 (test, nLen, FE11);
  if (ret<0) return ret;
  ret=FE2B11 (FE11, testResult, nLen);
  if (ret<0)  return ret;
  for (i=0; i<nLen-2; i++) {
    if (testResult[i] != 0xFF) {
      printf("testB2FE11 failed.\n");
    }
  }
  vector_free(FE11);
  /* END test B2FE11 and FE2B11 */


  /* BEGIN test B2FE12 and FE2B12 */
  vector_t FE12;
  int FEsize12 = (nLen*8)/12;
  FE12=vec_init(FEsize12);

  ret=B2FE12 (test, nLen, FE12);
  if (ret<0) return ret;
  ret=FE2B12 (FE12, testResult, nLen);
  if (ret<0) return ret;
  for (i=0; i<nLen-1; i++) {
    if (testResult[i] != 0xFF) {
      printf("testB2FE12 failed.\n");
    }
  }
  vector_free(FE12);
  /* END test B2FE12 and FE2B12 */
  return 0;
}

int testRLCEkeyIO(int scheme, int padding) {
  /* BEGIN generate private and public key*/
 
  int ret=0;
  int testENC=1;
  unsigned int para[PARASIZE];
  ret=getRLCEparameters(para,scheme,padding);
  RLCE_private_key_t sk=RLCE_private_key_init(para);
  RLCE_public_key_t pk=RLCE_public_key_init(para);
  ret=getSKPK(pk,sk);
  if (ret<0) return ret;
  ret=writeSK("sk.txt", sk, 1);
  if (ret<0) return ret;
  ret=writeSK("sk.bin", sk, 0);
  if (ret<0) return ret;
  ret=writePK("pk.bin", pk, 0);
  if (ret<0) return ret;
  ret=writePK("pk.txt", pk, 1);  
  if (ret<0) return ret;
  if (testENC==1) {
     RLCE_free_sk(sk);
     RLCE_free_pk(pk);
     sk=readSK("sk.txt", 1);
     pk=readPK("pk.txt",1);
     unsigned long long *mlen=malloc(sizeof(unsigned long long));
     mlen[0]=pk->para[6];
     unsigned char *msg=calloc(mlen[0],sizeof(unsigned char)); 
     unsigned long long *clen=malloc(sizeof(unsigned long long));
     clen[0]=pk->para[16];
     unsigned char *cipher=calloc(clen[0],sizeof(unsigned char));
     ret=getOneCipher(pk, cipher, clen);
     if (ret<0) return ret;
     printf("cipher is:\n");
     int i;
     for (i=0;i<clen[0];i++) printf("%02x",cipher[i]);
     printf("\n");
     ret=RLCE_decrypt(cipher,clen[0], sk, msg, mlen);
     if (ret<0) return ret;
     RLCE_free_sk(sk);
     RLCE_free_pk(pk);
     sk=readSK("sk.bin", 0);
     pk=readPK("pk.bin",0);
     ret=getOneCipher(pk, cipher, clen);
     if (ret<0) return ret;
     ret=RLCE_decrypt(cipher,clen[0], sk, msg, mlen);
     if (ret<0) return ret;
     free(cipher);
     free(msg);
     free(mlen);
     free(clen);
  }
  RLCE_free_sk(sk);
  RLCE_free_pk(pk);
  return 0;
}

int testRLCE(int numP, int numK, int numE, int numD,int t1RLCE,int ischeme,int ipad) {
  int base=0;
  int end=NUMOFSCHEME;
  int pbase=0;
  int pend=numP;
  if (t1RLCE>0) {
    base=ischeme;
    end=ischeme+1;
    pbase=ipad;
    pend=ipad+1;
  }
  double performance[end-base][pend-pbase][5];
  unsigned long long cpuperformance[end-base][pend-pbase][3];
  RLCE_private_key_t sk=NULL;
  RLCE_public_key_t pk=NULL;
  int ret=0, i=0;  
  FILE *f = fopen("TimeCost.txt", "w");
  if (f == NULL) return FILEERROR;
  FILE *g = fopen("CPUcycle.txt", "w");
  if (g == NULL) return FILEERROR;
  double total, KBpers;
  unsigned long long cycles;  
  clock_t start, finish;
  double seconds;
  int scheme=0, padding=0;
  unsigned long long mlen[]={0};
  unsigned long long clen[]={0};
  for (scheme=base; scheme<end; scheme+=1) {/* 0--7 */
    for (padding=pbase; padding<pend;padding++){
      printf("begin to test scheme %d-%d\n", scheme,padding);
      unsigned int para[PARASIZE];
      ret=getRLCEparameters(para,scheme,padding);
      start = clock();
      cycles = rdtsc();
      for (i=0;i<numK; i++) {
	if (sk!=NULL) RLCE_free_sk(sk);
	if (pk!=NULL) RLCE_free_pk(pk);
	sk=RLCE_private_key_init(para);
	pk=RLCE_public_key_init(para);
	ret=getSKPK(pk,sk);
      }
      if (ret<0) return ret;
      cycles = (rdtsc() - cycles)/numK;
      finish = clock();
      cpuperformance[scheme-base][padding-pbase][0]=cycles;
      seconds = ((double)(finish - start))/(numK*CLOCKS_PER_SEC);
      performance[scheme-base][padding-pbase][0]=seconds;

      mlen[0]=pk->para[6];
      unsigned char *msg=calloc(mlen[0],sizeof(unsigned char)); 
      clen[0]=pk->para[16];
      unsigned char *cipher=calloc(clen[0],sizeof(unsigned char));
    
      start=clock();
      cycles = rdtsc();
      for (i=0;i<numE; i++) ret=getOneCipher(pk, cipher, clen);
      if (ret<0) return ret;
      cycles = (rdtsc()-cycles)/numE;
      finish = clock();
      cpuperformance[scheme-base][padding-pbase][1]=cycles;
      seconds = ((double)(finish - start))/(numE*CLOCKS_PER_SEC);
      performance[scheme-base][padding-pbase][1]=seconds;
      total = (double) (numE*(pk->para[6]))/1024; 
      KBpers = total/((double)(finish - start)/CLOCKS_PER_SEC);
      performance[scheme-base][padding-pbase][2]=KBpers;

      start = clock();
      cycles = rdtsc();
      for (i=0;i<numD; i++)
	ret=RLCE_decrypt(cipher, clen[0],sk, msg, mlen);
      //for (i=0;i<55;i++) printf("%c", msg[i]);printf("\n");
      if (ret<0) return ret;
      finish = clock();
      cycles = (rdtsc() - cycles)/numD;
      cpuperformance[scheme-base][padding-pbase][2]=cycles;
      seconds = ((double)(finish - start))/(numD*CLOCKS_PER_SEC);
      performance[scheme-base][padding-pbase][3]=seconds;
      total = (double) (numD*(pk->para[6]))/1024; /* KB */
      KBpers = total/((double)(finish - start)/CLOCKS_PER_SEC);
      performance[scheme-base][padding-pbase][4]=KBpers;
      free(msg);
      free(cipher);		      
    }
  }
  int j,k;
  fprintf(f, "ID; sec/key; sec/enc; ENC KB/sec; sec/dec; DEC KB/sec\n");
  for (i=0; i<end; i++) {
    for (j=0; j<pend;j++) {
      fprintf(f, "%d(%d): ", i,j);
      for (k=0;k<5;k++){
	fprintf(f, "%f ", performance[i][j][k]);
      }
      fprintf(f, "\n");
    }
  }
  fclose(f);
  fprintf(g, "ID; key_setup; encryption; decryption\n");
  for (i=0; i<end; i++) {
    for (j=0; j<pend;j++) {
      fprintf(g, "%d(%d): ", i,j);
      for (k=0;k<3;k++){
	fprintf(g, "%llu ", cpuperformance[i][j][k]);
      }
      fprintf(g, "\n");
    }
  }
  fclose(g);
  
  if (sk != NULL) RLCE_free_sk(sk);
  if (pk !=NULL)  RLCE_free_pk(pk);
  return 0;
}

int hash_DRBG_Generate(hash_drbg_state_t drbgState,drbg_Input_t drbgInput,
		    unsigned char returned_bytes[],
		    unsigned long req_no_of_bytes);
int hash_DRBG_Instantiate(hash_drbg_state_t drbgState, drbg_Input_t drbgInput);
int hash_DRBG_Reseed(hash_drbg_state_t drbgState, drbg_Input_t drbgInput);

int testHashDRBG(void) {
  int ret=0;
  int i=0;
  hash_drbg_state_t drbgSHA1state, drbgSHA256state,drbgSHA512state;
  drbgSHA1state=drbgstate_init(0);
  drbgSHA256state=drbgstate_init(1);
  drbgSHA512state=drbgstate_init(2);

  char entropyhex1[] = "136cf1c174e5a09f66b962d994396525";
  unsigned char entropy[16];
  hex2char(entropyhex1, entropy, 16);
  char noncehex1[] = "fff1c6645f19231f";
  unsigned char nonce[8];
  hex2char(noncehex1, nonce, 8);
  
  unsigned char pers[1];
  unsigned char add[1];
  unsigned char output[80];
  drbg_Input_t drbgSHA1input, drbgSHA256input,drbgSHA512input;
  
  drbgSHA1input=drbgInput_init(entropy,16, nonce, 8, pers,0,add, 0);
  ret= hash_DRBG_Instantiate(drbgSHA1state, drbgSHA1input);
  if (ret<0) return ret;
  ret=hash_DRBG_Generate(drbgSHA1state, drbgSHA1input,output, 80);
  if (ret<0) return ret;
  ret=hash_DRBG_Generate(drbgSHA1state, drbgSHA1input,output, 80);
  if (ret<0) return ret;
  char hexstring[] = "0e28130fa5ca11edd3293ca26fdb8ae1810611f78715082ed3841e7486f16677b28e33ffe0b93d98ba57ba358c1343ab2a26b4eb7940f5bc639384641ee80a25140331076268bd1ce702ad534dda0ed8";
  unsigned char hexChar[80];
  hex2char(hexstring, hexChar, 80);
  for(i = 0; i < 80; i++) {
    if (!(output[i]==hexChar[i]))  ret=TESTERROR;
  }
  if (ret<0) {
    return ret;
  } else {
    printf("Hash_DRBG(SHA1) NIST Test Case 1 in drbg_pr passed!\n");
  }

  char entropyhex2[] = "1610b828ccd27de08ceea032a20e9208";
  unsigned char entropy2[16];
  hex2char(entropyhex2, entropy2, 16);
  char noncehex2[] = "492cf1709242f6b5";
  unsigned char nonce2[8];
  hex2char(noncehex2, nonce2, 8);
  char addhex2[] = "2b790052f09b364d4a8267a0a7de63b8";
  unsigned char add2[16];
  hex2char(addhex2, add2, 16);
  free_drbg_input(drbgSHA1input);
  drbgSHA1input=drbgInput_init(entropy2,16, nonce2, 8, pers,0,add, 0);
  ret= hash_DRBG_Instantiate(drbgSHA1state, drbgSHA1input);
  char entropyreseedhex2[] = "72d28c908edaf9a4d1e526d8f2ded544";
  hex2char(entropyreseedhex2, entropy2, 16);
  ret=hash_DRBG_Reseed(drbgSHA1state, drbgSHA1input); 
  ret=hash_DRBG_Generate(drbgSHA1state, drbgSHA1input,output, 80);
  char addhex21[] = "2ee0819a671d07b5085cc46aa0e61b56";
  hex2char(addhex21, add2, 16);
  ret=hash_DRBG_Generate(drbgSHA1state, drbgSHA1input,output, 80);
  char expouthex2[]="56f33d4fdbb9a5b64d26234497e9dcb87798c68d08f7c41199d4bddf97ebbf6cb5550e5d149ff4d5bd0f05f25a6988c17436396227184af84a564335658e2f8572bea333eee2abff22ffa6de3e22aca2";
  hex2char(expouthex2, hexChar, 80);
  for(i = 0; i < 80; i++) {
    if (!(output[i]==hexChar[i])) {
      ret=TESTERROR;
    }
  }
  if (ret<0) {
    return ret;
  } else {
    printf("Hash_DRBG(SHA1) NIST Test Case 2 with reseed in drbg_pr passed!\n");
  }

  char entropyhex3[] = "6466e1799a68012379631b3aae41f59b";
  unsigned char entropy3[16];
  hex2char(entropyhex3, entropy3, 16);
  char noncehex3[] = "6b0c61269f67c576";
  unsigned char nonce3[8];
  hex2char(noncehex3, nonce3, 8);
  char perhex3[] = "cc936b87c8c8c1ab85dde0ad2e9242b4";
  unsigned char pers3[16];
  hex2char(perhex3, pers3, 16);
  char addhex3[] = "d1033ac553ef08f22fd38f12b49b45bc";
  unsigned char add3[16];
  hex2char(addhex3, add3, 16);
  free_drbg_input(drbgSHA1input);
  drbgSHA1input=drbgInput_init(entropy3,16, nonce3, 8, pers3,16,add3, 16);
  ret= hash_DRBG_Instantiate(drbgSHA1state, drbgSHA1input);
  ret=hash_DRBG_Generate(drbgSHA1state, drbgSHA1input,output, 80);
  char addhex31[] = "f004ba01f51455430d84362e376eb775";
  hex2char(addhex31, add3, 16);
  ret=hash_DRBG_Generate(drbgSHA1state, drbgSHA1input,output, 80);
  char expouthex3[]="5d675d1e92490952703c194194e1b061b6ec4e219dc2e1edaa891ef2d1b7ed050a06342d3c095011eb339f198519779b01ab1a580bd2e34d6cf4e47c1befe0c7dc37b4aafb31128fa396267f3732095a";
  hex2char(expouthex3, hexChar, 80);
    for(i = 0; i < 80; i++) {
    if (!(output[i]==hexChar[i])) ret=TESTERROR;
  }
  if (ret<0) {
    return ret;
  } else {
    printf("Hash_DRBG(SHA1) NIST Test Case 3 with add_string and per_string in drbg_pr passed!\n");
  }
  free_drbg_input(drbgSHA1input);

  char entropyhex4[] = "a65ad0f345db4e0effe875c3a2e71f42c7129d620ff5c119a9ef55f05185e0fb";
  unsigned char entropy4[32];
  hex2char(entropyhex4, entropy4, 32);
  char noncehex4[] = "8581f9317517276e06e9607ddbcbcc2e";
  unsigned char nonce4[16];
  hex2char(noncehex4, nonce4, 16);
  drbgSHA256input=drbgInput_init(entropy4,32, nonce4,16, pers,0, add, 0);
  ret= hash_DRBG_Instantiate(drbgSHA256state, drbgSHA256input);
  unsigned char outputSHA256[128];
  ret=hash_DRBG_Generate(drbgSHA256state, drbgSHA256input,outputSHA256, 128);
  ret=hash_DRBG_Generate(drbgSHA256state, drbgSHA256input,outputSHA256, 128);
  char expouthex4[]="d3e160c35b99f340b2628264d1751060e0045da383ff57a57d73a673d2b8d80daaf6a6c35a91bb4579d73fd0c8fed111b0391306828adfed528f018121b3febdc343e797b87dbb63db1333ded9d1ece177cfa6b71fe8ab1da46624ed6415e51ccde2c7ca86e283990eeaeb91120415528b2295910281b02dd431f4c9f70427df";
  unsigned char expectedOutSHA256[128];
  hex2char(expouthex4, expectedOutSHA256, 128);
    for(i = 0; i < 128; i++) {
    if (!(outputSHA256[i]==expectedOutSHA256[i])) {
      ret=TESTERROR;
    }
  }
  if (ret<0) {
    return ret;
  } else {
    printf("Hash_DRBG(SHA256) NIST Test Case 1 w/o add_string or per_string in drbg_pr passed!\n");
  }

  char entropyhex5[] = "68c43a008fe46a823d260a9d7fa388fb9e401f0197e7e758a744b4babb3f4651";
  unsigned char entropy5[32];
  hex2char(entropyhex5, entropy5, 32);
  char noncehex5[] = "eb6825777856331884aaf3751b3e4006";
  unsigned char nonce5[16];
  hex2char(noncehex5, nonce5, 16);
  char perhex5[] = "23ce0d32cbf2d26467f0d62acff1a3acbaa6d2746dc3ee7aa9d32c880788afc8";
  unsigned char pers5[32];
  hex2char(perhex5, pers5, 32);
  char addhex5[] = "a31b9f13b58d4fa2f8d8ac42b62a207ff647339a146bd8b268b33d4aff57adbd";
  unsigned char add5[32];
  hex2char(addhex5, add5, 32);
  free_drbg_input(drbgSHA256input);
  drbgSHA256input=drbgInput_init(entropy5,32, nonce5,16, pers5,32, add5, 32);
  ret= hash_DRBG_Instantiate(drbgSHA256state, drbgSHA256input);
  ret=hash_DRBG_Generate(drbgSHA256state, drbgSHA256input,outputSHA256, 128);
  char addhex51[] = "d34fc6504eca4b568193c75357b0d3821a48c77ff80d6dbd21c6cf045ff489cf";
  hex2char(addhex51, add5, 32);
  ret=hash_DRBG_Generate(drbgSHA256state, drbgSHA256input,outputSHA256, 128);
  char expouthex5[]="abb4ecbacd4e8fa943c7221aed433861c3b203232657ec4c417d021f905d911db1058ff1e11e272232482ec96bae7cb4efc135502dbe41724077077f6de79b713670c385d04644e1281c3e582e0016255abbe5f8c06d0de57160559f0c08f7fb5be3563c649966190f8d3261364447537de2c7371c6e8c308933d27145bf90ab";
  hex2char(expouthex5, expectedOutSHA256, 128);
    for(i = 0; i < 128; i++) {
    if (!(outputSHA256[i]==expectedOutSHA256[i])) {
      ret=TESTERROR;
    }
  }
  if (ret<0) {
    return ret;
  } else {
    printf("Hash_DRBG(SHA256) NIST Test Case 2 with add_string and per_string in drbg_pr passed!\n");
  }

  char entropyhex5r[] = "6c623aea73bc8a59e28c6cd9c7c7ec8ca2e75190bd5dcae5978cf0c199c23f4f";
  unsigned char entropy5r[32];
  hex2char(entropyhex5r, entropy5r, 32);
  char noncehex5r[] = "e55db067a0ed537e66886b7cda02f772";
  unsigned char nonce5r[16];
  hex2char(noncehex5r, nonce5r, 16);
  char perhex5r[] = "1e59d798810083d1ff848e90b25c9927e3dfb55a0888b0339566a9f9ca7542dc";
  unsigned char pers5r[32];
  hex2char(perhex5r, pers5r, 32);
  char addhex5r[] = "4e8bead7cbba7a7bc9ae1e1617222c4139661347599950e7225d1e2faa5d57f5";
  unsigned char add5r[32];
  hex2char(addhex5r, add5r, 32);
  free_drbg_input(drbgSHA256input);
  drbgSHA256input=drbgInput_init(entropy5r,32, nonce5r,16, pers5r,32, add5r, 32);
  ret= hash_DRBG_Instantiate(drbgSHA256state, drbgSHA256input);
  char entropyreseedhex5r[] = "9ab40164744c7d00c78b4196f6f917ec33d70030a0812cd4606c5a25387568a9";
  hex2char(entropyreseedhex5r, entropy5r, 32);
  ret= hash_DRBG_Reseed(drbgSHA256state, drbgSHA256input);
  char addhex51r[] = "dcb22a5d9f149858636f3ede2253e419816fb7b1103194451ed6a573a8fe6271";
  hex2char(addhex51r, add5r, 32);
  ret=hash_DRBG_Generate(drbgSHA256state, drbgSHA256input,outputSHA256, 128);
  char addhex51r1[] = "8f9d5c78cdabc32e71ac3b3c49239caddf96053250f4fd92056efbd0be487d36";
  hex2char(addhex51r1, add5r, 32);
  ret=hash_DRBG_Generate(drbgSHA256state, drbgSHA256input,outputSHA256, 128);
  char expouthex5r[]="6e98a3b1f686f6ffa79355c9d8a5ab7f93312159d52659a2298315f10007c71adabc0b5ccb4164c0949fbdb221b43acdb62bed3099596f2d7bd5d0048173dd2360a543b234ab61a441ddb9299af84ca45c6e618fd521366dbf509d4ec06174da924361d642b107e5564ac1b32340dd2f3158bf4c00bcb4dcf12c6d67af4b74ee";
  hex2char(expouthex5r, expectedOutSHA256, 128);
    for(i = 0; i < 128; i++) {
    if (!(outputSHA256[i]==expectedOutSHA256[i])) {
      ret=TESTERROR;
    }
  }
  if (ret<0) {
    return ret;
  } else {
    printf("Hash_DRBG(SHA256) NIST Test Case 3 with reseed/add_string/per_string in drbg_pr passed!\n");
  }
  free_drbg_input(drbgSHA256input);
  
  char entropyhex6[] = "6b50a7d8f8a55d7a3df8bb40bcc3b722d8708de67fda010b03c4c84d72096f8c";
  unsigned char entropy6[32];
  hex2char(entropyhex6, entropy6, 32);
  char noncehex6[] = "3ec649cc6256d9fa31db7a2904aaf025";
  unsigned char nonce6[16];
  hex2char(noncehex6, nonce6, 16);
  drbgSHA512input=drbgInput_init(entropy6,32, nonce6,16, pers,0, add, 0);
  ret= hash_DRBG_Instantiate(drbgSHA512state, drbgSHA512input);
  unsigned char outputSHA512[256];
  ret=hash_DRBG_Generate(drbgSHA512state, drbgSHA512input,outputSHA512, 256);
  ret=hash_DRBG_Generate(drbgSHA512state, drbgSHA512input,outputSHA512, 256);
  char expouthex6[]="95b7f17e9802d3577392c6a9c08083b67dd1292265b5f42d237f1c55bb9b10bfcfd82c77a378b8266a0099143b3c2d64611eeeb69acdc055957c139e8b190c7a06955f2c797c2778de940396a501f40e91396acf8d7e45ebdbb53bbf8c975230d2f0ff9106c76119ae498e7fbc03d90f8e4c51627aed5c8d4263d5d2b978873a0de596ee6dc7f7c29e37eee8b34c90dd1cf6a9ddb22b4cbd086b14b35de93da2d5cb1806698cbd7bbb67bfe3d31fd2d1dbd2a1e058a3eb99d7e51f1a938eed5e1c1de23a6b4345d3191409f92f39b3670d8dbfb635d8e6a36932d81033d1448d63b403ddf88e121b6e819ac381226c1321e4b08644f6727c368c5a9f7a4b3ee2";
  unsigned char expectedOutSHA512[256];
  hex2char(expouthex6, expectedOutSHA512, 256);
    for(i = 0; i < 256; i++) {
    if (!(outputSHA512[i]==expectedOutSHA512[i])) {
      ret=TESTERROR;
    }
  }
  if (ret<0) {
    return ret;
  } else {
    printf("Hash_DRBG(SHA512) NIST Test Case 1 w/o add_string or per_string in drbg_pr passed!\n");
  }
  
  char entropyhex7[] = "31e8d6fbdc9026b0708405c20b558fcc0a107f3fdc836fe056f020df30d9dc57";
  unsigned char entropy7[32];
  hex2char(entropyhex7, entropy7, 32);
  char noncehex7[] = "2b8bbab9b486abb659c4ae8ff5978e22";
  unsigned char nonce7[16];
  hex2char(noncehex7, nonce7, 16);
  char perhex7[] = "949eb753762869aa5ea0ce725523595f9bc9b219735113e71feab228d0872c38";
  unsigned char pers7[32];
  hex2char(perhex7, pers7, 32);
  char addhex7[] = "88f1180d4ef564315280a9692f107ed9c0639d79bb7040dfc3b7d58bf24ef8f5";
  unsigned char add7[32];
  hex2char(addhex7, add7, 32);
  free_drbg_input(drbgSHA512input);
  drbgSHA512input=drbgInput_init(entropy7,32, nonce7,16, pers7,32, add7, 32);
  ret= hash_DRBG_Instantiate(drbgSHA512state, drbgSHA512input);
  ret=hash_DRBG_Generate(drbgSHA512state, drbgSHA512input,outputSHA512, 256);
  char addhex71[] = "f4fc8a26e0ad181838f1399fe5b8a4b86670e92ab92b2c4daf3913470724d3f2";
  hex2char(addhex71, add7, 32);
  ret=hash_DRBG_Generate(drbgSHA512state, drbgSHA512input,outputSHA512, 256);
  char expouthex7[]="10509641332a4d72a3c5936512c37cb9ab9874693902ee4c76e963675627ef86aa2e7d7029a152b800072fc53eeb6b41d12f481cde99b467dac3486836f6e146e9a79d3fb90d9b26f213ddbfac590ca083ed83fde4924395d25b645b96a6983e65fd662cae66112ebfa990f09b86b01270b7f0ef35f183eb01ffcbd7d5ec6adc4839cf3814dac858e013c6d79528ef273dd83724ccdc82b73dc63698fcf8ef0924f27b6a49d6d38f0ce261aa5a0a88779e47a413c29e1d7d20e4ab914bbabd5e6e0241cf53263a8efa321b4a632eb062b255c0ce5a0833114161dd073dd037967a1f03daf2dd7e927b801b40e62f26c0872ea100132807650232126aa8f29d70";
  hex2char(expouthex7, expectedOutSHA512, 256);
    for(i = 0; i < 256; i++) {
    if (!(outputSHA512[i]==expectedOutSHA512[i])) {
      ret=TESTERROR;
    }
  }
  if (ret<0) {
    return ret;
  } else {
    printf("Hash_DRBG(SHA512) NIST Test Case 2 with add_string and per_string in drbg_pr passed!\n");
  }

  char entropyhex7r[] = "4b23595b0a3640cfabb0ec34df6a613308b0448488a5d9ff99da4278e072eb34";
  unsigned char entropy7r[32];
  hex2char(entropyhex7r, entropy7r, 32);
  char noncehex7r[] = "8e696bffd9ca3a71d2e2f05e600c8364";
  unsigned char nonce7r[16];
  hex2char(noncehex7r, nonce7r, 16);
  char perhex7r[] = "010ba93ea68a3d4a200e5145859e299c5b5349b7645fb5bbcad687aba7d67313";
  unsigned char pers7r[32];
  hex2char(perhex7r, pers7r, 32);
  char addhex7r[] = "2b0c7c3efb36b71b917a44086d168313675b426b17c5ab3d0eb6af753f6040e0";
  unsigned char add7r[32];
  hex2char(addhex7r, add7r, 32);
  free_drbg_input(drbgSHA512input);
  drbgSHA512input=drbgInput_init(entropy7r,32, nonce7r,16, pers7r,32, add7r, 32);
  ret= hash_DRBG_Instantiate(drbgSHA512state, drbgSHA512input);
  char entropyreseedhex7r[] = "04de4babdbe143bde99aa4452f9aa43b0a164eb927555c0496aa0fc9328a521c";
  hex2char(entropyreseedhex7r, entropy7r, 32);
  ret=hash_DRBG_Reseed(drbgSHA512state, drbgSHA512input);
  char addhex71r[] = "d0b7d1d12ab15d3bba8f4eba07fee0974838962b247be480683b8e3d4a91033a";
  hex2char(addhex71r, add7r, 32);
  ret=hash_DRBG_Generate(drbgSHA512state, drbgSHA512input,outputSHA512, 256);
  char addhex71r1[] = "66c78ca12e45bdca003b49cb6440b977dd85b167e7c803890ed1a73666eaa869";
  hex2char(addhex71r1, add7r, 32);
  ret=hash_DRBG_Generate(drbgSHA512state, drbgSHA512input,outputSHA512, 256);
  char expouthex7r[]="4008cbd8281dc82fd6c368f650ef2609bb771e80c63d478a77fa938248dcbb8b79e54ead0265f6ff1ebfafe4e387c6e27df9f03e4a5225e86a4436e56ebf03b3be2cfbcb49c89c92ec1dfa5ee445dd4f6f64e02a2423a0b18ebd02eec52f5cc21bc3565e796b3ded6552f1b5a574a201c3b11018222806f9618d23d77fd02db879cf87fe24ed7ba11b3b108b559633db1f95c5121b28011aa4dd20399bd4978e1f8b8880c333a47ff1750679bf28d329347b26d347aae90ee562ae8029579cbe0336e066d6b8ba5e0169fec804c30189a4434c1bf8a5b0a249951d3d89554da38ff0751b8b1fef9ae18a0aa2bc477736d199a06f61d400039a4cc03869bb10ca";
  hex2char(expouthex7r, expectedOutSHA512, 256);
    for(i = 0; i < 256; i++) {
    if (!(outputSHA512[i]==expectedOutSHA512[i])) {
      ret=TESTERROR;
    }
  }
  if (ret<0) {
    return ret;
  } else {
    printf("Hash_DRBG(SHA512) NIST Test Case 3 with reseed/add_string/per_string in drbg_pr passed!\n");
  }
  free_drbg_input(drbgSHA512input);
  free_drbg_state(drbgSHA1state);
  free_drbg_state(drbgSHA256state);
  free_drbg_state(drbgSHA512state);
  return ret;
}

int testSHA(void){
  unsigned int hash1[5];
  unsigned int hash2[8];
  unsigned long hash3[8];
  int size;
  int pass=0;
  
  static unsigned char msg1[] = {'a', 'b', 'c'};
  size = 3;
  sha1_md(msg1, size, hash1);
  if ((hash1[0] != 0xa9993e36)||(hash1[1]!=0x4706816a )||(hash1[2]!=0xba3e2571 )
      ||(hash1[3]!=0x7850c26c)||(hash1[4]!=0x9cd0d89d)) {
    pass=1;
    printf("SHA1 with input abc failed\n");
  }
  
  sha256_md(msg1, size,hash2);
  if ((hash2[0] != 0xba7816bf)||(hash2[1]!=0x8f01cfea)||(hash2[2]!=0x414140de)
      ||(hash2[3]!=0x5dae2223)||(hash2[4]!=0xb00361a3)||(hash2[5]!=0x96177a9c)
      ||(hash2[6]!=0xb410ff61)||(hash2[7]!=0xf20015ad)
      ) {
    pass=1;
    printf("SHA256 with input abc failed\n");
  }
  
  sha512_md(msg1, size,hash3);
  if ((hash3[0] != 0xddaf35a193617aba)||(hash3[1]!=0xcc417349ae204131)||(hash3[2]!=0x12e6fa4e89a97ea2)
      ||(hash3[3]!=0x0a9eeee64b55d39a)||(hash3[4]!=0x2192992a274fc1a8)||(hash3[5]!=0x36ba3c23a3feebbd)
      ||(hash3[6]!=0x454d4423643ce80e)||(hash3[7]!=0x2a9ac94fa54ca49f)
      ) {
    pass=1;
    printf("SHA512 with input abc failed\n");
  }

  static unsigned char msg3[] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
  size = sizeof(msg3)-1;
  sha1_md(msg3, size, hash1);
  if ((hash1[0] != 0x84983e44)||(hash1[1]!=0x1c3bd26e)||(hash1[2]!=0xbaae4aa1)
      ||(hash1[3]!=0xf95129e5)||(hash1[4]!=0xe54670f1)) {
    pass=1;
    printf("SHA1 with input \'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq\' failed\n");
  }
  
  sha256_md(msg3, size,hash2);
  if ((hash2[0] != 0x248d6a61)||(hash2[1]!=0xd20638b8)||(hash2[2]!=0xe5c02693)
      ||(hash2[3]!=0x0c3e6039)||(hash2[4]!=0xa33ce459)||(hash2[5]!=0x64ff2167)
      ||(hash2[6]!=0xf6ecedd4)||(hash2[7]!=0x19db06c1)
      ) {
    pass=1;
    printf("SHA256 with input \'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq\' failed\n");
  }
  
  static unsigned char msg31[] ="abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
  size = sizeof(msg31)-1;
  sha512_md(msg31, size, hash3);
  if ((hash3[0] != 0x8e959b75dae313da)||(hash3[1]!=0x8cf4f72814fc143f)||(hash3[2]!=0x8f7779c6eb9f7fa1)
      ||(hash3[3]!=0x7299aeadb6889018)||(hash3[4]!=0x501d289e4900f7e4)||(hash3[5]!=0x331b99dec4b5433a)
      ||(hash3[6]!=0xc7d329eeb6dd2654)||(hash3[7]!=0x5e96e55b874be909)
      ) {
    pass=1;
    printf("SHA512 with input abcd....stu failed\n");
  }
  int i;
  static unsigned char msg4[1000000];
  for (i=0; i<1000000; i++) {
    msg4[i]='a';
  }
  size=1000000;
  sha1_md(msg4, size, hash1);
    if ((hash1[0] !=0x34aa973c)||(hash1[1]!=0xd4c4daa4)||(hash1[2]!=0xf61eeb2b)
      ||(hash1[3]!=0xdbad2731)||(hash1[4]!=0x6534016f)) {
    pass=1;
    printf("SHA1 with input 1000000 \'a\'s failed\n");
  }
 
  sha256_md(msg4, size,hash2);
  if ((hash2[0] != 0xcdc76e5c)||(hash2[1]!=0x9914fb92)||(hash2[2]!=0x81a1c7e2)
      ||(hash2[3]!=0x84d73e67)||(hash2[4]!=0xf1809a48)||(hash2[5]!=0xa497200e)
      ||(hash2[6]!=0x046d39cc)||(hash2[7]!=0xc7112cd0)
      ) {
    pass=1;
    printf("SHA256 with input 1000000 \'a\'s failed\n");
  }
  
  sha512_md(msg4, size,hash3);
  if ((hash3[0] != 0xe718483d0ce76964)||(hash3[1]!=0x4e2e42c7bc15b463)||(hash3[2]!=0x8e1f98b13b204428)
      ||(hash3[3]!=0x5632a803afa973eb)||(hash3[4]!=0xde0ff244877ea60a)||(hash3[5]!=0x4cb0432ce577c31b)
      ||(hash3[6]!=0xeb009c5c2c49aa2e)||(hash3[7]!=0x4eadb217ad8cc09b)
      ) {
    pass=1;
    printf("SHA512 with input 1000000 \'a\'s failed\n");
  }
  return pass;
}


int testReedSolomon(void) {
  unsigned int para[PARASIZE];
  int ret=0;
  ret=getRLCEparameters(para, CRYPTO_SCHEME, CRYPTO_PADDING);
  if (ret<0) {
    return ret;
  }
  int GFsize=para[3];
  int codeLen = (1u<< GFsize) -1;
  int zeroLen = codeLen - para[0];
  int codeDim = para[1]+zeroLen;
    
  
  poly_t codeword, corruptedCodeword, decodedWord, message, generator;
  int random;
  time_t tim;
  int tmp=0;
  
  generator=initialize_RS (codeLen, codeDim, GFsize);
  message =  poly_init(codeLen);
  poly_zero(message);
  int i;
  for (i=0; i<codeDim; i++) {
    message->coeff[i]='Y';
  }
  message->deg=codeDim-1;
    
  codeword =  poly_init(codeLen);
  corruptedCodeword  =  poly_init(codeLen);
  ret=rs_encode (generator, message, codeword, GFsize);
  poly_free(generator);
  poly_free(message);
  if (ret<0) {
    return ret;
  }
  poly_copy(codeword, corruptedCodeword);

  srand((unsigned) time(&tim));
  for (i=0; i< (codeLen-codeDim)/2; i++) {
    random = rand()%codeLen;  
    corruptedCodeword->coeff[random]=10;
  }
  poly_deg(corruptedCodeword);

  int numErrors=0;
  for (i=0; i<codeLen; i++) {
    if (codeword->coeff[i] != corruptedCodeword->coeff[i]) {
      numErrors++;
    }
  }
  field_t eLocation[codeLen-codeDim];
  decodedWord=rs_decode(0, corruptedCodeword, codeLen, codeDim, eLocation, GFsize);
  /* first parameter 0 for BM-decoder and 1 for Euclidean decoder */

  tmp=0;
  for (i=0; i<codeLen; i++) {
    if (codeword->coeff[i] != decodedWord->coeff[i]) {
      tmp++;
      /* printf("error at [%u] is not corrected\n", i);*/
    }
  }
  poly_free(decodedWord);
  poly_free(corruptedCodeword);
  poly_free(codeword);
  if (tmp == 0) {
    return 0;
  } else {
    return 0-tmp;
  }
}
 
int preComputelogExpTable(void) {

  clock_t start, finish;
  double seconds;
  start=clock();
  GF_init_logexp_table(8);
  finish = clock();
  seconds = ((double)(finish - start))/CLOCKS_PER_SEC;
  printf("%f seconds for GF(2^8) LOGEXP Table\n",seconds);

  start=clock();
  GF_init_logexp_table(9);
  finish = clock();
  seconds = ((double)(finish - start))/CLOCKS_PER_SEC;
  printf("%f seconds for GF(2^9) LOGEXP Table\n",seconds);
  
  start=clock();  
  GF_init_logexp_table(10);
  finish = clock();
  seconds = ((double)(finish - start))/CLOCKS_PER_SEC;
  printf("%f seconds for GF(2^10) LOGEXP Table\n",seconds);
  
  start=clock();
  GF_init_logexp_table(11);
  finish = clock();
  seconds = ((double)(finish - start))/CLOCKS_PER_SEC;
  printf("%f seconds for GF(2^11) LOGEXP Table\n",seconds);

  start=clock();
  GF_init_logexp_table(12);
  finish = clock();
  seconds = ((double)(finish - start))/CLOCKS_PER_SEC;
  printf("%f seconds for GF(2^12) LOGEXP Table\n",seconds);

  int i=0;
  FILE *f = fopen("gf8log", "w"); /* r or w */
  if (f == NULL) {
    return FILEERROR;
  }
  for (i=0; i<(1u<<8); i++) {
    fprintf(f, "0x%02x, ", GF_log(i,8));
  }
  fclose(f);

  f = fopen("gf8exp", "w"); /* r or w */
  if (f == NULL) {
    return FILEERROR;
  }
  for (i=0; i<(1u<<8); i++) {
    fprintf(f, "0x%02x, ", GF_exp(i,8));
  }
  fclose(f);

  f = fopen("gf9log", "w"); /* r or w */
  if (f == NULL) {
    return FILEERROR;
  }
  for (i=0; i<(1u<<9); i++) {
    fprintf(f, "0x%02x, ", GF_log(i,9));
  }
  fclose(f);

  f = fopen("gf9exp", "w"); /* r or w */
  if (f == NULL) {
    return FILEERROR;
  }
  for (i=0; i<(1u<<9); i++) {
    fprintf(f, "0x%02x, ", GF_exp(i,9));
  }
  fclose(f);

  f = fopen("gf10log", "w"); /* r or w */
  if (f == NULL) {
    return FILEERROR;
  }
  for (i=0; i<(1u<<10); i++) {
    fprintf(f, "0x%02x, ", GF_log(i,10));
  }
  fclose(f);

  f = fopen("gf10exp", "w"); /* r or w */
  if (f == NULL) {
    return FILEERROR;
  }
  for (i=0; i<(1u<<10); i++) {
    fprintf(f, "0x%02x, ", GF_exp(i,10));
  }
  fclose(f);

  f = fopen("gf11log", "w"); /* r or w */
  if (f == NULL) {
    return FILEERROR;
  }
  for (i=0; i<(1u<<11); i++) {
    fprintf(f, "0x%02x, ", GF_log(i,11));
  }
  fclose(f);

  f = fopen("gf11exp", "w"); /* r or w */
  if (f == NULL) {
    return FILEERROR;
  }
  for (i=0; i<(1u<<11); i++) {
    fprintf(f, "0x%02x, ", GF_exp(i,11));
  }
  fclose(f);

  f = fopen("gf12log", "w"); /* r or w */
  if (f == NULL) {
    return FILEERROR;
  }
  for (i=0; i<(1u<<12); i++) {
    fprintf(f, "0x%02x, ", GF_log(i,12));
  }
  fclose(f);

  f = fopen("gf12exp", "w"); /* r or w */
  if (f == NULL) {
    return FILEERROR;
  }
  for (i=0; i<(1u<<12); i++) {
    fprintf(f, "0x%02x, ", GF_exp(i,12));
  }
  fclose(f);  
  return 0;
}

int getMSG(unsigned char msg[], unsigned short msglen) {
  if (msglen >1595) {
    return REQIREDMSGTOOLONG;
  }
  char msgHEX[] = "f58720b0d421806aaabe738b219590ae748171e822e9575997e1f28538e83c7a39f0760a7b8bf07a5e9fbbb0962aa0e3eb3448b1fac64f72e9828362236ce4d4bf02cc30f36f5466b14d457a4732563f24deaa37f7fb18498fc06cc605f63b110c74836e66be8591d05f4c3fed09e8303a4b529e9e85d84d8a4b81a71b33272769583caffa9e828e749d6249902c83daf2a4dbd763d9f119f283809a6154bd9f3473e53b0dc28b90850dc2b36a2628b2924e610875744dcb13cf14d6f33f6abf281366875325562e7156ce23db2f2902c55151f08ec403263f2ba911b1eeb8646924b0eef466bfe268b3ee3db69cd9bc235a63293bfdc686613def32e7ab99f4794edfcd5490859b6964fef446a1a9af47c083405f3844687988f4fa5bd9965cc6279739337f4449458384ea97050aee44c98d2ad3c625844db0c172bff65420494a9d547240f402b26397ef432fdae6768b03e5f35bbf99388ad6d52a9272a3b3f56006901b9948023d262b85165f0590e0b47b441b5d5d4dbc7d58d69729467de0952cc5570d0d6f66f8acfbe9cdf08df6be3eaf6f7f0153b1164ce12fc7c9e3ccedbaf55a942607dd06080e455a3f6a5cb84c8884e71d91d9bcf0511b1bbd89dea4622ad06d19d99c4d1b980b91cdead66048d23c49349f32dd43b73c4e6f1f940b6f9e0f75303f9350402d6d5408b99500fb3c5147b842411be0b5e954d724d987b08f967eaf4a6f4226eb28ec34bf8aedd17560ac598bd1d34b12646d53512f2e91ac8d5e86aeb0f5e2a0e025c0d6daef1a7b0420315c8dce1465480bfdff4693567e531ec034c89866a8dce9d2b65ae05f2f42b6c5025e533535dd6013c99f616c45a690e60f759c132ce24a06329c9d80f1755680941c83386194228f9ba281dcf4e1936588a24a063551efb962a0b4b18d9035e68420e96ab3952d2cf994122b180d02a21de5e2a02e0852c27e4e98ce14dc8428a54ee6916edad4f74976b76c5fafd34c2b945925d4b69d789148ac0a34fc19b09f92242071f495f3abb0878e0c75968d99851f75f8a367787732bc90bfd0045cf1f30b3c4e00d27ee3ff25d4b69d789148ac0a34fc19b09f92242071f495f3abb0878e0c75968d99851f75f8a367787732bc90bfd0045cf1f30b3c4e00d27ee3ffb876f008394a498d0c89c7972b5760c19bc60b89fe853e808eb0a7e6d7925dae99f878d6583432c141e47dfb0301930edb4100119444e12df0cdb3a12b1b84a11146935e27aea2896cdf0bc02686b091bc230ddf9762fae515ae061221146ca745c0ce39db2358d2e308f0c0f6afa9fc78151ea70d081bcef2968c54fc8e9184682516aeb69e1b1d2d5af11097ea1df04cf7669cd2d5007c089013eebf37aae5e9a4c95c031551751386e8eb6d5672ae0e08871909851e611b58a1cd33b6c62563377cdab4fd7a27d2ec4eeb59fa07db4146b5733e923f9150f53eb465266a022dcf9f2876bb8164a289488802026c7d58514db3999f955517e42ce904827dd6d67591ca84d66338fde51a819247106c34707b0a47117860a0125d9ca07e2116d80845951f1a8ee2c86257ccae8f9c7faee5be4d15719779c65223bbc6607fab07adadfa1e059b54ca32808cc44ceb4e07262a765b786f2aae6ea9431ff2231e16f3ab33adaa8571832e02c35043d1dea81dc5e85a48e17c1d356dbbc0a40b68e63a32f076ae57592609ac0fc84fb7ea66914aa0f033919d737aa26962a863b24488b27c4d322f453e670d2f475ffb309b59018ebbe81cff227098fa8553d440f5f7532fa2a1ee9ea417aec1c069cd4a3e2f9185f0ba770451bee53cefbffbc20dfbbf29f90caaaa105c1abc67f290bfddda7c46bdd3f28ba346b58359c3fd4bf01ee14eb9aeb0f66f504e84a639661476386b66f08a8f0bd4bc1130ad7e40a914c58662b983e8e95ad929fb1d90ad61d50f83b94fa8dd13c3da03c39fea669e92abeb15ffcec8753d003cafd6a2e4f8de3f0835dc2769abc80a91f25f38604796a25820079161e9186b6eaaec114113a63c1c115115c0fbb4d2b285effb4e495fa3fe833180fb427029d7b9e9dd7379cc7e1519516233be1bad5cae238a9ce876150b8f70b0e50fa79691797231550b51fd707e57f83fdb77c1f9fe98d33668b2439641d0884e00dd04cb6cf383abddb1b4dae554f5bc965666742f368d4fba4013bcb388d464e04a454c31998754d5866992cf9ef8e01feae2170e904038b7af7d";
  int i=0;
  char buf[8];
  for(i = 0; i < msglen; i++) {
    sprintf(buf, "0x%c%c", msgHEX[2*i], msgHEX[2*i+1]);
    msg[i] = strtol(buf, NULL, 0);
  }
  return 0;
}

aeskey_t aeskey_init(unsigned short kappa);

int testAES(void) {
  int i;
  aeskey_t key=aeskey_init(128);
  if (key==NULL) {
    return -1;
  }
  char keystring[]="000102030405060708090a0b0c0d0e0f";
  hex2char(keystring, key->key, 16);
  char msgstring[]="00112233445566778899aabbccddeeff";
  unsigned char msg[16];
  unsigned char decryptedmsg[16];
  hex2char(msgstring, msg, 16);
  unsigned char cipher[16];
  AES_encrypt(msg, cipher,key);
  char ciphertring[]="69c4e0d86a7b0430d8cdb78070b4c55a";
  unsigned char expectedcipher[16];
  hex2char(ciphertring, expectedcipher, 16);
  int failed=0;
  for (i=0;i<16;i++) {
    if (expectedcipher[i] != cipher[i]) {
      failed =1;
    }
  }
  if (failed >0) {
    printf("AES-128 encryption failed\n");
  } else {
    printf("AES-128 encryprion succeeds\n");
  }

  AES_decrypt(cipher,decryptedmsg, key);

  failed=0;
  for (i=0;i<16;i++) {
    if (decryptedmsg[i] != msg[i]) {
      failed =1;
    }
  }

  if (failed >0) {
    printf("AES-128 decryption failed\n");
  } else {
    printf("AES-128 decryprion succeeds\n");
  }

  aeskey_free(key);
  key=aeskey_init(192);
  char keystring192[]="000102030405060708090a0b0c0d0e0f1011121314151617";
  hex2char(keystring192, key->key, 24);
  AES_encrypt(msg, cipher,key);
  char ciphertring192[]="dda97ca4864cdfe06eaf70a0ec0d7191";
  unsigned char expectedcipher192[16];
  hex2char(ciphertring192, expectedcipher192, 16);
  failed=0;
  for (i=0;i<16;i++) {
    if (expectedcipher192[i] != cipher[i]) {
      failed =1;
    }
  }
  if (failed >0) {
    printf("AES-192 encryption failed\n");
  } else {
    printf("AES-192 encryprion succeeds\n");
  }

  AES_decrypt(cipher,decryptedmsg, key);

  failed=0;
  for (i=0;i<16;i++) {
    if (decryptedmsg[i] != msg[i]) {
      failed =1;
    }
  }

  if (failed >0) {
    printf("AES-192 decryption failed\n");
  } else {
    printf("AES-192 decryprion succeeds\n");
  }

  aeskey_free(key);
  key=aeskey_init(256);
  char keystring256[]="000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
  hex2char(keystring256, key->key, 32);
  AES_encrypt(msg, cipher,key);
  char ciphertring256[]="8ea2b7ca516745bfeafc49904b496089";
  unsigned char expectedcipher256[16];
  hex2char(ciphertring256, expectedcipher256, 16);
  failed=0;
  for (i=0;i<16;i++) {
    if (expectedcipher256[i] != cipher[i]) {
      failed =1;
    }
  }
  if (failed >0) {
    printf("AES-256 encryption failed\n");
  } else {
    printf("AES-256 encryprion succeeds\n");
  }

  AES_decrypt(cipher,decryptedmsg, key);

  failed=0;
  for (i=0;i<16;i++) {
    if (decryptedmsg[i] != msg[i]) {
      failed =1;
    }
  }

  if (failed >0) {
    printf("AES-256 decryption failed\n");
  } else {
    printf("AES-256 decryprion succeeds\n");
  }
  aeskey_free(key);
  return 0;
}



ctr_drbg_state_t ctr_drbgstate_init(unsigned short aestype);
void free_ctr_drbg_state(ctr_drbg_state_t ctr_drbgState);
int ctr_DRBG_Instantiate_algorithm(ctr_drbg_state_t drbgState, drbg_Input_t drbgInput);
int ctr_DRBG_Instantiate_algorithm_DF(ctr_drbg_state_t drbgState, drbg_Input_t drbgInput);
int ctr_DRBG_Generate(ctr_drbg_state_t drbgState, drbg_Input_t drbgInput,
		      unsigned char returned_bytes[],
		      unsigned long req_no_of_bytes);
int ctr_DRBG_Generate_DF(ctr_drbg_state_t drbgState, drbg_Input_t drbgInput,
		       unsigned char returned_bytes[],
			 unsigned long req_no_of_bytes);
int ctr_DRBG_Reseed(ctr_drbg_state_t drbgState, drbg_Input_t drbgInput);
int ctr_DRBG_Reseed_DF(ctr_drbg_state_t drbgState, drbg_Input_t drbgInput);

int testCTRDRBG(void) {
  int ret=0;
  int i=0;
  ctr_drbg_state_t drbg128state, drbg192state,drbg256state;
  drbg128state=ctr_drbgstate_init(128);
  drbg192state=ctr_drbgstate_init(192);
  drbg256state=ctr_drbgstate_init(256);

  unsigned char entropy[48];
  unsigned char nonce[48];
  unsigned char pers[48];
  unsigned char add[48];
  unsigned char output[64];

  char entropyhex1[] = "50b96542a1f2b8b05074051fe8fb0e45adbbd5560e3594e12d485fe1bfcb741f";
  hex2char(entropyhex1, entropy, 32);  
  char addhex1[] = "1f1632058806d6d8e231288f3b15a3c324e90ccef4891bd595f09c3e80e27469";
  hex2char(addhex1, add, 32);
  char perhex1[] = "820c3030f97b3ead81a93b88b871937278fd3d711d2085d9280cba394673b17e";
  hex2char(perhex1, pers, 32);
  drbg_Input_t drbginput;
  drbginput=drbgInput_init(entropy,32, nonce, 0,pers, 32,add, 32);
  ret= ctr_DRBG_Instantiate_algorithm(drbg128state, drbginput);
  if (ret<0) return ret; 
  ret=ctr_DRBG_Generate(drbg128state, drbginput,output, 64);
  if (ret<0) return ret;
  char addhex11[] = "5cadc8bfd86d2a5d44f921f64c7d153001b9bdd7caa6618639b948ebfad5cb8a";
  hex2char(addhex11, add, 32);
  ret=ctr_DRBG_Generate(drbg128state, drbginput,output, 64);
  if (ret<0) return ret;
  char hexstring[] = "02b76a66f103e98d450e25e09c35337747d987471d2b3d81e03be24c7e985417a32acd72bc0a6eddd9871410dacb921c659249b4e2b368c4ac8580fb5db559bc";
  unsigned char hexChar[64];
  hex2char(hexstring, hexChar, 64);
  for(i = 0; i < 64; i++) {
    if (!(output[i]==hexChar[i])) ret=TESTERROR;
  }
  if (ret<0) {
    return ret;
  } else {
    printf("CTR_DRBG AES-128 noDF/additional/personal passed drbg_prdrbgvectors_no_reseed test!\n");
  }
  free_drbg_input(drbginput);

  char entropyhex4[] = "8db47ca284294daeb303e6459422e32577ca539c00fead8839d42946bad8eb30e489c6d858763a28";
  hex2char(entropyhex4, entropy, 40);
  char addhex2[] = "e9a3f24180345a0c0680aacdb89ce7cf841c7ad547ef92dad54f8262445e2f0c54c8f8e42350f79c";
  hex2char(addhex2, add, 40);
  char perhex2[] = "c2491a6ce1ef9bd13eb66a86c0f5be3d2f3239bf7f713e830e8ae8907a2084f873ed3f5eddf5b569";
  hex2char(perhex2, pers, 40);
  drbginput=drbgInput_init(entropy,40, nonce, 0, pers,40, add, 40);
  ret= ctr_DRBG_Instantiate_algorithm(drbg192state, drbginput);

  ret=ctr_DRBG_Generate(drbg192state, drbginput,output, 64);
  char addhex21[] = "e2427b93738424c0fce14cb6c5f1d6b6a0532787157b6d907bc55d1c9a670494776212a643a9fb2c";
  hex2char(addhex21, add, 40);
  ret=ctr_DRBG_Generate(drbg192state, drbginput,output, 64);
  char expouthex4[]="494b1957ab382b382054f54bb62f0b5b464afb3b18492c60809c26e86e45b6b9fa44524dd89ecdca99c60e68ed107ff336be1591cadd6fd7e35f742611809f2e";
  hex2char(expouthex4, hexChar, 64);
  for(i = 0; i < 64; i++) {
    if (!(output[i]==hexChar[i])) ret=TESTERROR;
  }
  if (ret<0) {
    return ret;
  } else {
    printf("CTR_DRBG(AES-192) noDF/personal/add_string passed drbg_prdrbgvectors_no_reseed test!\n");
  }
  free_drbg_input(drbginput);

  char entropyhex5[] = "0dd4d80062ecc0f359efbe7723020be9b88b550fe74088094069e74428395856f63eed4f5b0e7d1e006f0eaff74f638c";
  hex2char(entropyhex5, entropy, 48);
  char perhex3[] = "d2aa2ccd4bc6537e51f6550ab6d6294547bef3e971a7f128e4436f957de9982c93ee22110b0e40ab33a7d3dfa22f599d";
  hex2char(perhex3, pers, 48);
  char addhex3[] = "0b081bab6c74d86b4a010e2ded99d14e0c9838f7c3d69afd64f1b66377d95cdcb7f6ec5358e3516034c3339ced7e1638";
  hex2char(addhex3, add, 48);
  drbginput=drbgInput_init(entropy,48, nonce, 0, pers,48,add, 48);
  ret= ctr_DRBG_Instantiate_algorithm(drbg256state, drbginput);
  ret=ctr_DRBG_Generate(drbg256state, drbginput,output, 64);
  char addhex31[] = "ca818f938ae0c7f4f507e4cfec10e7baf51fe34b89a502f754d2d2be7395120fe1fb013c67ac2500b3d17b735da09a6e";
  hex2char(addhex31, add, 48);
  ret=ctr_DRBG_Generate(drbg256state, drbginput,output, 64);
  char expouthex5[]="6808268b13e236f642c06deba2494496e7003c937ebf6f7cb7c92104ea090f18484aa075560d7844a06eb559948c93b26ae40f2db98ecb53ad593eb4c78f82b1";
  hex2char(expouthex5, hexChar, 64);
  for(i = 0; i < 64; i++) {
    if (!(output[i]==hexChar[i])) ret=TESTERROR;
  }
  if (ret<0) {
    return ret;
  } else {
    printf("CTR_DRBG(AES-256) noDF/personal/add_string passed drbg_prdrbgvectors_no_reseed test!\n");
  }
  free_drbg_input(drbginput);

  printf("begin test CTR_DRBG with DF ... \n");

  char entropyhexdf1[] = "cae48dd80d298103ef1ec0bf1bb96270";
  hex2char(entropyhexdf1, entropy, 16);
  char noncedf1[] = "d827f91613e0b47f";
  hex2char(noncedf1, nonce, 8); 
  char addhexdf1[] = "7eaa1bbec79393a7f4a8227b691ecb68";
  hex2char(addhexdf1, add, 16);
  char perhexdf1[] = "cc928f3d2df31a29f4e444f3df08be21";
  hex2char(perhexdf1, pers, 16);
  drbginput=drbgInput_init(entropy,16, nonce,8,pers,16,add,16);
  ret= ctr_DRBG_Instantiate_algorithm_DF(drbg128state, drbginput);
  if (ret<0) return ret;
  ret=ctr_DRBG_Generate_DF(drbg128state, drbginput,output, 64);
  if (ret<0) return ret;
  char addhexdf11[] = "6869c6c7b9e6653b3977f0789e94478a";
  hex2char(addhexdf11, add, 16);
  ret=ctr_DRBG_Generate_DF(drbg128state, drbginput,output, 64);
  if (ret<0) return ret;
  char hexstringdf1[] = "920132cd284695b868b5bc4b703afea4d996624a8f57e9fbf5e793b509cb15b4beaf702dac28712d249ae75090a91fd35775294bf24ddebfd24e45d13f4a1748";
  hex2char(hexstringdf1, hexChar, 64);
  for(i = 0; i < 64; i++) {
    if (!(output[i]==hexChar[i])) ret=TESTERROR;
  }
  if (ret<0) {
    return ret;
  } else {
    printf("CTR_DRBG AES-128 DF/additional/personal passed drbg_prdrbgvectors_no_reseed test!\n");
  }
  free_drbg_input(drbginput);


  char entropyhexdf2[] = "d5973b5c9105cbf67e978f419924790d83023e86a8b5dd6b";
  hex2char(entropyhexdf2, entropy, 24);
  char noncedf2[] = "358af1ae9a842c6e03f88dfa2a311161";
  hex2char(noncedf2, nonce, 16); 
  char addhexdf2[] = "0805f31446c51d5d9d27b7cbb16e840b9e8b0dfe6fb4b69792bc8de9e3bd6d92";
  hex2char(addhexdf2, add, 32);
  char perhexdf2[] = "294d7d35f53a5d7ddef5ca4100f3547112c93e41251257dc0a19b6dfaa4a60a4";
  hex2char(perhexdf2, pers, 32);
  drbginput=drbgInput_init(entropy,24, nonce,16,pers,32,add,32);
  ret= ctr_DRBG_Instantiate_algorithm_DF(drbg192state, drbginput);
  if (ret<0) return ret;
  ret=ctr_DRBG_Generate_DF(drbg192state, drbginput,output, 64);
  if (ret<0) return ret;
  char addhexdf12[] = "934d7fd5e716376342607123ea113d6b20170ccda53fc86541407a156cd94904";
  hex2char(addhexdf12, add, 32);
  ret=ctr_DRBG_Generate_DF(drbg192state, drbginput,output, 64);
  if (ret<0) return ret;
  char hexstringdf2[] = "cb95459d1735cb9bce8a75bf097a099c9f7c70bad43e3e431f2d3829d7ca9d0617b9a99337af5248d4741cb5a60dff6f8c5221e23f3cb524a94ffdd2190bfb3b";
  hex2char(hexstringdf2, hexChar, 64);
  for(i = 0; i < 64; i++) {
    if (!(output[i]==hexChar[i])) ret=TESTERROR;
  }
  if (ret<0) {
    return ret;
  } else {
    printf("CTR_DRBG AES-192 DF/additional/personal passed drbg_prdrbgvectors_no_reseed test!\n");
  }
  free_drbg_input(drbginput);


  
  char entropyhexdf3[] = "ed12df77815585fc9ae7396620eee4ae68cc82a82ec30a792901e2858a59705d";
  hex2char(entropyhexdf3, entropy, 32);
  char noncedf3[] = "232a3db970b5cf1f31a5e09f02c0a97e";
  hex2char(noncedf3, nonce, 16); 
  char addhexdf3[] = "c9969a563374480bc08f61d4b46e587afc55126d3809e603e20e44a07636c678";
  hex2char(addhexdf3, add, 32);
  char perhexdf3[] = "2f9294db485305d48863b6f537c3faed903b9feb94bb848d00dc58e77d8f47c0";
  hex2char(perhexdf3, pers, 32);
  drbginput=drbgInput_init(entropy,32, nonce,16,pers,32,add,32);
  ret= ctr_DRBG_Instantiate_algorithm_DF(drbg256state, drbginput);
  if (ret<0) return ret;
  ret=ctr_DRBG_Generate_DF(drbg256state, drbginput,output, 64);
  if (ret<0) return ret;
  char addhexdf13[] = "03cfbaa739b33c1bc60abb1c730e155fae07837054b08ee848c458c88569ffc1";
  hex2char(addhexdf13, add, 32);
  ret=ctr_DRBG_Generate_DF(drbg256state, drbginput,output, 64);
  if (ret<0) return ret;
  char hexstringdf3[] = "78bd67eb4e660a4fe3474ec1e95b1fbdc1e4dc6867184ee4ea9e156814c5849c3c12d7ba06cced8c872712c2b96e7468536e11a20e93e53b8c778e9c0634c6cb";
  hex2char(hexstringdf3, hexChar, 64);
  for(i = 0; i < 64; i++) {
    if (!(output[i]==hexChar[i])) ret=TESTERROR;
  }
  if (ret<0) {
    return ret;
  } else {
    printf("CTR_DRBG AES-256 DF/additional/personal passed drbg_prdrbgvectors_no_reseed test!\n");
  }
  free_drbg_input(drbginput);

  printf("begin test CTR_DRBG with Reseed ... \n");

  char entropyhexre1[] = "e14ed7064a97814dd326b9a05bc44543";
  hex2char(entropyhexre1, entropy, 16);
  char noncere1[] = "876240c1f7de3dba";
  hex2char(noncere1, nonce, 8); 
  char addhexre1[] = "8835d28e7f85a4e95087bdd1bb7ad57e";
  hex2char(addhexre1, add, 16);
  char perhexre1[] = "26ccf56848a048721d0aad87d6fc65f0";
  hex2char(perhexre1, pers, 16);
  drbginput=drbgInput_init(entropy,16, nonce,8,pers,16,add,16);
  ret= ctr_DRBG_Instantiate_algorithm_DF(drbg128state, drbginput);
  if (ret<0) return ret;
  char entropyhexre10[] = "7ec4ac660fa0bbfa66ac3802e511901f";
  hex2char(entropyhexre10, entropy, 16);
  ctr_DRBG_Reseed_DF(drbg128state, drbginput);
  char addhexre10[] = "2a9bd50bbb20fefe24649f5f80eede66";
  hex2char(addhexre10, add, 16);
  ret=ctr_DRBG_Generate_DF(drbg128state, drbginput,output, 64);
  if (ret<0) return ret;
  char addhexre11[] = "f7ce3d5c6c381e56b25410c6909c1074";
  hex2char(addhexre11, add, 16);
  ret=ctr_DRBG_Generate_DF(drbg128state, drbginput,output, 64);
  if (ret<0) return ret;
  char hexstringre1[] = "d2f3130d309bed1da65545b9d793e035fd2564303d1fdcfb6c7fee019500d9f5d434fab2d3c8d15e39a25f965aaa804c7141407e90c4a86a6c8d303ce83bfb34";
  hex2char(hexstringre1, hexChar, 64);
  for(i = 0; i < 64; i++) {
    if (!(output[i]==hexChar[i])) ret=TESTERROR;
  }
  if (ret<0) {
    return ret;
  } else {
    printf("CTR_DRBG AES-128 DF/add/pers/reseed passed drbg_prdrbgvectors_no_reseed test!\n");
  }
  free_drbg_input(drbginput);


  char entropyhexre2[] = "c4b1e6a99587eacd7ec8517f40f9433ca432cea8686433f0";
  hex2char(entropyhexre2, entropy, 24);
  char noncere2[] = "d03a29e548e58ca7cbf0ac707b1464e3";
  hex2char(noncere2, nonce, 16); 
  char addhexre2[] = "f116a683ca485fda846a598b8d9b079e78c2828286ad530bf01f693cc8af9f84";
  hex2char(addhexre2, add, 32);
  char perhexre2[] = "0daaead21779b2a428d2b7fb12d9ab8316899edbe26b5460de1549c99e4781c9";
  hex2char(perhexre2, pers, 32);
  drbginput=drbgInput_init(entropy,24, nonce,16,pers,32,add,32);
  ret= ctr_DRBG_Instantiate_algorithm_DF(drbg192state, drbginput);
  if (ret<0) return ret;
  char entropyhexre20[] = "2229144c1b4efb79ab5fe079cda26bc33acbb2a0a87f642c";
  hex2char(entropyhexre20, entropy, 24);
  ctr_DRBG_Reseed_DF(drbg192state, drbginput);
  char addhexre20[] = "7c89de353298935bd26aa18517355313df0630da5f45ea0240e809179363080b";
  hex2char(addhexre20, add, 32);
  ret=ctr_DRBG_Generate_DF(drbg192state, drbginput,output, 64);
  if (ret<0) return ret;
  char addhexre12[] = "e978b8fe56afc908bed129a46d57a8698d66034d4dbcc7aba3a33d5796fb7559";
  hex2char(addhexre12, add, 32);
  ret=ctr_DRBG_Generate_DF(drbg192state, drbginput,output, 64);
  if (ret<0) return ret;
  char hexstringre2[] = "8ce7e9589c2975fd6989a450aa65da9114e515777c97351da037ccb72d4987eb69c680411724ed602e6ac76cd2d085725616c92777a4664d43a59c3ae9946134";
  hex2char(hexstringre2, hexChar, 64);
  for(i = 0; i < 64; i++) {
    if (!(output[i]==hexChar[i])) ret=TESTERROR;
  }
  if (ret<0) {
    return ret;
  } else {
    printf("CTR_DRBG AES-192 DF/add/pers/reseed passed drbg_prdrbgvectors_no_reseed test!\n");
  }
  free_drbg_input(drbginput);
  


  char entropyhexre3[] = "174b46250051a9e3d80c56ae7163dafe7e54481a56cafd3b8625f99bbb29c442";
  hex2char(entropyhexre3, entropy, 32);
  char noncere3[] = "98ffd99c466e0e94a45da7e0e82dbc6b";
  hex2char(noncere3, nonce, 16); 
  char addhexre3[] = "cdf6ad549e45b6aa5cd67d024931c33cd133d52d5ae500c3015020beb30da063";
  hex2char(addhexre3, add, 32);
  char perhexre3[] = "7095268e99938b3e042734b9176c9aa051f00a5f8d2a89ada214b89beef18ebf";
  hex2char(perhexre3, pers, 32);
  drbginput=drbgInput_init(entropy,32, nonce,16,pers,32,add,32);
  ret= ctr_DRBG_Instantiate_algorithm_DF(drbg256state, drbginput);
  if (ret<0) return ret;
  char entropyhexre30[] = "e88be1967c5503f65d23867bbc891bd679db03b4878663f6c877592df25f0d9a";
  hex2char(entropyhexre30, entropy, 32);
  ctr_DRBG_Reseed_DF(drbg256state, drbginput);
  char addhexre30[] = "c7228e90c62f896a09e11684530102f926ec90a3255f6c21b857883c75800143";
  hex2char(addhexre30, add, 32);
  ret=ctr_DRBG_Generate_DF(drbg256state, drbginput,output, 64);
  if (ret<0) return ret;
  char addhexre13[] = "76a94f224178fe4cbf9e2b8acc53c9dc3e50bb613aac8936601453cda3293b17";
  hex2char(addhexre13, add, 32);
  ret=ctr_DRBG_Generate_DF(drbg256state, drbginput,output, 64);
  if (ret<0) return ret;
  char hexstringre3[] = "1a6d8dbd642076d13916e5e23038b60b26061f13dd4e006277e0268698ffb2c87e453bae1251631ac90c701a9849d933995e8b0221fe9aca1985c546c2079027";
  hex2char(hexstringre3, hexChar, 64);
  for(i = 0; i < 64; i++) {
    if (!(output[i]==hexChar[i])) ret=TESTERROR;
  }
  if (ret<0) {
    return ret;
  } else {
    printf("CTR_DRBG AES-256 DF/add/pers/reseed passed drbg_prdrbgvectors_no_reseed test!\n");
  }
  free_drbg_input(drbginput);

  printf("begin test CTR_DRBG with Reseed without DF ... \n");


  char entropyhexren1[] = "289e5c8283cbd7dbe707255cb3cf2907d8a5ce5b347314966f9b2bebb1a1e200";
  hex2char(entropyhexren1, entropy, 32);
  char addhexren1[] = "f7a0378328d939f0f8521e39409d7175d87319c7597a9050414f7adc392a328d";
  hex2char(addhexren1, add, 32);
  char perhexren1[] = "7f7b59f23510b976fe155d047525c94e2dacb30d77ac8b09281544dd815d5293";
  hex2char(perhexren1, pers, 32);
  drbginput=drbgInput_init(entropy,32, nonce,0,pers,32,add,32);
  ret= ctr_DRBG_Instantiate_algorithm(drbg128state, drbginput);
  if (ret<0) return ret;
  char entropyhexren10[] = "98c522028f36fc6b85a8f3c003efd4b130dd90180ec81cf7c67d4c53d10f0022";
  hex2char(entropyhexren10, entropy, 32);
  ctr_DRBG_Reseed(drbg128state, drbginput);
  char addhexren10[] = "19c286f5b36194d1cc62c0188140bc9d61d2a9c5d88bb5aebc224bfb04dfca83";
  hex2char(addhexren10, add, 32);
  ret=ctr_DRBG_Generate(drbg128state, drbginput,output, 64);
  if (ret<0) return ret;
  char addhexren11[] = "820650c3201d347f5b20d3d25d1c8c7bef4d9f66a5a04c7dd9d669e95182a0c4";
  hex2char(addhexren11, add, 32);
  ret=ctr_DRBG_Generate(drbg128state, drbginput,output, 64);
  if (ret<0) return ret;
  char hexstringren1[] = "79a79d44edada58e3fc12a4e36ae900eeace290265f01262f40f2958a70dcbd4d4185f708c088ede7ff8c8375f44f4012f2512d38328a5df171a17029d90f185";
  hex2char(hexstringren1, hexChar, 64);
  for(i = 0; i < 64; i++) {
    if (!(output[i]==hexChar[i])) ret=TESTERROR;
  }
  if (ret<0) {
    return ret;
  } else {
    printf("CTR_DRBG AES-128 noDF/add/pers/reseed passed drbg_prdrbgvectors_no_reseed test!\n");
  }
  free_drbg_input(drbginput);

  
  char entropyhexren2[] = "4b58271b116237eedd4e9ff9360382a59f3e2a173d860f2bbd8b2bace142b2395c67cf5a513f06f3";
  hex2char(entropyhexren2, entropy, 40);
  char addhexren2[] = "6d44839aff8b7165deebd489ad088ecb7dcec11c32b1e747dba8f0e8a0b89f74a84ea8a05586fe9e";
  hex2char(addhexren2, add, 40);
  char perhexren2[] = "cf76c16cd5d270707ea9acc39744db69bfac63e566256fd6917bf9819679840f3fea2aa535d8df01";
  hex2char(perhexren2, pers, 40);
  drbginput=drbgInput_init(entropy,40, nonce,0,pers,40,add,40);
  ret= ctr_DRBG_Instantiate_algorithm(drbg192state, drbginput);
  if (ret<0) return ret;
  char entropyhexren20[] = "1867f371a345eef98b2d70fc1960397892645b7b29a4ead252e8835e0b600618a9bd6ff99785d890";
  hex2char(entropyhexren20, entropy, 40);
  ctr_DRBG_Reseed(drbg192state, drbginput);
  char addhexren20[] = "42248fce0994e0e63504209d629a6943eb3e2ad512f03f79cbd5102928392bce1cacbba056ac6ca9";
  hex2char(addhexren20, add, 40);
  ret=ctr_DRBG_Generate(drbg192state, drbginput,output, 64);
  if (ret<0) return ret;
  char addhexren12[] = "bd529b600273329423a58d6f8a12be0f17989a02e73e347bc7d49d9169337a6cff7c07e8a807a80a";
  hex2char(addhexren12, add, 40);
  ret=ctr_DRBG_Generate(drbg192state, drbginput,output, 64);
  if (ret<0) return ret;
  char hexstringren2[] = "02486d32cd55954f406ba55705f1460d384439592dede81a84fda221fd45c0d651d67ec4a81a8b404151a643f331ad051cb004352289de37bca71e8cc0a6aeab";
  hex2char(hexstringren2, hexChar, 64);
  for(i = 0; i < 64; i++) {
    if (!(output[i]==hexChar[i])) ret=TESTERROR;
  }
  if (ret<0) {
    return ret;
  } else {
    printf("CTR_DRBG AES-192 noDF/add/pers/reseed passed drbg_prdrbgvectors_no_reseed test!\n");
  }
  free_drbg_input(drbginput);


  

  char entropyhexren3[] = "ae7ebe062971f5eb32e5b21444750785de816595ad2cbe80a209c8f8ab04b5468166de8c6ae522d8f10b56386a3b424f";
  hex2char(entropyhexren3, entropy, 48); 
  char addhexren3[] = "ee4c88d1eb05f4853663eada501d2fc4b4984b283a88db579af2113031e03d9bc570de943dd168918f3ba8065581fea7";
  hex2char(addhexren3, add, 48);
  char perhexren3[] = "55860dae57fcac297087c137efb796878a75868f6e7681114e9b73ed0c67e3c62bfc9f5d77e8caa59bcdb223f4ffd247";
  hex2char(perhexren3, pers, 48);
  drbginput=drbgInput_init(entropy,48, nonce,0,pers,48,add,48);
  ret= ctr_DRBG_Instantiate_algorithm(drbg256state, drbginput);
  if (ret<0) return ret;
  char entropyhexren30[] = "a42407931bfeca70e6ee5dd197021a129525051c07468e8b25587c5ad50abe9204e882fe847b8fd47cf7b4360e5aa034";
  hex2char(entropyhexren30, entropy, 48);
  ctr_DRBG_Reseed(drbg256state, drbginput);
  char addhexren30[] = "4b4b03ef19b0f259dca2b3ee3ae4cd86c3895a784b3d8eee043a2003c08289f8fffdad141e6b1ab2174d8d5d79c1e581";
  hex2char(addhexren30, add, 48);
  ret=ctr_DRBG_Generate(drbg256state, drbginput,output, 64);
  if (ret<0) return ret;
  char addhexren13[] = "3062b33f116b46e20fe3c354726ae9b2a3a4c51922c8107863cb86f1f0bdad7554075659d91c371e2b11b1e8106a1ed5";
  hex2char(addhexren13, add, 48);
  ret=ctr_DRBG_Generate(drbg256state, drbginput,output, 64);
  if (ret<0) return ret;
  char hexstringren3[] = "0d270518baeafac160ff1cb28c11ef68712c764c0c01674e6c9ca2cc9c7e0e8accfd3c753635ee070081eee7628af6187fbc2854b3c204461a796cf3f3fcb092";
  hex2char(hexstringren3, hexChar, 64);
  for(i = 0; i < 64; i++) {
    if (!(output[i]==hexChar[i])) ret=TESTERROR;
  }
  if (ret<0) {
    return ret;
  } else {
    printf("CTR_DRBG AES-256 noDF/add/pers/reseed passed drbg_prdrbgvectors_no_reseed test!\n");
  }
  free_drbg_input(drbginput);
  
  free_ctr_drbg_state(drbg128state);
  free_ctr_drbg_state(drbg192state);
  free_ctr_drbg_state(drbg256state);

  
  /* printArray(drbgXXXstate->Key, 24);
  printArray(drbgXXXstate->V, 16);
  printArray(output, 64);

   printArray(drbg128state->Key, 16);
  printArray(drbg128state->V, 16);
  */
  
  return ret;
}


int test_poly_mul(int m){
    int i;
    poly_t pp=poly_init(3);
    poly_t qq=poly_init(4);
    poly_t rr, rr1, rr2, rr3;
    
    pp->deg = 2;
    pp->coeff[0]=1;
    pp->coeff[1]=2;
    pp->coeff[2]=1;
    qq->deg = 3;
    qq->coeff[0]=1;
    qq->coeff[1]=2;
    qq->coeff[2]=3;
    qq->coeff[3]=4;
    rr=poly_init(6);

    vector_t base,outputf;
    base=vec_init(m);
    for (i=0; i<m;i++) base->data[i]=GF_exp(i,m);
    outputf = vec_init(fieldSize(m));
    FFT(pp,outputf,base,m);
    for (i=0;i<fieldSize(m); i++) {
      if (outputf->data[i]!=poly_eval(pp,i,m))printf("FFT wrong\n"); 
    }				    
    
    poly_mul_karatsuba(pp,qq,rr,m);
    //poly_print(rr);
    //printf("standard one\n");
    poly_mul_standard(pp,qq,rr,m);
    //poly_print(rr);
    //printf("poly_mul_FFT\n");
    poly_mul_FFT(pp,qq,rr,m);
    //poly_print(rr);
    poly_free(pp);
    poly_free(qq);
    poly_free(rr);
   
    int size = 1010;
    int deg=size/3;
    int kara=0;
    int fft=0;
    pp=poly_init(size);
    for (int i=0; i<=deg; i++) pp->coeff[i]=i;
    pp->deg=deg;
    qq=poly_init(size);
    for (int i=0; i<=deg; i++) qq->coeff[i]=GF_exp(i,m);
    qq->deg=deg;
    rr1=poly_init(1+2*deg);
    rr2=poly_init(1+2*deg);
    rr3=poly_init(1+2*deg);
    poly_mul_standard(pp,qq,rr1,m);
    poly_mul_karatsuba(pp,qq,rr2,m);
    poly_mul_FFT(pp,qq,rr3,m);
    for (i=0; i<=rr1->deg; i++) {
      if (rr1->coeff[i] !=rr2->coeff[i]) kara=1;
      if (rr1->coeff[i] !=rr3->coeff[i]) fft=1;
    }
    poly_free(pp);
    poly_free(qq);
    poly_free(rr1);
    poly_free(rr2);
    poly_free(rr3);
    if (kara==1) {
      printf("poly_mul_karatsuba failed\n");
    } else printf("poly_mul_karatsuba passed\n");
    if (fft==1) {
      printf("poly_mul_FFT failed\n");
    } else printf("poly_mul_FFT passed\n");
    return 0;
}


void taylor(poly_t g, poly_t series[]);
int verifyTaylor(poly_t g, poly_t series[], int numSeries, int m);
int testTaylor(int size) {
    int seriesN=size/2;
    if (size%2 >0) seriesN++;
    poly_t p=poly_init(size);
    for (int i=0; i<size; i++) {
      p->coeff[i]=i;
    }
    p->deg = size-1;
    poly_t series[seriesN];
    for (int i=0; i<seriesN; i++) series[i]= poly_init(2);
    taylor(p, series);
    verifyTaylor(p, series, seriesN, 10);
    return 0;
}
