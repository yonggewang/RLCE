/* fieldMatrix.c
 * Yongge Wang 
 *
 * Code was written: November 10, 2016-
 *
 * fieldMatrix.c implements matrix operations
 * for RLCE scheme that is part of the package 
 * RLCE.tar - Random Linear Code Encryption Scheme
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

matrix_t matrix_init(int row, int column) {
  matrix_t mat;
  int i;
  mat = (matrix_t) malloc(sizeof (struct matrix));
  mat->numR = row;
  mat->numC = column;
  mat->data = calloc(row, sizeof(size_t*));
  for (i=0; i<row; i++) {
    mat->data[i]= (field_t *) calloc(column, sizeof(field_t));
  }
  return mat;
}

void matrix_free(matrix_t A){
  int i;
  for (i=0; i<A->numR; i++) free(A->data[i]);
  free(A->data);
  free(A);
  return;
}

void matrix_zero(matrix_t A) {
  int i;
  for (i=0; i<A->numR; i++) memset(A->data[i], 0, (A->numC)*sizeof(field_t));
  return;
}

matrix_t matrix_clone(matrix_t A) {
  matrix_t mat;
  int i;
  mat = matrix_init(A->numR, A->numC);
  for (i=0; i<A->numR; i++) {
    memcpy(mat->data[i], A->data[i], (A->numC)*sizeof(field_t));
  }
  return mat;
}

int matrix_copy(matrix_t A, matrix_t B) {
  if ((A->numR != B->numR) || (A->numC != B->numC)) {
    return MATRIXCOPYERROR;
  }
  int i;
  for (i=0; i<A->numR; i++) {
    memcpy(B->data[i], A->data[i], (A->numC)*sizeof(field_t));
  }
  return 0;
}


int matrixA_copy(matrixA_t mat, matrixA_t dest) {
  if (mat->size != dest->size) return MATRIXACOPYERROR;
  int i;
  int j;
  for (i=0; i<mat->size; i++) {
    for (j=0; j<2; j++) {
      memcpy((dest->A[i])->data[j], (mat->A[i])->data[j], 2*sizeof(field_t));
    }
  }
  return 0;
}

int vector_copy(vector_t v, vector_t dest) {
  dest->size = v->size;
  memcpy(dest->data, v->data, (v->size) * sizeof (field_t));
  return 0;
}

void vector_print(vector_t v) {
  int i;
  printf("vector size: %d\n", v->size);
  for (i=0; i<v->size; i++) {
    printf("0x%04x ", v->data[i]);
  }
  printf("\n");
}

void matrix_print(matrix_t X) {
  int i,j;
  for (i=0; i<X->numR; i++) {
    for (j=0; j<X->numC; j++) {
      printf("[%d][%d]:%d ",i,j, X->data[i][j]);
    }
    printf("\n\n");
  }
}

int matrix_vec_mat_mul_standard(field_t V[], int vsize, matrix_t B, field_t dest[], int dsize, size_t m) {
  if ((vsize>B->numR)||(B->numC<dsize)) return VECMATRIXMULERROR;
  int i;
  field_t *X;
  X=calloc(dsize, sizeof(field_t));
  memset(dest, 0, dsize*sizeof(field_t));
  for (i=0; i<vsize; i++) {
    if (V[i]) {
      GF_mulvec(V[i],B->data[i],X,dsize, m);
      GF_addvec(X,dest,NULL,dsize);
    }
  }
  free(X);
  return 0;
}

int matrix_standard_mul(matrix_t A, matrix_t B, matrix_t C, int m) {
  if ((A->numC!=B->numR)||(A->numR!=C->numR)||(B->numC!=C->numC))
    return MATRIXMULERROR;
  int i;
  for (i=0;i<C->numR;i++)
    matrix_vec_mat_mul_standard(A->data[i],A->numC,B,C->data[i],B->numC, m);
  return 0;
}

matrixA_t matrixA_init(int size) {
  matrixA_t matA;
  matA = (matrixA_t) malloc(sizeof (struct matrixA));
  matA->size = size;
  matA->A = malloc(size * sizeof(int*));
  int i;
  for (i=0; i<size; i++) matA->A[i]= matrix_init(2, 2);
  return matA;
}

void matrixA_free(matrixA_t A){
  int i;
  for (i=0; i<A->size; i++) {
    matrix_free(A->A[i]);
    A->A[i]=NULL;
  }
  free(A->A);
  A->A=NULL;
  free(A);
  A=NULL;
  return;
}

int matrix_col_permutation(matrix_t A, vector_t per) {
  /* per should contain a permutation of 
     0, 1, ..., A->numC */
  if (per->size != A->numC) return MATRIXCOLPERERROR;
  field_t tmp[A->numC];
  int i,j;
  for (i=0; i<A->numR; i++) {
    memcpy(tmp, A->data[i], (A->numC) * sizeof(field_t));
    for (j=0; j<A->numC; j++) A->data[i][j]=tmp[per->data[j]];
  }
  return 0;
}

int matrix_row_permutation(vector_t per, matrix_t A) {
    /* per should contain a permutation of 
     0, 1, ..., A->numR */
  if (per->size != A->numR) return MATRIXROWPERERROR;
  field_t **tmp;
  int i;
  tmp= malloc((A->numR) * sizeof(int*));  
  for (i=0; i<A->numR; i++) tmp[i]=A->data[i];
  for (i=0; i<A->numR; i++) A->data[i]=tmp[per->data[i]];
  return 0;
}

matrix_t matrix_mul_A(matrix_t G, matrixA_t A, int startP, int m) {
  /* multiply A starting from column "startP" of G */
  if ((G->numC - startP) != (2*(A->size))) return NULL;
  matrix_t mat;
  int i,j;
  mat = matrix_init(G->numR, G->numC);
  for (i=0;i<G->numR;i++) memcpy(mat->data[i], G->data[i], startP*sizeof(field_t));
  field_t b1,b2,b3,b4;
  for (j=0; j<A->size; j++) {
    for (i=0; i<G->numR; i++) {
      b1=GF_mul(G->data[i][startP+2*j],(A->A[j])->data[0][0], m);
      b2=GF_mul(G->data[i][startP+2*j], (A->A[j])->data[0][1], m);
      b3=GF_mul(G->data[i][startP+2*j+1], (A->A[j])->data[1][0], m);
      b4=GF_mul(G->data[i][startP+2*j+1], (A->A[j])->data[1][1], m);
      mat->data[i][startP+2*j]=b1 ^ b3;
      mat->data[i][startP+2*j+1]=b2^b4;
    }
  }
  return mat;
}

int matrix_echelon(matrix_t G, int m) {
  /* Gauss-Jordan elimination */
  int n= G->numR;
  if (G->numC <n) n=G->numC;
  int temp, i, j;
  field_t *tmp;
  field_t c;
  field_t *tmprow=calloc(G->numC, sizeof(field_t)); 
  for(j=0; j<n; j++) { /* converting first half to I */
    if (G->data[j][j] == 0) {
      temp=j;
      while  ((temp<G->numR) && (G->data[temp][j] == 0)) temp ++;
      if (temp == n) {
	free(tmprow);
	return -j;
      }
      tmp=G->data[j];
      G->data[j] = G->data[temp];
      G->data[temp]= tmp;
    }
    GF_vecdiv(G->data[j][j], &(G->data[j][j]), NULL,G->numC-j,m);
    //for (k=j;k<G->numC;k++) G->data[j][k]=GF_mul(G->data[j][k],c,m);
    for(i=0; i<n; i++) {
      if (i !=j) {
	c = G->data[i][j];
	if (c!=field_zero()){
	  GF_mulvec(c,&(G->data[j][j]),tmprow,(G->numC)-j,m);
	  GF_addvec(tmprow, &(G->data[i][j]),NULL,(G->numC)-j);
	  //for (k=j;k<G->numC;k++) G->data[i][k]^=GF_mul(G->data[j][k],c,m);
	}
      }
    }
  }
  free(tmprow);
  return n;
}

matrix_t matrix_join(matrix_t G, matrix_t R) {
  if ((G->numR != R->numR)||(G->numC < R->numC)) {
    return NULL;
  }
  matrix_t result;
  int i,j;
  result = matrix_init(G->numR, G->numC + R->numC);

  int d= G->numC - R->numC;
  for (i=0; i< G->numR; i++) {
    memcpy(result->data[i], G->data[i], d * sizeof(field_t));
  }
  for (i=0; i< G->numR; i++) {
    for (j=0; j<R->numC; j++) {
      result->data[i][d+2*j] = G->data[i][d+j];
      result->data[i][d+2*j+1]= R->data[i][j];
    }
  }
  return result;
}

vector_t vec_init(int n) {
  vector_t v;
  v = (vector_t) malloc(sizeof (struct vector));
  v->size = n;
  v->data = (field_t *) calloc(n, sizeof (field_t));
  return v;
}

void vector_free(vector_t v) {
  free(v->data);
  v->data=NULL;
  free(v);
  v=NULL;
}

vector_t permu_inv(vector_t p) {
  int i;
  vector_t result;
  result = vec_init(p->size);
  for (i=0; i<p->size; i++) {
    result->data[p->data[i]]=i;
  }
  return result;
}

int getRandomMatrix(matrix_t mat, field_t randE[]) {
  int i,j;
  for (j=0; j<mat->numC; j++) {
    for (i=0; i<mat->numR; i++) {
      mat->data[i][j]= randE[j*(mat->numR)+i];
    }
  }
  return 0;
}

vector_t getPermutation(int persize, int t, unsigned char randBytes[]) {
  /* this implements Fisher–Yates shuffle 
     in Knuth "Algorithm P" of The Art of Computer Programming */
  /* if t=persize, return a permutation of 0,...,persize-1. otherwise
   * only return the first t elements of the permutation*/
  vector_t permutation = vec_init(persize);
  int i;
  for (i=0; i<persize; i++) permutation->data[i]=i;

  unsigned short randomShortIntegers[t];
  int ret=getShortIntegers(randBytes, randomShortIntegers,t);
  if (ret <0) return NULL;
  
  unsigned short swapi;
  field_t tmp;
  for (i=0; i<t; i++) {
    swapi = randomShortIntegers[i] % (persize -i);
    swapi += i;
    tmp = permutation->data[i];
    permutation->data[i]=permutation->data[swapi];
    permutation->data[swapi]=tmp;    
  }
  return permutation;  
}

int randomBytes2FE(unsigned char randomBytes[], int nRB,
		   field_t output[], int outputSize, int m) {
  vector_t Vec;
  Vec =vec_init(outputSize);
  int i=0;
  int ret = 0;
  switch (m) {
  case 8:
    for (i=0; i<nRB; i++) Vec->data[i]=randomBytes[i];
    break;
  case 9:
    ret=B2FE9(randomBytes,nRB, Vec);
    if (ret<0) return ret;
    break;
  case 10:
    ret=B2FE10(randomBytes,nRB, Vec);
    if (ret<0) return ret;
    break;
  case 11:
    ret=B2FE11(randomBytes,nRB, Vec);
    if (ret<0) return ret;
    break;
  case 12:
    ret=B2FE12(randomBytes,nRB, Vec);
    if (ret<0) return ret;
    break;
  default:
    return B2FEORFE2BNOTDEFINED;
  }
  memcpy(output, Vec->data, outputSize *sizeof(field_t));
  vector_free(Vec);
  return 0; 	 
}

int getShortIntegers(unsigned char randB[], unsigned short output[], int outputSize) {
  int i;
  for (i=0; i<outputSize; i++) {
    output[i]=randB[2*i];
    output[i]= (output[i]<<8);
    output[i]= output[i] | randB[2*i+1];
  }
  return 0; 	 
}

int getRandomBytes(unsigned char seed[], int seedSize,
		   unsigned char pers[], int persSize,
		   unsigned char output[], int outputlen,int cryptotype) {
  int ret=0;
  if (cryptotype <3) {
    hash_drbg_state_t drbgState;
    drbgState=drbgstate_init(cryptotype);
    unsigned char nonce[8]={0xff, 0xf1, 0xc6, 0x64, 0x5f, 0x19, 0x23, 0x1f};
    unsigned char add[1];
    drbg_Input_t drbgInput;  
    drbgInput=drbgInput_init(seed,seedSize,nonce, 8, pers,persSize,add, 0);
    ret= hash_DRBG(drbgState, drbgInput, output, outputlen);
    free_drbg_state(drbgState);
    free_drbg_input(drbgInput);
  } else {
    ctr_drbg_state_t drbgState;
    drbgState=ctr_drbgstate_init(cryptotype);
    unsigned char nonce[1];
    unsigned char add[1];
    drbg_Input_t drbgInput;
    unsigned char newseed[drbgState->seedlen];
    memset(newseed, 0, drbgState->seedlen);
    int seedlen = seedSize;
    if (seedlen > drbgState->seedlen) seedlen = drbgState->seedlen;
    memcpy(newseed, seed, seedlen);
    drbgInput=drbgInput_init(seed,seedlen,nonce, 0, pers,persSize,add, 0);
    ret= ctr_DRBG(drbgState, drbgInput, output, outputlen);
    free_ctr_drbg_state(drbgState);
    free_drbg_input(drbgInput);
  } 
  return ret;  
}

void I2BS (size_t X, unsigned char S[], int slen) {
  int i;
  for (i=slen-1; i>=0; i--) S[i]=(0xFF & (X>>((slen-1-i)*8)));
}

int BS2I (unsigned char S[], int slen) {
  size_t X=0;
  int i;
  for (i=0; i<slen; i++) X=(X<<8)^S[i];
  return X;
}

int RLCE_MGF512(unsigned char mgfseed[], int mgfseedLen,
	     unsigned char mask[], int maskLen) {
  unsigned char seed[mgfseedLen+4];  
  memcpy(seed, mgfseed, mgfseedLen);
  int i,j,m,r;
  unsigned long hash512[8];
  m=maskLen/64;
  r=maskLen%64;
  for (i=0; i<m;i++){
    for (j=3; j>=0; j--) seed[mgfseedLen+j]=(0xFF & (i>> ((3-j)*8)));
    sha512_MD(seed, mgfseedLen+4, hash512);
    for (j=0;j<64;j++) mask[i*64+j]=(hash512[j/8]>>(56-(j%8)*8))&0xFF;
  }  
  if (r>0) {
    for (j=3; j>=0; j--) seed[mgfseedLen+j]=(0xFF & (m>>((3-j)*8)));
    sha512_MD(seed, mgfseedLen+4, hash512);
    for (j=0;j<r;j++) mask[m*64+j]=(hash512[j/8]>>(56-(j%8)*8))&0xFF;
  }
  return 0;  
}

int RLCE_MGF(unsigned char mgfseed[], int mgfseedLen,
	     unsigned char mask[], int maskLen, int shatype) {
  unsigned char seed[mgfseedLen+4];  
  memcpy(seed, mgfseed, mgfseedLen);
  int hashSize=0; /* hashLen = 4*hashSize */
  void (*sha)(unsigned char[], int, unsigned int[]);

  if (shatype ==0) {
    hashSize = 5;
    sha = sha1_MD;
  } else if (shatype == 1) {
    hashSize = 8;
    sha = sha256_MD;
  } else if (shatype == 2) {
    hashSize = 8;
  } else {
    return SHATYPENOTSUPPORTED;
  }
  unsigned int hash[hashSize];
  int i,j, m,r;
  if  ((shatype==0) || (shatype==1)) {
    m=maskLen/(4*hashSize);
    r=maskLen%(4*hashSize);
    for (i=0; i<m;i++){
      for (j=3; j>=0; j--) seed[mgfseedLen+j]=(0xFF & i>>((3-j)*8));
      (*sha)(seed, mgfseedLen+4, hash);
      for (j=0;j<(4*hashSize);j++) mask[i*(4*hashSize)+j]=(hash[i/4]>>(24-(i%4)*8)) & 0xFF;
    }
    if (r>0) {
      for (j=3; j>=0; j--) seed[mgfseedLen+j]=(0xFF & m>>((3-j)*8));
      (*sha)(seed, mgfseedLen+4, hash);
      for (j=0;j<r;j++) mask[m*(4*hashSize)+j]=(hash[i/4]>>(24-(i%4)*8)) & 0xFF; 
    }
  } else if (shatype ==2 ) {
    unsigned long hash512[8];
    m=maskLen/64;
    r=maskLen%64;
    for (i=0; i<m;i++){
      for (j=3; j>=0; j--) seed[mgfseedLen+j]=(0xFF & i>> ((3-j)*8));
      sha512_MD(seed, mgfseedLen+4, hash512);
      for (j=0;j<64;j++) mask[i*64+j]=(hash512[j/8]>>(56-(j%8)*8))&0xFF;
    }
    if (r>0) {
      for (j=3; j>=0; j--) seed[mgfseedLen+j]=(0xFF & m>> ((3-j)*8));
      sha512_MD(seed, mgfseedLen+4, hash512);
      for (j=0;j<r;j++) mask[m*64+j]=(hash512[j/8]>>(56-(j%8)*8))&0xFF;
    }
  }
  return 0;  
}


int B2FE9 (unsigned char bytes[], size_t BLen, vector_t FE) {
  size_t vecLen =FE->size;
  if (9*vecLen>8*BLen) {
    return BYTEVECTORTOOSMALL;
  }
  int j=0;
  size_t i;
  int used = 0;

  unsigned char bits = 0x00;
  for (i=0; i<vecLen; i++) {

    switch (used) {
    case 0:
      FE->data[i]=bytes[j];
      FE->data[i]=FE->data[i]<<1;
      j++;
      bits = (bytes[j] & 0x80);
      bits = bits >>7;
      FE->data[i]=(FE->data[i]) | bits;
      used = 1;
      break;
    case 1:
      FE->data[i]= (bytes[j]<< 1) & 0x00FF;
      FE->data[i]=FE->data[i]<<1;
      j++;
      bits = (bytes[j] & 0xC0);
      bits = bits >>6;
      FE->data[i]=(FE->data[i]) | bits;
      used = 2;
      break;
    case 2:
      FE->data[i]= (bytes[j]<< 2) & 0x00FF;
      FE->data[i]=FE->data[i]<<1;
      j++;
      bits = (bytes[j] & 0xE0);
      bits = bits >>5;
      FE->data[i]=(FE->data[i]) | bits;
      used = 3;
      break;
    case 3:
      FE->data[i]= (bytes[j]<< 3) & 0x00FF;
      FE->data[i]=FE->data[i]<<1;
      j++;
      bits = (bytes[j] & 0xF0);
      bits = bits >>4;
      FE->data[i]=(FE->data[i]) | bits;
      used = 4;
      break;
    case 4:
      FE->data[i]= (bytes[j]<< 4) & 0x00FF;
      FE->data[i]=FE->data[i]<<1;
      j++;
      bits = (bytes[j] & 0xF8);
      bits = bits >>3;
      FE->data[i]=(FE->data[i]) | bits;
      used = 5;
      break;
    case 5:
      FE->data[i]= (bytes[j]<< 5) & 0x00FF;
      FE->data[i]=FE->data[i]<<1;
      j++;
      bits = (bytes[j] & 0xFC);
      bits = bits >>2;
      FE->data[i]=(FE->data[i]) | bits;
      used = 6;
      break;
    case 6:
      FE->data[i]= (bytes[j]<< 6) & 0x00FF;
      FE->data[i]=FE->data[i]<<1;
      j++;
      bits = (bytes[j] & 0xFE);
      bits = bits >>1;
      FE->data[i]=(FE->data[i]) | bits;
      used = 7;
      break;
    case 7:
      FE->data[i]= (bytes[j]<< 7) & 0x00FF;
      FE->data[i]=FE->data[i]<<1;
      j++;
      bits = (bytes[j] & 0xFF);
      FE->data[i]=(FE->data[i]) | bits;
      j++;
      used = 0;
      break;
    default:
      return -1;
    }
  }
  return 0;
}

int FE2B9 (vector_t FE,  unsigned char bytes[], size_t BLen) {
  size_t vecLen =FE->size;
  if ((8*BLen) < (vecLen*9)) {
    return BYTEVECTORTOOSMALL;
  }
  int used = 0;
  int j=0;
  size_t i;
  bytes[j]=0x00;
  unsigned char bits = 0x00;
  for (i=0;i<vecLen;i++){
    switch (used) {
    case 0:
      bytes[j]=(FE->data[i])>>1;
      j++;
      bits = FE->data[i] & 0x0001;
      bytes[j]= bits <<7;
      used = 1;
      break;
    case 1:
      bytes[j]=(((FE->data[i])>>2) | bytes[j]);
      j++;
      bits = FE->data[i] & 0x0003;
      bytes[j]= bits<<6;
      used = 2;      
      break;
    case 2:
      bytes[j]=(((FE->data[i])>>3) | bytes[j]);
      j++;
      bits = FE->data[i] & 0x0007;
      bytes[j]= bits<<5;
      used = 3;      
      break;
    case 3:
      bytes[j]=(((FE->data[i])>>4) | bytes[j]);
      j++;
      bits = FE->data[i] & 0x000F;
      bytes[j]= bits<<4;
      used = 4;       
      break;      
    case 4:
      bytes[j]=(((FE->data[i])>>5) | bytes[j]);
      j++;
      bits = FE->data[i] & 0x001F;
      bytes[j]= bits<<3;
      used = 5;        
      break;
    case 5:
      bytes[j]=(((FE->data[i])>>6) | bytes[j]);
      j++;
      bits = FE->data[i] & 0x003F;
      bytes[j]= bits<<2;
      used = 6;       
      break;
    case 6:
      bytes[j]=(((FE->data[i])>>7) | bytes[j]);
      j++;
      bits = FE->data[i] & 0x007F;
      bytes[j]= bits<<1;
      used = 7;       
      break;      
    case 7:
      bytes[j]=(((FE->data[i])>>8) | bytes[j]);
      j++;
      bits = FE->data[i] & 0x00FF;
      bytes[j]= bits;
      j++;
      used = 0;        
      break;
    default:
      return -1;
    }
  }
  return 0;  
}

int B2FE10 (unsigned char bytes[], size_t BLen, vector_t FE) {
  size_t vecLen =FE->size;  
  if (10*vecLen>8*BLen) {
    return BYTEVECTORTOOSMALL;
  }
  int j=0;
  size_t i;
  int used = 0;

  unsigned char bits = 0x00;
  for (i=0; i<vecLen; i++) {

    switch (used) {
    case 0:
      FE->data[i]=bytes[j];
      FE->data[i]=FE->data[i]<<2;
      j++;
      bits = (bytes[j] & 0xC0);
      bits = bits >>6;
      FE->data[i]=(FE->data[i]) | bits;
      used = 2;
      break;
    case 2:
      FE->data[i]= (bytes[j]<< 2) & 0x00FF;
      FE->data[i]=FE->data[i]<<2;
      j++;
      bits = (bytes[j] & 0xF0);
      bits = bits >>4;
      FE->data[i]=(FE->data[i]) | bits;
      used = 4;
      break;
    case 4:
      FE->data[i]= (bytes[j]<< 4) & 0x00FF;
      FE->data[i]=FE->data[i]<<2;
      j++;
      bits = (bytes[j] & 0xFC);
      bits = bits >>2;
      FE->data[i]=(FE->data[i]) | bits;
      used = 6;
      break;
    case 6:
      FE->data[i]= (bytes[j]<< 6) & 0x00FF;
      FE->data[i]=FE->data[i]<<2;
      j++;
      bits = (bytes[j] & 0xFF);
      FE->data[i]=(FE->data[i]) | bits;
      j++;
      used = 0;
      break;
    default:
      return -1;
    }
  }
  return 0;
}

int FE2B10 (vector_t FE, unsigned char bytes[], size_t BLen) {
  size_t vecLen =FE->size;
  if ((8*BLen) < (vecLen *10)) {
    return BYTEVECTORTOOSMALL;
  }
  int used = 0;
  int j=0;
  size_t i;
  bytes[j]=0x00;
  unsigned char bits = 0x00;

  for (i=0;i<vecLen;i++){
    switch (used) {
    case 0:
      bytes[j]=(FE->data[i])>>2;
      j++;
      bits = FE->data[i] & 0x0003;
      bytes[j]= bits <<6;
      used = 2;
      break;
    case 2:
      bytes[j]=(((FE->data[i])>>4) | bytes[j]);
      j++;
      bits = FE->data[i] & 0x000F;
      bytes[j]= bits<<4;
      used = 4;      
      break;
    case 4:
      bytes[j]=(((FE->data[i])>>6) | bytes[j]);
      j++;
      bits = FE->data[i] & 0x003F;
      bytes[j]= bits<<2;
      used = 6;      
      break;
    case 6:
      bytes[j]=(((FE->data[i])>>8) | bytes[j]);
      j++;
      bits = FE->data[i] & 0x00FF;
      bytes[j]= bits;
      used = 0;
      j++;
      break;      
    default:
      return -1;
    }
  }
  return 0;  
}




int B2FE11 (unsigned char bytes[], size_t BLen, vector_t FE) {
  size_t vecLen =FE->size;  
  if (11*vecLen>8*BLen) {
    return BYTEVECTORTOOSMALL;
  }
  int j=0;
  size_t i;
  int used = 0;

  unsigned char bits = 0x00;
  for (i=0; i<vecLen; i++) {

    switch (used) {
    case 0:
      FE->data[i]=bytes[j];
      FE->data[i]=FE->data[i]<<3;
      j++;
      bits = (bytes[j] & 0xE0);
      bits = bits >>5;
      FE->data[i]=(FE->data[i]) | bits;
      used = 3;
      break;
    case 3:
      FE->data[i]= (bytes[j]<< 3) & 0x00FF;
      FE->data[i]=FE->data[i]<<3;
      j++;
      bits = (bytes[j] & 0xFC);
      bits = bits >>2;
      FE->data[i]=(FE->data[i]) | bits;
      used = 6;
      break;
    case 6:
      FE->data[i]= (bytes[j]<< 6) & 0x00FF;
      FE->data[i]=FE->data[i]<<2;
      j++;
      bits = (bytes[j] & 0xFF);
      FE->data[i]=(FE->data[i]) | bits;
      FE->data[i]=FE->data[i]<<1;
      j++;
      bits = (bytes[j] & 0x80);
      bits = bits >>7;
      FE->data[i]=(FE->data[i]) | bits;     
      used = 1;
      break;
    case 1:
      FE->data[i]= (bytes[j]<< 1) & 0x00FF;
      FE->data[i]=FE->data[i]<<3;
      j++;
      bits = (bytes[j] & 0xF0);
      bits = bits >>4;
      FE->data[i]=(FE->data[i]) | bits;
      used = 4;
      break;
    case 4:
      FE->data[i]= (bytes[j]<< 4) & 0x00FF;
      FE->data[i]=FE->data[i]<<3;
      j++;
      bits = (bytes[j] & 0xFE);
      bits = bits >>1;
      FE->data[i]=(FE->data[i]) | bits;
      used = 7;
      break;
    case 7:
      FE->data[i]= (bytes[j]<< 7) & 0x00FF;
      FE->data[i]=FE->data[i]<<1;
      j++;
      bits = (bytes[j] & 0xFF);
      FE->data[i]=(FE->data[i]) | bits;
      FE->data[i]=FE->data[i]<<2;
      j++;
      bits = (bytes[j] & 0xC0);
      bits = bits >>6;      
      FE->data[i]=(FE->data[i]) | bits;
      used = 2;
      break;
    case 2:
      FE->data[i]= (bytes[j]<< 2) & 0x00FF;
      FE->data[i]=FE->data[i]<<3;
      j++;
      bits = (bytes[j] & 0xF8);
      bits = bits >>3;
      FE->data[i]=(FE->data[i]) | bits;
      used = 5;
      break;      
    case 5:
      FE->data[i]= (bytes[j]<< 5) & 0x00FF;
      FE->data[i]=FE->data[i]<<3;
      j++;
      bits = (bytes[j] & 0xFF);
      FE->data[i]=(FE->data[i]) | bits;
      j++;
      used = 0;
      break;
    default:
      return -1;
    }
  }
  return 0;
}

int FE2B11 (vector_t FE, unsigned char bytes[], size_t BLen) {
  size_t vecLen =FE->size;
  if ((8*BLen) < (vecLen *11)) {
    return BYTEVECTORTOOSMALL;
  }
  int used = 0;
  int j=0;
  size_t i;
  bytes[j]=0x00;
  unsigned char bits = 0x00;

  for (i=0;i<vecLen;i++){
    switch (used) {
    case 0:
      bytes[j]=(FE->data[i])>>3;
      j++;
      bits = FE->data[i] & 0x0007;
      bytes[j]= bits <<5;
      used = 3;
      break;
    case 3:
      bytes[j]=(((FE->data[i])>>6) | bytes[j]);
      j++;
      bits = FE->data[i] & 0x003F;
      bytes[j]= bits<<2;
      used = 6;      
      break;
    case 6:
      bytes[j]=(((FE->data[i])>>9) | bytes[j]);
      j++;
      bytes[j] = (FE->data[i]>>1) & 0x00FF;
      j++;
      bits = FE->data[i] & 0x0001;
      bytes[j]= bits<<7;
      used = 1;      
      break;
    case 1:
      bytes[j]=(((FE->data[i])>>4) | bytes[j]);
      j++;
      bits = FE->data[i] & 0x000F;
      bytes[j]= bits<<4;
      used = 4;
      break;
    case 4:
      bytes[j]=(((FE->data[i])>>7) | bytes[j]);
      j++;
      bits = FE->data[i] & 0x007F;
      bytes[j]= bits<<1;
      used = 7;
      break;
    case 7:
      bytes[j]=(((FE->data[i])>>10) | bytes[j]);
      j++;
      bytes[j] = (FE->data[i]>>2) & 0x00FF;
      j++;
      bits = FE->data[i] & 0x0003;
      bytes[j]= bits<<6;
      used = 2;      
      break;
    case 2:
      bytes[j]=(((FE->data[i])>>5) | bytes[j]);
      j++;
      bits = FE->data[i] & 0x001F;
      bytes[j]= bits<<3;
      used = 5;
      break;
    case 5:
      bytes[j]=(((FE->data[i])>>8) | bytes[j]);
      j++;
      bytes[j] = (FE->data[i]) & 0x00FF;
      j++;
      used = 0;      
      break;      
    default:
      return -1;
    }
  }
  return 0;  
}

int B2FE12 (unsigned char bytes[], size_t BLen, vector_t FE) {
  size_t vecLen =FE->size;
  if (12*vecLen>8*BLen) {
    return BYTEVECTORTOOSMALL;
  }
  int j=0;
  size_t i;
  int used = 0;

  unsigned char bits = 0x00;
  for (i=0; i<vecLen; i++) {

    switch (used) {
    case 0:
      FE->data[i]=bytes[j];
      FE->data[i]=FE->data[i]<<4;
      j++;
      bits = (bytes[j] & 0xF0);
      bits = bits >>4;
      FE->data[i]=(FE->data[i]) | bits;
      used = 4;
      break;
    case 4:
      FE->data[i]= (bytes[j]<<4) & 0x00FF;
      FE->data[i]=FE->data[i]<<4;
      j++;
      FE->data[i]=(FE->data[i]) | bytes[j];
      j++;
      used = 0;
      break;
    default:
      return -1;
    }
  }
  return 0;
}

int FE2B12 (vector_t FE, unsigned char bytes[], size_t BLen) {
  size_t vecLen =FE->size;
  if ((8*BLen) < (vecLen *12)) {
    return BYTEVECTORTOOSMALL;
  }
  int used = 0;
  int j=0;
  size_t i;
  bytes[j]=0x00;
  unsigned char bits = 0x00;

  for (i=0;i<vecLen;i++){
    switch (used) {
    case 0:
      bytes[j]=(FE->data[i])>>4;
      j++;
      bits = FE->data[i] & 0x00FF;
      bytes[j]= bits <<4;
      used = 4;
      break;
    case 4:
      bytes[j]=(((FE->data[i])>>8) | bytes[j]);
      j++;
      bytes[j] = FE->data[i] & 0x00FF;
      j++;
      used = 0;      
      break;     
    default:
      return -1;
    }
  }
  return 0;  
}

int matrix_add(matrix_t A, matrix_t B, matrix_t C) {
  int i;
  for (i=0; i<A->numR; i++) {
    GF_addvec(A->data[i], B->data[i], C->data[i], C->numC);
  }
  return 0;
}

matrix_t matrix_initFrame(int row, int column) {
  matrix_t mat;
  mat = (matrix_t) malloc(sizeof (struct matrix));
  mat->numR = row;
  mat->numC = column;
  mat->data = calloc(row, sizeof(int*));
  return mat;
}


void matrix_framefree(matrix_t A) {
  free(A->data);
  free(A);
  return;
}

int matrix_vec_mat_mul(field_t V[], int vsize, matrix_t B, field_t dest[],int dsize, int m){
  return matrix_vec_mat_mul_standard(V,vsize, B, dest, dsize,m);
}

int matrix_mul(matrix_t A, matrix_t B, matrix_t C, int m) {
  return matrix_standard_mul(A,B,C,m);
}

