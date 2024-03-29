/* rlce.h
 * Copyright (C) 2016-2019 Yongge Wang
 * 
 * Yongge Wang
 * Department of Software and Information Systems
 * UNC Charlotte
 * Charlotte, NC 28223
 * yonwang@uncc.edu
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <time.h>
#include <math.h>
#include "config.h"

#ifndef _RLCEH_
#define _RLCEH_
#define field_unit() 1
#define field_zero() 0
#define fieldSize(m) (1 << m)
typedef unsigned short field_t;

typedef struct vector {
  int size;
  field_t *data;
} *vector_t;

typedef struct matrix {
  int numR;
  int numC;
  field_t **data;
} *matrix_t;

typedef struct matrixA {
  int size;
  matrix_t *A;
} *matrixA_t;

typedef struct polynomial {
  int deg, size; 
  field_t * coeff;
} * poly_t;


typedef struct RLCE_private_key {
  size_t* para;
  vector_t perm1; /* inverse of perm1*/
  vector_t perm2;/* inverse of perm2*/
  poly_t generator;
  matrixA_t A;/* inverse of A*/
  matrix_t S; /* inverse of S */
  vector_t grs;/* inverse of grs */
  matrix_t G; /* public key to speed up decryption */
} * RLCE_private_key_t;


typedef struct RLCE_public_key {
  size_t* para;
  matrix_t G;
} * RLCE_public_key_t;


typedef struct AESkey {
  unsigned short Nk;
  unsigned short Nr;
  unsigned short Nb;
  unsigned short wLen;
  unsigned short keylen;
  uint8_t * key;
} * aeskey_t;

typedef struct hash_drbg_state {
  int seedlen; /* 55 for SHA1 and SHA-256, 111 for SHA-512 */
  int shatype; /* hash type:  0 SHA1, 1 SHA256 and 2 SHA-512 */
  int hashSize; /* 5 for SHA1, 8 for SHA256, 8 for SHA-512 */
  int pf_flag; /* prediction_resistance_flag */
  unsigned long reseed_interval;
  int max_B_per_req; /* max_number_of_bytes_per_request */
  int security_strength;
  unsigned long reseed_counter;
  uint8_t *V;
  uint8_t *C;
} * hash_drbg_state_t;

typedef struct drbg_Input {
  int entropylen, noncelen, perslen, addlen;
  uint8_t *entropy;
  uint8_t *nonce;
  uint8_t *personalization_string;
  uint8_t *additional_input;
} * drbg_Input_t;

typedef struct ctr_drbg_state {
  /* administrative information */
  unsigned short seedlen; /* 256/8 for AES-128, 320/8 for AES-192, and 384/8 for AES-256 */
  unsigned short aestype; /* 128: AES-128, 192: AES-192, 256: AES-256 */
  unsigned short pf_flag; /* prediction_resistance_flag */
  int max_B_per_req; /* max_number_of_bytes_per_request */
  unsigned short security_strength;
  unsigned short ctr_len; /* should lie in [4, 128] */
  unsigned long reseed_interval;
  /* following three are the working_state */
  unsigned long reseed_counter;
  uint8_t *V; /* counter blocksize (16 byte) */
  uint8_t *Key;
} * ctr_drbg_state_t;

typedef struct {
  char *key;
  int val;
} strvalue_t;

#endif

int pk2B(RLCE_public_key_t pk, uint8_t pkB[], size_t *blen);
int sk2B(RLCE_private_key_t sk, uint8_t skB[], size_t *blen);
RLCE_public_key_t B2pk(const uint8_t binByte[], unsigned long long blen);
RLCE_private_key_t B2sk(const uint8_t binByte[], unsigned long long blen);
void hex2char(char * pos, uint8_t hexChar[], int charlen);
uint8_t* rlceReadFile(char* filename, unsigned long long *blen, int hex);
int rlceWriteFile(char* filename, uint8_t bytes[], unsigned long long blen, int hex);
aeskey_t aeskey_init(unsigned short kappa);
void aeskey_free(aeskey_t);
void AES_encrypt(uint8_t plain[], uint8_t cipher[], aeskey_t key);
void AES_decrypt(uint8_t cipher[], uint8_t plain[], aeskey_t key);

void sha1_md(uint8_t message[],int size, size_t md[5]);
void sha256_md(uint8_t message[], int size, size_t md[8]);
void sha512_md(uint8_t message[], int size, unsigned long md[8]);
hash_drbg_state_t drbgstate_init(int shatype);
void free_drbg_state(hash_drbg_state_t drbgState);
drbg_Input_t drbgInput_init(uint8_t entropy[],int entropylen,
			    uint8_t nonce[],int noncelen,
			    uint8_t personalization_string[],int perslen,
			    uint8_t additional_input[], int addlen);
int hash_DRBG_Instantiate(hash_drbg_state_t drbgState, drbg_Input_t drbgInput);
int hash_DRBG_Generate(hash_drbg_state_t drbgState,drbg_Input_t drbgInput,
		       uint8_t returned_bytes[],
		       long unsigned req_no_of_bytes);
int hash_DRBG_Reseed(hash_drbg_state_t drbgState, drbg_Input_t drbgInput);
void free_drbg_input(drbg_Input_t drbgInput);
int hash_DRBG(hash_drbg_state_t drbgState, drbg_Input_t drbgInput,
	      uint8_t output[], unsigned long outlen);

ctr_drbg_state_t ctr_drbgstate_init(unsigned short aestype);
void free_ctr_drbg_state(ctr_drbg_state_t ctr_drbgState);
int ctr_DRBG_Instantiate_algorithm(ctr_drbg_state_t drbgState, drbg_Input_t drbgInput);
int ctr_DRBG_Generate(ctr_drbg_state_t drbgState, drbg_Input_t drbgInput,
		      uint8_t returned_bytes[],
		      unsigned long req_no_of_bytes);
int ctr_DRBG_Reseed(ctr_drbg_state_t drbgState, drbg_Input_t drbgInput);
int ctr_DRBG(ctr_drbg_state_t drbgState, drbg_Input_t drbgInput,
	     uint8_t output[], unsigned long outlen);
int ctr_DRBG_DF(ctr_drbg_state_t drbgState, drbg_Input_t drbgInput,
		uint8_t output[], unsigned long outlen);

poly_t initialize_RS(int codelen, int codedim, int m);
int rs_encode (poly_t genPoly, poly_t message, poly_t code, int m);
poly_t rs_decode(int decoder, poly_t code, int codelen, int codedim,
		 field_t eLocation[], int m); /*eLocation[m-k]*/
poly_t list_decode(field_t beta[], int n, int k, int t, int omega, int Lomega,
		   field_t eLocation[], int m); /* eLocation[n-k] */

int FFT(poly_t f, vector_t output, vector_t base, int m);
/* output->size = 2^{base->size}*/
int GGIFFT(int i,vector_t base, field_t beta,vector_t output,poly_t r,matrix_t smat,int m);

RLCE_private_key_t RLCE_private_key_init (size_t para[]);
void RLCE_free_sk(RLCE_private_key_t sk);
RLCE_public_key_t RLCE_public_key_init (size_t para[]);
void RLCE_free_pk(RLCE_public_key_t pk);
int RLCE_key_setup (uint8_t entropy[], int entropylen,
		    uint8_t nonce[], int noncelen,
		    RLCE_public_key_t  pk, RLCE_private_key_t sk);

/* hex=0: binary file; hex=1: hex file */
int writeSK(char* filename,RLCE_private_key_t sk, int hex);
RLCE_private_key_t readSK(char* filename, int hex);
int writePK(char* filename,RLCE_public_key_t  pk, int hex);
RLCE_public_key_t readPK(char* filename, int hex);

int getRLCEparameters(size_t para[], size_t scheme, size_t padding);
int RLCE_encrypt(uint8_t msg[], uint8_t entropy[], size_t entropylen,
		 uint8_t nonce[], size_t noncelen,
		 RLCE_public_key_t pk, uint8_t cipher[], unsigned long long *clen);
int RLCE_decrypt(uint8_t cipher[], unsigned long long clen, RLCE_private_key_t sk,
		 uint8_t msg[], unsigned long long *mlen);

/* GaloisField.h */

extern short *GFlogTable[17];
extern short *GFexpTable[17];
extern short **GFmulTable[17];
extern short **GFdivTable[17];
extern int fieldOrder[17];
extern int fieldSize[17];
extern int GF_init_logexp_table(int m); /* 0 on success, -1 on failure */
extern field_t GF_tablediv(field_t x, field_t y, int m);
extern int GF_init_mult_table(int m);
void GF_expvec(field_t vec[], int size, int m);
void GF_vec_winograd(field_t x, field_t vec[],matrix_t B,matrix_t tmp, size_t m);
void GF_mulvec(field_t x, field_t vec[], field_t dest[],int dsize, size_t m);
void GF_vecdiv(field_t x, field_t vec[], field_t dest[],int dsize, size_t m);
void GF_mulexpvec2(field_t x, field_t vec[], field_t dest[],int dsize, size_t m);
void GF_logmulvec(int xlog, field_t vec[], field_t dest[],int dsize, size_t m);
void GF_vecinverse(field_t vec1[], field_t vec2[], int vecsize, int m);
extern int GF_addvec(field_t vec1[], field_t vec2[],field_t vec3[], size_t vecSize);
int GF_addF2vec(field_t x, field_t vec2[],field_t vec3[], size_t vecSize);
void GF_divvec(field_t vec1[],field_t vec2[], int vsize, size_t m);
int GF_vecreversemul(field_t vec1[],field_t vec2[],int vsize,int m);
void GF_evalpoly(int log, poly_t p, field_t input[], field_t output[], int size, int m);
void GF_rsgenerator2optG(matrix_t optG, poly_t generator, field_t randE[], int m);
void GF_vecvecmul(field_t v1[], field_t v2[], field_t v3[], int vsize, size_t m);
void getGenPoly (int deg, poly_t g, int m);
void rootsLocation(field_t rts[],int nRts,field_t eLoc[],field_t rtLog[],int m);
void GF_mulAinv(field_t cp[], matrixA_t A, field_t C1[], int m);
void GF_x2px(field_t vec[], field_t dest[], int size, int m);
extern field_t GF_fexp(field_t x, int y, int m);
extern void GF_print_log(int m);
void printArray(uint8_t toBeprint[], int len);
field_t GF_mul(field_t x, field_t y, int m);

#define GF_exp(x,m) GFexpTable[m][x]
#define GF_log(x,m) GFlogTable[m][x]
#define GF_div(x, y,m) ((x) ?  GFexpTable[m][GFlogTable[m][x]+fieldOrder[m]-GFlogTable[m][y]]:0)
#define GF_tablemul(x,y,m) GFmulTable[m][x][y]
#define GF_mulx(x,y,m) ((y)?GFexpTable[m][GFlogTable[m][x]+GFlogTable[m][y]]:0)
#define GF_regmul(x,y,m) ((x)?GF_mulx(x,y,m):0)
//#define GF_mul(x,y,m) ((GFMULTAB)?GF_tablemul(x,y,m):GF_regmul(x,y,m))


poly_t poly_init(size_t size);
void poly_clear(poly_t p);
void poly_zero(poly_t p);
void poly_copy(poly_t p, poly_t dest);
void poly_print(poly_t p);
void poly_free(poly_t p);
field_t poly_eval(poly_t p, field_t a, int m);
field_t poly_evalopt(poly_t p, field_t a, int m);
int poly_mul(poly_t f, poly_t g, poly_t r, int m);
int poly_mul_standard(poly_t p, poly_t q, poly_t r, int m);
int poly_mul_karatsuba(poly_t f, poly_t g, poly_t r, int m);
int poly_mul_FFT(poly_t p, poly_t q, poly_t r, int m);
int poly_div(poly_t p, poly_t d, poly_t q, poly_t dest, int m);
int poly_add(poly_t p, poly_t q, poly_t dest);
int poly_deg(poly_t p);
int poly_quotient (poly_t p, poly_t d, poly_t q, int m);
int poly_gcd(poly_t p1, poly_t p2, poly_t gcd, int m);
int find_roots (poly_t lambda, field_t roots[], field_t eLocation[], int m);
int find_roots_Chien (poly_t p, field_t roots[], field_t eLocation[],int m);
int find_roots_exhaustive (poly_t p, field_t roots[], int m);
int find_roots_BTA(poly_t p, field_t pRoots[], int m);
int find_roots_FFT(poly_t lambda, field_t roots[], int m); 

matrix_t matrix_init(int r, int c);
void matrix_free(matrix_t A);
void matrix_zero(matrix_t A);
matrix_t matrix_clone(matrix_t A);
int matrix_copy(matrix_t mat, matrix_t dest);
void matrix_print(matrix_t X);
int matrix_mul(matrix_t A, matrix_t B, matrix_t dest,int m);
int matrix_standard_mul(matrix_t A, matrix_t B, matrix_t C, int m);
int matrix_vec_mat_mul(field_t V[], int vsize, matrix_t B, field_t dest[],int dsize, int m);
int vector_copy(vector_t v, vector_t dest);
void vector_print(vector_t v);
matrixA_t matrixA_init(int size);
void matrixA_free(matrixA_t A);
int matrix_col_permutation(matrix_t A, vector_t per);
int matrix_row_permutation(vector_t per, matrix_t A);
matrix_t matrix_mul_A(matrix_t U, matrixA_t A, int start, int m);
int matrix_opt_mul_A(matrix_t G, matrixA_t A, int startP, int m);
int matrix_inv(matrix_t G, matrix_t Ginv, int m);
int matrix_echelon(matrix_t G, int m);
matrix_t matrix_join(matrix_t G, matrix_t R);
int matrixA_copy(matrixA_t mat, matrixA_t dest);
int RLCE_MGF512(uint8_t mgfseed[], int mgfseedLen,
		uint8_t mask[], int maskLen);
int RLCE_MGF(uint8_t mgfseed[], int mgfseedLen,
	     uint8_t mask[], int maskLen, int shatype);
  
vector_t vec_init(int n);
void vector_free(vector_t v);
vector_t permu_inv(vector_t p);
int getRandomMatrix(matrix_t mat, field_t randE[]);
vector_t getPermutation(int size, int t, uint8_t randBytes[]);
int randomBytes2FE(uint8_t randomBytes[], int nRB,
		   field_t output[], int outputSize, int m);
int getShortIntegers(uint8_t randomBytes[],
		     unsigned short output[], int outputSize);
int getMatrixAandAinv(matrixA_t mat, matrixA_t matInv,
			    field_t randomElements[], int randElen,int m);
int getRandomBytes(uint8_t seed[], int seedSize,
		   uint8_t pers[], int persSize,
		   uint8_t output[], int outputSize,
		   int shatype);

void I2BS (size_t X, uint8_t S[], int slen);
int BS2I (uint8_t S[], int slen);
int B2FE9 (uint8_t bytes[], size_t BLen, vector_t FE);
int FE2B9 (vector_t FE, uint8_t bytes[], size_t BLen);
int B2FE10 (uint8_t bytes[], size_t BLen, vector_t FE);
int FE2B10 (vector_t FE, uint8_t bytes[], size_t BLen);
int B2FE11 (uint8_t bytes[], size_t BLen, vector_t FE);
int FE2B11 (vector_t FE, uint8_t bytes[], size_t BLen);
int B2FE12 (uint8_t bytes[], size_t BLen, vector_t FE);
int FE2B12 (vector_t FE, uint8_t bytes[], size_t BLen);
void hashTObytes(uint8_t bytes[], int bSize, size_t hash[]);

void getPK(RLCE_private_key_t sk, RLCE_public_key_t pk);
int rlce_keypair(int crypto_scheme, char* keyfilename);
int rlce_encrypt(int kem, char* pubkey, char* plainfile);
int rlce_decrypt(char* prikey, char* cipherfile);

#define GFTABLEERR -6
#define TESTERROR -7
#define POLYMULTERRR -8
#define DRBGRESEEDREQUIRED -9
#define MATMULAINVERROR -10
#define POLYNOTFULLDIV -11
#define NEEDNEWRANDOMSEED -12
#define MATRIXCOPYERROR -13
#define MATRIXACOPYERROR -14
#define MATRIXMULERROR -15
#define VECMATRIXMULERROR -16
#define MATRIXVECMULERROR -17
#define MATRIXCOLPERERROR -18
#define MATRIXROWPERERROR -19
#define MATRIXMULAERROR -20
#define NOTIMPLEMENTEDYET -21
#define MATFASTMULAERROR -22
#define GETRANDOMMATAERROR -23
#define GETPERERROR -24
#define REENCODEERROR -25
#define EXEUCLIDEANERROR -26
#define MATRIXRNOTFULLRANK -27
#define MATRIXJOINERROR -28
#define DESPADDINGFAIL -29
#define DEPADDINGFAIL -30
#define RLCEPADDINGNOTDEFINED -31
#define RLCEIDPARANOTDEFINED -32
#define B2FEORFE2BNOTDEFINED -33
#define WRONGPARA -34
#define BYTEVECTORTOOSMALL -35
#define SPADPARAERR -36
#define PADPARAERR -37
#define SHATYPENOTSUPPORTED -38
#define SINVERROR -39
#define FILEERROR -40
#define DRBGREQ2MANYB -41
#define REQIREDMSGTOOLONG -42
#define FASTDECODINGERROR -43
#define ECHELONFAIL -44
#define DECODING2NOTINVERTIBLE -45
#define TOOMANYERRORSINCIPHER -46
#define AFFINE4NOSOLUTION -47
#define MORETHAN4SOLUTIONS -48
#define MATRIXNOTINVERTIBLE -49
#define MATRIXROWCOLUMNNOTMATCH -50
#define CTRDRBGSEEDLENWRONG -51
#define ENTROPYLENTOOSHORT -52
#define OUTPUTLENTOOLONG -53
#define EMPTYDECODEDWORD -54
#define FFTOUTPUTERR -55
#define TOOMANYERRORS -56
#define NOTENOUGHGOODCOL -57
#define CIPHERNULL -58
#define CIPHER2SMALL -59
#define CIPHERSIZEWRONG -60
#define MSGNULL -61
#define SMG2SMALL -62
#define KEYBYTE2SMALL -53
#define SKWRONG -64
#define SKNULL -65
#define BADCOMMANDLINEFLAG -66
#define CORRUPTEDKEYFILE -67
#define CORRUPTEDPLAINCIPHER -68
#define CIPHERNOTMULTIPLE -69
#define DECLENWRONG -70
#define PUBKEYHASHINCORRECTINCIPHER -71
#define FGETSWRONG -72
#define FREADWRONG -73

#define genkey128 1
#define genkey192 2
#define genkey256 3
#define encr 4
#define kemenc 5
#define decr 6
