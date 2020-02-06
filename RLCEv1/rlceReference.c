/* rlce.c
 *
 * Code was written: November 19, 2016-February 8, 2017
 *
 * rlce.c implements crypto oprations 
 * for RLCE scheme that is part of the package 
 * RLCE.tar - Random Linear Code Encryption Scheme
 *
 * Copyright (C) 2016-2017 Yongge Wang
 * 
 * Yongge Wang
 * Department of Software and Information Systems
 * UNC Charlotte
 * Charlotte, NC 28223
 * yonwang@uncc.edu
 *
 */

#include "rlce.h"
int RLCEspad(unsigned char bytes[],unsigned int BLen,
	     unsigned char padded[], unsigned int paddedLen,
	     RLCE_public_key_t pk,
	     unsigned char randomness[], unsigned int randLen,
	     unsigned char e0[], unsigned int e0Len);
int RLCEspadDecode(unsigned char encoded[],unsigned int encodedLen,
		   unsigned char message[], unsigned long long *mlen,
		   RLCE_private_key_t sk,
		   unsigned char e0[], unsigned int e0Len);

int RLCEpad(unsigned char bytes[],unsigned int bytesLen,
	    unsigned char padded[], unsigned int paddedLen,
	    RLCE_public_key_t pk,
	    unsigned char randomness[], unsigned int randLen,
	    unsigned char e0[], unsigned int e0Len);
int RLCEpadDecode(unsigned char encoded[],unsigned int encodedLen,
		  unsigned char message[], unsigned long long *mlen,
		  RLCE_private_key_t sk,
		  unsigned char e0[], unsigned int e0Len);

int getRLCEparameters(unsigned int para[], unsigned int scheme, unsigned int padding) {
  para[9]=padding;  /* 0 for RLCEspad-mediumEncoding
                        1 for RLCEpad-mediumEncoding
                        2 for RLCEspad-basicEncoding
                        3 for RLCEpad-basicEncoding
                        4 for RLCEspad-advancedEncoding
                        5 for RLCEpad-advancedEncoding*/
  para[10]=scheme;   /* scheme ID */
  switch (scheme) {
  case 0:
    para[0]=630; /* n */
    para[1]=470; /* k */
    para[2]=160; /* w */
    para[3]=10;  /* GFsize */
    para[4]=2;   /* hash type */
    para[11]=80;   /* t */
    para[12]=0;   /* omega for list-decoding */
    para[13]=0;   /* L_omega: for list-decoding only */
    para[14]=128; /* kappa-128 */
    para[15]=200; /* u: used for un-recovered msg symbols by RS */
    para[16]=988; /* cipher len in bytes*/
    if (DECODINGMETHOD!=2) {
      para[17]=310116; /* sk bytes for decodingalgorithm 0,1*/
    } else para[17]=192029; /* sk bytes for decoding algorithm 2*/
    para[18]=188001; /* pk bytes */
    para[19]=32; /* random input bytes*/
    switch (padding) {
    case 0: /* 0:RLCEspad */
      para[5]=5500; /*mLen for mediumEncoding */
      para[6]=171;  /* k1 for mediumEncoding */
      para[7]=171;  /* k2 for mediumEncoding */
      para[8]=346; /* k3 for mediumEncoding */
      break;
    case 1: /* 1:RLCEpad  */
      para[5]=5500; /*mLen for mediumEncoding */
      para[6]=624;  /* k1 for mediumEncoding */
      para[7]=32;  /* k2 for mediumEncoding */
      para[8]=32; /* k3 for mediumEncoding */
      break;
    case 2:
      para[5]=4700; /*mLen bEncoding */
      para[6]=146; /* k1 for basicEncoding */
      para[7]=146; /* k2 for basidEncoding */
      para[8]=296;/* k3 for basicEncoding */
      break;
    case 3:
      para[5]=4700; /*mLen bEncoding */
      para[6]=524; /* k1 for basicEncoding */
      para[7]=32; /* k2 for basidEncoding */
      para[8]=32;/* k3 for basicEncoding */
      break;
    case 4:
      para[5]=5869; /*mLen for advancedEncoding */
      para[6]=183; /* k1 for advancedEncoding */
      para[7]=183; /* k2 for advancedEncoding */
      para[8]=368; /* k3 for advancedEncoding */
      break;
    case 5:
      para[5]=5869; /*mLen for advancedEncoding */      
      para[6]=670; /* k1 for advancedEncoding */
      para[7]=32; /* k2 for advancedEncoding */
      para[8]=32;/* k3 for advancedEncoding */
      break;
    default:
      return RLCEPADDINGNOTDEFINED;
    }          
    break;    
  case 1:
    para[0]=532; /* n */
    para[1]=376; /* k */
    para[2]=96; /* w */
    para[3]=10;  /* GFsize */
    para[4]=2;   /* hash type */
    para[11]=78;   /* t */
    para[12]=0;   /* omega for list-decoding */
    para[13]=0;   /* L_omega: for list-decoding only */
    para[14]=128; /* kappa-128 */
    para[15]=123; /* u: used for un-recovered msg symbols by RS */
    para[16]=785; /* cipher len in bytes*/
    if (DECODINGMETHOD!=2) {
      para[17]=179946; /* sk bytes for decodingalgorithm 0,1*/
    } else para[17]=121666; /* sk bytes for decoding algorithm 2*/
    para[18]=118441; /* pk bytes */
    para[19]=32; /* random input bytes*/
    switch (padding) {
    case 0: /* 0:RLCEspad */
      para[5]=4540; /*mLen for mediumEncoding */
      para[6]=141;  /* k1 for mediumEncoding */
      para[7]=141;  /* k2 for mediumEncoding */
      para[8]=286; /* k3 for mediumEncoding */
      break;
    case 1: /* 1:RLCEpad  */
      para[5]=4540; /*mLen for mediumEncoding */
      para[6]=504;  /* k1 for mediumEncoding */
      para[7]=32;  /* k2 for mediumEncoding */
      para[8]=32; /* k3 for mediumEncoding */
      break;
    case 2:
      para[5]=3760; /*mLen bEncoding */
      para[6]=117; /* k1 for basicEncoding */
      para[7]=117; /* k2 for basidEncoding */
      para[8]=236;/* k3 for basicEncoding */
      break;
    case 3:
      para[5]=3760; /*mLen bEncoding */
      para[6]=406; /* k1 for basicEncoding */
      para[7]=32; /* k2 for basidEncoding */
      para[8]=32;/* k3 for basicEncoding */
      break;
    case 4:
      para[5]=4875; /*mLen for advancedEncoding */
      para[6]=152; /* k1 for advancedEncoding */
      para[7]=152; /* k2 for advancedEncoding */
      para[8]=306; /* k3 for advancedEncoding */
      break;
    case 5:
      para[5]=4875; /*mLen for advancedEncoding */      
      para[6]=546; /* k1 for advancedEncoding */
      para[7]=32; /* k2 for advancedEncoding */
      para[8]=32;/* k3 for advancedEncoding */
      break;
    default:
      return RLCEPADDINGNOTDEFINED;
    }             
    break;
  case 2:
    para[0]=1000; /* n */
    para[1]=764; /* k */
    para[2]=236; /* w */
    para[3]=10;  /* GFsize */
    para[4]=2;   /* hash type */
    para[11]=118;   /* t */
    para[12]=0;   /* omega for list-decoding */
    para[13]=0;   /* L_omega: for list-decoding only */
    para[14]=192; /* kappa-192 */
    para[15]=303; /* u: used for un-recovered msg symbols by RS */
    para[16]=1545; /* cipher len in bytes*/
    if (DECODINGMETHOD!=2) {
      para[17]=747393; /* sk bytes for decodingalgorithm 0,1*/
    } else para[17]=457073; /* sk bytes for decoding algorithm 2*/
    para[18]=450761; /* pk bytes */
    para[19]=40; /* random input bytes*/
    switch (padding) {
    case 0: /* 0:RLCEspad */
      para[5]=8820; /*mLen for mediumEncoding */
      para[6]=275;  /* k1 for mediumEncoding */
      para[7]=275;  /* k2 for mediumEncoding */
      para[8]=553; /* k3 for mediumEncoding */
      break;
    case 1: /* 1:RLCEpad  */
      para[5]=8820; /*mLen for mediumEncoding */
      para[6]=1007;  /* k1 for mediumEncoding */
      para[7]=48;  /* k2 for mediumEncoding */
      para[8]=48; /* k3 for mediumEncoding */
      break;
    case 2:
      para[5]=7640; /*mLen bEncoding */
      para[6]=238; /* k1 for basicEncoding */
      para[7]=238; /* k2 for basidEncoding */
      para[8]=479;/* k3 for basicEncoding */
      break;
    case 3:
      para[5]=7640; /*mLen bEncoding */
      para[6]=859; /* k1 for basicEncoding */
      para[7]=48; /* k2 for basidEncoding */
      para[8]=48;/* k3 for basicEncoding */
      break;
    case 4:
      para[5]=9377; /*mLen for advancedEncoding */
      para[6]=293; /* k1 for advancedEncoding */
      para[7]=293; /* k2 for advancedEncoding */
      para[8]=587; /* k3 for advancedEncoding */
      break;
    case 5:
      para[5]=9377; /*mLen for advancedEncoding */      
      para[6]=1077; /* k1 for advancedEncoding */
      para[7]=48; /* k2 for advancedEncoding */
      para[8]=48;/* k3 for advancedEncoding */
      break;
    default:
      return RLCEPADDINGNOTDEFINED;
    }     
    break;
  case 3:
    para[0]=846; /* n */
    para[1]=618; /* k */
    para[2]=144; /* w */
    para[3]=10;  /* GFsize */
    para[4]=2;   /* hash type */
    para[11]=114;   /* t */
    para[12]=0;   /* omega for list-decoding */
    para[13]=0;   /* L_omega: for list-decoding only */
    para[14]=192; /* kappa-192 */
    para[15]=190; /* u: used for un-recovered msg symbols by RS */
    para[16]=1238; /* cipher len in bytes*/
    if (DECODINGMETHOD!=2) {
      para[17]=440008; /* sk bytes for decodingalgorithm 0,1*/
    } else para[17]=292461; /* sk bytes for decoding algorithm 2*/
    para[18]=287371; /* pk bytes */
    para[19]=40; /* random input bytes*/
    switch (padding) {
    case 0: /* 0:RLCEspad */
      para[5]=7320; /*mLen for mediumEncoding */
      para[6]=228;  /* k1 for mediumEncoding */
      para[7]=228;  /* k2 for mediumEncoding */
      para[8]=459; /* k3 for mediumEncoding */
      break;
    case 1: /* 1:RLCEpad  */
      para[5]=7320; /*mLen for mediumEncoding */
      para[6]=819;  /* k1 for mediumEncoding */
      para[7]=48;  /* k2 for mediumEncoding */
      para[8]=48; /* k3 for mediumEncoding */
      break;
    case 2:
      para[5]=6180; /*mLen bEncoding */
      para[6]=193; /* k1 for basicEncoding */
      para[7]=193; /* k2 for basidEncoding */
      para[8]=387;/* k3 for basicEncoding */
      break;
    case 3:
      para[5]=6180; /*mLen bEncoding */
      para[6]=677; /* k1 for basicEncoding */
      para[7]=48; /* k2 for basidEncoding */
      para[8]=48;/* k3 for basicEncoding */
      break;
    case 4:
      para[5]=7825; /*mLen for advancedEncoding */
      para[6]=244; /* k1 for advancedEncoding */
      para[7]=244; /* k2 for advancedEncoding */
      para[8]=491; /* k3 for advancedEncoding */
      break;
    case 5:
      para[5]=7825; /*mLen for advancedEncoding */      
      para[6]=883; /* k1 for advancedEncoding */
      para[7]=48; /* k2 for advancedEncoding */
      para[8]=48;/* k3 for advancedEncoding */
      break;
    default:
      return RLCEPADDINGNOTDEFINED;
    }       
    break;
  case 4:
    para[0]=1360; /* n */
    para[1]=800;  /* k */
    para[2]=560;  /* w */
    para[3]=11;   /* GF size */
    para[4]=2;    /* hash type */
    para[11]=280;   /* t */
    para[12]=0;   /* omega for list-decoding */
    para[13]=0;   /* L_omega: for list-decoding only */
    para[14]=256; /* kappa-256 */
    para[15]=482; /* u: used for un-recovered msg symbols by RS */
    para[16]=2640; /* cipher len in bytes*/
    if (DECODINGMETHOD!=2) {
      para[17]=1773271; /* sk bytes for decodingalgorithm 0,1*/
    } else para[17]=1241971; /* sk bytes for decoding algorithm 2*/
    para[18]=1232001; /* pk bytes */
    para[19]=48; /* random input bytes*/
    switch (padding) {
    case 0: /* 0:RLCEspad */
      para[5]=11880; /*mLen for mediumEncoding */
      para[6]=371;  /* k1 for mediumEncoding */
      para[7]=371;  /* k2 for mediumEncoding */
      para[8]=743; /* k3 for mediumEncoding */
      break;
    case 1: /* 1:RLCEpad  */
      para[5]=11880; /*mLen for mediumEncoding */
      para[6]=1365;  /* k1 for mediumEncoding */
      para[7]=60;  /* k2 for mediumEncoding */
      para[8]=60; /* k3 for mediumEncoding */
      break;
    case 2:
      para[5]=8800; /*mLen bEncoding */
      para[6]=275; /* k1 for basicEncoding */
      para[7]=275; /* k2 for basidEncoding */
      para[8]=550;/* k3 for basicEncoding */
      break;
    case 3:
      para[5]=8800; /*mLen bEncoding */
      para[6]=980; /* k1 for basicEncoding */
      para[7]=60; /* k2 for basidEncoding */
      para[8]=60;/* k3 for basicEncoding */
      break;
    case 4:
      para[5]=13025; /*mLen for advancedEncoding */
      para[6]=407; /* k1 for advancedEncoding */
      para[7]=407; /* k2 for advancedEncoding */
      para[8]=815; /* k3 for advancedEncoding */
      break;
    case 5:
      para[5]=13205; /*mLen for advancedEncoding */      
      para[6]=1509; /* k1 for advancedEncoding */
      para[7]=60; /* k2 for advancedEncoding */
      para[8]=60;/* k3 for advancedEncoding */
      break;
    default:
      return RLCEPADDINGNOTDEFINED;
    }    
    break;
  case 5:
    para[0]=1160; /* n */
    para[1]=700; /* k */
    para[2]=311; /* w */
    para[3]=11;  /* GFsize */
    para[4]=2;   /* hash type */
    para[11]=230;   /* t */
    para[12]=0;   /* omega for list-decoding */
    para[13]=0;   /* L_omega: for list-decoding only */
    para[14]=256; /* kappa-256 */
    para[15]=309; /* u: used for un-recovered msg symbols by RS */
    para[16]=2023; /* cipher len in bytes*/
    if (DECODINGMETHOD!=2) {
      para[17]=1048176; /* sk bytes for decodingalgorithm 0,1*/
    } else para[17]=749801; /* sk bytes for decoding algorithm 2*/
    para[18]=742089; /* pk bytes */
    para[19]=48; /* random input bytes*/
    switch (padding) {
    case 0: /* 0:RLCEspad */
      para[5]=10230; /*mLen for mediumEncoding */
      para[6]=319;  /* k1 for mediumEncoding */
      para[7]=319;  /* k2 for mediumEncoding */
      para[8]=641; /* k3 for mediumEncoding */
      break;
    case 1: /* 1:RLCEpad  */
      para[5]=10230; /*mLen for mediumEncoding */
      para[6]=1159;  /* k1 for mediumEncoding */
      para[7]=60;  /* k2 for mediumEncoding */
      para[8]=60; /* k3 for mediumEncoding */
      break;
    case 2:
      para[5]=7700; /*mLen bEncoding */
      para[6]=240; /* k1 for basicEncoding */
      para[7]=240; /* k2 for basidEncoding */
      para[8]=483;/* k3 for basicEncoding */
      break;
    case 3:
      para[5]=7700; /*mLen bEncoding */
      para[6]=843; /* k1 for basicEncoding */
      para[7]=60; /* k2 for basidEncoding */
      para[8]=60;/* k3 for basicEncoding */
      break;
    case 4:
      para[5]=11145; /*mLen for advancedEncoding */
      para[6]=348; /* k1 for advancedEncoding */
      para[7]=348; /* k2 for advancedEncoding */
      para[8]=698; /* k3 for advancedEncoding */
      break;
    case 5:
      para[5]=11145; /*mLen for advancedEncoding */      
      para[6]=1274; /* k1 for advancedEncoding */
      para[7]=60; /* k2 for advancedEncoding */
      para[8]=60;/* k3 for advancedEncoding */
      break;
    default:
      return RLCEPADDINGNOTDEFINED;
    }  
    break;
  case 6:
    para[0]=40; /* n */
    para[1]=20; /* k */
    para[2]=5; /* w */
    para[3]=10;  /* GFsize */
    para[4]=2;   /* hash type */
    para[11]=10;   /* t */
    para[12]=0;   /* omega for list-decoding */
    para[13]=0;   /* L_omega: for list-decoding only */
    para[14]=128; /* kappa-128 */
    para[15]=7; /* u: used for un-recovered msg symbols by RS */
    para[16]=57; /* cipher len in bytes*/
    if (DECODINGMETHOD!=2) {
      para[17]=1059; /* sk bytes for decodingalgorithm 0,1*/
    } else para[17]=859; /* sk bytes for decoding algorithm 2*/
    para[18]=626; /* pk bytes */
    para[19]=4; /* random input bytes*/
    switch (padding) {
    case 0: /* 0:RLCEspad */
      para[5]=300; /*mLen for mediumEncoding */
      para[6]=9;  /* k1 for mediumEncoding */
      para[7]=9;  /* k2 for mediumEncoding */
      para[8]=20; /* k3 for mediumEncoding */
      break;
    case 1: /* 1:RLCEpad  */
      para[5]=300; /*mLen for mediumEncoding */
      para[6]=30;  /* k1 for mediumEncoding */
      para[7]=4;  /* k2 for mediumEncoding */
      para[8]=4; /* k3 for mediumEncoding */
      break;
    case 2:
      para[5]=200; /*mLen bEncoding */
      para[6]=6; /* k1 for basicEncoding */
      para[7]=6; /* k2 for basidEncoding */
      para[8]=13;/* k3 for basicEncoding */
      break;
    case 3:
      para[5]=200; /*mLen bEncoding */
      para[6]=17; /* k1 for basicEncoding */
      para[7]=4; /* k2 for basidEncoding */
      para[8]=4;/* k3 for basicEncoding */
      break;
    case 4:
      para[5]=331; /*mLen for advancedEncoding */
      para[6]=10; /* k1 for advancedEncoding */
      para[7]=10; /* k2 for advancedEncoding */
      para[8]=22; /* k3 for advancedEncoding */
      break;
    case 5:
      para[5]=331; /*mLen for advancedEncoding */      
      para[6]=34; /* k1 for advancedEncoding */
      para[7]=4; /* k2 for advancedEncoding */
      para[8]=4;/* k3 for advancedEncoding */
      break;
    default:
      return RLCEPADDINGNOTDEFINED;
    }  
    break;
  default:
    return RLCEIDPARANOTDEFINED;
  }
  return 0;
}


RLCE_private_key_t RLCE_private_key_init (unsigned int para[]) {
  RLCE_private_key_t key;
  key= (RLCE_private_key_t) malloc(sizeof (struct RLCE_private_key));
  key->para = malloc(PARASIZE * sizeof(unsigned int));
  int i;
  for (i=0; i<PARASIZE; i++) (key->para[i])=para[i];
  key->perm1 =vec_init(para[0]);
  key->perm2 =vec_init(para[0]+para[2]); /* n+w */
  key->A =matrixA_init(para[2]);
  if (DECODINGMETHOD!=2) key->S = matrix_init(para[1], para[15]+1);
  key->grs = vec_init(para[0]);
  key->G = matrix_init(para[1], para[0]+para[2]-para[1]); /* k\times (n+w)-k */
  return key;
}

void RLCE_free_sk(RLCE_private_key_t sk) {
  free(sk->para);
  if (DECODINGMETHOD!=2) matrix_free(sk->S);
  vector_free(sk->perm1);
  vector_free(sk->perm2);
  matrixA_free(sk->A);
  vector_free(sk->grs);
  if (sk->G !=NULL) matrix_free(sk->G);
  free(sk);
  sk=NULL;
}

RLCE_public_key_t RLCE_public_key_init (unsigned int para[]) {
  RLCE_public_key_t pk;
  int i;
  pk= (RLCE_public_key_t) malloc(sizeof (struct RLCE_public_key));
  pk->para = malloc(PARASIZE * sizeof(unsigned int));
  for (i=0; i<PARASIZE; i++) (pk->para[i])=para[i];
  pk->G = matrix_init(para[1], para[0]+para[2]-para[1]); /* k\times (n+w)-k */
  return pk;
}

void RLCE_free_pk(RLCE_public_key_t pk) {
  free(pk->para);
  if (pk->G != NULL) matrix_free(pk->G);
  free(pk);
  pk=NULL;
}

int pk2B (RLCE_public_key_t pk, unsigned char pkB[], unsigned int *blen) {
  int i, ret;
  if (blen[0]<pk->para[18]) return KEYBYTE2SMALL;
  pkB[0]= (pk->para[10])|(pk->para[9]<<4);
  unsigned int nplusw=pk->para[0]+pk->para[2];
  unsigned int k=pk->para[1];
  unsigned int pkLen=k*(nplusw-k);
  vector_t FE=vec_init(pkLen);
  for (i=0;i<k;i++) memcpy(&(FE->data[i*(nplusw-k)]),(pk->G)->data[i],(nplusw-k)*sizeof(field_t));
  blen[0] = (pkLen*(pk->para[3]))/8;
  if ((pkLen*(pk->para[3]))%8 > 0) blen[0]++;
  if ((pk->para[3])==10) ret=FE2B10(FE, &pkB[1], blen[0]);
  if ((pk->para[3])==11) ret=FE2B11(FE, &pkB[1], blen[0]);
  if (ret<0) return ret;
  vector_free(FE);
  blen[0]++;
  return 0;
}

int sk2B (RLCE_private_key_t sk, unsigned char skB[], unsigned int *blen) {
  unsigned int sklen =sk->para[17];
  if (blen[0]<sklen) return KEYBYTE2SMALL;
  int i,j,ret;
  int n=sk->para[0];
  int k=sk->para[1];
  int w=sk->para[2];
  skB[0]= (sk->para[10])|(sk->para[9]<<4);
  j=1;
  for (i=0;i<n;i++) {
    skB[j]=(((sk->perm1)->data[i])>>8);
    skB[j+1]=(sk->perm1)->data[i];
    j=j+2;
  }
  j=1+2*n;
  for (i=0;i<n+w;i++) {
    skB[j]=(((sk->perm2)->data[i])>>8);
    skB[j+1]=(sk->perm2)->data[i];
    j=j+2;
  }
  j=0;
  unsigned int invSLen=0;
  if (DECODINGMETHOD!=2) invSLen= ((sk->S)->numR) *  ((sk->S)->numC);
  unsigned int totalFELen=2*w+invSLen+n+k*(n+w-k);
  vector_t FE=vec_init(totalFELen);
  for (i=0; i<w; i++) {
    FE->data[j]=((sk->A)->A[i])->data[0][0];
    FE->data[j+1]=((sk->A)->A[i])->data[1][0];
    j=j+2;
  }
  if (invSLen>0) {
    for (i=0;i<(sk->S)->numR; i++) {
      memcpy(&(FE->data[j]),(sk->S)->data[i],((sk->S)->numC)*sizeof(field_t));
      j=j+(sk->S)->numC;
    }
  }
  memcpy(&(FE->data[j]),(sk->grs)->data,n*sizeof(field_t));
  j=j+n;
  for (i=0;i<sk->para[1]; i++) {
    memcpy(&(FE->data[j]),(sk->G)->data[i],(n+w-k)*sizeof(field_t));
    j=j+n+w-k;  
  }
  int byteLen = totalFELen*(sk->para[3])/8;
  if ((totalFELen*(sk->para[3]))%8 > 0) byteLen++;
  if (sklen != (4*n+2*w+1+byteLen)) return SKWRONG;
  if ((sk->para[3])==10) ret=FE2B10(FE, &skB[4*n+2*w+1], byteLen);
  if ((sk->para[3])==11) ret=FE2B11(FE, &skB[4*n+2*w+1], byteLen);
  if (ret<0) return ret;    
  vector_free(FE);
  return 0;
}

RLCE_public_key_t B2pk(const unsigned char binByte[], unsigned long long blen) {
  int i,ret=0;
  unsigned int scheme=binByte[0] & 0x0F;
  unsigned int padding=binByte[0]>>4;
  unsigned int para[PARASIZE];
  ret=getRLCEparameters(para, scheme,padding);
  if (ret<0) return NULL;
  RLCE_public_key_t pk = RLCE_public_key_init(para);
  unsigned int nplusw=pk->para[0]+pk->para[2];
  unsigned int k=pk->para[1];
  unsigned int pkLen=k*(nplusw-k);
  vector_t FE=vec_init(pkLen);
  int byteLen = (pkLen*(pk->para[3]))/8;
  if ((pkLen*(pk->para[3]))%8 > 0) byteLen++;
  if (byteLen>blen-1) return NULL;
  if ((pk->para[3])==10) ret=B2FE10((unsigned char*)&(binByte[1]), byteLen,FE);
  if ((pk->para[3])==11) ret=B2FE11((unsigned char*)&(binByte[1]), byteLen,FE);
  if (ret<0) return NULL;
  for (i=0;i<k;i++) memcpy((pk->G)->data[i], &(FE->data[i*(nplusw-k)]),(nplusw-k)*sizeof(field_t));
  vector_free(FE);
  return pk;
}

RLCE_private_key_t B2sk(const unsigned char binByte[], unsigned long long blen) {
  unsigned int scheme=binByte[0] & 0x0F;
  unsigned int padding=binByte[0]>>4;
  unsigned int para[PARASIZE];  
  getRLCEparameters(para, scheme,padding);
  RLCE_private_key_t sk = RLCE_private_key_init (para);
  int sklen =sk->para[17];
  if (blen<sklen) {
    RLCE_free_sk(sk);
    return NULL;
  }
  int i,j,ret;
  int n=sk->para[0];
  int k=sk->para[1];
  int w=sk->para[2];
  int SnumR=0, SnumC=0;
  if (DECODINGMETHOD!=2) {
    SnumR=k;
    SnumC=sk->para[15]+1;
  }  
  unsigned int invSLen=0;
  if (DECODINGMETHOD!=2) invSLen= SnumR * SnumC;
  unsigned int totalFELen=2*w+invSLen+n+k*(n+w-k);
  vector_t FE=vec_init(totalFELen);
  int permByteLen=4*n+2*w;
  j=1;  
  for (i=0;i<sk->para[0];i++) {
    (sk->perm1)->data[i]=binByte[j];
    (sk->perm1)->data[i]=((sk->perm1)->data[i]<<8);
    (sk->perm1)->data[i]= (binByte[j+1] | (sk->perm1)->data[i]);
    j=j+2;
  }
  j=2*n+1;
  for (i=0;i<n+w;i++) {
    (sk->perm2)->data[i]=binByte[j];
    (sk->perm2)->data[i]=((sk->perm2)->data[i]<<8);
    (sk->perm2)->data[i]=((sk->perm2)->data[i]|binByte[j+1]);
    j=j+2;
  }
  (sk->perm1)->size=n;
  (sk->perm2)->size=n+w;
  
  int byteLen = totalFELen*(sk->para[3])/8;
  if ((totalFELen*(sk->para[3]))%8 > 0) byteLen++;
  if (byteLen>blen-permByteLen-1) return NULL;  
  if ((sk->para[3])==10) ret=B2FE10((unsigned char*)&(binByte[permByteLen+1]), byteLen,FE);
  if ((sk->para[3])==11) ret=B2FE11((unsigned char*)&(binByte[permByteLen+1]), byteLen,FE);
  if (ret<0) return NULL;
  j=0;
  for (i=0; i<w; i++) {
    ((sk->A)->A[i])->data[0][0]=FE->data[j];
    ((sk->A)->A[i])->data[1][0]=FE->data[j+1];
    j=j+2;
  }
  j=2*w;
  if (invSLen>0) {
    for (i=0;i<SnumR; i++) {
      memcpy((sk->S)->data[i],&(FE->data[j]),SnumC*sizeof(field_t));
      j=j+SnumC;
    }
  }
  j=2*w+invSLen;
  memcpy((sk->grs)->data,&(FE->data[j]),n*sizeof(field_t));
  j=2*w+invSLen+n;
  for (i=0;i<k;i++) {
    memcpy((sk->G)->data[i],&(FE->data[j]),(n+w-k)*sizeof(field_t));
    j=j+n+w-k;  
  }  
  vector_free(FE);
  return sk;
}

int RLCE_key_setup (unsigned char entropy[], int entropylen,
		    unsigned char nonce[], int noncelen,
		    RLCE_public_key_t pk, RLCE_private_key_t sk) {
  int ret=0;
  int m=sk->para[3];
  int n=sk->para[0];
  int k= sk->para[1];
  int w=sk->para[2];
  int t=sk->para[11];
  int nplusw=n+w;
  int nminusw=n-w;
  int i,j;
  int LISTDECODE=0;
  if (2*t>n-k) LISTDECODE=1;
  int nRE=n+(4+k)*w+25;
  int nRBforRE =(m*nRE)/8;
  if ((m*nRE)%8 >0) nRBforRE++;

  int nRB = nRBforRE +4*n+2*w;
  unsigned char *randomBytes=calloc(nRB, sizeof(unsigned char));  

  unsigned char pers[] ="PostQuantumCryptoRLCEversion2017";
  int perlen = sizeof(pers)-1;
  unsigned char addS[]="GRSbasedPostQuantumENCSchemeRLCE";
  int addlen = sizeof(addS)-1;  
  if (DRBG==0) {  
    char noncehex[] = "5e7d69e187577b0433eee8eab9f77731";
    unsigned char newnonce[16];
    if (noncelen==0) {
      hex2char(noncehex, newnonce, 16);
      noncelen=16;
      if (nonce != NULL) free(nonce);
      nonce=newnonce;
    }  
    hash_drbg_state_t drbgState;
    drbgState=drbgstate_init(sk->para[4]);
    drbg_Input_t drbgInput;
    drbgInput=drbgInput_init(entropy,entropylen,nonce,noncelen,pers,perlen,addS,addlen);
    ret=hash_DRBG(drbgState,drbgInput,randomBytes, nRB);
    free_drbg_state(drbgState);
    free_drbg_input(drbgInput);
    if (ret<0) return ret;
  }
  if (DRBG==1) { 
    ctr_drbg_state_t drbgState;
    drbgState=ctr_drbgstate_init(sk->para[14]);
    drbg_Input_t drbgInput;
    drbgInput=drbgInput_init(entropy,entropylen,nonce,0,pers,perlen,addS,addlen);
    ret=ctr_DRBG(drbgState,drbgInput,randomBytes, nRB);
    free_ctr_drbg_state(drbgState);
    free_drbg_input(drbgInput);
    if (ret<0) return ret;   
  }
  if (DRBG==2) {
    int mgfseedLen=entropylen+perlen+addlen;
    unsigned char *mgfseed=calloc(mgfseedLen, sizeof(unsigned char));
    memcpy(mgfseed, entropy, entropylen*sizeof(unsigned char));
    memcpy(&mgfseed[entropylen], pers, perlen*sizeof(unsigned char));
    memcpy(&mgfseed[entropylen+perlen], addS, addlen*sizeof(unsigned char));
    RLCE_MGF512(mgfseed,mgfseedLen,randomBytes, nRB);     
  }

  field_t randE[nRE];  
  ret=randomBytes2FE(randomBytes, nRBforRE, randE,nRE,m);
  if (ret<0) return ret;
  vector_t per1 =getPermutation(n,n-1, &randomBytes[nRBforRE], 2*n-2);
  vector_t per1inv=permu_inv(per1);
  vector_copy(per1inv, sk->perm1);

  int done=0;
  unsigned short errorClearedNumber=0;
  vector_t per2,per2inv;
  unsigned short remDim;
  unsigned short *unknownIndex=calloc(k, sizeof(unsigned short));
  unsigned short *knownIndex=calloc(k, sizeof(unsigned short));
  unsigned short index1=0;
  unsigned short index2=0;    
  while (done >=0 ){
    errorClearedNumber=0;
    index1=0;
    index2=0;
    per2 =getPermutation(nplusw,nplusw-1,&randomBytes[nRBforRE+2*n-2+done], 2*nplusw-2);
    if (per2==NULL) return GETPERERROR;
    for (i=0; i<k; i++) {
      if (per2->data[i]<nminusw) {
	knownIndex[index2]=i;
	index2++;
	errorClearedNumber++;
      } else {
	unknownIndex[index1]=i;
	index1++;
      }
    }
    remDim=k-errorClearedNumber;
    if (remDim <=sk->para[15]) {
      per2inv=permu_inv(per2);
      vector_copy(per2inv, sk->perm2);
      done=-1;
    } else done++;
  }
  free(randomBytes);
  
  field_t *grsvec=calloc(n, sizeof(field_t));
  j=0;
  for (i=0;i<n; i++) {
    while (randE[j]==0) j++;
    grsvec[i]=randE[j];
    j++;
  }
  
  GF_vecinverse(grsvec,(sk->grs)->data,n, m);
  matrixA_t A=matrixA_init(w);
  ret=getMatrixAandAinv(A,sk->A,&randE[n+5],4*w+20,m);
  if(ret<0) return ret;

  poly_t generator=poly_init(n);
  if (LISTDECODE==0) getGenPoly(n-k, generator, m);
  matrix_t G= NULL;
  matrix_t G2= NULL;
    G=matrix_init(k, n);
    if (LISTDECODE==0) {
      for (i=0; i<k; i++) {
	for (j=i; j<i+1+n-k;j++) {
	  G->data[i][j]=GF_mul((generator)->coeff[j-i], grsvec[j], m);
	}
      }
    } else {
      for (i=0; i<k; i++) {
	for (j=0; j<n;j++) {
	  G->data[i][j]=GF_mul(GF_exp((i*j)%(fieldSize(m)-1),m),grsvec[j], m);
	}
      }
    }
    ret=matrix_col_permutation(G, per1);
    if (ret <0) return ret;
    matrix_t R=matrix_init(k, w);
    getRandomMatrix(R, &randE[n+4*w+25]);
    matrix_t G1=matrix_join(G, R);
    matrix_free(G);
    if (G1==NULL) return MATRIXJOINERROR;
    G2=matrix_mul_A(G1, A, nminusw, m);
    if (G2==NULL) return MATFASTMULAERROR;
    ret=matrix_col_permutation(G2, per2);
    if (ret<0) return ret;  
    matrix_free(R);
    matrix_free(G1);  
  free(grsvec);
  poly_free(generator);
  vector_free(per2inv);
  vector_free(per2);

  if (DECODINGMETHOD==0){
    for (i=0; i<G2->numR; i++)
      //memcpy((sk->S)->data[i],(G2->data)[i],(G2->numR)*sizeof(field_t));
      for (j=0; j<remDim; j++)
	(sk->S)->data[i][j]=(G2->data)[i][unknownIndex[j]];
  }
  ret=matrix_echelon(G2, m);
  if (ret<0) return ECHELONFAIL;
  for (i=0; i<k; i++) {
    memcpy((sk->G)->data[i], &(G2->data[i][k]), (nplusw-k)*sizeof(field_t));
    memcpy((pk->G)->data[i], &(G2->data[i][k]), (nplusw-k)*sizeof(field_t));
  }
  if (DECODINGMETHOD==1) {
    matrix_t W=matrix_init(remDim, 2*remDim);
    int workingIndexBase=0;
    int workingIndex=0;
    int listCtr=0;
    int test=1;
    int notdone = 1;
    while (notdone) {
      workingIndex = workingIndexBase;
      for (i=0; i<remDim; i++) {
	test = 1;
	while (test) {
	  if  ((sk->perm2)->data[workingIndex]<k) {
	    workingIndex++;
	    if (workingIndex >n-w-1) return DECODING2NOTINVERTIBLE;
	  } else test=0;
	}
	(sk->S)->data[listCtr][remDim]=workingIndex;
	listCtr++;
	for (j=0; j<remDim; j++)
	  W->data[j][i]=(sk->G)->data[unknownIndex[j]][(sk->perm2)->data[workingIndex]-k];
	for (j=0; j<errorClearedNumber; j++)
	  (sk->S)->data[remDim+j][i]=(sk->G)->data[knownIndex[j]][(sk->perm2)->data[workingIndex]-k];
	workingIndex++;
      }
      for (i=0; i<remDim; i++) {
	memset(&(W->data[i][remDim]), 0, remDim*sizeof(field_t));
	W->data[i][remDim+i]=1;
      }
      ret= matrix_echelon(W, m);
      if (ret<0) {
	workingIndexBase++;
	listCtr=0;
      } else notdone=0;
    }
    for (i=0; i<remDim;i++)
      memcpy((sk->S)->data[i], &W->data[i][remDim], remDim*sizeof(field_t));
    matrix_free(W);
  }  
  free(unknownIndex);
  free(knownIndex);
  matrix_free(G2);
  vector_free(per1inv);
  vector_free(per1);  
  matrixA_free(A);
  return 0;
}

int RLCE_encrypt(unsigned char msg[], unsigned long long msgLen,
                 unsigned char entropy[], unsigned int entropylen,
		 unsigned char nonce[], unsigned int noncelen,
                 RLCE_public_key_t pk, unsigned char cipher[], unsigned long long *clen){
  unsigned char pers[] ="PQENCRYPTIONRLCEver1";
  int perslen = sizeof(pers)-1;
  unsigned char add[]="GRSbasedPQEncryption0";
  int addlen = sizeof(add)-1;
  add[addlen-1]=0x00;
  int n=pk->para[0];
  int k=pk->para[1];
  int w=pk->para[2];
  int t = pk->para[11];
  int m=pk->para[3];
  int nplusw=n+w;
  unsigned int kPlust=k+t; 
  vector_t errValue=vec_init(t);
  field_t errLocation[t];
  vector_t FE_vec;

  int CTRPADDRBG=1; /* 0 for SHA-512, 1 for AES */
  if (pk->para[14]>192) CTRPADDRBG=0;

  /* pk->para[9]: 0,1 -> mediumEncoding */
  /* pk->para[9]: 2,3 -> basicEncoding */
  if ((pk->para[9] == 0) || (pk->para[9] == 1)) { 
    FE_vec =vec_init(kPlust);
  } else if ((pk->para[9] == 2) || (pk->para[9] == 3)) { 
    FE_vec =vec_init(k);
  } else return NOTIMPLEMENTEDYET;

  int ret=0, i,j;
  int nRB0=0, nRB1=0,nRB=0;
  nRB0=pk->para[8]+2*t;
  if ((pk->para[9] == 2) || (pk->para[9] == 3)) {
    nRB1 =(m*(t+10))/8;
    if ((m*(t+10))%8 >0) nRB1++;
  }
  nRB=nRB0+nRB1;
  unsigned char * randBytes;
  randBytes = (unsigned char *) calloc(nRB, sizeof(unsigned char));
  unsigned char * padrand;
  padrand =  (unsigned char *) calloc(pk->para[8], sizeof(unsigned char));
  hash_drbg_state_t drbgState=NULL;
  ctr_drbg_state_t ctrdrbgState=NULL;
  drbg_Input_t drbgInput=NULL;

  if ((CTRPADDRBG==0)&&(DRBG!=2)){
    unsigned char nonceAppend[]="RLCEencNonce";
    int nonceAppendlen = sizeof(nonceAppend)-1;
    unsigned char noncenew[noncelen+nonceAppendlen];
    if (noncelen >0) memcpy(noncenew, nonce, noncelen);
    memcpy(&noncenew[noncelen], nonceAppend, nonceAppendlen);
    noncelen=noncelen+nonceAppendlen;
    drbgState=drbgstate_init(pk->para[4]);
    drbgInput=drbgInput_init(entropy,entropylen,noncenew,noncelen,pers,perslen,add,addlen);    
    ret=hash_DRBG_Instantiate(drbgState, drbgInput);
    if (ret<0) return ret;
  }
  if ((CTRPADDRBG==1)&&(DRBG!=2)){
    ctrdrbgState=ctr_drbgstate_init(pk->para[14]);
    drbgInput=drbgInput_init(entropy,entropylen,nonce,0,pers,perslen,add,addlen);
    ret=ctr_DRBG_Instantiate_algorithm(ctrdrbgState, drbgInput);
    if (ret<0) return ret;
  }
  int mgfseedLen=entropylen+perslen+addlen;
  unsigned char *mgfseed=calloc(mgfseedLen, sizeof(unsigned char));
  if (DRBG==2) {
    memcpy(mgfseed, entropy, entropylen*sizeof(unsigned char));
    memcpy(&mgfseed[entropylen], pers, perslen*sizeof(unsigned char));
    memcpy(&mgfseed[entropylen+perslen], add, addlen*sizeof(unsigned char));
  }
  unsigned int ctr=0;
  unsigned short repeat = 1;
  int paddedLen= paddedLen=pk->para[6]+pk->para[7]+pk->para[8];
  unsigned char *paddedMSG=calloc(paddedLen, sizeof(unsigned char));
  while (repeat) { /* this loop makes sure that errors will not be zero */
    repeat = 0;    
    if ((CTRPADDRBG==0)&&(DRBG!=2)) hash_DRBG_Generate(drbgState, drbgInput,randBytes,nRB);
    if ((CTRPADDRBG==1)&&(DRBG!=2)) ctr_DRBG_Generate(ctrdrbgState,drbgInput,randBytes,nRB);    
    if (DRBG==2) {
      memcpy(&mgfseed[entropylen+perslen], add, addlen*sizeof(unsigned char));
      RLCE_MGF512(mgfseed,mgfseedLen,randBytes, nRB);
    }
    ctr++;
    add[addlen-1]=(ctr & 0xFF);
    memcpy(padrand, randBytes, pk->para[8]);
    /* BEGIN get positions for t-errors */   
    vector_t per =getPermutation(nplusw,t,&randBytes[pk->para[8]], 2*t);
    memcpy(errLocation, per->data, t * sizeof(field_t));
    vector_free(per);
    /*BEGIN sort errLocation */
    field_t *tempArray=calloc(nplusw, sizeof(field_t));
    for (i=0; i<t; i++) tempArray[errLocation[i]]=1;
    /* if error locations are: l_0<l_1<...<l_{t-1} then
     * e0=l_0||l_1||...||l_t where each l_i is two bytes*/
    int tmpidx =0;
    int e0Len = 4*t;
    unsigned char e0[e0Len];
    int usede0Len = 2*t; /*  mediumPadding: usede0Len = 2*t */
    for (i=0; i<nplusw; i++) {
      if (tempArray[i]==1) {
	errLocation[tmpidx]=i;
	e0[2*tmpidx]= (i>>8) & 0xFF;
	e0[2*tmpidx+1]= i & 0xFF;
	tmpidx++;
      }
    }
    free(tempArray);
    /* END get positions for t-errors */

    /* if basic Encoding, error values within e0 */
    if ((pk->para[9] == 2)||(pk->para[9] == 3)) {
      usede0Len = 4*t; /* basicPadding: usede0Len = 4*t */
      field_t bEncErr[t+10];
      ret=randomBytes2FE(&randBytes[nRB0], nRB1, bEncErr,t+10,m);
      if (ret<0) return ret;
      j=0;
      for (i=0; i<t+10; i++) {
	if ((bEncErr[i] != 0) && (j<t)) {
	  errValue->data[j]=bEncErr[i];
	  e0[2*(t+j)]= (bEncErr[i]>>8); 
	  e0[2*(t+j)+1]= bEncErr[i]; 
	  j++;
	}
      }
      repeat=0;
      if (j<t) repeat = 1;
    }
    if ((pk->para[9] == 2) || (pk->para[9] == 0)) { /* RLCEspad  */
	ret=RLCEspad(msg, pk->para[6],paddedMSG,paddedLen,pk,padrand,pk->para[8], e0, usede0Len);
	if (ret<0) return ret;
    } else { /* RLCEpad ((pk->para[9] == 1) || (pk->para[9] == 3)) */
      ret=RLCEpad(msg, pk->para[6],paddedMSG,paddedLen,pk,padrand,pk->para[8],e0,usede0Len);
      if (ret<0) return ret;
    }
    if (m==10) ret=B2FE10(paddedMSG,paddedLen, FE_vec);
    if (m==11) ret=B2FE11(paddedMSG,paddedLen, FE_vec);
    if (ret<0) return ret;
    
    if ((pk->para[9] == 0) || (pk->para[9] == 1)) {
      memcpy(errValue->data, &(FE_vec->data[k]), t*sizeof(field_t));
      for (i=0; i<t; i++) {
	if (errValue->data[i]==0) repeat=1;
      }
    }
  }

    
  free(paddedMSG);
  free(randBytes);
  if (drbgState !=NULL) free_drbg_state(drbgState);
  if (ctrdrbgState != NULL) free_ctr_drbg_state(ctrdrbgState);
  free(mgfseed);
  free_drbg_input(drbgInput);
  free(padrand);

  vector_t cipherFE=vec_init(nplusw);
  memcpy(cipherFE->data, FE_vec->data, k * sizeof(field_t));
  matrix_vec_mat_mul(FE_vec->data,k,pk->G,&(cipherFE->data[k]),nplusw-k,m);
  for (i=0; i<t; i++) cipherFE->data[errLocation[i]] ^= errValue->data[i];
  vector_free(FE_vec);
  vector_free(errValue);
  
  if (cipher==NULL) return CIPHERNULL;
  if (clen==NULL) return CIPHERNULL;
  if (clen[0]<pk->para[16]) return CIPHER2SMALL;
  if ((pk->para[3])==10) ret=FE2B10(cipherFE, cipher, clen[0]);
  if ((pk->para[3])==11) ret=FE2B11(cipherFE, cipher, clen[0]);
  vector_free(cipherFE);
  return 0;
}

int recoverRem(int ex, field_t eLocationIndicator[],field_t dest[],RLCE_private_key_t sk) {
  int n=sk->para[0];
  int k=sk->para[1];
  int w=sk->para[2];
  int m=sk->para[3];
  int i,j,ret;
  int errClearPos=0;
  if (ex>0) {
    for (i=0; i<k;i++) if (eLocationIndicator[i]<3) errClearPos++;
  } else {
    for (i=0; i<k;i++) if (eLocationIndicator[i]<2) errClearPos++;
  }
  int remDim=k-errClearPos;
  unsigned short unknownIndex[remDim];
  unsigned short knownIndex[errClearPos];
  unsigned short index1=0, index2=0;
  if (ex>0) {
    for (i=0; i<k;i++) {
      if (eLocationIndicator[i]>2){
	unknownIndex[index1++]=i;
      } else knownIndex[index2++]=i;
    }
    int ctr=0;
    for (i=k; i<n+w-1;i++) if (eLocationIndicator[i]<3) ctr++;
    if (ctr-remDim<ex) ex=ctr-remDim;
  } else {
    for (i=0; i<k;i++) {
      if (eLocationIndicator[i]>1){
	unknownIndex[index1++]=i;
      } else knownIndex[index2++]=i;
    }
  }
  
  field_t *clearedmsg=calloc(errClearPos, sizeof(field_t)); 
  for (i=0;i<errClearPos; i++) clearedmsg[i]=dest[knownIndex[i]];
  matrix_t W=matrix_init(remDim+ex, remDim+1);
  matrix_t U=matrix_init(1+errClearPos, remDim+ex);  
  index1=k;
  int test=1;
  int notdone = 1;
  while (notdone) {
    index2 = index1;
    for (i=0; i<W->numR; i++) {
      test = 1;
      while (test) {
	if (eLocationIndicator[index2]>1) {
	  if (index2++>n+w-1) return NOTENOUGHGOODCOL;
	} else test=0;
      }
      for (j=0;j<remDim;j++) W->data[i][j]=(sk->G)->data[unknownIndex[j]][index2-k];
      for (j=0;j<errClearPos;j++) U->data[j][i]=(sk->G)->data[knownIndex[j]][index2-k];
      U->data[errClearPos][i]=dest[index2++];
    }
    for (j=0;j<U->numR-1;j++) {
      GF_mulvec(clearedmsg[j], U->data[j],NULL,U->numC,m);
    }
    for (j=0;j<U->numR-1;j++) GF_addvec(U->data[j],U->data[j+1],NULL,U->numC);
    for (j=0;j<U->numC;j++) W->data[j][remDim]=U->data[errClearPos][j];
    ret=matrix_echelon(W,m);
    if (ex>0) {
      if ((ret<0) && (ret >-remDim)) {
	index1++;
      } else notdone=0;
    } else {
      if (ret<0) {
	index1++;
      } else notdone=0;
    }
  }
  if (ex>0) {
    if (ret ==-remDim) {
      for (i=0;i<remDim;i++) dest[unknownIndex[i]]=W->data[i][remDim];
      ret = 0;
    }
  } else {
    for (i=0;i<remDim;i++) dest[unknownIndex[i]]=W->data[i][remDim];
  }
  free(clearedmsg);
  matrix_free(U);
  matrix_free(W);
  return ret;
}

int RLCE_decrypt(unsigned char cipher[], unsigned long long clen, RLCE_private_key_t sk, unsigned char msg[],
		 unsigned long long *mlen){
  if (sk==NULL) return SKNULL;
  int n=sk->para[0];
  int k=sk->para[1];
  int w=sk->para[2];
  int m=sk->para[3];
  int t=sk->para[11];
  int codeLen = (1u<< m) -1;
  int zeroLen = codeLen - n;
  int codeDim = k+zeroLen;
  int nplusw = n+w;
  int nminusw = n-w;
  int i, j, ret;
  int LISTDECODE=0;
  if (2*t>n-k) LISTDECODE=1;

  vector_t cipherFE=vec_init(nplusw);
  if ((sk->para[3])==10) ret=B2FE10(cipher, clen, cipherFE);
  if ((sk->para[3])==11) ret=B2FE11(cipher, clen, cipherFE);
  if (ret<0) return CIPHERSIZEWRONG;  
    
  field_t *cp=calloc(nplusw, sizeof(field_t));
  for (j=0; j<nplusw; j++) cp[j]=cipherFE->data[(sk->perm2)->data[j]];
  field_t *C1=calloc(n, sizeof(field_t));
  memcpy(C1, cp, nminusw*sizeof(field_t));
  GF_mulAinv(&(cp[nminusw]), sk->A, &(C1[nminusw]), m);
  /* cp task done, now we use it for other purpose. only n elements used */
  for (j=0; j<n; j++) cp[j]=C1[(sk->perm1)->data[j]];
  free(C1);
  GF_vecvecmul((sk->grs)->data,cp,NULL,(sk->grs)->size,m);
  poly_t decodedWord=NULL;
  poly_t listdecodedWord=NULL;
  field_t *eLocation=calloc(n-k, sizeof(field_t));
  if (LISTDECODE ==0) {
    poly_t code=NULL;
    code=poly_init(codeLen); 
    memcpy(&(code->coeff[zeroLen]), cp, n * sizeof(field_t));
    poly_deg(code);
    decodedWord=rs_decode(DECODER, code, codeLen, codeDim, eLocation,m);
    poly_free(code);
  } else {
    listdecodedWord=list_decode(cp,n,k,t,sk->para[12],sk->para[13],eLocation,m);
    if (listdecodedWord==NULL) {
      free(cp);
      free(eLocation);
      return EMPTYDECODEDWORD;
    }
    decodedWord = poly_init(codeLen);
    memcpy(&(decodedWord->coeff[zeroLen]), listdecodedWord->coeff, n*sizeof(field_t));
    poly_free(listdecodedWord);
  }
  free(cp);
  field_t *eLocationIndicator=calloc(nplusw, sizeof(field_t));
  int numRoots=0;
  for (i=0; i<n-k; i++) {
    if (eLocation[i]>=zeroLen) {
      eLocationIndicator[eLocation[i]-zeroLen]=1;
      numRoots++;
    }
  }
  free(eLocation);
  
  field_t *dest=calloc(nplusw, sizeof(field_t)); /* dest contains field elements that were encrypted */
  field_t *eLocationAfterP1=calloc(n, sizeof(field_t));
  field_t *cipherB4A=calloc(nminusw, sizeof(field_t));
  field_t *decodedGRS;
  field_t *grsinv=calloc(n, sizeof(field_t));
  decodedGRS=grsinv;
  GF_vecinverse((sk->grs)->data, grsinv, n, m);
  GF_vecvecmul(&decodedWord->coeff[zeroLen],grsinv,decodedGRS,n,m);
  for (i=0; i<n; i++)
    if ((sk->perm1)->data[i]<nminusw) cipherB4A[(sk->perm1)->data[i]]=decodedGRS[i];
  free(grsinv);
  for (i=0;i<n;i++) eLocationAfterP1[(sk->perm1)->data[i]]=eLocationIndicator[i];
  /* eLocationIndicator will now be used for errors after P2.
   * eLocationIndicator[i]=0: no error since RS shows no error
   * eLocationIndicator[i]=1: contains RS fixed error
   * eLocationIndicator[i]=2: maybe no error
   * eLocationIndicator[i]=3: maybe error   */

  /* if we can correct cipher[0..k-1], then we recover the message.
   * First check which positions [0..n-w] is mapped to cipher[0..k-1] under P2.
   * These values are part of values for the message[0..k-1].
   * using RS decoding information, we identify these i<k such that
   * eLocationIndicator[i]=0/1. Then we recover cipher[i]=message[i]
   * Next check positions obtained after applying P2 to [n-w..n]. 
   * If the value has no error in RS-decoding process, then it may 
   * be correct and we mark it as eLocationIndicator[i]=2.
   * Otherwise, we mark it as eLocationIndicator[i]=3.
   */
  memset(eLocationIndicator, 0, nplusw*sizeof(field_t));
  
  vector_t perm2=permu_inv(sk->perm2);
  unsigned short errClearPos=0;
  int remDim;
  unsigned short *unknownIndex=NULL;
  unsigned short *knownIndex=NULL;
  for (i=0;i<nminusw;i++) {
    dest[(sk->perm2)->data[i]]=cipherB4A[i];
    eLocationIndicator[(sk->perm2)->data[i]]=eLocationAfterP1[i];
    if ((sk->perm2)->data[i]<k) errClearPos++;
  }
  for (i=0; i<w; i++) {
    eLocationIndicator[(sk->perm2)->data[nminusw+2*i]]=2+eLocationAfterP1[nminusw+i];
    eLocationIndicator[(sk->perm2)->data[nminusw+2*i+1]]=2+eLocationAfterP1[nminusw+i];
  }

  field_t *tmpvec=NULL;
  if (DECODINGMETHOD != 2) {
    unsigned short index1=0;
    unsigned short index2=0;
    remDim=k-errClearPos;
    unknownIndex =calloc(remDim, sizeof(unsigned short));
    knownIndex =calloc(errClearPos, sizeof(unsigned short));
    for (i=0; i<k; i++) {
      if (perm2->data[i]<nminusw) {
	knownIndex[index2]=i;
	index2++;
      } else {
	unknownIndex[index1]=i;
	index1++;
      }
    }
    tmpvec=calloc(remDim, sizeof(field_t));
  }  
  if (DECODINGMETHOD==0) {
    poly_t q=poly_init(codeLen);
    poly_t generator=poly_init(n);
    getGenPoly(n-k, generator, m); 
    ret=poly_quotient(decodedWord, generator, q, m);
    poly_free(generator);
    if (ret<0) return ret;
    matrix_vec_mat_mul(&(q->coeff[zeroLen]),k,sk->S,tmpvec,remDim, m);
    for (i=0; i<remDim; i++) dest[unknownIndex[i]]=tmpvec[i];
    poly_free(q);    
  }  
  poly_free(decodedWord);
  
  if (DECODINGMETHOD==1) {
    matrix_t W=matrix_init(remDim, remDim);
    matrix_t X=matrix_init(errClearPos, remDim);
    for (i=0;i<remDim;i++) memcpy(W->data[i], (sk->S)->data[i], remDim*sizeof(field_t));
    for (i=0;i<errClearPos;i++) 
      memcpy(X->data[i], (sk->S)->data[remDim+i], remDim*sizeof(field_t));    
    field_t *tmp2vec;
    field_t *knownvec;
    tmp2vec=calloc(remDim, sizeof(field_t));
    knownvec=calloc(errClearPos, sizeof(field_t));
    for (i=0; i<errClearPos; i++) knownvec[i]=dest[knownIndex[i]];
    matrix_vec_mat_mul(knownvec,errClearPos,X, tmpvec,remDim, m);
    for (i=0; i<remDim; i++) tmpvec[i] ^= cipherB4A[(sk->S)->data[i][remDim]];
    matrix_vec_mat_mul(tmpvec,remDim, W, tmp2vec,remDim,m);
    for (i=0;i<remDim; i++) dest[unknownIndex[i]]=tmp2vec[i];
    free(knownvec);
    free(tmp2vec);
    matrix_free(W);
    matrix_free(X);
  }
  
  if (unknownIndex!=NULL) free(unknownIndex);
  if (knownIndex!=NULL) free(knownIndex);
  if (tmpvec !=NULL) free(tmpvec);
  
  if (DECODINGMETHOD==2) {
    for (i=0;i<k;i++) if (eLocationIndicator[i]==2) dest[i]=cipherFE->data[i];
    ret=recoverRem(t-numRoots,eLocationIndicator,dest,sk);
    if (ret!=0) ret=recoverRem(0,eLocationIndicator,dest,sk);
    if (ret<0) return ret;
  }

  /* Errors and error locations */
  unsigned int errLocation[t];
  memset(errLocation, 0, t*sizeof(unsigned int));
  vector_t errValue=vec_init(t);
    vector_t cipherNoError=vec_init(nplusw);
    field_t *cipherNoError1;
    cipherNoError1=calloc(nplusw-k, sizeof(field_t));
    ret=matrix_vec_mat_mul(dest,k,sk->G, cipherNoError1, nplusw-k,sk->para[3]);
    if (ret<0) return ret;
    memcpy(cipherNoError->data, dest, k*sizeof(field_t));
    memcpy(&(cipherNoError->data[k]), cipherNoError1, (nplusw-k)*sizeof(field_t));
    int tmpidx =0;
    for (i=0; i<cipherFE->size; i++) {
      if (cipherFE->data[i] !=cipherNoError->data[i]) {
	if (tmpidx<t) {
	  errLocation[tmpidx]=i;
	  errValue->data[tmpidx]= (cipherFE->data[i] ^ cipherNoError->data[i]);
	  tmpidx++;
	} else {
	}
      }
    }  
    free(cipherNoError1);
    vector_free(cipherNoError);
  vector_free(cipherFE);
  vector_free(perm2);

  
  /* BEGIN convert feildElement vector to padded message bytes of k1+k2+k3 */
  unsigned short kPlust=k+t; 
  vector_t FE_vec;
  int paddedLen=sk->para[6]+sk->para[7]+sk->para[8];
  if ((sk->para[9] == 0)||(sk->para[9] == 1)) {
    FE_vec=vec_init(kPlust);
    memcpy(FE_vec->data, dest, k*sizeof(field_t));
    memcpy(&(FE_vec->data[sk->para[1]]),errValue->data,t*sizeof(field_t));
  } else if  ((sk->para[9] == 2)||(sk->para[9] == 3)) {
    FE_vec=vec_init(sk->para[1]);
    memcpy(FE_vec->data, dest,k*sizeof(field_t));
  } else if ((sk->para[9] == 4)||(sk->para[9] == 5)) {
    return NOTIMPLEMENTEDYET;
  }
  
  //vector_print(dest);
  //vector_print(errValue);
  free(eLocationAfterP1); 
  free(eLocationIndicator);
  free(cipherB4A);
  free(dest);
  unsigned char paddedMSG[paddedLen]; /* padded msg k1+k1+k2 bytes */
  if ((sk->para[3])==10) ret=FE2B10(FE_vec, paddedMSG,paddedLen);
  if ((sk->para[3])==11) ret=FE2B11(FE_vec, paddedMSG,paddedLen);
  if (ret<0) return ret;  
  vector_free(FE_vec);
  /* END convert feildElement vector to padded message bytes */
  
  /* BEGIN message de-padding */
  int e0Len = 4*t;
  unsigned char e0[e0Len];/* bytes used for padding purpose */
  for (i=0; i<t; i++) {
    e0[2*i]= errLocation[i]>>8;
    e0[2*i+1]= errLocation[i];
  }

  if ((sk->para[9] == 2) || (sk->para[9] == 3)) { /* bEncoding */
    for (i=0; i<t; i++) {
      e0[2*(t+i)]= (errValue->data[i]>>8);
      e0[2*(t+i)+1]= errValue->data[i];
    }
    if (sk->para[9] == 2) { /* RLCEspad  */
      ret=RLCEspadDecode(paddedMSG,paddedLen, msg, mlen, sk, e0, e0Len);
      if (ret<0) return ret;
    } else if (sk->para[9] == 3) { /* RLCEpad */
      ret=RLCEpadDecode(paddedMSG,paddedLen, msg, mlen, sk, e0, e0Len);
      if (ret<0) return ret;
    }
	
  } else if ((sk->para[9] == 0) || (sk->para[9] == 1)) { /* mEncoding */
    if (sk->para[9] == 0) { /* RLCEspad  */
      ret=RLCEspadDecode(paddedMSG,paddedLen, msg, mlen, sk, e0, 2*t);
      if (ret<0) return ret;
    } else if (sk->para[9] == 1) { /* RLCEpad */
      ret=RLCEpadDecode(paddedMSG,paddedLen, msg, mlen, sk, e0, 2*t);
      if (ret<0) return ret;
    }
  } else if ((sk->para[9] == 2)||(sk->para[9] == 3)) { /* aEncoding */
    return NOTIMPLEMENTEDYET;
  }
  vector_free(errValue);
  return 0;
}

int rlceWriteFile(char* filename, unsigned char bytes[], unsigned long long blen, int hex) {
  FILE *f = fopen(filename, "w"); /* r or w */
  if (f == NULL) return FILEERROR;
  int i;
  if (hex==1) for (i=0; i<blen; i++) fprintf(f, "%02x", bytes[i]);
  if (hex==0) fwrite(bytes,1,blen,f);
  fclose(f);
  return 0;
}

unsigned char* rlceReadFile(char* filename, unsigned long long *blen, int hex) {
  FILE *f = fopen(filename, "rb");
  if (f==NULL) return NULL;
  fseek (f,0,SEEK_END);
  blen[0]=ftell(f);
  rewind(f);  
  char *buffer=calloc(blen[0]+1, sizeof(char)); 
  fread(buffer, 1,blen[0],f);
  fclose(f);
  if (hex==0) return (unsigned char*) buffer;
  if ((blen[0]%2)>0) return NULL;
  blen[0] = blen[0]/2;
  char buf[10];
  unsigned char *hexBin=NULL; 
  hexBin=calloc(blen[0], sizeof(unsigned char));
  int count;
  for(count = 0; count<blen[0]; count++) {
    sprintf(buf, "0x%c%c", buffer[2*count], buffer[2*count+1]);
    hexBin[count] = strtol(buf, NULL, 0);
  }
  free(buffer);
  return hexBin;
}

int writeSK(char* filename, RLCE_private_key_t sk, int hex) {
  int ret=0;
  unsigned int sklen=sk->para[17];
  unsigned char *skB=calloc(sklen, sizeof(unsigned char));
  ret=sk2B(sk, skB, &sklen);
  if (ret<0) return ret;
  ret=rlceWriteFile(filename,skB,sklen, hex);
  free(skB);
  return ret;
}

RLCE_private_key_t readSK(char* filename, int hex) {
  unsigned long long blen=0;
  unsigned char* binByte=rlceReadFile(filename, &blen, hex);
  if (binByte==NULL) return NULL;  
  RLCE_private_key_t sk=B2sk(binByte, blen);
  free(binByte);
  return sk;
}

int writePK(char* filename,  RLCE_public_key_t pk, int hex) {
  int ret;  
  unsigned int pklen =pk->para[18];
  unsigned char *pkB=calloc(pklen, sizeof(unsigned char));
  ret=pk2B(pk,pkB,&pklen);
  if (ret<0) return ret;
  ret=rlceWriteFile(filename,pkB,pklen, hex);
  free(pkB);
  return ret;
}

RLCE_public_key_t readPK(char* filename, int hex) {
  unsigned long long blen=0;
  unsigned char* binByte=rlceReadFile(filename, &blen, hex);
  if (binByte==NULL) return NULL;
  RLCE_public_key_t pk=B2pk(binByte, blen);
  free(binByte);
  return pk;
}

int RLCEspad(unsigned char bytes[],unsigned int bytesLen,
	     unsigned char padded[], unsigned int paddedLen,
	     RLCE_public_key_t pk,
	     unsigned char randomness[], unsigned int randLen,
	     unsigned char e0[], unsigned int e0Len) {
  int i = 0;
  int k1=pk->para[6];
  int k2=pk->para[7];
  int k3=pk->para[8]; 
  if ((bytesLen!= k1)||(randLen!= k3)||(paddedLen!=k1+k2+k3))
    return SPADPARAERR;
  unsigned int alpha=8*(k1+k2+k3)-pk->para[5];
  unsigned char mask = 0xFF << alpha;
  randomness[k3-1] &= mask; /* set the last alpha bits as zero */  
  unsigned char re0[k3+e0Len];
  memcpy(re0, randomness, k3);
  if (e0Len !=0) memcpy(&re0[k3], e0, e0Len);
  unsigned char mre0[k1+k3+e0Len];
  memcpy(mre0, bytes, k1);
  memcpy(&mre0[k1], re0, k3+e0Len);
  unsigned char h1mre0[k2]; 
  RLCE_MGF512(mre0, k1+k3+e0Len, h1mre0, k2);
  unsigned char h2re0[k1+k2]; 
  RLCE_MGF512(re0, k3+e0Len, h2re0,k1+k2);
  memcpy(padded, bytes, k1);
  memcpy(&padded[k1], h1mre0,k2);
  memcpy(&padded[k1+k2],randomness, k3);
  for (i=0;i<k1+k2;i++) padded[i]=padded[i]^h2re0[i];
  return 0;
}

int RLCEspadDecode(unsigned char encoded[],unsigned int encodedLen,
		   unsigned char message[], unsigned long long *mlen,
		   RLCE_private_key_t sk,
		   unsigned char e0[], unsigned int e0Len) {
  int i= 0;
  int k1=sk->para[6];
  int k2=sk->para[7];
  int k3=sk->para[8];
  if (encodedLen!=(k1+k2+k3)) return SPADPARAERR;
  if ((mlen==NULL) || (message==NULL)) return MSGNULL;
  if (mlen[0]< k1) return SMG2SMALL;
  unsigned char randomness[k3];
  memcpy(randomness, &encoded[k1+k2],k3);
  unsigned int alpha=8*(k1+k2+k3)-sk->para[5]; 
  unsigned char mask = 0xFF << alpha;
  randomness[k3-1] &= mask; /* set the last alpha bits as zero */
  unsigned char re0[k3+e0Len];
  memcpy(re0, randomness,k3);
  if (e0Len !=0) memcpy(&re0[k3], e0, e0Len);
  unsigned char h2re0[k1+k2]; 
  RLCE_MGF512(re0,k3+e0Len, h2re0,k1+k2);
  for (i=0;i<k1+k2;i++) encoded[i] = encoded[i] ^h2re0[i];
  memcpy(message, encoded, k1);
  unsigned char h1mre0[k2];
  unsigned char mre0[k1+k3+e0Len];
  memcpy(mre0, message, k1);
  memcpy(&mre0[k1], re0, k3+e0Len);
  RLCE_MGF512(mre0, k1+k3+e0Len, h1mre0,k2);
  for (i=k1;i<k1+k2;i++) if (h1mre0[i-k1]!=encoded[i]) return DESPADDINGFAIL;
  return 0;
}

int RLCEpad(unsigned char bytes[],unsigned int bytesLen,
	    unsigned char padded[], unsigned int paddedLen,
	    RLCE_public_key_t pk,
	    unsigned char randomness[], unsigned int randLen,
	    unsigned char e0[], unsigned int e0Len) {
  int k1=pk->para[6];
  int k2=pk->para[7];
  int k3=pk->para[8]; 
  int i = 0;
  if ((bytesLen!=k1)||(randLen!=k3)||(paddedLen!=(k1+k2+k3))){
    return PADPARAERR;
  }
  unsigned int alpha=8*(k1+k2+k3)-pk->para[5];
  unsigned char mask = 0xFF << alpha;
  randomness[k3-1] &= mask; /* set the last alpha bits as zero */
  unsigned char re0[k3+e0Len];
  memcpy(re0, randomness, k3);
  if (e0Len !=0) memcpy(&re0[k3], e0, e0Len);
  unsigned char mre0[k1+k3+e0Len];
  memcpy(mre0, bytes, k1);
  memcpy(&mre0[k1], re0, k3+e0Len);
  unsigned char h1mre0[k2]; 
  RLCE_MGF512(mre0, k1+k3+e0Len, h1mre0,k2);
  unsigned char h2re0[k1+k2];
  RLCE_MGF512(re0, k3+e0Len, h2re0,k1+k2);
  memcpy(padded, bytes, k1);
  memcpy(&padded[k1], h1mre0,k2);
  memcpy(&padded[k1+k2],randomness,k3);
  for (i=0;i<k1+k2;i++) padded[i]=padded[i]^h2re0[i];
  unsigned char mh1Ph2[k1+k2]; 
  memcpy(mh1Ph2, padded, k1+k2);
  unsigned char h3mh1Ph2[k3];
  RLCE_MGF512(mh1Ph2,k1+k2, h3mh1Ph2,k3);
  for (i=0; i<k3; i++) padded[k1+k2+i]^=h3mh1Ph2[i];
  return 0;
}

int RLCEpadDecode(unsigned char encoded[],unsigned int encodedLen,
		  unsigned char message[], unsigned long long *mlen,
		  RLCE_private_key_t sk,
		  unsigned char e0[], unsigned int e0Len) {
  int k1=sk->para[6];
  int k2=sk->para[7];
  int k3=sk->para[8]; 
  int i = 0;
  if (encodedLen!=(k1+k2+k3)) return PADPARAERR;
  if ((mlen==NULL) || (message==NULL)) return MSGNULL;
  if (mlen[0]< k1) return SMG2SMALL;  
  unsigned char mh1Ph2[k1+k2];
  memcpy(mh1Ph2, encoded, k1+k2);
  unsigned char h3mh1Ph2[k3];
  RLCE_MGF512(mh1Ph2,k1+k2, h3mh1Ph2,k3);
  unsigned char randomness[k3];
  for (i=0; i<k3; i++) randomness[i]=encoded[k1+k2+i] ^  h3mh1Ph2[i];
  unsigned int alpha=8*(k1+k2+k3)-sk->para[5]; 
  unsigned char mask = 0xFF << alpha;
  randomness[k3-1] &= mask; /* set the last alpha bits as zero */
  unsigned char re0[k3+e0Len];
  memcpy(re0, randomness, k3);
  if (e0Len !=0) memcpy(&re0[k3], e0, e0Len);
  unsigned char h2re0[k1+k2];
  RLCE_MGF512(re0,k3+e0Len,h2re0,k1+k2);
  for (i=0; i<k1+k2; i++) encoded[i] ^= h2re0[i];
 
  memcpy(message, encoded, k1);
  unsigned char h1mre0[k2];
  unsigned char mre0[k1+k3+e0Len];
  memcpy(mre0, message, k1);
  memcpy(&mre0[k1],re0, k3+e0Len);
  RLCE_MGF512(mre0, k1+k3+e0Len,h1mre0, k2);
  for (i=k1;i<k1+k2;i++) if (h1mre0[i-k1]!=encoded[i]) return DEPADDINGFAIL;
  return 0;
}

void hex2char(char hex[], unsigned char hexChar[], int charlen){
  int i=0;
  char buf[8];
  for(i = 0; i < charlen; i++) {
    sprintf(buf, "0x%c%c", hex[2*i], hex[2*i+1]);
    hexChar[i] = strtol(buf, NULL, 0);
  }
}
