/* fieldPoly.c
 * Yongge Wang 
 *
 * Code was written: November 4, 2016-
 *
 * fieldPoly.c implements polynomial arithmetics 
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

poly_t poly_init(int n) {
  poly_t p;
  p = (poly_t) malloc(sizeof (struct polynomial));
  p->deg = -1;
  p->size = n;
  p->coeff = (field_t *) calloc(n, sizeof (field_t));
  return p;
}

void poly_clear(poly_t p) {
  memset(&(p->coeff[1+p->deg]), 0, (p->size -1-(p->deg))*sizeof(field_t));
}

void poly_zero(poly_t p) {
  p->deg = -1;
  memset(p->coeff, 0, (p->size)*sizeof(field_t));
}

void poly_copy(poly_t p, poly_t q) {
  memset(q->coeff, 0, (q->size)*sizeof(field_t));
  q->deg = p->deg;
  memcpy(q->coeff, p->coeff, (p->size) * sizeof (field_t));
}


void poly_free(poly_t p) {
  free(p->coeff);
  p->coeff=NULL;
  free(p);
  p=NULL;
}

field_t poly_eval(poly_t p, field_t a, int m) {
  field_t result;
  int i;
  int d = p->deg;
  if (d<0) return 0;
  if ((d==0)||(a==0)) return p->coeff[0];
  result=p->coeff[d];
  for (i=d-1; i>=0; i--) {
    if (result != field_zero()) {
      result = GF_mul(result, a, m) ^ p->coeff[i];
    } else {
      result = p->coeff[i];
    }
  }
  return result; 
}



field_t poly_evalopt(poly_t p, field_t a, int m) {
  field_t result=0;
  int i;
  int d = p->deg;
  if (d<0) return 0;
  if ((d==0)||(a==0)) return p->coeff[0];
  field_t *dest;
  dest = calloc(d+1, sizeof(field_t));
  GF_mulexpvec2(a, p->coeff,  dest, d+1, m);
  for (i=0; i<d+1; i++) result ^= dest[i];
  free(dest);
  return result; 
}


int poly_deg(poly_t p) {
  int i;
  for (i=(p->size - 1); i>=0; i--) {
    if (p->coeff[i] != field_zero()) {
      p->deg = i;
      return i;
    }
  }
  p->deg= -1;
  return -1;
}

void poly_print(poly_t p) {
  int i;
  printf("poly size: %d, degree: %d\n", p->size, p->deg);
  for (i=0; i<=p->deg; i++) {
    printf("0x%04x ", p->coeff[i]);
  }
  printf("\n");
}


int poly_mul_old(poly_t p, poly_t q, poly_t r, int m) {
  /* multiplication is done over field GF(2^m), r contains result */
  int d1, d2, d, i, j;
  field_t tmp;
  d1=p->deg;
  d2=q->deg;
  d=d1+d2;
  if (d >= r->size) return POLYMULTERRR;
  poly_zero(r);
  for (i = 0; i <= d1; ++i) {
    if (p->coeff[i] !=field_zero()) {
      for (j = 0; j <= d2; ++j) {
	tmp=GF_mul(q->coeff[j], p->coeff[i], m);
	r->coeff[i+j] ^= tmp;
      }
    }
  }
  poly_deg(r);
  return 0;
}

int poly_mul_karatsuba(poly_t f, poly_t g, poly_t r, int m) {  
  int d= f->deg + g->deg; 
  if (d >= r->size) return POLYMULTERRR;
  int maxdeg =0;
  int mindeg=0;
  int middeg=0;
  if ((f->deg) > (g->deg)) {
    maxdeg = f->deg;
    mindeg = g->deg;
  } else {
    maxdeg = g->deg;
    mindeg = f->deg;
  }
  if (mindeg <35) return poly_mul_standard(f,g, r, m);
  middeg = 1+maxdeg/2;

  poly_t f1 = poly_init(middeg);
  poly_t f2 = poly_init(middeg);
  poly_t g1 = poly_init(middeg);
  poly_t g2 = poly_init(middeg);
  poly_t h1 = poly_init(2*middeg);
  poly_t h2 = poly_init(2*middeg);
  poly_t h3 = poly_init(2*middeg);
  if ((1+f->deg - middeg)>0)
    memcpy(f1->coeff, &(f->coeff[middeg]), (1+f->deg - middeg)*sizeof(field_t));  
  memcpy(f2->coeff, f->coeff, middeg *sizeof(field_t));  
  if ((1+g->deg - middeg)>0)
    memcpy(g1->coeff, &(g->coeff[middeg]), (1+g->deg - middeg)*sizeof(field_t));
  memcpy(g2->coeff, g->coeff, middeg *sizeof(field_t));
  poly_deg(f1);
  poly_deg(g1);

  if ((f1->deg >= 0) && (g1->deg >= 0)) {
    poly_mul_karatsuba(f1, g1, h1, m);
    poly_deg(h1);
    memcpy(&(r->coeff[2*middeg]), h1->coeff, (h1->deg+1)*sizeof(field_t));
  }
  poly_deg(f2);
  poly_deg(g2);
  if ((f2->deg>=0) && (g2->deg >=0)) {
    poly_mul_karatsuba(f2, g2, h3, m);
    memcpy(r->coeff, h3->coeff, (1+h3->deg)*sizeof(field_t));
  }

  GF_addvec(f1->coeff, f2->coeff, NULL,f1->size);
  GF_addvec(g1->coeff, g2->coeff, NULL,g1->size);
  poly_deg(f2);
  poly_deg(g2);
  if ((f2->deg>=0) && (g2->deg >=0)) {
    poly_mul_karatsuba(f2, g2, h2, m);
  }
  GF_addvec(h1->coeff, h2->coeff,NULL, h1->size);
  GF_addvec(h3->coeff, h2->coeff,NULL, h3->size);

  poly_deg(h2);
  GF_addvec(h2->coeff, &(r->coeff[middeg]),NULL, 1+h2->deg);
  
  poly_deg(r);  
  poly_free(f1);
  poly_free(f2);
  poly_free(g1);
  poly_free(g2);
  poly_free(h1);
  poly_free(h2);
  poly_free(h3);
  return 0;
}

int poly_mul_FFT(poly_t f, poly_t g, poly_t r, int m) {
  int deg =f->deg + g->deg;
  if (deg >= r->size) return POLYMULTERRR;
  if (((f->deg) < 30) ||((g->deg) < 30)) poly_mul_standard(f,g,r,m);
  int i, ret, d=1;
  matrix_t smat=matrix_init(m-1,m); // smat[i][j]=GF_log(s[i]->coeff[2^j],m);  
  int precomputation = 1;
  field_t alphai;
  if (precomputation != 1) {
    poly_t s[m];
    poly_t polytemp=poly_init(2+fieldSize(m));
    for (i=0; i<m;i++) s[i]=poly_init(2+fieldSize(m));
    s[0]->deg=2;
    s[0]->coeff[1]=1;
    s[0]->coeff[2]=1;
    for (i=1; i<m-1;i++) {
      alphai=GF_exp(i,m);
      poly_copy(s[i-1], polytemp);
      polytemp->coeff[0] ^=poly_evalopt(s[i-1],alphai,m);
      poly_mul_standard(s[i-1], polytemp, s[i], m);
    }
    for (i=1; i<m-1;i++) {
      for (int j=0; j<=i+1; j++) {
	printf("smat->data[%d][%d]=0x%.4x;\n", i, j,s[i]->coeff[1<<j]);
	smat->data[i][j]=GF_log(s[i]->coeff[1<<j],m);
	//printf("smat->data[%d][%d]=0x%.4x;\n", i, j,smat->data[i][j]);
      }
    }
    poly_free(polytemp);
    for (i=0; i<m;i++) poly_free(s[i]);
  }
    
  if (m==10) {
    smat->data[1][0]=0x004e;
    smat->data[1][1]=0x03bc;
    smat->data[1][2]=0x0000;
    smat->data[2][0]=0x00f5;
    smat->data[2][1]=0x004c;
    smat->data[2][2]=0x036c;
    smat->data[3][0]=0x0241;
    smat->data[3][1]=0x003c;
    smat->data[3][2]=0x032c;
    smat->data[3][3]=0x017b;
    smat->data[3][4]=0x0000;
    smat->data[4][0]=0x0379;
    smat->data[4][1]=0x032c;
    smat->data[4][2]=0x0364;
    smat->data[4][3]=0x0153;
    smat->data[4][4]=0x034e;
    smat->data[5][0]=0x00e2;
    smat->data[5][1]=0x028f;
    smat->data[5][2]=0x0238;
    smat->data[5][3]=0x02b5;
    smat->data[5][4]=0x03f0;
    smat->data[5][5]=0x038f;
    smat->data[6][0]=0x039c;
    smat->data[6][1]=0x0076;
    smat->data[6][2]=0x0014;
    smat->data[6][3]=0x0372;
    smat->data[6][4]=0x01cb;
    smat->data[6][5]=0x03e9;
    smat->data[6][6]=0x0235;
    smat->data[7][0]=0x0012;
    smat->data[7][1]=0x01ee;
    smat->data[7][2]=0x03e3;
    smat->data[7][3]=0x032c;
    smat->data[7][4]=0x0348;
    smat->data[7][5]=0x03a1;
    smat->data[7][6]=0x02ec;
    smat->data[7][7]=0x006e;
    smat->data[8][0]=0x03fe;
    smat->data[8][1]=0x03fc;
    smat->data[8][2]=0x03f8;
    smat->data[8][3]=0x03f0;
    smat->data[8][4]=0x03e0;
    smat->data[8][5]=0x03c0;
    smat->data[8][6]=0x0380;
    smat->data[8][7]=0x0300;
    smat->data[8][8]=0x0200;   
  }
  if (m==11) {
    smat->data[1][0]=0x0406;
    smat->data[1][1]=0x05d8;
    smat->data[2][0]=0x05f2;
    smat->data[2][1]=0x07b4;
    smat->data[2][2]=0x0580;
    smat->data[3][0]=0x0579;
    smat->data[3][1]=0x003e;
    smat->data[3][2]=0x05e9;
    smat->data[3][3]=0x07b1;
    smat->data[4][0]=0x04e6;
    smat->data[4][1]=0x0749;
    smat->data[4][2]=0x06f9;
    smat->data[4][3]=0x0082;
    smat->data[4][4]=0x0761;
    smat->data[5][0]=0x041d;
    smat->data[5][1]=0x0509;
    smat->data[5][2]=0x03f7;
    smat->data[5][3]=0x0188;
    smat->data[5][4]=0x07e7;
    smat->data[5][5]=0x05a9;
    smat->data[6][0]=0x01ce;
    smat->data[6][1]=0x03ba;
    smat->data[6][2]=0x07b9;
    smat->data[6][3]=0x03c6;
    smat->data[6][4]=0x0237;
    smat->data[6][5]=0x06f8;
    smat->data[6][6]=0x0396;
    smat->data[7][0]=0x04b5;
    smat->data[7][1]=0x060b;
    smat->data[7][2]=0x040b;
    smat->data[7][3]=0x023b;
    smat->data[7][4]=0x05a3;
    smat->data[7][5]=0x0287;
    smat->data[7][6]=0x0524;
    smat->data[7][7]=0x061c;
    smat->data[8][0]=0x00fa;
    smat->data[8][1]=0x03dc;
    smat->data[8][2]=0x00b0;
    smat->data[8][3]=0x02e0;
    smat->data[8][4]=0x028f;
    smat->data[8][5]=0x0162;
    smat->data[8][6]=0x0443;
    smat->data[8][7]=0x013b;
    smat->data[8][8]=0x043b;
    smat->data[9][0]=0x07fa;
    smat->data[9][1]=0x07f0;
    smat->data[9][2]=0x07dc;
    smat->data[9][3]=0x07b4;
    smat->data[9][4]=0x0764;
    smat->data[9][5]=0x06c4;
    smat->data[9][6]=0x0584;
    smat->data[9][7]=0x0304;
    smat->data[9][8]=0x0603;
    smat->data[9][9]=0x0402;
  }
  
  while ((1<<d)<deg) d++;
  vector_t base, output1,output2,output3;
  base=vec_init(d);
  for (i=0; i<d;i++) base->data[i]=GF_exp(i,m);
  output1 = vec_init(1<<d);
  ret = FFT(f,output1,base,m);
  if (ret<0) return ret;
  output2 = vec_init(1<<d);
  ret = FFT(g,output2,base,m);
  if (ret<0) return ret;
  output3 = vec_init(1<<d);
  for (i=0;i<output3->size;i++) output3->data[i]=GF_mul(output1->data[i],output2->data[i],m);
  poly_zero(r);
  ret=GGIFFT(d-1,base,0,output3,r,smat,m);  
  vector_free(base);
  vector_free(output1);
  vector_free(output2);
  vector_free(output3);
  return ret;
}

int poly_mul_FFT_fullField(poly_t f, poly_t g, poly_t r, int m) {  
  if ((f->deg + g->deg) >= r->size) return POLYMULTERRR;
  if (((f->deg) < 100) ||((g->deg) < 100)) poly_mul_standard(f,g, r, m);
  int i, ret;
  vector_t base,output1,output2,output3;
  base=vec_init(m);
  for (i=0; i<m;i++) base->data[i]=GF_exp(i,m);
  output1 = vec_init(fieldSize(m));
  ret = FFT(f,output1,base,m);
  if (ret<0) return ret;
  output2 = vec_init(fieldSize(m));
  ret = FFT(g,output2,base,m);
  if (ret<0) return ret;
  output3 = vec_init(fieldSize(m));
  for (i=0;i<fieldSize(m);i++) output3->data[i]=GF_mul(output1->data[i],output2->data[i],m);
  poly_t R;
  R=poly_init(fieldSize(m));
  R->coeff[0]=output3->data[1];
  for (i=1;i<fieldSize(m)-1;i++) R->coeff[fieldSize(m)-1-i]=output3->data[GF_exp(i,m)];
  poly_deg(R);
  ret = FFT(R,output3,base,m);
  if (ret<0) return ret;
  poly_zero(r);
  for (i=0;i<=(f->deg)+(g->deg);i++) r->coeff[i]=output3->data[GF_exp(i,m)];
  poly_deg(r);

  vector_free(output1);
  vector_free(base);
  vector_free(output2);
  vector_free(output3);
  poly_free(R);
  return 0;
}

int poly_mul_standard(poly_t p, poly_t q, poly_t r, int m) {
  /* multiplication is done over field GF(2^m), r contains result */
  int d1, d2,i;
  d1=p->deg;
  d2=q->deg;
  if (p->deg + q->deg >=r->size) return POLYMULTERRR;
  poly_zero(r);
  field_t *tmp;
  tmp = calloc(d2+1, sizeof(field_t));
  for (i=0; i<=d1; i++) {    
    if (p->coeff[i] !=field_zero()){
      GF_mulvec(p->coeff[i], q->coeff, tmp, d2+1, m);
      GF_addvec(tmp, &r->coeff[i],NULL, d2+1);
    }
  }
  poly_deg(r);
  free(tmp);
  return 0;
}


int poly_add(poly_t p, poly_t q, poly_t r) {
  poly_zero(r);
  int i=1;
  int d1=p->deg;
  int d2=q->deg;
  int d=d1;
  if (d2<d) {
    d=d2;
    i=2;
  }
  GF_addvec(p->coeff,q->coeff, r->coeff, d+1);
  if (i==1) {
    memcpy(&(r->coeff[d+1]), &(q->coeff[d+1]), (d2-d)*sizeof(field_t));
  } else {
    memcpy(&(r->coeff[d+1]), &(p->coeff[d+1]), (d1-d)*sizeof(field_t));
  }
  poly_deg(r);
  return 0;
}

int poly_div(poly_t p, poly_t d, poly_t q, poly_t r, int m) {
  /* input: p, d; output: p(x)=d(x)q(x)+r(x) */
  poly_copy(p,r);
  poly_zero(q);
  int dDegree = poly_deg(d);
  int rDegree = poly_deg(r);
  int j;
  if(dDegree<0) return 0;
  field_t *tmp;
  tmp=calloc(1+dDegree, sizeof(field_t));
  field_t bb;
  j = rDegree-dDegree;
  q->deg = j>0?j:0;
  for(; j>=0; j--) {
    if (r->coeff[j+dDegree] !=0) {
      bb=GF_div(r->coeff[j+dDegree],d->coeff[dDegree],m);
      GF_mulvec(bb,d->coeff,tmp,dDegree+1,  m);
      GF_addvec(tmp, &(r->coeff[j]),NULL,1+dDegree);
      q->coeff[j] = bb;
    }
  }
  free(tmp);
  poly_deg(r);
  return 0;
}

int poly_quotient (poly_t p, poly_t d, poly_t q, int m) {
  /* input: p, d; output: p(x)=d(x)q(x) */
  poly_t r=poly_init(p->size);
  poly_deg(p);
  poly_deg(d);
  
  poly_div(p, d, q, r, m);
  if (r->deg == -1) {
    poly_free(r);
    return 0;
  } else {
    poly_free(r);
    return POLYNOTFULLDIV;
  }
}

int poly_gcd(poly_t p1, poly_t p2, poly_t gcd, int m) {
  if (poly_deg(p2) == -1) {
    poly_copy(p1, gcd);
    return 0;
  } else {
    poly_t tmpQ=poly_init(p1->size);
    poly_t tmpR=poly_init(p1->size);
    poly_div(p1, p2, tmpQ, tmpR, m);
    poly_copy(tmpR, p1);
    poly_free(tmpQ);
    poly_free(tmpR);
    poly_gcd(p2, p1, gcd, m);
  }
  return 0;
}

int find_roots_exhaustive (poly_t p, field_t roots[], int m) {
  int i, j=0;
  field_t result;
  for (i=0; i<= fieldSize(m)-1; i++) {
    result = poly_evalopt(p,i,m);
    if (result == field_zero()) {
      roots[j]=i;
      j++;
    }
  }
  return j;
}

int find_roots_Chien (poly_t lambda, field_t lambdaRoots[], field_t eLocation[], int m) {  
  int i, j;
  matrix_t mat=matrix_init(1+lambda->deg, fieldSize(m));
  for (j=0;j<fieldSize(m);j++) mat->data[0][j]=lambda->coeff[0];  
  for (i=1;i<mat->numR;i++) mat->data[i][0]=lambda->coeff[i];
  for (i=1;i<mat->numR;i++) {
    GF_logmulvec(i,mat->data[i], &(mat->data[i][1]), mat->numC-1, m);
    GF_addvec(mat->data[i-1], mat->data[i],NULL, fieldSize(m));
  }
  i=0;
  for (j=0;j<fieldSize(m); j++) {
    if ((mat->data[lambda->deg][j])==field_zero()) {
      lambdaRoots[i]=j;
      if (j==0) {
	eLocation[i]=0;
      } else {
	eLocation[i]=fieldSize(m)-1-j;
      }
      i++;
    }
  }
  GF_expvec(lambdaRoots,i, m);
  matrix_free(mat);
  return i;
}

int find_roots_FFT(poly_t f, field_t roots[], int m) {
  int ret, i, j=0;
  vector_t base;
  base=vec_init(m);
  for (i=0; i<m;i++) base->data[i]=i;
  GF_expvec(base->data,m, m);
  vector_t output;
  output = vec_init(fieldSize(m));
  ret=FFT(f,output,base,m);
  if (ret<0) return ret;
  for (i=1; i<output->size; i++) { 
    if (output->data[i]==0) {
      roots[j]=i;
      j++;
    }
  }
  vector_free(base);
  vector_free(output);
  return j;
}

int find_roots (poly_t p, field_t roots[], field_t eLocation[], int m) {
  int numRoots;
  if (p->deg <=4) {
    numRoots = find_roots_BTA(p,roots,m);
  } else {
    if (ROOTFINDING==0) return numRoots= find_roots_Chien(p, roots, eLocation, m);
    if (ROOTFINDING==1) numRoots= find_roots_exhaustive(p, roots, m);
    if (ROOTFINDING==2) numRoots = find_roots_BTA(p,roots,m);
    if (ROOTFINDING==3) numRoots= find_roots_FFT(p,roots, m);
  }
  field_t* rootsLog=calloc(numRoots, sizeof(field_t));
  rootsLocation(roots, numRoots, eLocation, rootsLog,m);
  free(rootsLog);
  return numRoots;
}

int poly_mul(poly_t p, poly_t q, poly_t r, int m) {
  int mindeg=0;
  if ((p->deg) > (q->deg)) {
    mindeg = q->deg;
  } else {
    mindeg = p->deg;
  }
  if (mindeg <115) return poly_mul_standard(p, q, r, m);  
  if (KARATSUBA ==0) return poly_mul_standard(p, q, r, m);
  if (KARATSUBA ==1) return poly_mul_karatsuba(p, q, r, m);
  if (KARATSUBA ==2) return poly_mul_FFT(p, q, r, m);
  return 0;
}
