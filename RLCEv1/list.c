/* list.c
 * Yongge Wang 
 *
 * Code was written: May 30, 2017
 *
 * list.c implements list-decoding arithmetics
 * for RLCE scheme that is part of the package 
 * RLCE.tar - Random Linear Code Encryption Scheme
 *
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

typedef struct bipolynomial {
  int deg;
  int k;
  int Lx;
  int Ly;
  int maxX;
  int maxY;
  int xcol;
  int yrow;
  field_t ** coeff;
} * bipoly_t;


typedef struct RRtree {
  int deg;/* the exponent of the list poly corresponding to the node*/
  bipoly_t Q;
  int k; /* the k in the [n,k] MDS code */
  int L; /* the final list size or maximum y degree */
  int m; /* field size m */
  field_t a; /* the root corresponding to this node: or the coefficient for the list f */
  field_t *rootList;
  int rootRemaining;
  struct RRtree *parent;
  struct RRtree *kid; /* we reuse the kid link, 
		       * so only one kid. When a kid task is done, it is freed */
} * RRtree_t;

unsigned long long binomial(unsigned long long n, unsigned long long k) {
  if(k > n) return 0;
  if(k == 0) return 1;
  if(k > n/2) binomial(n,n-k);
  return n * binomial(n-1,k-1) / k;
}

int binomialMOD2(size_t n, size_t k) {
  /* https://en.wikipedia.org/wiki/Lucas%27s_theorem */
  if (k>n) return 0;
  int len=0, i;
  size_t tmp=1;
  while (n>tmp){
    tmp =(tmp<<1);
    len++;
  }
  for (i=0; i<=len; i++) {
    if ((0x00000001 & n) <(0x00000001 & k)) return 0;
    n = (n>>1);
    k = (k>>1);
  }
  return 1;
}


bipoly_t bipoly_init(int yrow, int xcol, int k) {
  bipoly_t p;
  p=(bipoly_t) malloc(sizeof (struct bipolynomial));
  int i;
  p->xcol = xcol;
  p->yrow = yrow;
  p->coeff = calloc(yrow, sizeof(int*));
  for (i=0; i<yrow; i++) p->coeff[i]= (field_t *) calloc(xcol, sizeof(field_t));
  p->deg = -1;
  p->k =k;
  p->Lx=0;
  p->Ly=0;
  p->maxX=0;
  p->maxY=0;
  return p;
}

void bipoly_free(bipoly_t p){
  int i;
  for (i=0; i<p->yrow; i++) free(p->coeff[i]);
  free(p->coeff);
  free(p);
  return;
}

bipoly_t bipoly_copy(bipoly_t p){ /* copy p to q */
  bipoly_t q= bipoly_init(p->yrow, p->xcol, p->k);
  int i;
  for (i=0; i<p->yrow; i++) {
    memcpy(q->coeff[i], p->coeff[i], (p->xcol)*sizeof(field_t));
  }
  q->deg = p->deg;
  q->Lx = p->Lx;
  q->Ly = p->Ly;
  q->maxX = p->maxX;
  q->maxY = p->maxY;
  return 0;
}

int bipoly_deg(bipoly_t p){ 
  int i,j,deg;
  int maxDeg = p->deg;
  p->deg = -1;
  p->maxX = 0;
  p->maxY = 0;
  int xbound;
  for (i=0; i<p->yrow; i++) {
    if (maxDeg>=0) {/* if maxDeg = -1, then we have no prediction on max deg */
      xbound= maxDeg - (p->k -1) * i;
      if (xbound <0) xbound =0;
    } else {
      xbound = p->xcol-1;
    }
    for (j=0; j<=xbound; j++) {
      if (p->coeff[i][j] !=0) {
	deg = j+(p->k-1)*i;
	if (p->deg < deg) {
	  p->deg = deg;
	  p->Lx = j;
	  p->Ly = i;
	} else if (p->deg == deg) {
	  if (i> p->Ly) {
	    p->Lx = j;
	    p->Ly = i;
	  }
	}
	if (p->maxX<j) p->maxX=j;
	if (p->maxY<i) p->maxY=i;
      }
    }
  }
  return 0;
}

void bipoly_print(bipoly_t p){
  int i, j;
  printf("bipoly: xcol=%d, yrow=%d, deg=%d, Lx=%d, Ly=%d, maxX=%d, maxY=%d\n",  p->xcol, p->yrow,p->deg, p->Lx,p->Ly,p->maxX, p->maxY);
  for (i=0; i<p->yrow; i++) {
    printf("%d-th row\n", i);
    for (j=0; j<p->xcol; j++) {
      printf("[%d]:%d ",j, p->coeff[i][j]);
    }
    printf("\n");
  }
  printf("\n");
}

int verifyZeroOrder( bipoly_t  Q, int n, int omega, field_t alpha[], field_t beta[], int m) {
  field_t delta;
  int yes=0;
  size_t tmp;
  int i,r,s,u,v, alphalog, betalog;
  for (i=0; i<n; i++) {
    alphalog=GF_log(alpha[i],m);
    for (r=0; r<omega; r++) {
      for (s=0; s<omega-r; s++) {
	delta=0;
	for (u=r; u<=Q->maxX; u++) {
	  for (v=s; v<=Q->maxY; v++) {
	    tmp=binomialMOD2(u,r) * binomialMOD2(v,s);
	    if (((tmp%2) == 1) && ((Q->coeff[v][u]) !=0)) {
	      if (beta[i] == 0) {
		if (v==s) {
		  delta^= GF_fexp(Q->coeff[v][u], (alphalog*(u-r) % (fieldSize(m)-1)),m);
		}
	      } else {
		betalog=GF_log(beta[i],m);
		delta^= GF_fexp(Q->coeff[v][u], (alphalog*(u-r)+betalog*(v-s)) % (fieldSize(m)-1),m);
	      }
	    }
	  }
	}
	if (delta !=0) {
	  yes = -1;
	}
      }
    }
  }
  return yes;
}

int verifyZeroOrderOne( bipoly_t  Q, int omega, field_t alpha, field_t beta, int m) {
  field_t delta;
  int yes=0;
  size_t tmp;
  int r,s,u,v, alphalog, betalog;
  alphalog=GF_log(alpha,m);
  for (r=0; r<omega; r++) {
    for (s=0; s<omega-r; s++) {
      delta=0;
      for (u=r; u<=Q->maxX; u++) {
	for (v=s; v<=Q->maxY; v++) {
	  tmp=binomialMOD2(u,r) * binomialMOD2(v,s);
	  if (((tmp%2) == 1) && ((Q->coeff[v][u]) !=0)) {
	    if (beta == 0) {
	      if (v==s) {
		delta^= GF_fexp(Q->coeff[v][u], (alphalog*(u-r) % (fieldSize(m)-1)),m);
	      }
	    } else {
	      betalog=GF_log(beta,m);
	      delta^= GF_fexp(Q->coeff[v][u], (alphalog*(u-r)+betalog*(v-s)) % (fieldSize(m)-1),m);
	    }
	  }
	}
      }
      if (delta !=0) {
	yes = -1;
      }
    }
  }
  return yes;
}

bipoly_t koetterInterpolation(int n, int k, int omega, int Lomega, field_t alpha[], field_t beta[], int m) {
  int i,j,r,s,u,v,jj;
  int maxXdeg = ((int) sqrt( (double)2*(k-1)*n*omega*(omega+1) /2))+1;
  bipoly_t  g[Lomega+1];
  bipoly_t  xgj0=bipoly_init(Lomega+1, 1+maxXdeg, k);
  for (j=0; j<=Lomega; j++) {
    g[j]= bipoly_init(Lomega+1, 1+maxXdeg, k);
    g[j]->deg = j*(k-1);
    g[j]->coeff[j][0]=1;
    g[j]->Lx=0;
    g[j]->Ly=j;
  }
  field_t delta[Lomega+1], deltaxj0;
  size_t tmp;
  int alphalog, j0;
  int betalog=0;
  size_t deltaj0log, deltajlog, deltaxj0log;
  int ubound;
  for (i=0; i<n; i++) {
    alphalog=GF_log(alpha[i],m);
    if (beta[i] !=0) {
      betalog=GF_log(beta[i],m);
    }
    for (r=0; r<omega; r++) {
      for (s=0; s<omega-r; s++) {
	j0=-1;
	for (j=0; j<=Lomega; j++){
	  delta[j]=0;
	  for (v=s; v<=Lomega; v++) {	    
	    ubound= g[j]->deg - (g[j]->k -1) * v;
	    if (ubound <r) ubound =r;
	    for (u=r; u<=ubound; u++) {
	    //for (u=r; u<=maxXdeg; u++) {	    
	      tmp=(binomialMOD2(u,r)%2) * (binomialMOD2(v,s)%2);
	      if (((tmp%2) == 1) && ((g[j]->coeff[v][u]) !=0)) {
		if (beta[i] == 0) {
		  if (v==s) {
		    delta[j] ^= GF_fexp(g[j]->coeff[v][u], (alphalog*(u-r) % (fieldSize(m)-1)),m);
		  }
		} else {
		  delta[j] ^= GF_fexp(g[j]->coeff[v][u], (alphalog*(u-r)+betalog*(v-s)) % (fieldSize(m)-1),m);
		}
	      }
	    }
	  }
	}
	for (j=0; j<=Lomega; j++) {  
	  if (delta[j] !=0) {
	    if (j0==-1) j0=j;
	    if (g[j0]->deg == g[j]->deg) {
	      if (g[j]->Ly < g[j0]->Ly) j0=j;
	    } else if (g[j]->deg< g[j0]->deg) j0=j;
	  }
	}
	if (j0 >=0) {
	  deltaj0log=GF_log(delta[j0],m);
	  for  (j=0; j<=Lomega; j++) {	    	    
	    if (j != j0) { // g_j = delta_{j0}g_j - delta_j g_{j0}
	      if (delta[j] !=0) {
		deltajlog=GF_log(delta[j],m);
		for (v=0; v<=Lomega; v++) {
		  ubound= g[j]->deg - (g[j]->k -1) * v;
		  if (ubound <0) ubound =0;
		  for (u=0; u<=ubound; u++) {
		    //for (u=0; u<=maxXdeg; u++) {		  
		    g[j]->coeff[v][u]= GF_fexp(g[j]->coeff[v][u], deltaj0log, m) ^
		      GF_fexp(g[j0]->coeff[v][u], deltajlog, m);
		  }
		}
		if (g[j]->maxX < g[j0]->maxX) g[j]->maxX = g[j0]->maxX;
		if (g[j]->deg < g[j0]->deg) g[j]->deg=g[j0]->deg;
		bipoly_deg(g[j]);
	      }	    
	    }
	  }

	  if (g[j0]->maxX > maxXdeg-1 ) { // g_{j0} = (x-alpha_i) g_{j0}
	    printf("debug: g[j0]->maxX > maxXdeg-1\n");
	  }
	  for (jj=0; jj<=Lomega; jj++) { // xgj0 = x g_{j0}
	    memset(xgj0->coeff[jj], 0, (1+maxXdeg)*sizeof(field_t));
	    memcpy(&(xgj0->coeff[jj][1]), g[j0]->coeff[jj], (1+g[j0]->maxX)*sizeof(field_t));
	  }
	  deltaxj0=0;
	  for (v=s; v<=Lomega; v++) {
	    ubound= g[j0]->deg - (g[j0]->k -1) * v +1;
	    if (ubound <0) ubound =0;
	    for (u=0; u<=ubound; u++) {
	      //for (u=r; u<=maxXdeg; u++) {
	      tmp=(binomialMOD2(u,r)%2) * (binomialMOD2(v,s)%2);
	      if (((tmp%2) == 1) && ((xgj0->coeff[v][u]) !=0)) {
		if (beta[i] == 0) {
		  if (v==s) {
		    deltaxj0 ^= GF_fexp(xgj0->coeff[v][u], (alphalog*(u-r) % (fieldSize(m)-1)),m);
		  }
		} else {
		  deltaxj0 ^= GF_fexp(xgj0->coeff[v][u], (alphalog*(u-r)+betalog*(v-s)) % (fieldSize(m)-1),m);
		}
	      }
	    }
	  }
	  if (deltaxj0 !=0) {
	    deltaxj0log=GF_log(deltaxj0, m);
	  }
	  for (v=0; v<=Lomega; v++) {
	    ubound= g[j0]->deg - (g[j0]->k -1) * v +1;
	    if (ubound <0) ubound =0;
	    for (u=0; u<=ubound; u++) {
	      //for (u=0; u<=(1+g[j0]->maxX); u++) { //g_{j0} = delta_j0 xg_{j0} - deltaxj0 g_{j0} 	    
	      if (deltaxj0 !=0) {
		g[j0]->coeff[v][u]=GF_fexp(xgj0->coeff[v][u],deltaj0log,m) ^ GF_fexp(g[j0]->coeff[v][u],deltaxj0log,m);
	      } else {
		g[j0]->coeff[v][u]=GF_fexp(xgj0->coeff[v][u],deltaj0log,m);
	      }
	    }
	  }
	  g[j0]->maxX = 1+g[j0]->maxX;
	  g[j0]->deg = 1+g[j0]->deg;
	  bipoly_deg(g[j0]);
	}
      }
    }
  }
  j0=0;
  for (j=0; j<=Lomega; j++) {
    if ((g[j0]->deg) > (g[j]->deg)) {
      j0=j;
    } else if ((g[j0]->deg) == (g[j]->deg)) {
      if (g[j0]->Ly > g[j]->Ly) j0=j;
    }
  }

  for (j=0; j<=Lomega; j++) if (j!=j0) bipoly_free(g[j]);
  bipoly_free(xgj0);
  /*
  int ret=verifyZeroOrder(g[j0],n,k,omega,alpha,beta,m);
  if (ret<0) {
    printf("g[%d] does not have zero of order %d\n", j0, omega);
    bipoly_print(g[j0]);
  } else {
    printf("g[%d] has zero of order %d\n", j0, omega);
  }
  */
  return g[j0];
}

RRtree_t RRtree_init(int L, int m){
  RRtree_t T;
  T= (RRtree_t) malloc(sizeof(struct RRtree));
  T->rootList = (field_t *) malloc(L*sizeof(field_t));
  T->rootRemaining = -1;
  T->L = L;
  T->m =m;
  T->kid = NULL;
  T->Q=NULL;
  return T;
}

void RRtree_free(RRtree_t T) {
  if ((T->rootList)!=NULL) free(T->rootList);
  if (T->kid!= NULL) RRtree_free(T->kid);
  if ((T->Q) !=NULL) bipoly_free(T->Q);
  if (T!= NULL) free(T);
  return;
}

static void copyF(RRtree_t T, poly_t f) {
  if (T==NULL) return;
  if (T->deg >f->size-1) return;
  if (T->deg >=0) f->coeff[T->deg]=T->a;
  copyF(T->parent, f);
  return;
}

static bipoly_t xxyPalpha(bipoly_t Q, field_t alpha, int m) {
  /* returns Q(x, xy+alpha) */
  bipoly_t newQ=NULL;
  if (alpha==0) return NULL;
  size_t tmp;
  int alphalog=GF_log(alpha,m);
  newQ=bipoly_init(1+Q->maxY, 1+(Q->maxY)+(Q->maxX),Q->k);
  int r,s,j;
  for (r=0; r<= Q->maxX; r++) {
    for (s=0; s<=Q->maxY; s++) {
      newQ->coeff[s][r+s]=0;
      for (j=s; j<=Q->maxY; j++) {
	tmp=binomialMOD2(j,s);
	if((tmp%2)==1) {
	  newQ->coeff[s][r+s] ^= GF_fexp(Q->coeff[j][r], (alphalog * (j-s)) % (fieldSize(m)-1), m);
	}
      }
      newQ->deg = -1;
      bipoly_deg(newQ);
    }
  }
  return newQ;
}

static int DFS(RRtree_t T, poly_t *f){
  RRtree_t tempT=NULL;
  int numF=0;
  int ret=0;
  if (T==NULL) return 0;
  int i,j, xd, test;
  int done = 1;
  poly_t Qy;
  field_t eLocation[2*(T->L)];
  bipoly_t QxxyPalpha = NULL;
  memset(eLocation, 0, (2*(T->L))*sizeof(field_t));
  for (j=0; j< (T->Q)->maxX; j++) {
    if (((T->Q)->coeff[0][j]) != 0) done = 0;
  }
  if (done ==1) {
    f[0]->deg = T->deg;
    copyF(T,f[0]);
    //poly_print(f[0]);
    numF++;
    tempT = T->parent;
    ret=DFS(tempT, f+1);
    if (ret > 0) numF+=ret;
  } else {
    if (T->deg < ((T->k)-1)) {   
      if (T->rootRemaining == -1) {
	Qy=poly_init(1+(T->Q)->maxY);
	for (i=0; i<= (T->Q)->maxY; i++) {
	  Qy->coeff[i]= (T->Q)->coeff[i][0];
	  poly_deg(Qy);
	}
	memset(T->rootList, 0, (T->L) *sizeof(field_t));
	if (Qy->deg>4) {
	  T->rootRemaining=find_roots_Chien(Qy,T->rootList, eLocation, T->m);
	} else if (Qy->deg>0) {
	  T->rootRemaining=find_roots_BTA(Qy,T->rootList, T->m);	  
	} else {
	  T->rootRemaining=0;
	}
	poly_free(Qy);
      }
      if (T->rootRemaining == 0) return DFS(T->parent, f);
      if (T->rootRemaining > 0) {
	if (T->kid == NULL) T->kid =RRtree_init(T->L, T->m);
	(T->kid)->parent = T;
	(T->kid)->deg = 1+T->deg;
	(T->kid)->k=T->k;
	(T->kid)->L=T->L;
	(T->kid)->m=T->m;
	(T->kid)->a= T->rootList[0];
	(T->kid)->rootRemaining=-1;
	if ((T->kid)->a != 0) {
	  QxxyPalpha = xxyPalpha(T->Q, (T->kid)->a, T->m);
	} else {
	  QxxyPalpha = bipoly_copy(T->Q);
	}
	xd=0;
	test=1;
	while (test>0) {
	  for (i=0; i<=QxxyPalpha->maxY; i++) {
	    if (QxxyPalpha->coeff[i][xd] !=0) test = 0;
	  }
	  if (test>0) xd++;
	}
	if (((T->kid)->Q) != NULL) bipoly_free((T->kid)->Q);
	(T->kid)->Q=bipoly_init(1+QxxyPalpha->maxY, 1+(QxxyPalpha->maxX)-xd,T->k);
	for (i=0; i<= QxxyPalpha->maxY; i++) {
	  memcpy(((T->kid)->Q)->coeff[i], &(QxxyPalpha->coeff[i][xd]), (1+(QxxyPalpha->maxX)-xd)*sizeof(field_t));
	}
	((T->kid)->Q)->maxX = (((T->kid)->Q)->maxX) -xd;
	bipoly_deg((T->kid)->Q);
	bipoly_free(QxxyPalpha);
	(T->rootRemaining)--;
	for (i=0; i<T->rootRemaining; i++) T->rootList[i]=T->rootList[i+1];
	return DFS(T->kid,f);
      }
    } else {
      return DFS(T->parent, f);
    }
  }
  return numF;
}

int RRfactorization(bipoly_t Q, poly_t *f, int m) {
  int ret;
  RRtree_t T =RRtree_init(Q->yrow,m);
  T->parent=NULL;
  T->kid=NULL;
  T->deg=-1;
  T->a=0;
  T->k =Q->k;
  T->rootRemaining=-1;
  T->Q = Q;
  ret =DFS(T, f);
  /*
  printf("found %d f-polynomial\n", ret); 
  int i;
  for (i=0;i<ret; i++) {
    poly_deg(f[i]);
    poly_print(f[i]);
  }
  */
  if (T !=NULL) RRtree_free(T);
  return ret;
}

poly_t list_decode(field_t beta[], int n, int k, int t, int omega, int Lomega,
		   field_t eLocation[], int m){ /*eLocation[n-k]*/
  int ret, i, j;
  int numF=0;
  poly_t decodedWord=poly_init(n);
  field_t alpha[n];
  int yes=0;
  int zeroLen = (1u<< m) -1 - n;
  for (i=0; i<n; i++) alpha[i]=GF_exp(i,m);
  bipoly_t Q=koetterInterpolation(n, k, omega, Lomega, alpha, beta, m);
  printf("Interpolation is done\n");
  RRtree_t T=RRtree_init(Lomega,  m);
  poly_t *f;
  f = (poly_t *)malloc(Lomega*sizeof(poly_t));
  for (i=0; i<Lomega; i++)  f[i]=poly_init(k);
  numF= RRfactorization(Q,f,m);
  printf("RRfactorization is done with %d-size list\n", numF);
  if (numF>0) {
    matrix_t F=matrix_init(numF,k+1);
    for (i=0; i<numF; i++) {
      memcpy(F->data[i],f[i]->coeff, k*sizeof(field_t));
      F->data[i][k]=1;
    }
    matrix_t G=matrix_init(k+1, n);
    for (i=0; i<k; i++) {
      for (j=0; j<n;j++) {
	G->data[i][j]=GF_exp((i*j)%(fieldSize(m)-1),m);
      }
    }
    memcpy(G->data[k], beta, n*sizeof(field_t));
    matrix_t mat=matrix_init(numF, n);
    ret=matrix_mul(F, G, mat, m);
    if (ret<0) return NULL;
    field_t ctr[numF];
    int tmp=0;
    memset(ctr,0,numF*sizeof(field_t));
    for (i=0; i<numF; i++) {
      for (j=0;j<n;j++)	if (mat->data[i][j] !=0) ctr[i]++;
      if (ctr[i]<=t) {
	yes=1;
	GF_addvec(beta,mat->data[i], decodedWord->coeff,n);
	tmp =0;
	memset(eLocation, 0, (n-k)*sizeof(field_t));
	for (j=0;j<n;j++) {
	  if (mat->data[i][j] !=0) {
	    eLocation[tmp]=j+zeroLen;
	    tmp++;
	  }
	}
      }
      printf("t=%d, ctr[%d]=%d",t,i,ctr[i]);
    }
    printf("\n");
    matrix_free(mat);
    matrix_free(G);
    matrix_free(F);
  } 
  for (i=0; i<Lomega; i++) poly_free(f[i]);
  free(f);
  if (T!=NULL) RRtree_free(T);
  
  if ((yes==0) || (numF==0)) {
    poly_free(decodedWord);
    printf("-debug: list decode failed, yes=%d, numF=%d\n", yes, numF);
    return NULL;
  }
  poly_deg(decodedWord);
  return decodedWord;
}
