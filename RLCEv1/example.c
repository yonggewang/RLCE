/* RLCE example.c */
#include "rlce.h"
#include "api.h"
void printCPUinfo(void);
int testRRfactorization (void);
int testFE2B2FE (int scheme, int padding);
int testRLCEkeyIO(int scheme, int padding);
int testRLCE(int nPad, int nK, int nE, int nD,int t1,int sch,int pad);
int testSHA(void);
int testReedSolomon(void);
int preComputelogExpTable(void);
int testHashDRBG(void);
int testAES(void);
int testCTRDRBG(void);
void testReedSolomonper(void);
void test_matper_per(int);
void test_roots_per(void);
void test_polymul_per(void);
void test_DRBBG_per(void);
int test_poly_mul(int m);
int testTaylor(int size);
void testpolyEvalPer(void);
void tRAM(int testRAM,int scheme,int padding);
int main (int argc, char *argv[]) {
  int ret, numK=1, numE=1, numD=1;
  int scheme = 5; /* or CRYPTO_SCHEME;*/
  int padding = 1; /* or CRYPTO_PADDING; */
  int nPad =2; /* number of padding to test: 1, 2, 3, 4 */

  int testRAM = 0; /* 1: key setup; 2: encryption; 3: decryption */
  int prelogexptable = 0;
  int tFE2B2FE = 0;
  int tRLCEkeyIO = 0; /* test read/write sk/pk */
  int t1RLCE = 0; /* 1: test function; 2: test performance */
  int tRLCE = 0; /* 1: test function; 2: test performance */
  int tSHA = 0; /* test whether SHA works */
  int tReedSolomon = 0; /* test whether Reed-Somolon encoding-decoding works */
  int testhashDRBG = 0; /* Hash_DRBG testing using (DRBGVS)*/
  int testctrDRBG = 0; /* CTR_DRBG testing using (DRBGVS)*/
  int testAESfunc = 0; /* test AES */
  int vTaylor = 0; /* verify that Taylor series is constructed correctly*/
  int vPolymul =0; /* verify that poly multiplicaiotn works */
  int tDRBGper = 0;/* compare the performance of using AES and SHA */
  int tRootper =0; /* compare the performance of findings roots */
  int tpolyMulper =0; /* compare the performance of poly multiplication */
  int tpolyMatper =1; /* compare the performance of matrix mul and inverse */
  int tRSper=0; /* test the performance for RS decoding */
  int tPolEva=0; /* test the performance for poly evaluation */
  int tlistRLCE=0; /* test list decoding RLCE */
  int tCPUinfo=0; /* test CPU info */  
  if ((tRLCE>1)||(t1RLCE>1)) {
    numK=10;
    numE=1000;
    numD=1000;
  }
  if (testRAM>0) tRAM(testRAM,scheme,padding);
  if (tPolEva==1) testpolyEvalPer();  
  if (tRSper==1) testReedSolomonper();
  if (tpolyMatper== 1) test_matper_per(1);
  if (tRootper== 1) test_roots_per();
  if (tpolyMulper==1) test_polymul_per();  
  if (tDRBGper== 1) test_DRBBG_per();  
  if (vPolymul== 1) ret=test_poly_mul(10);
  if (testAESfunc==1) ret = testAES();
  if (vTaylor == 1) ret= testTaylor(50);
  if (testAESfunc ==1) ret = testAES();
  if (testhashDRBG==1) ret=testHashDRBG();
  if (testctrDRBG==1) ret=testCTRDRBG();
  if (tReedSolomon==1) ret=testReedSolomon();
  if (tSHA==1) ret=testSHA();
  if (tRLCEkeyIO==1) ret=testRLCEkeyIO(scheme,padding);
  if (prelogexptable==1) preComputelogExpTable();
  if (tFE2B2FE==1) ret=testFE2B2FE (scheme,padding);
  if (tlistRLCE==1) for (int i=7; i<15;i++) ret=testRLCE(1,1,1,1,1,i,0);
  if ((tRLCE>0)||(t1RLCE>0)) ret=testRLCE(nPad,numK,numE,numD,t1RLCE,scheme,padding);
  if (ret==0) printf("test succeeds!\n");
  if (ret!=0) printf("test failed with code (if testRS, number of errors): %d\n", ret);
  if (tCPUinfo==1) printCPUinfo();
  exit(0);
}

