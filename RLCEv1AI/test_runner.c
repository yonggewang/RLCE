#include "rlce.h"
#include <stdio.h>
#include <stdlib.h>

// External declarations from test.c (assuming they are not static)
extern void test_roots_per(void);
extern void test_polymul_per(void);
extern void test_matper_per(int num);
extern void test_DRBBG_per(void);

int main() {
  printf("Running Baseline Benchmarks...\n");

  printf("\n--- Roots Performance ---\n");
  test_roots_per();

  printf("\n--- Poly Mul Performance ---\n");
  test_polymul_per();

  // printf("\n--- Matrix Performance ---\n");
  // test_matper_per(100);

  return 0;
}
