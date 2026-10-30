/* Rank of a dense matrix over GF(2^m) (m <= 12), entries in polynomial-basis integer
 * representation, read from a file: int64 rows, cols; then rows*cols uint16.
 * usage: rank2m file m poly prim        (poly, prim as integers, e.g. 1135 2 for galois GF(2^10))
 * Gaussian elimination with log/antilog tables; OpenMP over rows.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <omp.h>

static int Q, Q1;                      /* field size, Q-1 */
static uint16_t *EXP, *LOG;            /* EXP[0..2Q-2], LOG[1..Q-1] */

static void build_tables(int m, unsigned poly, unsigned prim) {
    Q = 1 << m; Q1 = Q - 1;
    EXP = malloc(2 * Q * sizeof *EXP); LOG = malloc(Q * sizeof *LOG);
    unsigned x = 1;
    for (int i = 0; i < Q1; ++i) {
        EXP[i] = (uint16_t)x; LOG[x] = (uint16_t)i;
        /* x *= prim  (carry-less multiply mod poly) */
        unsigned a = x, b = prim, r = 0;
        while (b) { if (b & 1) r ^= a; b >>= 1; a <<= 1; if (a & Q) a ^= poly; }
        x = r;
    }
    if (x != 1) { fprintf(stderr, "prim is not primitive for this poly\n"); exit(2); }
    for (int i = Q1; i < 2 * Q; ++i) EXP[i] = EXP[i - Q1];
    LOG[0] = 0;
}

static long rank_gf2m(uint16_t *M, long r, long c) {
    uint16_t **row = malloc(r * sizeof *row);
    for (long i = 0; i < r; ++i) row[i] = M + (size_t)i * c;
    long rank = 0;
    int *lp = malloc(c * sizeof *lp);
    for (long col = 0; col < c && rank < r; ++col) {
        long piv = -1;
        for (long i = rank; i < r; ++i) if (row[i][col]) { piv = i; break; }
        if (piv < 0) continue;
        if (piv != rank) { uint16_t *t = row[piv]; row[piv] = row[rank]; row[rank] = t; }
        uint16_t *p = row[rank];
        /* normalise pivot row so p[col] = 1 */
        int inv = (Q1 - LOG[p[col]]) % Q1;
        for (long j = col; j < c; ++j) if (p[j]) p[j] = EXP[LOG[p[j]] + inv];
        for (long j = col; j < c; ++j) lp[j] = p[j] ? LOG[p[j]] : -1;
        #pragma omp parallel for schedule(dynamic, 64)
        for (long i = rank + 1; i < r; ++i) {
            uint16_t *x = row[i];
            uint16_t f = x[col];
            if (!f) continue;
            int lf = LOG[f];
            for (long j = col; j < c; ++j) if (lp[j] >= 0) x[j] ^= EXP[lf + lp[j]];
        }
        ++rank;
    }
    free(row); free(lp);
    return rank;
}

int main(int argc, char **argv) {
    if (argc < 5) { fprintf(stderr, "usage: rank2m file m poly prim\n"); return 2; }
    int m = atoi(argv[2]); unsigned poly = (unsigned)strtoul(argv[3], 0, 0), prim = (unsigned)strtoul(argv[4], 0, 0);
    build_tables(m, poly, prim);
    FILE *f = fopen(argv[1], "rb"); if (!f) { puts("cannot open"); return 2; }
    int64_t hdr[2]; if (fread(hdr, 8, 2, f) != 2) return 2;
    long r = hdr[0], c = hdr[1];
    uint16_t *M = malloc((size_t)r * c * 2); if (!M) { puts("oom"); return 2; }
    if (fread(M, 2, (size_t)r * c, f) != (size_t)r * c) { puts("short read"); return 2; }
    fclose(f);
    for (size_t i = 0; i < (size_t)r * c; ++i) if (M[i] >= Q) { puts("entry out of field"); return 2; }
    double t0 = omp_get_wtime();
    long rk = rank_gf2m(M, r, c);
    long kernel = c - rk, generic = c > r ? c - r : 0;
    printf("rows=%ld cols=%ld rank=%ld kernel=%ld generic=%ld excess=%ld row_deps=%ld time=%.1fs\n",
           r, c, rk, kernel, generic, kernel - generic, r - rk, omp_get_wtime() - t0);
    return 0;
}
