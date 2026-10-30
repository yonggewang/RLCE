/* Left null space of a matrix M over GF(2^m) stored as the rank2m file
 * (int64 rows, cols; rows*cols uint16).  Left kernel {y : y M = 0} = right
 * null space of M^T.  We load M^T (cols x rows), reduce to row echelon with
 * pivot tracking, and back-substitute the free columns to a null basis, which
 * we write as: int64 ker, len(=rows); then ker*len uint16 (each row a basis
 * vector of the left kernel of M, length = rows of M).
 * usage: nullspace2m infile outfile m poly prim
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <omp.h>

static int Q, Q1;
static uint16_t *EXP, *LOG;
static void build_tables(int m, unsigned poly, unsigned prim) {
    Q = 1 << m; Q1 = Q - 1;
    EXP = malloc(2 * Q * sizeof *EXP); LOG = malloc(Q * sizeof *LOG);
    unsigned x = 1;
    for (int i = 0; i < Q1; ++i) {
        EXP[i] = x; LOG[x] = i;
        unsigned a = x, b = prim, r = 0;
        while (b) { if (b & 1) r ^= a; b >>= 1; a <<= 1; if (a & Q) a ^= poly; }
        x = r;
    }
    for (int i = Q1; i < 2 * Q; ++i) EXP[i] = EXP[i - Q1];
    LOG[0] = 0;
}
static inline uint16_t mul(uint16_t a, uint16_t b) { return (a && b) ? EXP[LOG[a] + LOG[b]] : 0; }
static inline uint16_t inv(uint16_t a) { return EXP[Q1 - LOG[a]]; }

int main(int argc, char **argv) {
    if (argc < 6) { fprintf(stderr, "usage: nullspace2m in out m poly prim\n"); return 2; }
    int m = atoi(argv[3]); unsigned poly = strtoul(argv[4], 0, 0), prim = strtoul(argv[5], 0, 0);
    build_tables(m, poly, prim);
    FILE *f = fopen(argv[1], "rb"); if (!f) { puts("open"); return 2; }
    int64_t hdr[2]; if (fread(hdr, 8, 2, f) != 2) return 2;
    long R = hdr[0], C = hdr[1];                 /* M is R x C */
    /* A = M^T, shape C x R, row-major */
    uint16_t *A = malloc((size_t)C * R * 2); if (!A) { puts("oom"); return 2; }
    uint16_t *buf = malloc((size_t)C * 2);
    for (long i = 0; i < R; ++i) {
        if (fread(buf, 2, C, f) != (size_t)C) { puts("short"); return 2; }
        for (long j = 0; j < C; ++j) A[(size_t)j * R + i] = buf[j];
    }
    fclose(f); free(buf);
    long nr = C, nc = R;                          /* A is nr x nc */
    long *pivcol = malloc(nr * sizeof *pivcol);
    char *isfree = malloc(nc); for (long j = 0; j < nc; ++j) isfree[j] = 1;
    long rank = 0;
    double t0 = omp_get_wtime();
    for (long col = 0; col < nc && rank < nr; ++col) {
        long piv = -1;
        for (long i = rank; i < nr; ++i) if (A[(size_t)i * nc + col]) { piv = i; break; }
        if (piv < 0) continue;
        if (piv != rank) for (long j = 0; j < nc; ++j) { uint16_t t = A[(size_t)piv*nc+j]; A[(size_t)piv*nc+j]=A[(size_t)rank*nc+j]; A[(size_t)rank*nc+j]=t; }
        uint16_t *pr = A + (size_t)rank * nc, iv = inv(pr[col]);
        for (long j = col; j < nc; ++j) if (pr[j]) pr[j] = mul(pr[j], iv);
        int plog[1]; (void)plog;
        #pragma omp parallel for schedule(dynamic,32)
        for (long i = 0; i < nr; ++i) {
            if (i == rank) continue;
            uint16_t fac = A[(size_t)i*nc+col];
            if (!fac) continue;
            int lf = LOG[fac];
            uint16_t *ri = A + (size_t)i*nc;
            for (long j = col; j < nc; ++j) if (pr[j]) ri[j] ^= EXP[lf + LOG[pr[j]]];
        }
        pivcol[rank] = col; isfree[col] = 0; ++rank;
    }
    long ker = nc - rank;
    fprintf(stderr, "A=%ldx%ld rank=%ld leftkernel=%ld reduce=%.1fs\n", nr, nc, rank, ker, omp_get_wtime()-t0);
    /* null basis: for each free column f, x[f]=1, x[pivcol[i]] = -A[i][f] (RREF) */
    FILE *g = fopen(argv[2], "wb");
    int64_t oh[2] = { ker, nc }; fwrite(oh, 8, 2, g);
    uint16_t *x = malloc((size_t)nc * 2);
    for (long f = 0; f < nc; ++f) {
        if (!isfree[f]) continue;
        memset(x, 0, (size_t)nc * 2);
        x[f] = 1;
        for (long i = 0; i < rank; ++i) x[pivcol[i]] = A[(size_t)i*nc + f]; /* -a = a in char 2 */
        fwrite(x, 2, nc, g);
    }
    fclose(g);
    printf("leftkernel=%ld len=%ld written to %s\n", ker, nc, argv[2]);
    return 0;
}
