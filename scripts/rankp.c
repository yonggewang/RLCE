/* Rank of a dense matrix over F_P (P prime < 2^12) read from a file:
 * header int64 rows, cols; then rows*cols uint16 entries row-major.
 * Blocked Gaussian elimination with lazy reduction (panel of PB pivots, then one
 * trailing update accumulated in uint32).  Compile: gcc -O3 -fopenmp -DP=101 rankp.c
 * usage: rankp file
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <omp.h>
static uint32_t P = 101u;
#define PB 64

static uint32_t inv(uint32_t a) {
    uint32_t r = 1, e = P - 2; a %= P;
    while (e) { if (e & 1) r = r * a % P; a = a * a % P; e >>= 1; }
    return r;
}

static long rank_mod(uint16_t *M, long r, long c) {
    uint16_t **row = malloc(r * sizeof *row);
    uint32_t *Pn = malloc((size_t)r * PB * 4), *P0 = malloc((size_t)r * PB * 4);
    uint32_t *mul = malloc((size_t)r * PB * 4);
    char *is_piv = malloc(r);
    long live = r, rank = 0;
    for (long i = 0; i < r; ++i) row[i] = M + (size_t)i * c;
    for (long c0 = 0; c0 < c && live > 0; c0 += PB) {
        long w = c - c0 < PB ? c - c0 : PB, b = 0, prow[PB], pcol[PB];
        for (long i = 0; i < live; ++i) {
            is_piv[i] = 0;
            for (long t = 0; t < w; ++t) Pn[i * PB + t] = P0[i * PB + t] = row[i][c0 + t];
        }
        for (long t = 0; t < w; ++t) {
            long piv = -1;
            for (long i = 0; i < live; ++i) if (!is_piv[i] && Pn[i * PB + t]) { piv = i; break; }
            if (piv < 0) continue;
            is_piv[piv] = 1; prow[b] = piv; pcol[b] = t; ++b;
            uint32_t *pp = Pn + piv * PB, iv = inv(pp[t]);
            for (long u = t; u < w; ++u) pp[u] = pp[u] * iv % P;
            for (long i = 0; i < live; ++i) {
                uint32_t *x = Pn + i * PB, g = P - x[t];
                if (is_piv[i] || g == P) continue;
                for (long u = t; u < w; ++u) x[u] = (x[u] + g * pp[u]) % P;
            }
        }
        if (b == 0) continue;
        /* A = original pivot block (b x b), invert: multipliers m_i = P0_i[pcol] A^-1 */
        uint32_t *A = malloc((size_t)b * 2 * b * 4);
        for (long a = 0; a < b; ++a)
            for (long e = 0; e < 2 * b; ++e)
                A[a * 2 * b + e] = e < b ? P0[prow[a] * PB + pcol[e]] : (e - b == a);
        for (long col = 0; col < b; ++col) {
            long piv = col;
            while (!A[piv * 2 * b + col]) ++piv;
            if (piv != col) for (long e = 0; e < 2 * b; ++e) { uint32_t t = A[piv * 2 * b + e]; A[piv * 2 * b + e] = A[col * 2 * b + e]; A[col * 2 * b + e] = t; }
            uint32_t iv = inv(A[col * 2 * b + col]);
            for (long e = 0; e < 2 * b; ++e) A[col * 2 * b + e] = A[col * 2 * b + e] * iv % P;
            for (long a = 0; a < b; ++a)
                if (a != col && A[a * 2 * b + col]) {
                    uint32_t g = P - A[a * 2 * b + col];
                    for (long e = 0; e < 2 * b; ++e) A[a * 2 * b + e] = (A[a * 2 * b + e] + g * A[col * 2 * b + e]) % P;
                }
        }
        #pragma omp parallel for schedule(static)
        for (long i = 0; i < live; ++i) {
            if (is_piv[i]) continue;
            for (long e = 0; e < b; ++e) {
                uint64_t s = 0;
                for (long a = 0; a < b; ++a) s += (uint64_t)P0[i * PB + pcol[a]] * A[a * 2 * b + b + e];
                mul[i * PB + e] = (uint32_t)((P - s % P) % P);
            }
        }
        free(A);
        long cs = c0 + w;
        /* trailing update: row_i += sum_e mul[i][e] * row_{prow[e]}  (lazy, uint32: PB*P^2 < 2^32) */
        #pragma omp parallel for schedule(dynamic, 16)
        for (long i = 0; i < live; ++i) {
            if (is_piv[i]) continue;
            const uint32_t *mm = mul + i * PB;
            uint16_t *x = row[i];
            long jn = c - cs;
            uint32_t *acc = malloc(jn * 4);
            for (long j = 0; j < jn; ++j) acc[j] = x[cs + j];
            for (long e = 0; e < b; ++e) {
                uint32_t g = mm[e];
                if (!g) continue;
                const uint16_t *pr = row[prow[e]] + cs;
                for (long j = 0; j < jn; ++j) acc[j] += g * pr[j];
            }
            for (long j = 0; j < jn; ++j) x[cs + j] = (uint16_t)(acc[j] % P);
            free(acc);
        }
        long o = 0;
        for (long i = 0; i < live; ++i) if (!is_piv[i]) row[o++] = row[i];
        live = o; rank += b;
    }
    free(row); free(Pn); free(P0); free(mul); free(is_piv);
    return rank;
}

int main(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "usage: rankp file prime\n"); return 2; }
    P = (uint32_t)strtoul(argv[2], 0, 0);
    if (P < 2 || P > 8000) { fprintf(stderr, "prime out of range\n"); return 2; }
    FILE *f = fopen(argv[1], "rb");
    if (!f) { puts("cannot open"); return 2; }
    int64_t hdr[2];
    if (fread(hdr, 8, 2, f) != 2) return 2;
    long r = hdr[0], c = hdr[1];
    uint16_t *M = malloc((size_t)r * c * 2);
    if (!M) { puts("oom"); return 2; }
    if (fread(M, 2, (size_t)r * c, f) != (size_t)r * c) { puts("short read"); return 2; }
    fclose(f);
    double t0 = omp_get_wtime();
    long rk = rank_mod(M, r, c);
    long kernel = c - rk, generic = c > r ? c - r : 0, deps = r - rk;
    printf("rows=%ld cols=%ld rank=%ld kernel=%ld generic=%ld excess=%ld row_deps=%ld time=%.1fs\n",
           r, c, rk, kernel, generic, kernel - generic, deps, omp_get_wtime() - t0);
    return 0;
}
