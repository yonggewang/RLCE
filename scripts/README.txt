Cubic-jet experiments (companion to "Cubic Jets and Hidden Pairings").

Prime fields (UVW toys):
  python3 jet.py q n k1 k2 k_l mode seed             mode: uvw1 | uvw2 | uuv | ctrl_rand | ctrl_twin
  python3 jet_general.py q n k1 k2 k_l d r mode seed out.bin   (any degree d, order r; prints n0,n1,n2 and Delta)
  gcc -O3 -fopenmp -o rankp rankp.c ; ./rankp out.bin q
  python3 jet_structure.py q n k1 k2 k_l uvw2 seed   (blocks, pairs, ratios)
RLCE:
  python3 jet_rlce.py n k w k_l grs|random seed      (F_257 toy, pure Python rank)
  python3 jet_rlce_structure.py n k w k_l seed       (blocks, pairs, GRS directions)
  python3 jet_rlce_gf2m.py n k w k_l grs|random|none seed   (GF(2^10) toy via galois)
  python3 rlce_full.py m n k w k_l grs|random|none seed out.bin ; gcc -O3 -fopenmp -o rank2m rank2m.c ; ./rank2m out.bin m 1135 2
  (1135 = galois' irreducible polynomial for GF(2^10) as an integer, 2 = primitive element; GF(2^11): 2053 2)
Requires numpy; galois for GF(2^m); gcc with OpenMP.

Jet-degree invariant experiments (Section 9):
  python3 tuple_force.py            # per-tuple curve-point forcing: jet degree = j+1 (Table 9)
  python3 jet_jway.py p n0 k0 j k_l d r mode seed out.bin   # j-way mixing key + jet system
                                     # mode: jway | ctrl_rand | ctrl_block
  python3 jet_alternant.py p m n deg k_l d r seed           # alternant (subfield subcode) jet system
Goppa/alternant jet degree Theta(log n) is cited from GIJS 2026/1630, Weis 2026/1984,
HOVER 2026/1778; not recomputed here.

Strengthening (this revision):
  python3 simplex_form.py                 # simplex-form lower bound delta>=j+1 (Lemma 20), j=2..6
  python3 rlce_recover.py m n k w k_l seed workdir   # full-size RLCE key-structure recovery
                                          # (needs ./nullspace2m, built from nullspace2m.c)
  gcc -O3 -march=native -fopenmp -o nullspace2m nullspace2m.c

Forcing law, master count, redundancy law, landscape (this revision, Section 9):
  python3 forcing_law.py                  # Theorem (forcing law): kernel = monomial count and
                                          # Q forced iff j r > (j-1) d, all 210 triples j<=6, d<=8
  python3 jet_mask.py p k1 k2 widths k_l d r mode seed out.bin ; ./rankp out.bin p
        widths "2x50" = 50 tuples of width 2; "1x40,2x20" = RLCE-like; "3x12" = width 3
        mode: mask (random mixing coefficients) | uvw (lambda = (1,-1), i.e. UVW1)
              | uuvgen | uuvplain (Marquez-Corbella--Tillich (U|U+V) with RS U and V, common support)
              | uuvperm (same, V on a permuted support) | ctrl_rand
        prints the survival profile and the master-count prediction
        sum_tuples (j' r - (j'-1) d)^+ - d(k2-1) - 1 and the hierarchy closed form d(rho+1)-R-k_l-1
    examples (Sect. 9.3, 9.5):
      jet_mask.py 337 188 148 2x336 27 2 1 uvw 11 x.bin    # ePrint 128b, shortened square: excess 14
      jet_mask.py 101 16 3 3x12 19 4 3 mask 3 x.bin        # width 3 at (4,3): 630 generic + 3
      jet_mask.py 101 10 10 2x20 20 4 3 uvw 5 x.bin        # tiny-U UVW at (4,3): 780 generic + 3
      jet_mask.py 101 35 15 2x50 11 2 1 uuvgen 2 x.bin     # (U|U+V)-RS scroll: square dim 3(k_l-1)
  python3 rnc_jets.py                     # Veronese threshold (Remark: exactness): jets at m points
                                          # of a rational normal curve saturate at 2(k2-1)^2+2
  python3 grs_rank1.py p n k k_l d r seed out.bin ; ./rankp out.bin p   # BBCRS m=1: GRS + rank-1

Dual leaks and the limits of masking (Section "Beyond the Curve"):
  Requires numpy, scipy; CryptographicEstimators for the cost columns.
  polar.py                 binary polar codes over F2, RLCE transform, rank/nullspace over F2
  polar_reliab.py          underflow-free BEC(1/2) polar construction (logit domain); d, d_perp
                           (agrees with 1500-digit arithmetic at m=12; the float recursion does not)
  minweight_count.py       number of minimum-weight words of a polar code and its dual
                           (Bardet et al. formula, checked against enumeration in 94 codes)
  dual_distance.py         d and d_perp formulas vs exact enumeration; primal/dual vs GV table
  polar_invariants.py t k w seed      polarRLCE primal side: minimum distance and affine survivors
  family_invariants.py ldpc_rlce|uvw  LDPC-RLCE dual leak; UVW matched-pair subspace (polar/LDPC)
  nogo_analysis.py origsets|uvw|polar|ldpc   dual-leak verdicts and escape searches
  hirate_polarrlce.py [lambda]        high-rate polarRLCE: multiplicity, leak law, Prange costs
  talvardy.py [m]                     Tal-Vardy degrading construction: rigorous upper bounds on the
                                      SC failure probability of a polar code on BSC(p) (Table: SC bounds)
  window_search.py lambda [top]       the illusory high-rate window (t = t_max/2): Prange floor, Stern
                                      re-pricing of the cheapest points
  polar_closure.py m dfr_exp lambda   Prange necessary condition over (p, R, w) with certified failure
                                      bound <= 2^-dfr_exp (Proposition: no secure polarRLCE parameters)
  polar_closure_stern.py lambda dfr_exp "p,R ..." [m]   Stern-family re-pricing of the Prange survivors
  polar_closure_fast.py lambda closure.out m            fast Stern exclusion of Prange survivors (dual at
                                                        Prange's largest w; Stern alone, an upper bound)
  polar_closure_stern2.py lambda closure.out m [i n]    full Stern-only re-pricing of all Prange survivors
                                                        (shard i of n); Table: polarRLCE at n=32768
  rm_rlce2.py [lambda]                Reed-Muller codes under RLCE: dual-leak cost with multiplicity,
                                      t_req for message recovery, t_BD and t_max (Table: RM under RLCE)
