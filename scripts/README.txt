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
