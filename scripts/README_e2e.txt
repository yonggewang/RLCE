End-to-end long-key RLCE key recovery (Sect. "End-to-end key recovery of long-key RLCE at full size")
======================================================================================================

Files (to be placed in RLCE/scripts next to rlce_recover.py, rank2m.c, nullspace2m.c):
  rlce_keygen_export.py  key generation for STRICT MODE: writes pk.npy and ct.npy, and the secret key and
                       plaintext under outdir/secret/, which the attack scripts never open.
  rlce_e2e.py          jet stage (adaptive shortening rounds, read-off, ratios), fold, Sidelnikov-Shestakov
                       over GF(2^m), Berlekamp-Welch decryption of a fresh ciphertext. Resumable via workdir/state.json.
  rlce_endgame_sq.py   square-code stage on the folded code (CLT's regime once w' < n-k-k_l+1):
                       shortened Veronese matrix, left kernel, off-curve columns, pair planes meeting the curve.
  sim_rounds.py        survival-model simulation of the number of jet rounds (random vs adaptive shortening).
  logs_r1/             logs of the run reported in Table "End-to-end recovery" (R-1, key seed 1).

Dependencies: requirements.txt pins the tested versions (Python 3.13, Linux x86_64): numpy 2.5.3, galois 0.4.11,
numba 0.68.1, scipy 1.18.1; cryptographic-estimators 2.1.1 for the cost-analysis scripts only.
  python3 -m pip install -r requirements.txt
  gcc -O3 -march=native -fopenmp -o nullspace2m nullspace2m.c

Two modes.
  Default (scoring) mode: the script generates the key from the key seed and uses the secret key ONLY to print
  [truth] scoring lines; nothing from it enters the recovery, which reads the public key G alone.
  STRICT mode (PKDIR=<dir>): the attack reads <dir>/pk.npy and <dir>/ct.npy written by rlce_keygen_export.py
  and has no secret-key access at all (no [truth] lines are printed); it writes the decrypted message to
  workdir/recovered_msg.npy, which is compared with <dir>/secret/msg.npy by a separate command afterwards.
  The key seed argument of rlce_e2e.py is then ignored for the key (it only seeds the shortening choices).

  Strict-mode reproduction of the headline break (new key, seed 2; ~35 min on two cores). The square-code
  handover with k_l=21 needs w' < n-k-k_l+1 = 94, i.e. at least 21 known pairs; the seed-2 key exposes
  7, 6, 8, 5 pairs in rounds 1-4: two rounds (13 pairs) are NOT enough, three reach the threshold (21),
  and the logged run used four for margin (26). Run four jet rounds:
    python3 rlce_keygen_export.py 10 846 732 114 57 2 key_r1s
    PKDIR=key_r1s python3 rlce_e2e.py 10 846 732 114 39 57 77 run_r1s 4            # four jet rounds
    PKDIR=key_r1s SQSEED=77 python3 rlce_endgame_sq.py 10 846 732 114 21 1 run_r1s 1500 run_r1s/state.json
    cp run_r1s/state_sq.json run_r1s/state.json
    PKDIR=key_r1s python3 rlce_e2e.py 10 846 732 114 39 57 77 run_r1s                 # fold, S-S, decrypt
    python3 -c "import numpy as np; print(np.array_equal(np.load('run_r1s/recovered_msg.npy'), np.load('key_r1s/secret/msg.npy')))"
  Log of this run (patched source, complete: key export, 4 jet rounds, square-code stage, Sidelnikov-Shestakov,
  decryption, separate plaintext comparison): logs_r1/strict_run_r1s.log.
  logs_r1/strict_state/ holds that run's public key (pk.npy), ciphertext (ct.npy), final pairing state
  (state.json) and recovered message (recovered_msg.npy); it contains no secret material (the secret key and
  plaintext are regenerated deterministically by rlce_keygen_export.py with seed 2).
  logs_r1/strict_run_r1s_first_attempt.log is the earlier attempt kept for the record: it stopped after two jet
  rounds (13 pairs, handover not yet reachable) and its back end hit a Moebius-parameter-at-infinity bug in
  Sidelnikov-Shestakov, fixed in the current source (the parameter is now re-chosen when u = 0).

Reproducing the R-1 run (n=846, k=732, w=114, t=57, GF(2^10)), two cores:

  # jet stage, k_l = 39, key seed 1 (rounds 1-15 deterministic ordering; rounds 16-17 randomized -- the
  # script now always randomizes from round 2 on, see the gumbel line)
  python3 rlce_e2e.py 10 846 732 114 39 57 1 r1 17          # stops after 17 rounds (max_rounds); ~90 min
  # square-code stage from the saved state (101 pairs) with k_l = 25, shortening seed 2002
  SQSEED=2002 python3 rlce_endgame_sq.py 10 846 732 114 25 1 r1 1500 r1/state.json   # writes r1/state_sq.json
  # back end: fold, Sidelnikov-Shestakov, decryption (resumes with all pairs known, skips the rounds)
  cp r1/state_sq.json r1/state.json && python3 rlce_e2e.py 10 846 732 114 39 57 1 r1

Early handover (two jet rounds, then square code with k_l = 21, shortening seed 7):
  python3 rlce_e2e.py 10 846 732 114 39 57 1 r1b 2
  SQSEED=7 python3 rlce_endgame_sq.py 10 846 732 114 21 1 r1b 1500 r1b/state.json
  cp r1b/state_sq.json r1b/state.json && python3 rlce_e2e.py 10 846 732 114 39 57 1 r1b

Toy check (seconds): python3 rlce_e2e.py 10 60 30 30 21 15 1 toy

Notes
  * The state file keeps the pairs in order of recovery, so "the 24 pairs of rounds 1-2" is state['known'][:24].
  * Square-code window: k_l must satisfy C(k_l+1,2) >= n' = N'-k+k_l (k_l >= 21 for R-1) and
    w' < n-k-k_l+1 for the deficiency to be visible.
  * The logs in logs_r1 were produced with the nullspace2m binary at two OpenMP threads; timings vary with load.
