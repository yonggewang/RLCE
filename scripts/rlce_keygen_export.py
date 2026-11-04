"""Generate an RLCE key pair and a fresh ciphertext, and write them to separate files, so that the
attack scripts can be run on the public key alone (strict mode: PKDIR=<dir>).
usage: python3 rlce_keygen_export.py m n k w t seed outdir
writes outdir/pk.npy (public generator, k x N, galois integer repr), outdir/ct.npy, and, in outdir/secret/,
sk.npz and msg.npy. In strict mode the attack scripts never open outdir/secret/."""
import sys, os, numpy as np, galois
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from rlce_recover import keygen
m, n, k, w, t = map(int, sys.argv[1:6]); seed = int(sys.argv[6]); out = sys.argv[7]
GF = galois.GF(2 ** m); rng = np.random.default_rng(seed)
G, sk = keygen(GF, n, k, w, rng); N = n + w
msg = GF(rng.integers(0, GF.order, size=k)); e = GF.Zeros(N)
epos = rng.choice(N, size=t, replace=False); e[epos] = GF(rng.integers(1, GF.order, size=t))
ct = msg @ G + e
os.makedirs(os.path.join(out, 'secret'), exist_ok=True)
np.save(os.path.join(out, 'pk.npy'), np.array(G, dtype=np.int64)); np.save(os.path.join(out, 'ct.npy'), np.array(ct, dtype=np.int64))
np.save(os.path.join(out, 'secret', 'msg.npy'), np.array(msg, dtype=np.int64))
np.savez(os.path.join(out, 'secret', 'sk.npz'), Gs=np.array(sk['Gs'], dtype=np.int64), S=np.array(sk['S'], dtype=np.int64), perm=sk['perm'])
print(f"wrote {out}/pk.npy ({k}x{N}), {out}/ct.npy (t={t}); secret material in {out}/secret/")
