"""High-rate polarRLCE window, searched with the three costs that actually bind:
  dual   : min_D SD(N,N-k,D) - log2(N_dperp * P[dperp+Y<=D])          (Lemma dual preservation)
  msg    : SD(N,k,t), t = floor(t_max/2)
  primal : SD(N,k,d+w/2) - log2(N_d)   if d+w/2 < GV(N,k), else closed
             (a minimum-weight polar word gains ~w/2 ones on the inserted columns; exact survivors
              need m R = 0, expected N_d 2^{-w} << 1 for all w considered)
No w >= k/2 floor.  Pass 1: Prange (necessary condition) over a fine grid -> floor on the key;
pass 2: Stern-family re-pricing of the cheapest Prange-passing points -> confirmed sets.
usage: python3 window_search.py lambda [stern_top]
"""
import sys, numpy as np
from math import ceil, log2
from hirate_polarrlce import evaluate, codes, prange_find, h2inv
from nogo_analysis import gv

def prange_all(m,k,w,lam):
    r=evaluate(m,k,w); N=r['N']; n=r['n']
    d,Nd=r['d'],r['Nd']; Dp=d+w//2; g=gv(N,k)
    prim = float('inf') if Dp>=g else prange_find(N,k,Dp,log2(Nd))
    r['prim_bits']=prim; r['gv']=g
    r['ok']= r['dual_bits']>=lam and r['msg_bits']>=lam and prim>=lam
    return r

def min_w(m,k,lam):
    """dual cost increases with w, msg decreases: scan w on a geometric+linear grid, keep cheapest passing."""
    n=1<<m; best=None
    for w in sorted(set([int(x) for x in np.linspace(200,n,40)]+[n-k, ceil(k/2)])):
        if w<1 or w>n: continue
        r=prange_all(m,k,w,lam)
        if r['ok'] and (best is None or r['key']<best['key']): best=r
    return best

if __name__=="__main__":
    lam=int(sys.argv[1]); top=int(sys.argv[2]) if len(sys.argv)>2 else 6
    cands=[]
    for m in (12,13,14):
        n=1<<m
        for k in range(int(0.60*n), int(0.95*n), n//128):
            r=min_w(m,k,lam)
            if r: cands.append(r)
    cands.sort(key=lambda r:r['key'])
    print(f"lambda={lam}: {len(cands)} (m,k) with a Prange-passing w; cheapest:")
    for r in cands[:top]:
        print(f"  m={r['m']} k={r['k']} R={r['k']/r['n']:.3f} w={r['w']} N={r['N']} d={r['d']} dperp={r['dp']} t={r['t']}/{r['tcap']} "
              f"key={r['key']/2**20:.2f}MiB | Prange dual={r['dual_bits']:.0f} msg={r['msg_bits']:.0f} primal={'closed' if r['prim_bits']==float('inf') else f'{r['prim_bits']:.0f}'}", flush=True)
    # Stern re-pricing of the top candidates
    from cryptographic_estimators.SDEstimator import SDEstimator
    from cryptographic_estimators.SDEstimator.SDAlgorithms import BJMM, BJMMplus, BJMMdw, BJMMpdw, MayOzerov, BothMay
    SLOW=[BJMM,BJMMplus,BJMMdw,BJMMpdw,MayOzerov,BothMay]
    def sd(N,K,wt):
        e=SDEstimator(n=N,k=K,w=wt,excluded_algorithms=SLOW)
        return min(v['estimate']['time'] for v in e.estimate().values())
    print("Stern-family re-pricing:")
    for r in cands[:top]:
        N=r['N']; k=r['k']
        dual=sd(N,N-k,r['D'])-log2(r['mult']); msg=sd(N,k,r['t'])
        Dp=r['d']+r['w']//2
        prim = float('inf') if Dp>=r['gv'] else sd(N,k,Dp)-log2(r['Nd'])
        print(f"  m={r['m']} k={k} w={r['w']} key={r['key']/2**20:.2f}MiB: dual={dual:.1f} msg={msg:.1f} primal={'closed' if prim==float('inf') else f'{prim:.1f}'} -> {'CONFIRMED' if min(dual,msg,prim)>=lam else 'fails'}", flush=True)
