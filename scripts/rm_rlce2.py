"""RM-heavy decreasing sets under RLCE, priced correctly.

Dual leak cost = min over D of  SD(N, N-k, D) - log2( N_dperp * P[d_perp + Y <= D] ),
  Y ~ Bin(X,1/3), X ~ Hypergeom(n, w, d_perp)  (Lemma: dual preservation, A_i uniform in GL2(F2)).
The minimisation is done with the Prange formula (fast), then the argmin D is re-priced with the
Stern-family estimator.  Message recovery: t_req = smallest t with SD_Stern(N,k,t) >= lambda.
Also reported: t_BD = (d-1)/2 (bounded-distance radius of RM(r0,m)) and t_max (capacity).
"""
import sys, numpy as np
from math import comb, log2, ceil, lgamma
from scipy.stats import hypergeom, binom
from cryptographic_estimators.SDEstimator import SDEstimator
from cryptographic_estimators.SDEstimator.SDAlgorithms import BJMM, BJMMplus, BJMMdw, BJMMpdw, MayOzerov, BothMay
from minweight_count import formula_count
SLOW=[BJMM,BJMMplus,BJMMdw,BJMMpdw,MayOzerov,BothMay]
def sd(N,K,wt):
    e=SDEstimator(n=N,k=K,w=wt,excluded_algorithms=SLOW)
    return min(v['estimate']['time'] for v in e.estimate().values())
def lc(n,k): return (lgamma(n+1)-lgamma(k+1)-lgamma(n-k+1))/np.log(2) if 0<=k<=n else float('-inf')
def prange_find(N,K,D): return -(log2(D)+lc(N-D,K-1)-lc(N,K))+3*log2(N)
def h2inv(y):
    lo,hi=0.0,0.5
    for _ in range(80):
        x=(lo+hi)/2; H=-x*log2(x)-(1-x)*log2(1-x) if x>0 else 0
        lo,hi=(x,hi) if H<y else (lo,x)
    return (lo+hi)/2
def leak_cdf(n,w,dp):
    xs=np.arange(0,dp+1); px=hypergeom.pmf(xs,n,w,dp); ys=np.arange(0,dp+1); P=np.zeros(dp+1)
    for x,p in zip(xs,px):
        if p>1e-300: P+=p*binom.cdf(ys,x,1/3)
    return P
def dual_cost(n,k,w,dp,Ndp):
    N=n+w; K=N-k; cdf=leak_cdf(n,w,dp); best=(1e9,None,None)
    for y in range(0,dp+1):
        mult=Ndp*cdf[y]
        if mult<1: continue                      # no leaked word of this weight expected
        c=prange_find(N,K,dp+y)-log2(mult)
        if c<best[0]: best=(c,dp+y,mult)
    c_p,D,mult=best
    c_s=sd(N,K,D)-log2(mult)
    return c_p,c_s,D,mult
def treq(N,k,lam,lo,hi):
    while hi-lo>1:
        mid=(lo+hi)//2
        if sd(N,k,mid)>=lam: hi=mid
        else: lo=mid
    return hi
if __name__=="__main__":
    lam=int(sys.argv[1]) if len(sys.argv)>1 else 143
    rows=[(11,5),(11,6),(12,5),(12,6),(12,7),(13,6),(13,7),(14,6),(14,7)]
    print(f"lambda={lam}; w=max(n-k,k/2)")
    for (m,r0) in rows:
        n=1<<m; pc=lambda x: bin(x).count('1')
        k=sum(comb(m,j) for j in range(r0+1)); R=k/n
        d=1<<(m-r0); dp=1<<(r0+1); w=max(n-k,ceil(k/2)); N=n+w
        I=[i for i in range(n) if pc(i)>=m-r0]; F=[i for i in range(n) if pc(i)<m-r0]
        J=[(n-1)^i for i in F]; _,Ndp=formula_count(m,J,2)
        cp,cs,D,mult=dual_cost(n,k,w,dp,Ndp)
        tmax=int(n*h2inv(1-R)); tbd=(d-1)//2
        tr=treq(N,k,lam,1,max(2,min(N//3,4*tmax)))
        print(f"m={m} RM({r0},{m}): k={k} R={R:.2f} d={d} dperp={dp} log2Ndperp={log2(Ndp):.0f} w={w} N={N} key={k*(N-k)/8/2**20:.2f}MiB | "
              f"dual @D={D} mult=2^{log2(mult):.0f}: Prange {cp:.0f} Stern {cs:.0f} | t_req={tr} t_BD={tbd} t_max={tmax}  "
              f"-> {'dual broken' if cs<lam else ('msg: t_req>t_max' if tr>tmax else 'NOT EXCLUDED (needs t>=%d)'%tr)}", flush=True)
