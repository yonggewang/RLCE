"""High-rate polarRLCE: primal closed by w>=k/2, dual words heavy (d_perp>=64).
For each (m,k,w):  d, d_perp, N_dperp (validated formula), leaked-weight law
  image weight = d_perp + Y,  Y ~ Bin(X, 1/3),  X ~ Hypergeom(n, w, d_perp)
(A_i uniform in GL_2(F_2): A^{-T}(1,0)^T is a uniform nonzero vector, weight 2 w.p. 1/3),
expected #leaked words of weight <= D, and Prange-type costs for
  (dual) finding one leaked word in the public dual [N, N-k]   (divided by multiplicity)
  (msg)  decoding t = floor(theta * t_cap) errors in the public [N, k].
"""
import sys, numpy as np
from math import lgamma, log2, ceil, comb
from scipy.stats import hypergeom, binom
from polar_reliab import order
from minweight_count import formula_count

def lc(n,k): return (lgamma(n+1)-lgamma(k+1)-lgamma(n-k+1))/np.log(2) if 0<=k<=n else float('-inf')
def h2inv(y):
    lo,hi=0.0,0.5
    for _ in range(80):
        x=(lo+hi)/2; H=-x*log2(x)-(1-x)*log2(1-x) if x>0 else 0
        lo,hi=(x,hi) if H<y else (lo,x)
    return (lo+hi)/2

def codes(m,k):
    n=1<<m; o=order(m); I=sorted(o[:k].tolist()); F=sorted(o[k:].tolist())
    J=[(n-1)^i for i in F]
    d,Nd=formula_count(m,I,2); dp,Ndp=formula_count(m,J,2)
    return d,Nd,dp,Ndp

def leak_cdf(n,w,dp):
    """P(image weight <= dp + y) for y=0..dp"""
    xs=np.arange(0,dp+1); px=hypergeom.pmf(xs, n, w, dp)
    ys=np.arange(0,dp+1); P=np.zeros(dp+1)
    for x,p in zip(xs,px):
        if p<1e-300: continue
        P+=p*binom.cdf(ys, x, 1/3)
    return P

def prange_find(N,K,D,logmult):
    p=log2(D)+lc(N-D,K-1)-lc(N,K)+logmult
    return max(-p,0)+3*log2(N)
def prange_msg(N,k,t): return lc(N,t)-lc(N-k,t)+3*log2(N)

def evaluate(m,k,w,theta=0.5):
    n=1<<m; N=n+w; K=N-k
    d,Nd,dp,Ndp=codes(m,k)
    cdf=leak_cdf(n,w,dp)
    best=(1e9,None)
    for y in range(0,dp+1,max(1,dp//32)):
        mult=Ndp*cdf[y]
        if mult<=0: continue
        c=prange_find(N,K,dp+y,log2(mult) if mult>0 else -1e9)
        if c<best[0]: best=(c,dp+y,mult)
    tcap=int(n*h2inv(1-k/n)); t=int(theta*tcap)
    return dict(m=m,n=n,k=k,w=w,N=N,d=d,Nd=Nd,dp=dp,Ndp=Ndp,dual_bits=best[0],D=best[1],
                mult=best[2],tcap=tcap,t=t,msg_bits=prange_msg(N,k,t),key=k*(N-k)/8)

if __name__=="__main__":
    lam=int(sys.argv[1]) if len(sys.argv)>1 else 128
    rows=[]
    for m in (11,12,13):
        n=1<<m
        for R in np.arange(0.66,0.93,0.02):
            k=int(round(R*n)); wlo=max(n-k,ceil(k/2))
            for w in sorted(set([wlo, (wlo+n)//2, n])):
                rows.append(evaluate(m,k,w))
    ok=[r for r in rows if r['dual_bits']>=lam and r['msg_bits']>=lam]
    print(f"{len(rows)} points; {len(ok)} with Prange(dual, multiplicity-adjusted)>=lam and Prange(msg@t=0.5tcap)>=lam")
    for r in sorted(ok,key=lambda r:r['key'])[:15]:
        print(f" m={r['m']} k={r['k']} R={r['k']/r['n']:.2f} w={r['w']} N={r['N']} d={r['d']} dperp={r['dp']} "
              f"log2Ndperp={log2(r['Ndp']):.1f} D*={r['D']} dual={r['dual_bits']:.0f} t={r['t']}/{r['tcap']} msg={r['msg_bits']:.0f} key={r['key']/2**20:.2f}MiB")
