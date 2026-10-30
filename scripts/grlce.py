"""gRLCE: generalized RLCE with an ARBITRARY hidden [n,k] code in place of GRS.
Stage 2 gate: is the pairing still information-theoretically determined?
Tests:
 (a) hidden dual subcode D still exists, dim w, orthogonal to public code
 (b) is D still anomalous?  (for GRS, dim D^*2 = 2w-1 << generic. For random hidden code?)
 (c) is the TRUE pairing still distinguishable from a random pairing by ANY invariant we have?
"""
import numpy as np, itertools
from ff import GF, square_dim
gf=GF(257); p=257

def rand_inv(k,rng):
    while True:
        S=rng.integers(0,p,size=(k,k),dtype=np.int64)
        if gf.rank(S)==k: return S
def inv(M):
    nn=M.shape[0]; R,piv=gf.rref(np.hstack([M%p,np.eye(nn,dtype=np.int64)])); return R[:,nn:]

def grlce(n,k,w,rng,hidden="random"):
    """hidden in {'random','grs'}"""
    if hidden=="grs":
        x=rng.choice(np.arange(1,p),size=n,replace=False).astype(np.int64)
        y=rng.integers(1,p,size=n,dtype=np.int64)
        Gs=np.zeros((k,n),dtype=np.int64); row=y.copy()
        for i in range(k): Gs[i]=row%p; row=(row*x)%p
    else:
        while True:
            Gs=rng.integers(0,p,size=(k,n),dtype=np.int64)
            if gf.rank(Gs)==k: break
    R=rng.integers(0,p,size=(k,w),dtype=np.int64)
    G1=np.hstack([Gs[:,:n-w]]+[np.column_stack([Gs[:,n-w+i],R[:,i]]) for i in range(w)])%p
    N=n+w
    A=np.eye(N,dtype=np.int64); As=[]
    for i in range(w):
        a=n-w+2*i
        while True:
            Ai=rng.integers(1,p,size=(2,2),dtype=np.int64)
            if (Ai[0,0]*Ai[1,1]-Ai[0,1]*Ai[1,0])%p!=0: break
        A[a:a+2,a:a+2]=Ai; As.append(Ai)
    perm2=rng.permutation(N); P2=np.zeros((N,N),dtype=np.int64)
    for i,j in enumerate(perm2): P2[i,j]=1
    S=rand_inv(k,rng)
    G=gf.matmul(gf.matmul(gf.matmul(S,G1),A),P2)
    return G,dict(Gs=Gs,R=R,A=A,As=As,P2=P2,perm2=perm2,n=n,k=k,w=w,N=N)

def hidden_D(sk):
    n,k,w,N=sk['n'],sk['k'],sk['w'],sk['N']
    Hs=gf.nullspace(sk['Gs'])
    U=np.zeros((Hs.shape[0],N),dtype=np.int64); U[:,:n-w]=Hs[:,:n-w]
    for i in range(w): U[:,n-w+2*i]=Hs[:,n-w+i]
    AP=gf.matmul(sk['A'],sk['P2'])
    return gf.matmul(U,inv(AP).T)

def pair_cons(sk):
    n,w,N=sk['n'],sk['w'],sk['N']; out=[]
    for i in range(w):
        a=n-w+2*i; v=(np.array([1,0])@inv(sk['As'][i].T))%p
        pa,pb=sk['perm2'][a],sk['perm2'][a+1]
        c=np.zeros(N,dtype=np.int64); c[pa]=v[1]; c[pb]=(-v[0])%p; out.append(c)
    return out
def constrained(Cp,cons):
    if not cons: return Cp
    xs=gf.nullspace(gf.matmul(np.array(cons),Cp.T)); return gf.matmul(xs,Cp)

n,k=40,32; w=n-k; N=n+w
for hidden in ["grs","random"]:
    G,sk=grlce(n,k,w,np.random.default_rng(21),hidden=hidden)
    Cp=gf.nullspace(G); D=hidden_D(sk); cons=pair_cons(sk)
    orth=bool(np.all(gf.matmul(G,D.T)%p==0))
    print(f"\n--- hidden={hidden} ---")
    print(f" dim D={gf.rank(D)} (w={w})  D orthogonal to C: {orth}")
    print(f" dim D^*2 = {square_dim(gf,D)}   GRS-value 2w-1={2*w-1}   generic for [n,w]={min(n,w*(w+1)//2)}")
    # (c) true pairing vs random pairing: residual square dim at full constraint
    Xt=constrained(Cp,cons); 
    rng=np.random.default_rng(5); 
    def wrongcons(j):
        out=[]
        for _ in range(j):
            a,b=rng.choice(N,2,replace=False); lam=int(rng.integers(1,p))
            c=np.zeros(N,dtype=np.int64); c[a]=lam; c[b]=p-1; out.append(c)
        return out
    Xw=constrained(Cp,wrongcons(w))
    print(f" full-constraint residual: TRUE dim={gf.rank(Xt)} sq={square_dim(gf,Xt)} | RANDOM dim={gf.rank(Xw)} sq={square_dim(gf,Xw)}")
    print(f"   -> pairing detectable by square test: {square_dim(gf,Xt)<square_dim(gf,Xw)}")
