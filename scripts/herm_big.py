"""Larger HermitianRLCE cubic-jet test at a chosen rate, using a subset of n points
of the genus-g Hermitian curve over GF(2^m).  char 2, uses rank2m.
usage: python3 herm_big.py q alpha n w k_l mode seed
"""
import sys, os, itertools, subprocess, numpy as np, galois
from hermitian import affine_points, lspace_basis, rlce_transform
SCR="/tmp/claude-0/-home-claude/eb45358c-0a59-5730-962a-e2da8f38d9ec/scratchpad/jet"

def gen_subset(GF,q,alpha,n,rng):
    pts=affine_points(GF,q)
    idx=rng.choice(len(pts),size=n,replace=False); pts=[pts[i] for i in idx]
    B=lspace_basis(q,alpha); k=len(B)
    G=GF.Zeros((k,n))
    for r,(i,j) in enumerate(B):
        col=GF([ (x**i)*(y**j) for (x,y) in pts ])
        G[r]=col
    return G,k

def shorten(GF,G,Z):
    L=G[:,Z].T.null_space(); Gs=L@G; keep=[c for c in range(G.shape[1]) if c not in set(Z)]
    return np.array(Gs)[:,keep]

def jet_build(GF,X,d,r):
    p=GF.characteristic; npts,kl=X.shape
    mons=list(itertools.combinations_with_replacement(range(kl),d))
    E=np.zeros((len(mons),kl),dtype=np.int64)
    for i,mon in enumerate(mons):
        for t in mon: E[i,t]+=1
    ders=list(itertools.combinations_with_replacement(range(kl),r-1))
    D=np.zeros((len(ders),kl),dtype=np.int64)
    for i,der in enumerate(ders):
        for t in der: D[i,t]+=1
    Nd=len(mons);nder=len(ders);rows=npts*nder
    FF=np.ones((d+1,r),dtype=np.int64)
    for e in range(d+1):
        for a in range(1,r): FF[e,a]=(FF[e,a-1]*(e-a+1))%p if a<=e else 0
    M=GF.Zeros((rows,Nd)); Xg=GF(np.array(X,dtype=np.int64))
    for jp in range(npts):
        x=Xg[jp]; PT=GF.Zeros((kl,d+1)); PT[:,0]=GF(1)
        for a in range(1,d+1): PT[:,a]=PT[:,a-1]*x
        for di in range(nder):
            a=D[di]; valid=np.all(E>=a[None,:],axis=1); coef=np.ones(Nd,dtype=np.int64)
            for t in range(kl):
                if a[t]: coef=(coef*FF[E[:,t],a[t]])%p
            row=GF(coef.astype(np.int64)%p); expo=E-a[None,:]
            for t in range(kl): row=row*PT[t,np.clip(expo[:,t],0,d)]
            row[~valid]=GF(0); row[coef%p==0]=GF(0); M[jp*nder+di]=row
    return M,rows,Nd

def main():
    q=int(sys.argv[1]);alpha=int(sys.argv[2]);n=int(sys.argv[3]);w=int(sys.argv[4]);kl=int(sys.argv[5])
    mode=sys.argv[6];seed=int(sys.argv[7])
    GF=galois.GF(q*q);g=q*(q-1)//2;m=int(round(np.log2(GF.order)));rng=np.random.default_rng(seed)
    G,k=gen_subset(GF,q,alpha,n,rng)
    if mode=='herm': Gp,sk=rlce_transform(GF,G,w,rng)
    elif mode=='randhidden': Gp,sk=rlce_transform(GF,GF(rng.integers(0,q*q,size=(k,n))),w,rng)
    else: Gp=GF(rng.integers(0,q*q,size=(k,n+w)))
    N=Gp.shape[1];l=k-kl;order=rng.permutation(N);Z=sorted(order[:l].tolist())
    Gsh=shorten(GF,Gp,Z);X=np.array(GF(np.array(Gsh).T))
    print(f"[build] q={q} g={g} alpha={alpha} k={k} n={n} w={w} N={N} k_l={kl} rate={k/n:.3f} {mode}",flush=True)
    M,rows,Nd=jet_build(GF,X,3,2)
    f=f"{SCR}/hb_{os.getpid()}.bin";os.makedirs(SCR,exist_ok=True)
    with open(f,'wb') as fh: np.array([rows,Nd],dtype=np.int64).tofile(fh);np.array(M,dtype=np.uint16).tofile(fh)
    print(f"[rank] {rows}x{Nd} ...",flush=True)
    out=subprocess.run(['./rank2m',f,str(m),str(int(GF.irreducible_poly)),str(int(GF.primitive_element))],capture_output=True,text=True)
    tok=dict(t.split('=') for t in out.stdout.split() if '=' in t);rk=int(tok['rank']);os.remove(f)
    print(f"RESULT q={q} alpha={alpha} k={k} n={n} w={w} k_l={kl} rate={k/n:.3f} {mode}: rows={rows} cols={Nd} rank={rk} EXCESS={rows-rk}",flush=True)

if __name__=='__main__': main()
