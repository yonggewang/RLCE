"""Number of minimum-weight codewords of a polar (decreasing-monomial) code and of its dual.
Candidate formula (Bardet-Dragoi-Otmani-Tillich): sum over max-degree monomials f in the code of
|Orb_LTA(f)| = 2^{r + |lambda_f|}.  We test conventions against exact enumeration."""
import numpy as np, itertools
from polar import Fkron, left_null_f2
from polar_reliab import order

def exact_count(G):
    k,n=G.shape; rows=[]
    for r in range(k):
        x=0
        for c in range(n):
            if G[r,c]&1: x|=1<<c
        rows.append(x)
    best=n+1; cnt=0; acc=0
    for i in range(1,1<<k):
        b=(i&-i).bit_length()-1; acc^=rows[b]; w=acc.bit_count()
        if w<best: best,cnt=w,1
        elif w==best: cnt+=1
    return best,cnt

def formula_count(m, idxset, conv):
    """idxset: row indices of F^{otimes m} spanning the code.  Monomial of index i: variables at
    the ZERO bits of i (degree m-pc(i), evaluation weight 2^{pc(i)}).  conv selects how variable
    positions are numbered for lambda."""
    pcs={i:bin(i).count('1') for i in idxset}
    pmin=min(pcs.values()); r=m-pmin
    tot=0
    for i in idxset:
        if pcs[i]!=pmin: continue
        zeros=[j for j in range(m) if not (i>>j)&1]          # variables of the monomial
        if conv==1: js=sorted(zeros)
        else:       js=sorted(m-1-j for j in zeros)
        lam=sum(js[l]-l for l in range(r))
        tot+=2**(r+lam)
    return 1<<pmin, tot

if __name__=="__main__":
    res={1:0,2:0}; tests=0
    for m in (4,5,6):
        n=1<<m; o=order(m)
        for k in range(2,n-1):
            I=sorted(o[:k].tolist()); F=sorted(o[k:].tolist())
            G=Fkron(m)[I]%2
            cases=[]
            if k<=18: cases.append(("primal",G,I))
            if n-k<=18:
                J=[(n-1)^i for i in F]                           # dual = span of rows J
                cases.append(("dual",Fkron(m)[J]%2,J))
            for lab,M,S in cases:
                d,c=exact_count(M)
                tests+=1
                for conv in (1,2):
                    fd,fc=formula_count(m,S,conv)
                    if (fd,fc)==(d,c): res[conv]+=1
    print("tests:",tests,"matches conv1:",res[1],"conv2:",res[2])
