"""Underflow-free polar construction for BEC(1/2).
Track a=log Z, b=log(1-Z).  Children of Z (Arikan order: [upper, lower]):
  upper  Z'=2Z-Z^2=Z(2-Z):      a'=a+log1p(e^b),  b'=2b
  lower  Z''=Z^2:               a''=2a,           b''=log(1-Z^2)=b+log1p(e^a)
All four are cancellation-free.  Key: logit(Z)=a-b, monotone in Z, finite in both tails."""
import numpy as np
def bec_logit(m):
    a = np.array([np.log(0.5)]); b = np.array([np.log(0.5)])
    for _ in range(m):
        au = a + np.log1p(np.exp(b)); bu = 2*b
        al = 2*a;                     bl = b + np.log1p(np.exp(a))
        a = np.concatenate([au, al]); b = np.concatenate([bu, bl])
    return a - b
def order(m):
    return np.argsort(bec_logit(m), kind='stable')
def info_set(m, k):
    return np.sort(order(m)[:k])
def popcounts(m):
    idx = np.arange(1 << m, dtype=np.int64); pc = np.zeros(1 << m, dtype=np.int64)
    for j in range(m): pc += (idx >> j) & 1
    return pc
def dists(m, k):
    o = order(m); pc = popcounts(m); I, F = o[:k], o[k:]
    d = 1 << int(pc[I].min())
    dperp = (1 << (m - int(pc[F].max()))) if len(F) else (1 << m)
    return d, dperp
