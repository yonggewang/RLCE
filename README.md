# RLCE
A project to develop post-quantum public encryption scheme

# How to: 
clone the entire RLCEv1 directory. Then run:

make  
./rlce

and follow the instructions

# Documentation
1. Yongge Wang: Random Linear Code Based Public Key Encryption Scheme RLCE. In Proc ISIT 2016. <https://arxiv.org/abs/1512.08454>
2. Yongge Wang: Decoding Generalized Reed-Solomon Codes and Its Application to RLCE Encryption Schemes. Manuscripts 2017. <http://arxiv.org/abs/1702.07737>
3. Yongge Wang. Revised Quantum Resistant Public Key Encryption Scheme RLCE and IND-CCA2 Security for McEliece Schemes <https://eprint.iacr.org/2017/206/>
4. Yongge Wang. RLCE Key Encapsulation Mechanism (RLCE-KEM) Specification [RLCEspec.pdf](https://github.com/yonggewang/RLCE/blob/master/RLCEspec.pdf)
5. Gretchen Mattthews and Yongge Wang. Quantum Resistant Public Key Encryption Scheme HermitianRLCE. Proc. Code Based Cryptography. 2019 <https://doi.org/10.1007/978-3-030-25922-8_1>
6. Liu, Jingang, Yongge Wang, Zongxinag Yi, and Dingyi Pei. "Quantum Resistant Public Key Encryption Scheme polarRLCE." In International Conference on Algebra, Codes and Cryptology, pp. 114-128. Springer, Cham, 2019. <https://link.springer.com/chapter/10.1007/978-3-030-36237-9_7>

# liboqsRLCE
This is the revised RLCE codes that could be integrated to [libOQS](https://github.com/open-quantum-safe/liboqs) project. There are some integrations of RLCE into OpenSSL and LibOQL. The examples are: 
* Mugove T. Kangai's 2018 integrated libOQS (https://github.com/mutapa/liboqs) with details (https://github.com/yonggewang/RLCE/blob/master/IntegrateRLCEOpenSSLversion1.0.2.pdf)
* Wagner, J. (2022). Integrating Random Linear Code Based Encryption Scheme Rlce Algorithm Into Post-quantum Openssl. Unc Charlotte Electronic Theses And Dissertations. (https://ninercommons.charlotte.edu/islandora/object/etd%3A3126)
