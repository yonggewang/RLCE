/* config.h
 * Code was written: June 1, 2017
 * Copyright (C) 2017 Yongge Wang
 * Department of Software and Information Systems
 * UNC Charlotte
 * Charlotte, NC 28223
 * yonwang@uncc.edu
 */
#ifndef _CONFIGH_
#define _CONFIGH_

#define DECODINGMETHOD 1 /* 0:include S; 1: W^{-1}; 2: no help matrix  */
#define CRYPTO_SCHEME 0 /* 0 for AES128,1 for AES192,2 for AES256 */
#define CRYPTO_PADDING 1 /* 0, 1, 2, 3  */

/* FOLLOWING PARAMETER HAS BEEN OPTIMIZED FOR 64-BIT CPUS.                 *
 * DO NOT CHANGE UNLESS YOU ARE USING 32-BITS OR 16-BITS CPUS              */
#define STRASSENCONST 750 /* mat-dim below this use standard multi.        */
#define PARASIZE 20       /* plese do not change!!!!!                      */
#endif 
