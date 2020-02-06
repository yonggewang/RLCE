# RLCE.tar - Random Linear Code Encryption Scheme
# Copright (C) 2017 Yongge Wang
# 
# Yongge Wang
# Department of Software and Information Systems
# UNC Charlotte
# Charlotte, NC 28223
# yonwang@uncc.edu

RANLIB = ranlib
AR = ar
VERSION = v1
DIRNAME = RLCE$(VERSION)
CC = gcc
DEBUG_FLAGS = -g
INCLUDE := -I.
LIBDIR = lib/
CFLAGS = -Wall -Wstrict-prototypes  $(OPTIMIZE_FLAGS) $(DEBUG_FLAGS)  $(INCLUDE)

LIB_CSRC = reedsolomon.c GaloisField.c fieldPoly.c bta.c list.c fieldMatrix.c sha.c drbg.c rlce.c test.c aes.c FFT.c encrypt.c kem.c
LIB_HSRC = rlce.h api.h
LIB_OBJS = reedsolomon.o GaloisField.o fieldPoly.o bta.o list.o fieldMatrix.o sha.o drbg.o rlce.o test.o aes.o FFT.o encrypt.o kem.o

TARGET_LIB = libRLCE.a
TEST_PROGS = example NISTexample

TARGETS = $(TARGET_LIB) $(TEST_PROGS)

all: $(TARGETS)


$(TARGET_LIB): $(LIB_OBJS)
	$(RM) $@
	$(AR) cq $@ $(LIB_OBJS)
	if [ "$(RANLIB)" ]; then $(RANLIB) $@; fi

example: example.o
	gcc -o example example.o -L. -lRLCE -lm
NISTexample: NISTexample.o
	gcc -o NIST NISTexample.o -L. -lRLCE -lm

clean:
	rm -f *.o example NIST libRLCE.a *~

dist:
	(cd ..; tar -cvf RLCE$(VERSION).tar $(DIRNAME); rm RLCE$(VERSION).tar.gz; gzip RLCE$(VERSION).tar)

depend:
	makedepend $(SRCS)

