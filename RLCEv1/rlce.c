/* rlce.h
 * Copyright (C) February 2019 Yongge Wang
 * 
 * Yongge Wang
 * Department of Software and Information Systems
 * UNC Charlotte
 * Charlotte, NC 28223
 * yongge.wang@gmail.com
 */

#include "rlce.h"


static strvalue_t lookuptable[] = {
  {"genkey128", genkey128 },
  {"genkey192", genkey192},
  {"genkey256", genkey256},
  {"encr", encr},
  {"kemenc", kemenc},
  {"decr", decr} 
};

int comfromstring(char* com) {
  int i;
  int nOptions = sizeof(lookuptable)/sizeof(strvalue_t);
  for (i=0; i < nOptions; i++) {
    strvalue_t* sym = &lookuptable[i];
    if (strcmp(sym->key, com) == 0)
      return sym->val;
  }
  return BADCOMMANDLINEFLAG;
}

int main (int argc, char *argv[]) {
  int ret;
  if ( argc == 1 ) {
    printf("\nTo generate RLCE keys, use the command:\n");
    printf("    %s genkey128 KEYNAME\n", argv[0]);
    printf("    %s genkey192 KEYNAME\n", argv[0]);
    printf("    %s genkey256 KEYNAME\n", argv[0]);
    printf("To encrypt a message using RLCE only, use the command:\n");
    printf("    %s encr RLCE_PUBLIC_KEY_FILE FILE_TO_BE_ENCRYPTED\n", argv[0]);
    printf("To encrypt a message using RLCE-AES, use the command:\n");
    printf("    %s kemenc RLCE_PUBLIC_KEY_FILE FILE_TO_BE_ENCRYPTED\n", argv[0]);
    printf("To decrypt a message, use the command:\n");
    printf("    %s decr RLCE_PRIVETE_KEY_FILE FILE_TO_BE_DECRYPTED\n\n\n", argv[0]);
  } else {
    switch(comfromstring(argv[1])) {
    case genkey128:
      if (argc !=3) {
	printf("use command: %s genkey128 KEYNAME\n", argv[0]);
	exit(1);
      } 
      ret=rlce_keypair(0,argv[2]);
      if (ret <0) printf("error code %d\n", ret);
      printf("RLCE public/private key for security level 128 was generated!\n");
      exit(0);
    case genkey192:
      if (argc !=3) {
	printf("use command: %s genkey128 KEYNAME\n", argv[0]);
	exit(1);
      } 
      ret=rlce_keypair(1,argv[2]);
      if (ret <0) printf("error code %d\n", ret);
      printf("RLCE public/private key for security level 128 was generated!\n");
      exit(0);
    case genkey256:
      if (argc !=3) {
	printf("use command: %s genkey128 KEYNAME\n", argv[0]);
	exit(1);
      } 
      ret=rlce_keypair(2,argv[2]);
      if (ret <0) printf("error code %d\n", ret);
      printf("RLCE public/private key for security level 128 was generated!\n");
      exit(0);
    case encr:
      if (argc !=4) {
	printf("use command: %s encr RLCE_PUBLIC_KEY_FILE FILE_TO_BE_ENCRYPTED\n", argv[0]);
	exit(1);
      }
      ret=rlce_encrypt(0,argv[2],argv[3]);
      if (ret <0) printf("error code %d\n", ret);
      exit(0);
    case kemenc:
      if (argc !=4) {
	printf("use command: %s kemenc RLCE_PUBLIC_KEY_FILE FILE_TO_BE_ENCRYPTED\n", argv[0]);
	exit(1);
      }
      ret=rlce_encrypt(1, argv[2],argv[3]);
      if (ret <0) printf("error code %d\n", ret);
      exit(0);
    case decr:
      if (argc !=4) {
	printf("use command: %s decr RLCE_PRIVETE_KEY_FILE FILE_TO_BE_DECRYPTED\n", argv[0]);
	exit(1);
      }
      ret=rlce_decrypt(argv[2],argv[3]);
      if (ret <0) printf("error code %d\n", ret);
      exit(0);
    default:
      printf("the flag %s is not defined\n", argv[1]);
      return BADCOMMANDLINEFLAG;
    }
  }
  
  exit(0);
}


