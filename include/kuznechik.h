#ifndef _KUZNECHIK_H

#define _KUZNECHIK_H

#ifndef _STDINT_H 
#include <stdint.h>
#endif

#ifndef _STDIN_H 
#include <stdio.h>
#endif

#ifndef _STRING_H
#include <malloc.h> 
#endif

#ifndef _STRING_H
#include <string.h> 
#endif

#ifndef _PTHREAD_H
#include <pthread.h>
#endif

#if !defined(ENCRYPT) || !defined(DECRYPT)
#define ENCRYPT 1
#define DECRYPT -1
#endif

#define SIZE_BLOCK 16
#define PROC_ADD_NULLS_1 1
#define PROC_ADD_NULLS_2 2
#define PROC_ADD_NULLS_3 3
// ECB
#define CRYPT_BLOCK 2
#define START 1
#define WAIT 0
#define END -1
//IMITO
#define CREATE_KEY_1 1
#define CREATE_KEY_2 2

typedef union {
    uint8_t bytes[16];
    uint64_t half[2];
} vector128bit;

/// Functions from Kuznechik.c
int createIterationKeysKuz(vector128bit * key, vector128bit * array_for_keys);
int encryptBlockKuz(vector128bit * block, vector128bit * arr_keys);
int decryptBlockKuz(vector128bit * block, vector128bit * arr_keys);
uint64_t getSizeFile(FILE* input);
int readLastBlock(FILE* input, vector128bit * block, int mode_padding_nulls, uint8_t count_last_bytes);
void procPaddingNulls(uint8_t* data, int count_adding_bytes, int mode);
uint8_t getCountBytesInLastBlock(uint8_t* block);

#endif
//TODO: test ECB and change IMITO