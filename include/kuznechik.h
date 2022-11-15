#pragma once

#ifndef _STDINT_H 
#include <stdint.h>
#endif

#ifndef _STDIO_H 
#include <stdio.h>
#endif

#ifndef _MALLOC_H
#include <malloc.h> 
#endif

#ifndef _STRING_H
#include <string.h> 
#endif

#if !defined(ENCRYPT) || !defined(DECRYPT)
#define ENCRYPT 1
#define DECRYPT -1
#endif

#define SIZE_BLOCK 16
#define PROC_ADD_NULLS_1 1
#define PROC_ADD_NULLS_2 2
#define PROC_ADD_NULLS_3 3

// Modes of encryption 
#define ECB 1
#define CBC 2 
#define CTR 3 
#define OFB 4 
#define CFB 5 
#define IMITO 6

// IMITO
#define CREATE_KEY_1 1
#define CREATE_KEY_2 2

typedef union {
    uint8_t bytes[16];
    uint64_t half[2];
} vector128_t;

/// Functions from Kuznechik.c
int createIterationKeysKuz(vector128_t * key, vector128_t * array_for_keys);
int encryptBlockKuz(vector128_t * block, vector128_t * arr_keys);
int decryptBlockKuz(vector128_t * block, vector128_t * arr_keys);
uint64_t getSizeFile(FILE* input);
int readLastBlock(FILE* input, vector128_t * block, int mode_padding_nulls, uint8_t count_last_bytes);
void procPaddingNulls(uint8_t* data, int count_adding_bytes, int mode);
uint8_t getCountBytesInLastBlock(uint8_t* block);

