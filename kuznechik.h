#ifndef _STDINT_H 
#include <stdint.h>
#endif
#ifndef _STDIN_H 
#include <stdio.h>
#endif

typedef union {
    uint8_t bytes[16];
    uint64_t half[2];
} vector128bit;

/**
 * Functions from kuznechik.c
*/
static void Xbox(vector128bit * block, vector128bit key);
static void SboxEncrypt(vector128bit * block);
static void LboxEncrypt(vector128bit * block);
static void SboxDecrypt(vector128bit * block);
static void LboxDecrypt(vector128bit * block);

