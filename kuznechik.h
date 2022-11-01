#ifndef _KUZNECHIK_H

#define _KUZNECHIK_H
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
static uint8_t GF256Mul(uint8_t x, uint8_t y);
static void SboxEncrypt(vector128bit * block);
static void RboxEncrypt(vector128bit * block);
static void LboxEncrypt(vector128bit * block);
static void SboxDecrypt(vector128bit * block);
static void LboxDecrypt(vector128bit * block);

#endif
