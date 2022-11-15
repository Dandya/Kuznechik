#pragma once

#ifndef _STDINT_H
#include <stdint.h>
#endif

#ifndef _STDIO_H 
#include <stdio.h>
#endif

#ifndef _STRING_H
#include <malloc.h> 
#endif

typedef union {
    uint8_t bytes[32];
    uint32_t dwords[8];
    uint64_t qwords[4]; 
} vector256_t;

typedef union {
    uint8_t bytes[64];
    uint32_t dwords[16];
    uint64_t qwords[8]; 
} vector512_t;

int sha256(uint8_t * array, uint64_t size_in_bytes, vector256_t * result);