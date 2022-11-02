#ifndef _KUZNECHIK_H
#define _KUZNECHIK_H
#ifndef _STDINT_H 
#include <stdint.h>
#endif
#ifndef _STDIN_H 
#include <stdio.h>
#endif

#if !defined(ENCRYPT) || !defined(DECRYPT)
#define ENCRYPT 1
#define DECRYPT -1
#endif

typedef union {
    uint8_t bytes[16];
    uint64_t half[2];
} vector128bit;

/**
 * Functions from kuznechik.c
*/


#endif
