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

typedef union
{
    uint8_t bytes[16];
    uint64_t half[2];
} vector128_t;

/// Functions from Kuznechik.c
int createIterationKeysKuz(vector128_t *key, vector128_t *array_for_keys);
int encryptBlockKuz(vector128_t *block, vector128_t *arr_keys);
int decryptBlockKuz(vector128_t *block, vector128_t *arr_keys);
uint64_t getSizeFile(FILE *input);
int readLastBlock(FILE *input, vector128_t *block, int mode_padding_nulls, uint8_t count_last_bytes);
void procPaddingNulls(uint8_t *data, int count_adding_bytes, int mode);
uint8_t getCountBytesInLastBlock(uint8_t *block);
// Functions from ECB.c
int encryptECBKuz(FILE *input, FILE *output, vector128_t *iteration_keys, int mode_padding_nulls, uint64_t size_input_file);
int decryptECBKuz(FILE *input, FILE *output, vector128_t *iteration_keys, int mode_padding_nulls, int length_last_block, uint64_t size_input_file);
// Functions from CBC.c
int encryptCBCKuz(FILE *input, FILE *output, vector128_t *iteration_keys, int mode_padding_nulls, int size_register_in_bytes, vector128_t *initial_vector, uint64_t size_input_file);
int decryptCBCKuz(FILE *input, FILE *output, vector128_t *iteration_keys, int mode_padding_nulls, int length_last_block, int size_register_in_bytes, vector128_t *initial_vector, uint64_t size_input_file);
// Functions from CTR.c
int encryptCTRKuz(FILE *input, FILE *output, vector128_t *iteration_keys, int size_block_in_bytes, vector128_t *initial_vector, uint64_t size_input_file);
int decryptCTRKuz(FILE *input, FILE *output, vector128_t *iteration_keys, int size_block_in_bytes, vector128_t *initial_vector, uint64_t size_input_file);
// Functions from OFB.c
int encryptOFBKuz(FILE *input, FILE *output, vector128_t *iteration_keys, int size_block_in_bytes, int size_register_in_bytes, vector128_t *initial_vector, uint64_t size_input_file);
int decryptOFBKuz(FILE *input, FILE *output, vector128_t *iteration_keys, int size_block_in_bytes, int size_register_in_bytes, vector128_t *initial_vector, uint64_t size_input_file);
// Functions from CFB.c
int encryptCFBKuz(FILE *input, FILE *output, vector128_t *iteration_keys, int size_block_in_bytes, int size_register_in_bytes, uint8_t *initial_vector, uint64_t size_input_file);
int decryptCFBKuz(FILE *input, FILE *output, vector128_t *iteration_keys, int size_block_in_bytes, int size_register_in_bytes, uint8_t *initial_vector, uint64_t size_input_file);
// Functions from IMITO.c
int createMAC(FILE *input, uint8_t *MAC, vector128_t *iteration_keys, uint8_t size_MAC, uint64_t size_input_file);