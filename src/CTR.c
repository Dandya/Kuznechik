#ifndef _KUZNECHIK_H
#include "../include/kuznechik.h"
#endif

static void addOne(vector128bit * a) {
    static uint64_t tmp = a->half[0];
    a->half[0] += 1;
    if( tmp > a->half[0] ) { 
        a->half[1] += 1; 
    }
}

/// @brief Function encrypt file and write result using ECB algorithm from GOST 34.13-2018. Standart use PROC_PADDING_NULLS_2.
/// @param input is pointer of structure which defines file.
/// @param output is pointer of structure which defines file.
/// @param key is pointer on block of memory of size 256 bit.
/// @param mode_padding_nulls is function using which  bytes are padded in last block.
/// @param size_register_in_bytes is size of register in bytes which is a multiple of 16.
/// @param initial_vector is array which haves size of size_register_in_bytes and stores the random value.
/// @return 0 is good, -1 is key = NULL, -2 is error of read or write file, -5 is.
int encryptCTRKuz(FILE* input, FILE* output, vector128bit * key, int size_block_in_bytes, vector128bit * initial_vector) {
    if( key == NULL )                              { return -1; }
    if( input == NULL || output == NULL )          { return -2; }
    if( size_block_in_bytes > 16 || size_block_in_bytes <= 0 ) { return -3; }
    if( initial_vector == NULL)                    { return -4; }

    uint64_t size_input_file = getSizeFile(input);
    if( size_input_file == 0 ) { return 0; }

    
    vector128bit iteration_keys[10];
    int result = createIterationKeysKuz(key, iteration_keys);
    if( result < 0 ) { 
        fprintf(stderr, "error create iteration keys\n");
        return result; 
    }

    vector128bit gamma;
    gamma.half[0] = 0;
    gamma.half[1] = initial_vector->half[0];
    vector128bit gamma_for_encrypt;
    int index_of_start = SIZE_BLOCK - size_block_in_bytes;

    uint8_t * buffer;
    int buffer_size;
    if( size_input_file >= 1048576) { buffer_size = 1048576 - 1048576%size_block_in_bytes; } 
    else { buffer_size = 1024 - 1024%size_block_in_bytes; } 
    buffer = (uint8_t *)malloc(buffer_size);
    if( buffer == NULL ) { buffer_size = 0; }
    
    uint64_t count_blocks_in_buffer = buffer_size/size_block_in_bytes;
    uint64_t count_full_buffers = 0;
    uint64_t iteration;
    if(buffer_size != 0) {
        count_full_buffers = size_input_file/buffer_size;  
        for(iteration = 0; iteration < count_full_buffers; iteration++) {
            if( fread(buffer, buffer_size, 1, input) != 1 ) { 
                fprintf(stderr, "%d: Error in fread\n", __LINE__);
                return -2; 
            }
            for(int i = 0; i < count_blocks_in_buffer; i++) {
                gamma_for_encrypt = gamma;
                encryptBlockKuz(&gamma_for_encrypt, iteration_keys);
                for(int k = 0; k < size_block_in_bytes; k++) {
                    buffer[i*size_block_in_bytes + k] ^= gamma_for_encrypt.bytes[index_of_start + k];
                }
                addOne(&gamma);
            }
            if( fwrite(buffer, buffer_size, 1, output) != 1) { 
                fprintf(stderr, "%d: Error in fwrite\n", __LINE__);
                return -2; 
            }
        }
        free(buffer);
    }
    vector128bit block;
    uint64_t count_full_blocks = size_input_file/size_block_in_bytes;
    for(iteration = count_full_buffers * count_blocks_in_buffer; iteration < count_full_blocks; iteration++) {
        if( fread(&block, size_block_in_bytes, 1, input) != 1 ) {
            fprintf(stderr,"%d: Error in fread\n", __LINE__);
            return -2;
        }
        gamma_for_encrypt = gamma;
        encryptBlockKuz(&gamma_for_encrypt, iteration_keys);
        for(int k = 0; k < size_block_in_bytes; k++) {
            block.bytes[k] ^= gamma_for_encrypt.bytes[index_of_start + k];
        }
        addOne(&gamma);
        if( fwrite(&block, size_block_in_bytes, 1, output) != 1) { 
            fprintf(stderr, "%d: Error in fwrite\n", __LINE__);
            return -2; 
        }
    }

    int count_last_bytes = size_input_file % size_block_in_bytes;
    if( count_last_bytes != 0 ) {
        if( fread(&block, count_last_bytes, 1, input) != 1 ) {
            fprintf(stderr,"%d: Error in fread\n", __LINE__);
            return -2;
        }
        gamma_for_encrypt = gamma;
        encryptBlockKuz(&gamma_for_encrypt, iteration_keys);
        for(int k = 0; k < count_last_bytes; k++) {
            block.bytes[k] ^= gamma_for_encrypt.bytes[index_of_start + k];
        }
        if( fwrite(&block, count_last_bytes, 1, output) != 1) { 
            fprintf(stderr, "%d: Error in fwrite\n", __LINE__);
            return -2; 
        }
    }
    
    return 0;
}

int decryptCTRKuz(FILE* input, FILE* output, vector128bit * key, int size_block_in_bytes, vector128bit * initial_vector) {
    return encryptCTRKuz(input, output, key, size_block_in_bytes, initial_vector);
}