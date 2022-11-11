#ifndef _KUZNECHIK_H
#include "../include/kuznechik.h"
#endif

/// @brief Function encrypt file and write result using ECB algorithm from GOST 34.13-2018. Standart use PROC_PADDING_NULLS_2.
/// @param input is pointer of structure which defines file.
/// @param output is pointer of structure which defines file.
/// @param key is pointer on block of memory of size 256 bit.
/// @param mode_padding_nulls is function using which  bytes are padded in last block.
/// @param size_register_in_bytes is size of register in bytes which is a multiple of 16.
/// @param initial_vector is array which haves size of size_register_in_bytes and stores the random value.
/// @return 0 is good, -1 is key = NULL, -2 is error of read or write file, -5 is.
int encryptCBCKuz(FILE* input, FILE* output, vector128bit * key, int mode_padding_nulls, 
    int size_register_in_bytes, vector128bit * initial_vector) {
    if( key == NULL )                              { return -1; }
    if( input == NULL || output == NULL )          { return -2; }
    if( size_register_in_bytes % SIZE_BLOCK != 0 ) { return -3; }
    if( initial_vector == NULL)                    { return -4; }
    if( mode_padding_nulls != PROC_ADD_NULLS_1 && 
        mode_padding_nulls != PROC_ADD_NULLS_2 && 
        mode_padding_nulls != PROC_ADD_NULLS_3 ) { mode_padding_nulls = PROC_ADD_NULLS_2; }

    uint64_t size_input_file = getSizeFile(input);
    if( size_input_file == 0 ) { return 0; }

    
    vector128bit iteration_keys[10];
    int result = createIterationKeysKuz(key, iteration_keys);
    if( result < 0 ) { 
        fprintf(stderr, "error create iteration keys\n");
        return result; 
    }

    int count_blocks_in_register = size_register_in_bytes / SIZE_BLOCK;
    vector128bit * regist = (vector128bit *)malloc(size_register_in_bytes);
    if( regist == NULL ) {  return -5; }
    for( int i = 0; i < count_blocks_in_register; i++ ) {
        regist[i] = initial_vector[i];
    }
    int index_block_in_register = count_blocks_in_register - 1;

    vector128bit * buffer;
    int buffer_size;
    if( size_input_file >= 1048576) { buffer_size = 1048576; } 
    else { buffer_size = 1024; }
    buffer = (vector128bit *)malloc(buffer_size);
    if( buffer == NULL ) { buffer_size = 0; }
    
    uint64_t count_blocks_in_buffer = buffer_size/SIZE_BLOCK;
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
                buffer[i].half[0] ^= regist[index_block_in_register].half[0];
                buffer[i].half[1] ^= regist[index_block_in_register].half[1];
                encryptBlockKuz(buffer+i, iteration_keys);
                regist[index_block_in_register] = buffer[i];
                if(--index_block_in_register == -1) { 
                    index_block_in_register = count_blocks_in_register - 1;
                }
            }
            if( fwrite(buffer, buffer_size, 1, output) != 1) { 
                fprintf(stderr, "%d: Error in fwrite\n", __LINE__);
                return -2; 
            }
        }
        free(buffer);
    }
    vector128bit block;
    uint64_t count_full_blocks = size_input_file/SIZE_BLOCK;
    for(iteration = count_full_buffers * count_blocks_in_buffer; iteration < count_full_blocks; iteration++) {
        if( fread(&block, SIZE_BLOCK, 1, input) != 1 ) {
            fprintf(stderr,"%d: Error in fread\n", __LINE__);
            return -2;
        }
        block.half[0] ^= regist[index_block_in_register].half[0];
        block.half[1] ^= regist[index_block_in_register].half[1];
        encryptBlockKuz(&block, iteration_keys);
        regist[index_block_in_register] = block;
        if(--index_block_in_register == -1) { 
            index_block_in_register = count_blocks_in_register - 1;
        }
        if( fwrite(&block, SIZE_BLOCK, 1, output) != 1) { 
            fprintf(stderr, "%d: Error in fwrite\n", __LINE__);
            return -2; 
        }
    }

    
    uint8_t count_last_bytes = size_input_file % SIZE_BLOCK;
    if( count_last_bytes != 0 ) {
        result = readLastBlock(input, &block, mode_padding_nulls, count_last_bytes);
        if( result == -2 )  { return -2; }
        block.half[0] ^= regist[index_block_in_register].half[0];
        block.half[1] ^= regist[index_block_in_register].half[1];
        encryptBlockKuz(&block, iteration_keys);
        if( fwrite(&block, SIZE_BLOCK, 1, output) != 1) { 
            fprintf(stderr, "%d: Error in fwrite\n", __LINE__);
            return -2; 
        }
    } else if( mode_padding_nulls == PROC_ADD_NULLS_2 ){
        block.half[0] = 0x0000000000000001 ^ regist[index_block_in_register].half[0];
        block.half[1] = regist[index_block_in_register].half[1];
        encryptBlockKuz(&block, iteration_keys);
        if( fwrite(&block, SIZE_BLOCK, 1, output) != 1) { 
            fprintf(stderr, "%d: Error in fwrite\n", __LINE__);
            return -2; 
        }
    }

    free(regist);
    return 0;
}

/// @brief Function decrypt file and write result using ECB algorithm from GOST 34.13-2018.
/// @param input is pointer of structure which defines file.
/// @param output is pointer of structure which defines file.
/// @param key is pointer on block of memory of size 256 bit.
/// @param mode_padding_nulls is function using which  bytes are padded in last block.
/// @param length_last_block is count of bytes in last block for PROC_ADD_NULLS_1. 
///     If mode_padding_nulls != PROC_ADD_NULLS_1 then this parameter is ignored.
/// @return 0 is good, -1 is key = NULL, -2 is error of read or write file, 
///     -3 if using PROC_ADD_NULLS_1 and length_last_block > 16 or length_last_block <= 0.
int decryptCBCKuz(FILE* input, FILE* output, vector128bit * key, int mode_padding_nulls, int length_last_block, 
    int size_register_in_bytes, vector128bit * initial_vector)
{
    if( key == NULL )                                        { return -1; }
    if( input == NULL || output == NULL )                    { return -2; }
    if( mode_padding_nulls == PROC_ADD_NULLS_1 && 
        (length_last_block <= 0 || length_last_block > 16) ) { return -3; }
    if( size_register_in_bytes % SIZE_BLOCK != 0 )           { return -4; }
    if( initial_vector == NULL)                              { return -5; }
    if( mode_padding_nulls != PROC_ADD_NULLS_1 && 
        mode_padding_nulls != PROC_ADD_NULLS_2 && 
        mode_padding_nulls != PROC_ADD_NULLS_3 ) { mode_padding_nulls = PROC_ADD_NULLS_2; }

    uint64_t size_input_file = getSizeFile(input);
    if( size_input_file == 0 ) { return 0; }

    vector128bit iteration_keys[10];
    int result = createIterationKeysKuz(key, iteration_keys);
    if( result < 0 ) { 
        fprintf(stderr, "error create iteration keys\n");
        return result; 
    }

    int count_blocks_in_register = size_register_in_bytes / SIZE_BLOCK;
    vector128bit * regist = (vector128bit *)malloc(size_register_in_bytes);
    vector128bit tmp_block;
    if( regist == NULL ) {  return -5; }
    for( int i = 0; i < count_blocks_in_register; i++ ) {
        regist[i] = initial_vector[i];
    }
    int index_block_in_register = count_blocks_in_register - 1;

    vector128bit * buffer;
    int buffer_size;
    if( size_input_file >= 1048576) { buffer_size = 1048576; } 
    else { buffer_size = 1024; }
    buffer = (vector128bit *)malloc(buffer_size);
    if( buffer == NULL ) { buffer_size = 0; }

    uint64_t count_blocks_in_buffer = buffer_size/SIZE_BLOCK;
    uint64_t count_full_buffers = 0;
    uint64_t iteration;
    if(buffer_size != 0) {
        // in DECRYPT mode last full block decrypt using deletion of padding nulls
        count_full_buffers = (size_input_file % buffer_size == 0) ? size_input_file/buffer_size - 1 : size_input_file/buffer_size;  
        for(iteration = 0; iteration < count_full_buffers; iteration++) {
            if( fread(buffer, buffer_size, 1, input) != 1 ) { 
                fprintf(stderr, "%d: Error in fread\n", __LINE__);
                return -2; 
            }
            for(int i = 0; i < count_blocks_in_buffer; i++) {
                tmp_block = buffer[i];
                decryptBlockKuz(buffer+i, iteration_keys);
                buffer[i].half[0] ^= regist[index_block_in_register].half[0];
                buffer[i].half[1] ^= regist[index_block_in_register].half[1];
                regist[ index_block_in_register ] = tmp_block;
                if(--index_block_in_register == -1) { 
                    index_block_in_register = count_blocks_in_register - 1;
                }
            }
            if( fwrite(buffer, buffer_size, 1, output) != 1) { 
                fprintf(stderr, "%d: Error in fwrite\n", __LINE__);
                return -2; 
            }
        }
        free(buffer);
    }
    vector128bit block;
    // in DECRYPT mode last full block decrypt using deletion of padding nulls 
    uint64_t count_blocks_for_decrypt = size_input_file/SIZE_BLOCK - 1;
    for(iteration = count_full_buffers * count_blocks_in_buffer; iteration < count_blocks_for_decrypt; iteration++) {
        if( fread(&block, SIZE_BLOCK, 1, input) != 1 ) {
            fprintf(stderr,"%d: Error in fread\n", __LINE__);
            return -2;
        }
        tmp_block = block;
        decryptBlockKuz(&block, iteration_keys);
        block.half[0] ^= regist[index_block_in_register].half[0];
        block.half[1] ^= regist[index_block_in_register].half[1];
        regist[ index_block_in_register ] = tmp_block;
        if(--index_block_in_register == -1) { 
            index_block_in_register = count_blocks_in_register - 1;
        }
        if( fwrite(&block, SIZE_BLOCK, 1, output) != 1) { 
            fprintf(stderr, "%d: Error in fwrite\n", __LINE__);
            return -2; 
        }
    }

    if( fread(&block, SIZE_BLOCK, 1, input) != 1 ) {
        fprintf(stderr, "%d: Error in fread\n", __LINE__);
        return -2;
    }
    decryptBlockKuz(&block, iteration_keys);
    block.half[0] ^= regist[index_block_in_register].half[0];
    block.half[1] ^= regist[index_block_in_register].half[1];
    if( mode_padding_nulls == PROC_ADD_NULLS_1 ) { result = length_last_block; }
    else { result = getCountBytesInLastBlock((uint8_t*)&block); }
    if( result != 0 ) {
        if( fwrite(&block, result, 1, output) != 1 ) { 
            fprintf(stderr, "%d: Error in fwrite\n", __LINE__);
            return -2; 
        }
    }

    free(regist);
    return 0;
}