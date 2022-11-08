#ifndef _KUZNECHIK_H
#include "../include/kuznechik.h"
#endif

static vector128bit createHelpingKey(vector128bit * arr_keys, int number_of_keys) {
    vector128bit key; 
    key.half[0] = 0; 
    key.half[1] = 0;
    encryptBlockKuz(&key, arr_keys);
    
    if(((key.half[1] & (1<<63))>>63) == 0) {
        uint64_t tmp = key.half[0]>>63;
        key.half[0] <<= 1;
        key.half[1] = key.half[1]<<1 | tmp;
    } else {
        uint64_t tmp = key.half[0]>>63;
        key.half[0] = (key.half[0]<<1)^0b10000111;
        key.half[1] = key.half[1]<<1 | tmp;
    }
    if(numberOfKeyToCreate == CREATE_KEY_1) {
        return key; // K_1
    }
    // CREATE_KEY_2
   if(((key.half[1] & (1<<63))>>63) == 0) {
        uint64_t tmp = key.half[0]>>63;
        key.half[0] <<= 1;
        key.half[1] = key.half[1]<<1 | tmp;
    } else {
        uint64_t tmp = key.half[0]>>63;
        key.half[0] = (key.half[0]<<1)^0b10000111;
        key.half[1] = key.half[1]<<1 | tmp;
    }
    return key; // K_2
}

vector128bit getMAC(FILE * input, vector128bit * key , uint8_t size_MAC)
{
    if( key == NULL )                   { return -1; }
    if(input == NULL)                   { return -2; }
    if(size_MAC > 128 || size_MAC <= 0) { return -3; }
    
    uint64_t size_input_file = getSizeFile(input);
    if( size_input_file == 0 ) { return 0; }
    
    vector128bit * buffer;
    int buffer_size;
    if( size_input_file >= 1048576) { buffer_size = 1048576; } 
    else { buffer_size = 1024; }
    buffer = (vector128bit *)malloc(buffer_size);
    if( buffer == NULL ) { buffer_size = 0; }
    
    
    vector128bit iteration_keys[10];
    int result = createIterationKeysKuz(key, iteration_keys);
    if( result < 0 ) { 
        fprintf(stderr, "Error create iteration keys\n");
        return result; 
    }

    vector128bit imito;
    imito.half[0] = 0;
    imito.half[1] = 0;    
    uint64_t count_blocks_in_buffer = buffer_size/SIZE_BLOCK;
    uint64_t count_buffers_for_crypt = 0;
    uint64_t iteration;
    if(buffer_size != 0) {
        // last iteration of algorithm creating imito uses last block
        count_buffers_for_crypt = (size_input_file % buffer_size != 0) ?  size_input_file/buffer_size : size_input_file/buffer_size - 1;  
        for(iteration = 0; iteration < count_buffers_for_crypt; iteration++) {
            if( fread(buffer, buffer_size, 1, input) != 1 ) { 
                fprintf(stderr, "%d: Error in fread\n", __LINE__);
                return -2; 
            }
            for(int i = 0; i < count_blocks_in_buffer; i++) {
                imito.half[0] ^= buffer[i].half[0];
                imito.half[1] ^= buffer[i].half[1];
                encryptBlockKuz(&imito, iteration_keys);
            }
        }
        free(buffer);
    }
    vector128bit block;
    int remainder = size_input_file % SIZE_BLOCK;
    // last iteration of algorithm creating imito uses last block
    uint64_t count_blocks_for_crypt = (remainder != 0) ? size_input_file/SIZE_BLOCK : size_input_file/SIZE_BLOCK - 1;
    for(iteration = count_buffers_for_crypt * count_blocks_in_buffer; iteration < count_blocks_for_crypt; iteration++) {
        if( fread(&block, SIZE_BLOCK, 1, input) != 1 ) {
            fprintf(stderr,"%d: Error in fread\n", __LINE__);
            return -2;
        }
        imito.half[0] ^= buffer[i].half[0];
        imito.half[1] ^= buffer[i].half[1];
        encryptBlockKuz(&imito, iteration_keys);
    }

    vector128bit helping_key;
    if(remainder != 0)
    {
        result = readLastBlock(input, &block, PROC_ADD_NULLS_3, remainder);
        if( result == -2 ) { return -2; }
        helping_key = createHelpingKey(iteration_keys, CREATE_KEY_2);
    }
    else
    {
        if( fread(&block, SIZE_BLOCK, 1, input) != 1) { 
            fprintf(stderr,"%d: Error in fread\n", __LINE__);
            return -2;
        }
        helping_key = createHelpingKey(iteration_keys, CREATE_KEY_1);
    }
    imito.half[0] ^= block.half[0];
    imito.half[1] ^= block.half[1];
    imito.half[0] ^= helping_key.half[0];
    imito.half[1] ^= helping_key.half[1];
    encryptBlockKuz(&imito, iteration_keys);
    int value_of_shift_right = 128 - size_MAC;
    for(int i = 0; i < value_of_shift_right; i++) {
        imito.half[0] = (imito.half[0]>>1) | ((imito.half[1]&1)<<63);
        imito.half[1] >>= 1; 
    }
    return imito;
}