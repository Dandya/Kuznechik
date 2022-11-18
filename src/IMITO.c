#include "../include/kuznechik.h"

static vector128_t createHelpingKey(vector128_t *arr_keys, int number_of_keys)
{
    vector128_t key;
    key.half[0] = 0;
    key.half[1] = 0;
    encryptBlockKuz(&key, arr_keys);

    if (((key.half[1] & ((uint64_t)1 << 63)) >> 63) == 0)
    {
        uint64_t tmp = key.half[0] >> 63;
        key.half[0] <<= 1;
        key.half[1] = key.half[1] << 1 | tmp;
    }
    else
    {
        uint64_t tmp = key.half[0] >> 63;
        key.half[0] = (key.half[0] << 1) ^ 0b10000111;
        key.half[1] = key.half[1] << 1 | tmp;
    }
    if (number_of_keys == CREATE_KEY_1)
    {
        return key; // K_1
    }
    // CREATE_KEY_2
    if (((key.half[1] & ((uint64_t)1 << 63)) >> 63) == 0)
    {
        uint64_t tmp = key.half[0] >> 63;
        key.half[0] <<= 1;
        key.half[1] = key.half[1] << 1 | tmp;
    }
    else
    {
        uint64_t tmp = key.half[0] >> 63;
        key.half[0] = (key.half[0] << 1) ^ 0b10000111;
        key.half[1] = key.half[1] << 1 | tmp;
    }
    return key; // K_2
}

int createMAC(FILE *input, uint8_t *MAC, vector128_t *iteration_keys, uint8_t size_MAC, uint64_t size_input_file)
{
    if (input == NULL)
    {
        return -1;
    }
    if (iteration_keys == NULL)
    {
        return -2;
    }
    if (MAC == NULL)
    {
        return -3;
    }
    if (size_MAC > 128 || size_MAC <= 0)
    {
        return -4;
    }
    if (size_input_file == 0)
    {
        return 0;
    }

    vector128_t *buffer;
    int buffer_size;
    if (size_input_file >= 1048576)
    {
        buffer_size = 1048576;
    }
    else
    {
        buffer_size = 1024;
    }
    buffer = (vector128_t *)malloc(buffer_size);
    if (buffer == NULL)
    {
        buffer_size = 0;
    }

    vector128_t imito;
    imito.half[0] = 0;
    imito.half[1] = 0;
    uint64_t count_blocks_in_buffer = buffer_size / SIZE_BLOCK;
    uint64_t count_buffers_for_crypt = 0;
    uint64_t iteration;
    if (buffer_size != 0)
    {
        // last iteration of algorithm creating imito uses last block
        count_buffers_for_crypt = (size_input_file % buffer_size != 0) ? size_input_file / buffer_size : size_input_file / buffer_size - 1;
        for (iteration = 0; iteration < count_buffers_for_crypt; iteration++)
        {
            if (fread(buffer, buffer_size, 1, input) != 1)
            {
                fprintf(stderr, "%d: Error in fread\n", __LINE__);
                free(buffer);
                return -1;
            }
            for (int i = 0; i < count_blocks_in_buffer; i++)
            {
                imito.half[0] ^= buffer[i].half[0];
                imito.half[1] ^= buffer[i].half[1];
                encryptBlockKuz(&imito, iteration_keys);
            }
        }
        free(buffer);
    }
    vector128_t block;
    int remainder = size_input_file % SIZE_BLOCK;
    // last iteration of algorithm creating imito uses last block
    uint64_t count_blocks_for_crypt = (remainder != 0) ? size_input_file / SIZE_BLOCK : size_input_file / SIZE_BLOCK - 1;
    for (iteration = count_buffers_for_crypt * count_blocks_in_buffer; iteration < count_blocks_for_crypt; iteration++)
    {
        if (fread(&block, SIZE_BLOCK, 1, input) != 1)
        {
            fprintf(stderr, "%d: Error in fread\n", __LINE__);
            return -1;
        }
        imito.half[0] ^= block.half[0];
        imito.half[1] ^= block.half[1];
        encryptBlockKuz(&imito, iteration_keys);
    }

    int result;
    vector128_t helping_key;
    if (remainder != 0)
    {
        result = readLastBlock(input, &block, PROC_ADD_NULLS_3, remainder);
        if (result == -1)
        {
            return -1;
        }
        helping_key = createHelpingKey(iteration_keys, CREATE_KEY_2);
    }
    else
    {
        if (fread(&block, SIZE_BLOCK, 1, input) != 1)
        {
            fprintf(stderr, "%d: Error in fread\n", __LINE__);
            return -1;
        }
        helping_key = createHelpingKey(iteration_keys, CREATE_KEY_1);
    }
    imito.half[0] ^= block.half[0];
    imito.half[1] ^= block.half[1];
    imito.half[0] ^= helping_key.half[0];
    imito.half[1] ^= helping_key.half[1];
    encryptBlockKuz(&imito, iteration_keys);
    int value_of_shift_right = 128 - size_MAC;
    for (int i = 0; i < value_of_shift_right; i++)
    {
        imito.half[0] = (imito.half[0] >> 1) | ((imito.half[1] & 1) << 63);
        imito.half[1] >>= 1;
    }
    uint8_t size_MAC_in_bytes = size_MAC / 8 + (size_MAC % 8 != 0 ? 1 : 0);
    for (int i = 0; i < size_MAC_in_bytes; i++)
    {
        MAC[i] = imito.bytes[i];
    }
    return 0;
}