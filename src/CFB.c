#include "../include/kuznechik.h"

static vector128_t getBlock(uint8_t *regist, int size_regist_in_bytes, int index_gamma_in_register, int size_block_in_bytes)
{
    vector128_t block128bit;
    int index_start_block = index_gamma_in_register - (SIZE_BLOCK - size_block_in_bytes);
    if (index_start_block < 0)
    {
        index_start_block = size_block_in_bytes - index_start_block;
    }
    for (int i = 0; i < SIZE_BLOCK; i++)
    {
        block128bit.bytes[i] = regist[(index_start_block + i) % size_regist_in_bytes];
    }
    return block128bit;
}

int encryptCFBKuz(FILE *input, FILE *output, vector128_t *iteration_keys, int size_block_in_bytes,
                  int size_register_in_bytes, uint8_t *initial_vector, uint64_t size_input_file)
{
    if (input == NULL || output == NULL)
    {
        return -1;
    }
    if (iteration_keys == NULL)
    {
        return -2;
    }
    if (size_block_in_bytes > 16 || size_block_in_bytes <= 0)
    {
        return -3;
    }
    if (size_register_in_bytes < SIZE_BLOCK)
    {
        return -4;
    }
    if (initial_vector == NULL)
    {
        return -5;
    }
    if (size_input_file == 0)
    {
        return 0;
    }

    uint8_t *regist = (uint8_t *)malloc(size_register_in_bytes);
    if (regist == NULL)
    {
        return -5;
    }
    for (int i = 0; i < size_register_in_bytes; i++)
    {
        regist[i] = initial_vector[i];
    }
    int index_gamma_in_register = size_register_in_bytes - size_block_in_bytes;
    int index_of_start = SIZE_BLOCK - size_block_in_bytes;

    uint8_t *buffer;
    int buffer_size;
    if (size_input_file >= 1048576)
    {
        buffer_size = 1048576 - 1048576 % size_block_in_bytes;
    }
    else
    {
        buffer_size = 1024 - 1024 % size_block_in_bytes;
    }
    buffer = (uint8_t *)malloc(buffer_size);
    if (buffer == NULL)
    {
        buffer_size = 0;
    }

    uint64_t count_blocks_in_buffer = buffer_size / size_block_in_bytes;
    uint64_t count_full_buffers = 0;
    uint64_t iteration;
    vector128_t tmp_block_128b;
    if (buffer_size != 0)
    {
        count_full_buffers = size_input_file / buffer_size;
        for (iteration = 0; iteration < count_full_buffers; iteration++)
        {
            if (fread(buffer, buffer_size, 1, input) != 1)
            {
                fprintf(stderr, "%d: Error in fread\n", __LINE__);
                free(buffer);
                free(regist);
                return -1;
            }
            for (int i = 0; i < count_blocks_in_buffer; i++)
            {
                tmp_block_128b = getBlock(regist, size_register_in_bytes, index_gamma_in_register, size_block_in_bytes);
                encryptBlockKuz(&tmp_block_128b, iteration_keys);
                for (int k = 0; k < size_block_in_bytes; k++)
                {
                    buffer[i * size_block_in_bytes + k] ^= tmp_block_128b.bytes[index_of_start + k];
                    regist[(index_gamma_in_register + k) % size_register_in_bytes] = buffer[i * size_block_in_bytes + k];
                }
                index_gamma_in_register -= size_block_in_bytes;
                if (index_gamma_in_register < 0)
                {
                    index_gamma_in_register = size_register_in_bytes + index_gamma_in_register;
                }
            }
            if (fwrite(buffer, buffer_size, 1, output) != 1)
            {
                fprintf(stderr, "%d: Error in fwrite\n", __LINE__);
                free(buffer);
                free(regist);
                return -1;
            }
        }
        free(buffer);
    }
    vector128_t block;
    uint64_t count_full_blocks = size_input_file / size_block_in_bytes;
    for (iteration = count_full_buffers * count_blocks_in_buffer; iteration < count_full_blocks; iteration++)
    {
        if (fread(&block, size_block_in_bytes, 1, input) != 1)
        {
            fprintf(stderr, "%d: Error in fread\n", __LINE__);
            free(regist);
            return -1;
        }
        tmp_block_128b = getBlock(regist, size_register_in_bytes, index_gamma_in_register, size_block_in_bytes);
        encryptBlockKuz(&tmp_block_128b, iteration_keys);
        for (int k = 0; k < size_block_in_bytes; k++)
        {
            block.bytes[k] ^= tmp_block_128b.bytes[index_of_start + k];
            regist[(index_gamma_in_register + k) % size_register_in_bytes] = block.bytes[k];
        }
        index_gamma_in_register -= size_block_in_bytes;
        if (index_gamma_in_register < 0)
        {
            index_gamma_in_register = size_register_in_bytes + index_gamma_in_register;
        }
        if (fwrite(&block, size_block_in_bytes, 1, output) != 1)
        {
            fprintf(stderr, "%d: Error in fwrite\n", __LINE__);
            free(regist);
            return -1;
        }
    }

    int count_last_bytes = size_input_file % size_block_in_bytes;
    if (count_last_bytes != 0)
    {
        if (fread(&block, count_last_bytes, 1, input) != 1)
        {
            fprintf(stderr, "%d: Error in fread\n", __LINE__);
            free(regist);
            return -1;
        }
        tmp_block_128b = getBlock(regist, size_register_in_bytes, index_gamma_in_register, size_block_in_bytes);
        encryptBlockKuz(&tmp_block_128b, iteration_keys);
        for (int k = 0; k < size_block_in_bytes; k++)
        {
            block.bytes[k] ^= tmp_block_128b.bytes[index_of_start + k];
        }
        if (fwrite(&block, count_last_bytes, 1, output) != 1)
        {
            fprintf(stderr, "%d: Error in fwrite\n", __LINE__);
            free(regist);
            return -1;
        }
    }

    free(regist);
    return 0;
}

int decryptCFBKuz(FILE *input, FILE *output, vector128_t *iteration_keys, int size_block_in_bytes,
                  int size_register_in_bytes, uint8_t *initial_vector, uint64_t size_input_file)
{
    if (input == NULL || output == NULL)
    {
        return -1;
    }
    if (iteration_keys == NULL)
    {
        return -2;
    }
    if (size_block_in_bytes > 16 || size_block_in_bytes <= 0)
    {
        return -3;
    }
    if (size_register_in_bytes < SIZE_BLOCK)
    {
        return -4;
    }
    if (initial_vector == NULL)
    {
        return -5;
    }
    if (size_input_file == 0)
    {
        return 0;
    }

    uint8_t *regist = (uint8_t *)malloc(size_register_in_bytes);
    if (regist == NULL)
    {
        return -5;
    }
    for (int i = 0; i < size_register_in_bytes; i++)
    {
        regist[i] = initial_vector[i];
    }
    int index_gamma_in_register = size_register_in_bytes - size_block_in_bytes;
    int index_of_start = SIZE_BLOCK - size_block_in_bytes;

    uint8_t *buffer;
    int buffer_size;
    if (size_input_file >= 1048576)
    {
        buffer_size = 1048576 - 1048576 % size_block_in_bytes;
    }
    else
    {
        buffer_size = 1024 - 1024 % size_block_in_bytes;
    }
    buffer = (uint8_t *)malloc(buffer_size);
    if (buffer == NULL)
    {
        buffer_size = 0;
    }

    uint64_t count_blocks_in_buffer = buffer_size / size_block_in_bytes;
    uint64_t count_full_buffers = 0;
    uint64_t iteration;
    vector128_t tmp_block_128b;
    if (buffer_size != 0)
    {
        count_full_buffers = size_input_file / buffer_size;
        for (iteration = 0; iteration < count_full_buffers; iteration++)
        {
            if (fread(buffer, buffer_size, 1, input) != 1)
            {
                fprintf(stderr, "%d: Error in fread\n", __LINE__);
                free(buffer);
                free(regist);
                return -1;
            }
            for (int i = 0; i < count_blocks_in_buffer; i++)
            {
                tmp_block_128b = getBlock(regist, size_register_in_bytes, index_gamma_in_register, size_block_in_bytes);
                encryptBlockKuz(&tmp_block_128b, iteration_keys);
                for (int k = 0; k < size_block_in_bytes; k++)
                {
                    regist[(index_gamma_in_register + k) % size_register_in_bytes] = buffer[i * size_block_in_bytes + k];
                    buffer[i * size_block_in_bytes + k] ^= tmp_block_128b.bytes[index_of_start + k];
                }
                index_gamma_in_register -= size_block_in_bytes;
                if (index_gamma_in_register < 0)
                {
                    index_gamma_in_register = size_register_in_bytes + index_gamma_in_register;
                }
            }
            if (fwrite(buffer, buffer_size, 1, output) != 1)
            {
                fprintf(stderr, "%d: Error in fwrite\n", __LINE__);
                free(buffer);
                free(regist);
                return -1;
            }
        }
        free(buffer);
    }
    vector128_t block;
    uint64_t count_full_blocks = size_input_file / size_block_in_bytes;
    for (iteration = count_full_buffers * count_blocks_in_buffer; iteration < count_full_blocks; iteration++)
    {
        if (fread(&block, size_block_in_bytes, 1, input) != 1)
        {
            fprintf(stderr, "%d: Error in fread\n", __LINE__);
            free(regist);
            return -1;
        }
        tmp_block_128b = getBlock(regist, size_register_in_bytes, index_gamma_in_register, size_block_in_bytes);
        encryptBlockKuz(&tmp_block_128b, iteration_keys);
        for (int k = 0; k < size_block_in_bytes; k++)
        {
            regist[(index_gamma_in_register + k) % size_register_in_bytes] = block.bytes[k];
            block.bytes[k] ^= tmp_block_128b.bytes[index_of_start + k];
        }
        index_gamma_in_register -= size_block_in_bytes;
        if (index_gamma_in_register < 0)
        {
            index_gamma_in_register = size_register_in_bytes + index_gamma_in_register;
        }
        if (fwrite(&block, size_block_in_bytes, 1, output) != 1)
        {
            fprintf(stderr, "%d: Error in fwrite\n", __LINE__);
            free(regist);
            return -1;
        }
    }

    int count_last_bytes = size_input_file % size_block_in_bytes;
    if (count_last_bytes != 0)
    {
        if (fread(&block, count_last_bytes, 1, input) != 1)
        {
            fprintf(stderr, "%d: Error in fread\n", __LINE__);
            free(regist);
            return -1;
        }
        tmp_block_128b = getBlock(regist, size_register_in_bytes, index_gamma_in_register, size_block_in_bytes);
        encryptBlockKuz(&tmp_block_128b, iteration_keys);
        for (int k = 0; k < size_block_in_bytes; k++)
        {
            block.bytes[k] ^= tmp_block_128b.bytes[index_of_start + k];
        }
        if (fwrite(&block, count_last_bytes, 1, output) != 1)
        {
            fprintf(stderr, "%d: Error in fwrite\n", __LINE__);
            free(regist);
            return -1;
        }
    }

    free(regist);
    return 0;
}