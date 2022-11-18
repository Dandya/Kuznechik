#include "../include/kuznechik.h"

static void addOne(vector128_t *a)
{
    static uint64_t tmp = a->half[0];
    a->half[0] += 1;
    if (tmp > a->half[0])
    {
        a->half[1] += 1;
    }
}

int encryptCTRKuz(FILE *input, FILE *output, vector128_t *iteration_keys, int size_block_in_bytes, vector128_t *initial_vector, uint64_t size_input_file)
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
    if (initial_vector == NULL)
    {
        return -4;
    }
    if (size_input_file == 0)
    {
        return 0;
    }

    vector128_t gamma;
    gamma.half[0] = 0;
    gamma.half[1] = initial_vector->half[0];
    vector128_t gamma_for_encrypt;
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
    if (buffer_size != 0)
    {
        count_full_buffers = size_input_file / buffer_size;
        for (iteration = 0; iteration < count_full_buffers; iteration++)
        {
            if (fread(buffer, buffer_size, 1, input) != 1)
            {
                fprintf(stderr, "%d: Error in fread\n", __LINE__);
                return -1;
            }
            for (int i = 0; i < count_blocks_in_buffer; i++)
            {
                gamma_for_encrypt = gamma;
                encryptBlockKuz(&gamma_for_encrypt, iteration_keys);
                for (int k = 0; k < size_block_in_bytes; k++)
                {
                    buffer[i * size_block_in_bytes + k] ^= gamma_for_encrypt.bytes[index_of_start + k];
                }
                addOne(&gamma);
            }
            if (fwrite(buffer, buffer_size, 1, output) != 1)
            {
                fprintf(stderr, "%d: Error in fwrite\n", __LINE__);
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
            return -1;
        }
        gamma_for_encrypt = gamma;
        encryptBlockKuz(&gamma_for_encrypt, iteration_keys);
        for (int k = 0; k < size_block_in_bytes; k++)
        {
            block.bytes[k] ^= gamma_for_encrypt.bytes[index_of_start + k];
        }
        addOne(&gamma);
        if (fwrite(&block, size_block_in_bytes, 1, output) != 1)
        {
            fprintf(stderr, "%d: Error in fwrite\n", __LINE__);
            return -1;
        }
    }

    int count_last_bytes = size_input_file % size_block_in_bytes;
    if (count_last_bytes != 0)
    {
        if (fread(&block, count_last_bytes, 1, input) != 1)
        {
            fprintf(stderr, "%d: Error in fread\n", __LINE__);
            return -1;
        }
        gamma_for_encrypt = gamma;
        encryptBlockKuz(&gamma_for_encrypt, iteration_keys);
        for (int k = 0; k < count_last_bytes; k++)
        {
            block.bytes[k] ^= gamma_for_encrypt.bytes[index_of_start + k];
        }
        if (fwrite(&block, count_last_bytes, 1, output) != 1)
        {
            fprintf(stderr, "%d: Error in fwrite\n", __LINE__);
            return -1;
        }
    }

    return 0;
}

int decryptCTRKuz(FILE *input, FILE *output, vector128_t *iteration_keys, int size_block_in_bytes, vector128_t *initial_vector, uint64_t size_input_file)
{
    return encryptCTRKuz(input, output, iteration_keys, size_block_in_bytes, initial_vector, size_input_file);
}