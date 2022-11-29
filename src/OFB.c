#include "../include/kuznechik.h"

/// @brief Function encrypt file and write result using OFB algorithm from GOST 34.13-2018.
/// @param input pointer of structure which defines file opened for reading.
/// @param output pointer of structure which defines file opened for writing.
/// @param iteration_keys pointer on block of memory with ten iteration keys.
/// @param size_block_in_bytes size of block of data for encrypt in bytes from 1 to 16.
/// @param size_register_in_bytes size of register multiple SIZE_BLOCK in bytes which is used for encrypt and don't equal null.
/// @param initial_vector pointer on memory with size 256 bits.
/// @param size_input_file size of input file in bytes.
/// @return 0 is good, -1 is error of read or write file, -2 is iteration_keys == NULL,
///     -3 if bad @size_block_in_bytes, -4 if bad @size_register_in_bytes, -5 if initial_vector == NULL.
int encryptOFBKuz(FILE *input, FILE *output, vector128_t *iteration_keys, int size_block_in_bytes,
                  int size_register_in_bytes, vector128_t *initial_vector, uint64_t size_input_file)
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
    if (size_register_in_bytes % SIZE_BLOCK != 0 && size_register_in_bytes != 0)
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

    int count_blocks_in_register = size_register_in_bytes / SIZE_BLOCK;
    vector128_t *regist = (vector128_t *)malloc(size_register_in_bytes);
    if (regist == NULL)
    {
        return -5;
    }
    for (int i = 0; i < count_blocks_in_register; i++)
    {
        regist[i] = initial_vector[i];
    }
    int index_block_in_register = count_blocks_in_register - 1;
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
                free(buffer);
                free(regist);
                return -1;
            }
            for (int i = 0; i < count_blocks_in_buffer; i++)
            {
                encryptBlockKuz(regist + index_block_in_register, iteration_keys);
                for (int k = 0; k < size_block_in_bytes; k++)
                {
                    buffer[i * size_block_in_bytes + k] ^= regist[index_block_in_register].bytes[index_of_start + k];
                }
                if (--index_block_in_register == -1)
                {
                    index_block_in_register = count_blocks_in_register - 1;
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
        encryptBlockKuz(regist + index_block_in_register, iteration_keys);
        for (int k = 0; k < size_block_in_bytes; k++)
        {
            block.bytes[k] ^= regist[index_block_in_register].bytes[index_of_start + k];
        }
        if (--index_block_in_register == -1)
        {
            index_block_in_register = count_blocks_in_register - 1;
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
        encryptBlockKuz(regist + index_block_in_register, iteration_keys);
        for (int k = 0; k < size_block_in_bytes; k++)
        {
            block.bytes[k] ^= regist[index_block_in_register].bytes[index_of_start + k];
        }
        if (--index_block_in_register == -1)
        {
            index_block_in_register = count_blocks_in_register - 1;
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

/// @brief Function decrypt file and write result using OFB algorithm from GOST 34.13-2018.
/// @param input pointer of structure which defines file opened for reading.
/// @param output pointer of structure which defines file opened for writing.
/// @param iteration_keys pointer on block of memory with ten iteration keys.
/// @param size_block_in_bytes size of block of data for encrypt in bytes from 1 to 16.
/// @param size_register_in_bytes size of register multiple SIZE_BLOCK in bytes which is used for encrypt and don't equal null.
/// @param initial_vector pointer on memory with size 256 bits.
/// @param size_input_file size of input file in bytes.
/// @return 0 is good, -1 is error of read or write file, -2 is iteration_keys == NULL,
///     -3 if bad @size_block_in_bytes, -4 if bad @size_register_in_bytes, -5 if initial_vector == NULL.
int decryptOFBKuz(FILE *input, FILE *output, vector128_t *iteration_keys, int size_block_in_bytes,
                  int size_register_in_bytes, vector128_t *initial_vector, uint64_t size_input_file)
{
    return encryptOFBKuz(input, output, iteration_keys, size_block_in_bytes, size_register_in_bytes, initial_vector, size_input_file);
}