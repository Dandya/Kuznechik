#include "../include/kuznechik.h"

/// @brief Function encrypt file and write result using CBC algorithm from GOST 34.13-2018. Standart use PROC_PADDING_NULLS_2.
/// @param input pointer of structure which defines file opened for reading.
/// @param output pointer of structure which defines file opened for writing.
/// @param iteration_keys pointer on block of memory with ten iteration keys.
/// @param mode_padding_nulls is number of procedure of padding nulls [PROC_ADD_NULLS_1, PROC_ADD_NULLS_2, PROC_ADD_NULLS_3].
/// @param size_register_in_bytes size of register multiple SIZE_BLOCK in bytes which is used for encrypt and don't equal null.
/// @param initial_vector pointer on memory with size 256 bits.
/// @param size_input_file size of input file in bytes.
/// @return 0 is good, -1 is error of read or write file, -2 is iteration_keys == NULL,
///     -3 if bad @size_register_in_bytes, -4 if initial_vector == NULL.
int encryptCBCKuz(FILE *input, FILE *output, vector128_t *iteration_keys, int mode_padding_nulls,
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
    if (size_register_in_bytes % SIZE_BLOCK != 0 && size_register_in_bytes != 0)
    {
        return -3;
    }
    if (initial_vector == NULL)
    {
        return -4;
    }
    if (mode_padding_nulls != PROC_ADD_NULLS_1 &&
        mode_padding_nulls != PROC_ADD_NULLS_2 &&
        mode_padding_nulls != PROC_ADD_NULLS_3)
    {
        mode_padding_nulls = PROC_ADD_NULLS_2;
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

    uint64_t count_blocks_in_buffer = buffer_size / SIZE_BLOCK;
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
                free(regist);
                return -1;
            }
            for (int i = 0; i < count_blocks_in_buffer; i++)
            {
                buffer[i].half[0] ^= regist[index_block_in_register].half[0];
                buffer[i].half[1] ^= regist[index_block_in_register].half[1];
                encryptBlockKuz(buffer + i, iteration_keys);
                regist[index_block_in_register] = buffer[i];
                if (--index_block_in_register == -1)
                {
                    index_block_in_register = count_blocks_in_register - 1;
                }
            }
            if (fwrite(buffer, buffer_size, 1, output) != 1)
            {
                fprintf(stderr, "%d: Error in fwrite\n", __LINE__);
                free(regist);
                return -1;
            }
        }
        free(buffer);
    }
    vector128_t block;
    uint64_t count_full_blocks = size_input_file / SIZE_BLOCK;
    for (iteration = count_full_buffers * count_blocks_in_buffer; iteration < count_full_blocks; iteration++)
    {
        if (fread(&block, SIZE_BLOCK, 1, input) != 1)
        {
            fprintf(stderr, "%d: Error in fread\n", __LINE__);
            free(regist);
            return -1;
        }
        block.half[0] ^= regist[index_block_in_register].half[0];
        block.half[1] ^= regist[index_block_in_register].half[1];
        encryptBlockKuz(&block, iteration_keys);
        regist[index_block_in_register] = block;
        if (--index_block_in_register == -1)
        {
            index_block_in_register = count_blocks_in_register - 1;
        }
        if (fwrite(&block, SIZE_BLOCK, 1, output) != 1)
        {
            fprintf(stderr, "%d: Error in fwrite\n", __LINE__);
            free(regist);
            return -1;
        }
    }

    int result;
    uint8_t count_last_bytes = size_input_file % SIZE_BLOCK;
    if (count_last_bytes != 0)
    {
        result = readLastBlock(input, &block, mode_padding_nulls, count_last_bytes);
        if (result == -2)
        {
            free(regist);
            return -1;
        }
        block.half[0] ^= regist[index_block_in_register].half[0];
        block.half[1] ^= regist[index_block_in_register].half[1];
        encryptBlockKuz(&block, iteration_keys);
        if (fwrite(&block, SIZE_BLOCK, 1, output) != 1)
        {
            fprintf(stderr, "%d: Error in fwrite\n", __LINE__);
            free(regist);
            return -1;
        }
    }
    else if (mode_padding_nulls == PROC_ADD_NULLS_2)
    {
        block.half[0] = 0x0000000000000001 ^ regist[index_block_in_register].half[0];
        block.half[1] = regist[index_block_in_register].half[1];
        encryptBlockKuz(&block, iteration_keys);
        if (fwrite(&block, SIZE_BLOCK, 1, output) != 1)
        {
            fprintf(stderr, "%d: Error in fwrite\n", __LINE__);
            free(regist);
            return -1;
        }
    }

    free(regist);
    return 0;
}

/// @brief Function decrypt file and write result using CBC algorithm from GOST 34.13-2018. Standart use PROC_PADDING_NULLS_2.
/// @param input pointer of structure which defines file opened for reading.
/// @param output pointer of structure which defines file opened for writing.
/// @param iteration_keys pointer on block of memory with ten iteration keys.
/// @param mode_padding_nulls is number of procedure of padding nulls [PROC_ADD_NULLS_1, PROC_ADD_NULLS_2, PROC_ADD_NULLS_3].
/// @param length_last_block is count of bytes in last block for PROC_ADD_NULLS_1.
///     If mode_padding_nulls != PROC_ADD_NULLS_1 then this parameter is ignored.
/// @param size_register_in_bytes size of register multiple SIZE_BLOCK in bytes which is used for encrypt and don't equal null.
/// @param initial_vector pointer on memory with size 256 bits.
/// @param size_input_file size of input file in bytes.
/// @return 0 is good, -1 is error of read or write file, -2 is iteration_keys == NULL,
///     -3 if bad @length_last_block, -4 if bad @size_register_in_bytes, -4 if initial_vector == NULL.
int decryptCBCKuz(FILE *input, FILE *output, vector128_t *iteration_keys, int mode_padding_nulls, int length_last_block,
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
    if (mode_padding_nulls == PROC_ADD_NULLS_1 &&
        (length_last_block <= 0 || length_last_block > 16))
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
    if (mode_padding_nulls != PROC_ADD_NULLS_1 &&
        mode_padding_nulls != PROC_ADD_NULLS_2 &&
        mode_padding_nulls != PROC_ADD_NULLS_3)
    {
        mode_padding_nulls = PROC_ADD_NULLS_2;
    }
    if (size_input_file == 0)
    {
        return 0;
    }

    int count_blocks_in_register = size_register_in_bytes / SIZE_BLOCK;
    vector128_t *regist = (vector128_t *)malloc(size_register_in_bytes);
    vector128_t tmp_block; // need for save value of decrypted block
    if (regist == NULL)
    {
        return -5;
    }
    for (int i = 0; i < count_blocks_in_register; i++)
    {
        regist[i] = initial_vector[i];
    }
    int index_block_in_register = count_blocks_in_register - 1;

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

    uint64_t count_blocks_in_buffer = buffer_size / SIZE_BLOCK;
    uint64_t count_full_buffers = 0;
    uint64_t iteration;
    if (buffer_size != 0)
    {
        // in DECRYPT mode last full block decrypt using deletion of padding nulls
        count_full_buffers = (size_input_file % buffer_size == 0) ? size_input_file / buffer_size - 1 : size_input_file / buffer_size;
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
                tmp_block = buffer[i];
                decryptBlockKuz(buffer + i, iteration_keys);
                buffer[i].half[0] ^= regist[index_block_in_register].half[0];
                buffer[i].half[1] ^= regist[index_block_in_register].half[1];
                regist[index_block_in_register] = tmp_block;
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
    // in DECRYPT mode last full block decrypt using deletion of padding nulls
    uint64_t count_blocks_for_decrypt = (size_input_file > SIZE_BLOCK) ? size_input_file / SIZE_BLOCK - 1 : 0;
    for (iteration = count_full_buffers * count_blocks_in_buffer; iteration < count_blocks_for_decrypt; iteration++)
    {
        if (fread(&block, SIZE_BLOCK, 1, input) != 1)
        {
            fprintf(stderr, "%d: Error in fread\n", __LINE__);
            free(regist);
            return -1;
        }
        tmp_block = block;
        decryptBlockKuz(&block, iteration_keys);
        block.half[0] ^= regist[index_block_in_register].half[0];
        block.half[1] ^= regist[index_block_in_register].half[1];
        regist[index_block_in_register] = tmp_block;
        if (--index_block_in_register == -1)
        {
            index_block_in_register = count_blocks_in_register - 1;
        }
        if (fwrite(&block, SIZE_BLOCK, 1, output) != 1)
        {
            fprintf(stderr, "%d: Error in fwrite\n", __LINE__);
            free(regist);
            return -1;
        }
    }

    int result;
    if (fread(&block, SIZE_BLOCK, 1, input) != 1)
    {
        fprintf(stderr, "%d: Error in fread\n", __LINE__);
        free(regist);
        return -1;
    }
    decryptBlockKuz(&block, iteration_keys);
    block.half[0] ^= regist[index_block_in_register].half[0];
    block.half[1] ^= regist[index_block_in_register].half[1];
    if (mode_padding_nulls == PROC_ADD_NULLS_1)
    {
        result = length_last_block;
    }
    else
    {
        result = getCountBytesInLastBlock((uint8_t *)&block);
    }
    if (result != 0)
    {
        if (fwrite(&block, result, 1, output) != 1)
        {
            fprintf(stderr, "%d: Error in fwrite\n", __LINE__);
            free(regist);
            return -1;
        }
    }

    free(regist);
    return 0;
}