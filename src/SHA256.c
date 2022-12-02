#ifndef SHA256_h
#include "../include/sha256.h"
#endif

static uint32_t k_values[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

/// @brief Function copy vector with size 512 bits to array with big-ending order of four bytes. 
/// @param vec pointer to memory with size 512 bits.
/// @param array pointer to array with size 512 bits or more.
static void copyVec512ToArray(vector512_t *vec, uint8_t *array)
{
    for (int i = 0; i < 16; i++)
    {
        for (int j = 3; j >= 0; j--)
        {
            array[i * 4 + 3 - j] = vec->bytes[i * 4 + j];
        }
    }
}

/// @brief Function writes nulls to array from @begin index to @end.
static void writeNullsToArray(uint32_t *array, int begin, int end)
{
    for (int i = begin; i < end; i++)
    {
        array[i] = 0;
    }
}

/// @brief Function does cyclic shift to the right for @value by @offset.
/// @return shifted @value.
static uint32_t rotr(uint32_t value, uint8_t offset)
{
    uint32_t tmp = value & (0xffffffff >> (32 - offset));
    return (value >> offset) | (tmp << (32 - offset));
}


/// @brief Function creates values for algorithm SHA256.
static void createAddingValues(uint32_t *dwords)
{
    for (int i = 16; i < 64; i++)
    {
        dwords[i] = dwords[i - 16] + dwords[i - 7] +
                    (rotr(dwords[i - 15], 7) ^ rotr(dwords[i - 15], 18) ^ (dwords[i - 15] >> 3)) +
                    (rotr(dwords[i - 2], 17) ^ rotr(dwords[i - 2], 19) ^ (dwords[i - 2] >> 10));
    }
}

/// @brief Function hashed @array with size @size_in_bytes and save result in @result.
/// @param array pointer to memory with size @size_in_bytes.
/// @param size_in_bytes size of the array.
/// @param result pointer to memory with size 256 bits.
/// @return 0 is good, -1 if array == NULL, -2 if result == NULL, -3 if error of malloc.
int sha256(uint8_t *array, uint64_t size_in_bytes, vector256_t *result)
{
    if (array == NULL && size_in_bytes != 0)
    {
        return -1;
    }
    if (result == NULL)
    {
        return -2;
    }
    int8_t count_last_bytes = size_in_bytes % 64;
    // count_last_bytes + 1 + count_adding_nulls = 56 (mod 64)
    int8_t count_adding_nulls = 55 - count_last_bytes;
    if (count_adding_nulls < 0)
    {
        count_adding_nulls += 64;
    }
    uint64_t size_data_in_bytes = size_in_bytes + 1 + count_adding_nulls + 8;

    uint8_t *data = (uint8_t *)malloc(size_data_in_bytes);
    if (data == NULL)
    {
        return -3;
    }
    uint64_t i = 0;
    while (i < size_in_bytes)
    {
        data[i] = array[i];
        i++;
    }
    data[i] = 0x80; // 0b1000_0000
    i++;
    uint64_t offset_to_len = size_data_in_bytes - 8;
    while (i < offset_to_len)
    {
        data[i] = 0x00;
        i++;
    }
    uint64_t length_array_in_bits = size_in_bytes * 8;
    while (i < size_data_in_bytes)
    {
        data[i] = *((uint8_t *)(&length_array_in_bits) + size_data_in_bytes - 1 - i);
        i++;
    }
    vector512_t *data_v512 = (vector512_t *)data;
    uint64_t count_vec512 = size_data_in_bytes / 64;
    uint32_t dwords[64] = {0};

    uint32_t h0 = 0x6a09e667;
    uint32_t h1 = 0xbb67ae85;
    uint32_t h2 = 0x3c6ef372;
    uint32_t h3 = 0xa54ff53a;
    uint32_t h4 = 0x510e527f;
    uint32_t h5 = 0x9b05688c;
    uint32_t h6 = 0x1f83d9ab;
    uint32_t h7 = 0x5be0cd19;
    uint32_t a, b, c, d, e, f, g, h, t1, t2;
    for (int iteration_for_vec512 = 0; iteration_for_vec512 < count_vec512; iteration_for_vec512++)
    {
        copyVec512ToArray(data_v512 + iteration_for_vec512, (uint8_t *)dwords);
        writeNullsToArray(dwords, 16, 64);
        createAddingValues(dwords);
        a = h0;
        b = h1;
        c = h2;
        d = h3;
        e = h4;
        f = h5;
        g = h6;
        h = h7;
        for (i = 0; i < 64; i++)
        {
            t1 = h + k_values[i] + dwords[i] + (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + ((e & f) ^ (~e & g));
            t2 = (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }
        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
        h4 += e;
        h5 += f;
        h6 += g;
        h7 += h;
    }
    free(data);
    result->dwords[0] = h7;
    result->dwords[1] = h6;
    result->dwords[2] = h5;
    result->dwords[3] = h4;
    result->dwords[4] = h3;
    result->dwords[5] = h2;
    result->dwords[6] = h1;
    result->dwords[7] = h0;
    return 0;
}