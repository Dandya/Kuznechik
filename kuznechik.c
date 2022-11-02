#ifndef _KUZNECHIK_H
#include "kuznechik.h"
#endif

/// @brief Substitution for substitutionFunc with mode ENCRYPT. 
static const uint8_t k_substitution_enc[256] = {
    252, 238, 221, 17, 207, 110, 49, 22, 251, 196, 250, 218, 35, 197, 4, 77, 233, 119, 240, 219, 147, 46, 153, 
    186, 23, 54, 241, 187, 20, 205, 95, 193, 249, 24, 101, 90, 226, 92, 239, 33, 129, 28, 60, 66, 139, 1, 142, 
    79, 5, 132, 2, 174, 227, 106, 143, 160, 6, 11,237, 152, 127, 212, 211, 31, 235, 52, 44, 81, 234, 200, 72, 
    171, 242, 42, 104, 162, 253, 58, 206, 204, 181, 112, 14, 86, 8, 12, 118, 18, 191, 114, 19, 71, 156, 183, 
    93, 135, 21,161, 150, 41, 16, 123, 154, 199, 243, 145, 120, 111, 157, 158, 178, 177, 50, 117, 25, 61,255,
    53, 138, 126, 109, 84, 198, 128, 195, 189, 13, 87, 223, 245, 36, 169, 62, 168, 67, 201, 215, 121, 214, 246, 
    124, 34, 185, 3, 224, 15, 236, 222, 122, 148, 176, 188, 220, 232, 40, 80, 78, 51, 10, 74, 167, 151, 96, 115, 
    30, 0, 98, 68, 26, 184, 56, 130, 100, 159, 38, 65, 173, 69, 70, 146, 39, 94, 85, 47, 140, 163, 165, 125, 105,
    213, 149, 59, 7, 88, 179, 64, 134, 172, 29, 247, 48, 55, 107, 228, 136, 217, 231, 137, 225, 27, 131,73, 76, 63, 
    248, 254, 141,83, 170, 144, 202, 216, 133, 97, 32, 113, 103, 164, 45, 43, 9, 91,203, 155, 37, 208, 190, 229, 
    108, 82, 89, 166, 116, 210, 230, 244, 180, 192, 209, 102, 175, 194, 57, 75, 99, 182
};    

/// @brief Substitution for function substitutionFunc with mode DECRYPT. 
static const uint8_t k_substitution_dec[256] = {
    165, 45, 50, 143, 14, 48, 56, 192, 84, 230, 158, 57, 85, 126, 82, 145, 100, 3, 87, 90, 28, 96, 7, 24, 33, 
    114, 168, 209, 41, 198, 164, 63, 224, 39, 141, 12, 130, 234, 174, 180, 154, 99, 73, 229, 66, 228, 21, 183, 
    200, 6, 112, 157, 65, 117, 25, 201, 170, 252, 77, 191, 42, 115, 132, 213, 195, 175, 43, 134, 167, 177, 178, 
    91, 70, 211, 159, 253, 212, 15, 156, 47, 155, 67, 239, 217, 121, 182, 83, 127, 193, 240, 35, 231, 37, 94, 
    181, 30, 162, 223, 166, 254, 172, 34, 249, 226, 74, 188, 53, 202, 238, 120, 5, 107, 81, 225, 89, 163, 242, 
    113, 86, 17, 106, 137, 148, 101, 140, 187, 119, 60, 123, 40, 171, 210, 49, 222, 196, 95, 204, 207, 118, 44, 
    184, 216, 46, 54, 219, 105, 179, 20, 149, 190, 98, 161, 59, 22, 102, 233, 92, 108, 109, 173, 55, 97, 75, 185, 
    227, 186, 241, 160, 133, 131, 218, 71, 197, 176, 51, 250, 150, 111, 110, 194, 246, 80, 255, 93, 169, 142, 23, 
    27, 151, 125, 236, 88, 247, 31, 251, 124, 9, 13, 122, 103, 69, 135, 220, 232, 79, 29, 78, 4, 235, 248, 243, 62, 
    61, 189, 138, 136, 221, 205, 11, 19, 152, 2, 147, 128, 144, 208, 36, 52, 203, 237, 244, 206, 153, 16, 68, 64, 
    146, 58, 1, 38, 18, 26, 72, 104, 245, 129, 139, 199, 214, 32, 10, 8, 0, 76, 215, 116
};

/// @brief Сoefficients for function Rfunc. 
static const uint8_t k_coeff_for_Lfunc[16] = { 1, 148, 32, 133, 16, 194, 192, 1, 251, 1, 192, 194, 16, 133, 32, 148 };

/// @brief XOR with two block of memory.
/// @param block is pointer on memory block with size of 128 bits.
/// @param key is memory block with size of 128 bits.
static void XOR(vector128bit * block, vector128bit key) {
    block->half[0] ^= key.half[0];
    block->half[1] ^= key.half[1];
}

/// @brief Function multiples two vectors of 8 bit in GF(2^8).
/// x^8+x^7+x^6+x+1 is 451 = 0x1c3, x^8 (mod x^8+x^7+x^6+x+1) = x^7+x^6+x+1 is 195 = 0xc3
static uint8_t mulGF256(uint8_t x, uint8_t y) {
    uint8_t result = 0;
    while(y != 0) {
        if(y & 1 == 1) {
            result ^= x;
        }
        x = (x << 1) ^ ((x & 0x80) ? 0xc3 : 0); 
        y >>= 1;
    }
    return result;
} 

/// @brief Function uses substitutions for crypt block
/// @param block is pointer on block of memory of size 128bit.
/// @param mode is ENCRYPT or DECRYPT.
static void substitutionFunc(vector128bit * block, int mode) {
    if(mode == ENCRYPT) {
        for(int i = 0; i < 16; i++) {
            block->bytes[i] = k_substitution_enc[block->bytes[i]];
        } 
    } else { // mode == DECRYPT
        for(int i = 0; i < 16; i++) {
            block->bytes[i] = k_substitution_dec[block->bytes[i]];
        } 
    }
}

/// @brief Function uses multiple in GF(2^8) for crypt block and relocate bytes in vector.
/// @param block is pointer on block of memory of size 128bit.
/// @param mode is ENCRYPT or DECRYPT.
static void relocateBytes(vector128bit * block, int mode) {
    uint8_t result = 0;
    if(mode == ENCRYPT) {
        for(int i = 0; i < 15; i++) {
            result ^= mulGF256(block->bytes[i], k_coeff_for_Lfunc[i]); 
            block->bytes[i] = block->bytes[i+1];
        }
        block->bytes[15] = mulGF256(block->bytes[15], k_coeff_for_Lfunc[15]) ^ result;
    } else { // mode == DECRYPT
        uint8_t byte = block->bytes[15];
        for(int i = 15; i > 0; i--) {
            block->bytes[i] = block->bytes[i-1];
            result ^= mulGF256(block->bytes[i], k_coeff_for_Lfunc[i]); 
        }
        block->bytes[0] = mulGF256(byte, k_coeff_for_Lfunc[0]) ^ result;
    }
}

/// @brief Function uses relocateBytes 16 times for cryption of all block.
/// @param block is pointer on block of memory of size 128bit.
/// @param mode is ENCRYPT or DECRYPT.
static void linearFunc(vector128bit * block, int mode) {
    for(int i = 0; i < 16; i++) {
        relocateBytes(block, mode);
    }
}


/// @brief Function was used to creating itertion keys.
/// @param key is value for creating keys.
/// @param v_1 is pointer on block of memory of size 128bit.
/// @param v_0 is pointer on block of memory of size 128bit.
static void createTwoIterationKeys(vector128bit key, vector128bit * v_1, vector128bit * v_0) {
    vector128bit tmp = *v_1;
    XOR(v_1, key);
    substitutionFunc(v_1, ENCRYPT);
    linearFunc(v_1, ENCRYPT);
    v_1->half[0] ^= v_0->half[0];
    v_1->half[1] ^= v_0->half[1];
    *v_0 = tmp;
}

/// @brief Function creates 10 iteration keys.
/// @param key is array of 2 vector128bit or block of memory of size 256 bits.
/// @param array_for_keys is pointer to 10 vector128bit or memory with size 160 bytes.
/// @return 0 is good, -1 is key = NULL, -2 is array_for_keys = NULL.
int createIterationKeysKuz(vector128bit * key, vector128bit * array_for_keys) {
    if(key == NULL)            { return -1; }
    if(array_for_keys == NULL) { return -2; }
    array_for_keys[0] = key[1];
    array_for_keys[1] = key[0];
    vector128bit coeff;
    for(int i = 1; i <= 4; i++) {
        array_for_keys[2*i]   = array_for_keys[2*i-2];
        array_for_keys[2*i+1] = array_for_keys[2*i-1];
        for(int j = 1; j <= 8; j++) {
            coeff.half[0] = 8*(i-1)+j;
            coeff.half[1] = 0; 
            linearFunc(&coeff, ENCRYPT);
            createTwoIterationKeys(coeff, array_for_keys+2*i, array_for_keys+2*i+1);
        }
    }
    return 0;
}

/// @brief Function crypts block of data in memory using base algorithm from GOST 34.12-2018.
/// @param block is pointer of data in memory for enc. Size block is 16 bytes.
/// @param arr_keys is array of iteration keys. Size of key is 128 bits.
/// @param mode is ENCRYPT or DECRYPT.
/// @return 0 is good, -1 is key = NULL, -2 is block = NULL.
int cryptBlockKuz(vector128bit * block, vector128bit * arr_keys, int mode) {
    if(arr_keys == NULL) { return -1; }
    if(block == NULL)    { return -2; }
    if(mode == ENCRYPT) {
        for(int i = 0; i < 9; i++) {
            XOR(block, arr_keys[i]);
            substitutionFunc(block, ENCRYPT);
            linearFunc(block, ENCRYPT);
        }
        XOR(block, arr_keys[9]);
    } else { // mode == DECRYPT
        for(int i = 9; i > 0; i--) {
            XOR(block, arr_keys[i]);
            linearFunc(block, DECRYPT);
            substitutionFunc(block, DECRYPT);
        }
        XOR(block, arr_keys[0]);
    }
    return 0;
}