#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#else
#include <stdlib.h>
#endif
#include <stdio.h>
#include <sys/types.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdint.h>
#include <limits.h>
#include <errno.h>
#include "../include/kuznechik.h"
#include "../include/sha256.h"
#include "./Kuznechik.c"
#include "./SHA256.c"
#include "./ECB.c"
#include "./CBC.c"
#include "./CTR.c"
#include "./OFB.c"
#include "./CFB.c"
#include "./IMITO.c"

struct header
{
    char *name;             // 256 bytes for the name.
    char type;              // directory ('d') or file ('f').
    uint64_t size;          // size of data.
    vector256_t sha256_sum; // hash of name.
};

typedef struct
{
    char *value;
    uint64_t len;
} String;

#define REGFILE 1
#define DIRECTORY 2

int parameterDefinition(char *prm);
int strEQ(char *strFirst, char *strSecond);
int modeDefinition(char *mode);
int createInitialVector();
int getTypeFile(String path);
char *createHeaderCryptofile(uint32_t *size);
int encryptFile(FILE *input, FILE *output, uint64_t size_input_file);
int decryptFile(FILE *input, FILE *output, uint64_t size_input_file, uint8_t length_last_block);
void cleanMemory(String str, int size);
int writeDirectory(String path, String name, FILE *output);
String createPath(String path, String name);
int writeFile(char *path, char *name, FILE *output);
char *createHeader(char *name, char type, uint64_t size, vector256_t sha256_sum);
String getName(String path);
String getAbsolutePath(char *path);
int readHeader(FILE *input, struct header *header);
int createDirectory(char *path, int mode);
int readCryptofile(FILE *input, String path, uint64_t size);
int printMACFile(char *path);
int printMACDirectory(char *path);

// settings for working
vector128_t *iteration_keys;
vector128_t *initial_vector;
int mode_encryption;
int mode_padding_nulls;
int size_register_in_bytes;
int size_block_in_bytes;
uint8_t *MAC;
uint8_t size_MAC;

/// @brief The program encrypts input files and directories and saves the result into one file. 
/// Parameters:
/// *  -i names of input files or/and directores for encryption and name of cryptofile for decryption #1
/// *  -o name of output cryptofile for encryption or name of directory with decrypted files or/and directores for decryption #2
/// *  -k string with key #3
/// *  -m mode of a encryption {"ECB", "CBC", "CTR", "OFB", "CFB", "IMITO"} #4
/// *  -p mode of padding block {1, 2, 3} #5
/// *  -c encrypt or decrypt {e, d} #6
/// *  -s size MAC in bits {1-128} #7
/// *  -r size register in bytes multiple by 16 for modes of encryption or decryption "CBC", "OFB", "CFB" #8
/// *  -b size block in bytes from 1 to 16 for modes of encryption or decryption "CTR", "OFB", "CFB" #9
/// *  -h help #10
/// Standart parameters:
/// *  mode is ENCRYPT.
/// *  mode of a encryption is "ECB".
/// *  mode of padding block is 1.
/// *  size register is 32 bytes.
/// *  size block is 16 bytes.
/// *  size MAC for mode "IMITO" is 64 bits.
/// *  output name for encryption is "cryptofile.out" and for decryption is "decryption_dir".
/// @return 0 is good, 1 is error of malloc, 2 is error in parameters, 3 is error of read/write file or directory;
int main(int argc, char **argv)
{
    // struct input_names list_names;
    int index_begining_names = 0;
    int count_names = 0;
    char *output_name = NULL;
    char *key_str = NULL;
    int mode = ENCRYPT;
    mode_encryption = ECB;
    mode_padding_nulls = PROC_ADD_NULLS_2;
    size_MAC = 64;
    size_register_in_bytes = 32;
    size_block_in_bytes = 16;

    uint8_t count_i_params = 0;
    uint8_t count_o_params = 0;
    uint8_t count_k_params = 0;
    uint8_t count_m_params = 0;
    uint8_t count_p_params = 0;
    uint8_t count_c_params = 0;
    uint8_t count_s_params = 0;
    uint8_t count_r_params = 0;
    uint8_t count_b_params = 0;
    // read and set parameters of working
    for (int index = 1; index < argc; index++)
    {
        switch (parameterDefinition(argv[index]))
        {
        case 1:
        { // -i
            index++;
            if (index == argc)
            {
                fprintf(stderr, "Empty parameter -i\n");
                return 2;
            }
            count_i_params++;
            if (count_i_params >= 2)
            {
                fprintf(stderr, "Using first parameter -i\n");
                continue;
            }
            index_begining_names = index;
            while (index < argc)
            {
                if (parameterDefinition(argv[index]) != -1)
                {
                    break;
                }
                count_names++;
                index++;
            }
            if (count_names == 0)
            {
                fprintf(stderr, "Empty parameter -i\n");
                return 2;
            }
            index--;
            break;
        }
        case 2:
        { // -o
            index++;
            if (index == argc)
            {
                fprintf(stderr, "Empty parameter -o\n");
                return 2;
            }
            count_o_params++;
            if (count_o_params >= 2)
            {
                fprintf(stderr, "Using first parameter -o\n");
                continue;
            }
            output_name = argv[index];
            if (parameterDefinition(output_name) != -1)
            {
                fprintf(stderr, "Empty parameter -o\n");
                return 2;
            }
            break;
        }
        case 3:
        { // -k
            index++;
            if (index == argc)
            {
                fprintf(stderr, "Empty parameter -k\n");
                return 2;
            }
            count_k_params++;
            if (count_k_params >= 2)
            {
                fprintf(stderr, "Using first parameter -k\n");
                continue;
            }
            key_str = argv[index];
            if (parameterDefinition(key_str) != -1)
            {
                fprintf(stderr, "Empty parameter -k\n");
                return 2;
            }
            break;
        }
        case 4:
        { // -m
            index++;
            if (index == argc)
            {
                fprintf(stderr, "Empty parameter -m\n");
                return 2;
            }
            count_m_params++;
            if (count_m_params >= 2)
            {
                fprintf(stderr, "Using first parameter -m\n");
                continue;
            }
            mode_encryption = modeDefinition(argv[index]);
            if (mode_encryption == 0)
            {
                fprintf(stderr, "Unknown mode in parameter -m\n");
                return 2;
            }
            break;
        }
        case 5:
        { // -p
            index++;
            if (index == argc)
            {
                fprintf(stderr, "Empty parameter -p\n");
                return 2;
            }
            count_p_params++;
            if (count_p_params >= 2)
            {
                fprintf(stderr, "Using first parameter -p\n");
                continue;
            }
            mode_padding_nulls = *(argv[index]) - '0';
            if (mode_padding_nulls < 1 || mode_padding_nulls > 3)
            {
                fprintf(stderr, "Invalid mode of padding block\n");
                return 2;
            }
            break;
        }
        case 6:
        { // -c
            index++;
            if (index == argc)
            {
                fprintf(stderr, "Empty parameter -c\n");
                return 2;
            }
            count_c_params++;
            if (count_c_params >= 2)
            {
                fprintf(stderr, "Using first parameter -c\n");
                continue;
            }
            mode = *(argv[index]);
            if (mode == 'e')
            {
                mode = ENCRYPT;
            }
            else if (mode == 'd')
            {
                mode = DECRYPT;
            }
            else
            {
                fprintf(stderr, "Invalid mode encrypt or decrypt\n");
                return 2;
            }
            break;
        }
        case 7:
        { // -s
            index++;
            if (index == argc)
            {
                fprintf(stderr, "Empty parameter -s\n");
                return 2;
            }
            count_s_params++;
            if (count_s_params >= 2)
            {
                fprintf(stderr, "Using first parameter -s\n");
                continue;
            }
            size_MAC = (uint8_t)atoi(argv[index]);
            if (size_MAC > 128 || size_MAC < 1)
            {
                fprintf(stderr, "Invalid size MAC\n");
                return 2;
            }
            break;
        }
        case 8:
        { // -r
            index++;
            if (index == argc)
            {
                fprintf(stderr, "Empty parameter -s\n");
                return 2;
            }
            count_r_params++;
            if (count_r_params >= 2)
            {
                fprintf(stderr, "Using first parameter -r\n");
                continue;
            }
            size_register_in_bytes = (uint8_t)atoi(argv[index]);
            if (size_register_in_bytes <= 0 || size_register_in_bytes % SIZE_BLOCK != 0)
            {
                fprintf(stderr, "Invalid size register\n");
                return 2;
            }
            break;\
        }
        case 9:
        { // -b
            index++;
            if (index == argc)
            {
                fprintf(stderr, "Empty parameter -s\n");
                return 2;
            }            
            count_b_params++;
            if (count_b_params >= 2)
            {
                fprintf(stderr, "Using first parameter -b\n");
                continue;
            }
            size_block_in_bytes = (uint8_t)atoi(argv[index]);
            if (size_block_in_bytes <= 0 || size_block_in_bytes > 16)
            {
                fprintf(stderr, "Invalid size of block\n");
                return 2;
            }
            break;
        }
        case 10:
        { // -h
            fprintf(stderr, "The program encrypts input files and directories and saves the result into one file.\n Parameters:\n *  -i names of input files or/and directores for encryption and name of cryptofile for decryption.\n *  -o name of output cryptofile for encryption or name of directory with decrypted files or/and directores for decryption.\n *  -k string with key.\n *  -m mode of a encryption {\"ECB\", \"CBC\", \"CTR\", \"OFB\", \"CFB\", \"IMITO\"}.\n *  -p mode of padding block {1, 2, 3}.\n *  -c encrypt or decrypt {e, d}.\n *  -s size MAC in bits {1-128}.\n *  -r size register in bytes multiple by 16 for modes of encryption or decryption \"CBC\", \"OFB\", \"CFB\".\n *  -b size block in bytes from 1 to 16 for modes of encryption or decryption \"CTR\", \"OFB\", \"CFB\".\n *  -h help.\nStandart parameters:\n *  mode is ENCRYPT.\n *  mode of a encryption is \"ECB\".\n *  mode of padding block is 1.\n *  size register is 32 bytes.\n *  size block is 16 bytes.\n *  size MAC for mode \"IMITO\" is 64 bits.\n *  output name for encryption is \"cryptofile.out\" and for decryption is \"decryption_dir\".\n The program returns 0 is good, 1 is error of malloc, 2 is error in parameters, 3 is error of read/write file or directory.\n");
            return 0;
        }
        case -1:
        {
            fprintf(stderr, "Invalid parameter: %s\n", argv[index]);
            return 2;
        }
        }
    }

    if (index_begining_names == 0 || key_str == NULL)
    {
        fprintf(stderr, "Fatal error: insufficient parameters input name or key\n");
        return 2;
    }

    if (output_name == NULL)
    {
        if (mode == ENCRYPT)
        {
            output_name = "./cryptofile.out";
        }
        else
        {
            output_name = "./decryption_dir";
        }
    }

    // generate the key
    vector128_t key_vec[2];
    int result = sha256((uint8_t *)key_str, strlen(key_str), (vector256_t *)key_vec);
    if (result < 0)
    {
        fprintf(stderr, "Fatal error: error of getting hash of key\n Result: %d\n", result);
    }

    // generate iteration keys
    iteration_keys = malloc(10 * sizeof(vector128_t));
    if (iteration_keys == NULL)
    {
        fprintf(stderr, "Fatal error: error of creating of iteration keys\n");
        return 1;
    }
    result = createIterationKeysKuz(key_vec, iteration_keys);
    if (result < 0)
    {
        fprintf(stderr, "Fatal error: error of creating of iteration keys\n Result: %d\n", result);
        return result;
    }

    // main part
    if (mode == ENCRYPT || mode_encryption == IMITO)
    {
        if (mode_encryption != IMITO)
        {
            // generate initial vector
            if (mode_encryption != ECB)
            {
                result = createInitialVector();
                if (result != 0)
                {
                    fprintf(stderr, "Fatal error: error of creating initial vector\n");
                    free(iteration_keys);
                    return result;
                }
            }

            FILE *cryptofile = fopen(output_name, "wb");
            uint32_t size_header_cryptofile;
            char *header_cryptofile = createHeaderCryptofile(&size_header_cryptofile);
            if (header_cryptofile == NULL)
            {
                free(iteration_keys);
                if (initial_vector != NULL)
                {
                    free(initial_vector);
                }
                return 1;
            }
            for (int i = 0; i < size_header_cryptofile / SIZE_BLOCK; i++)
            {
                encryptBlockKuz(((vector128_t *)header_cryptofile) + i, iteration_keys);
            }
            if (fwrite(header_cryptofile, 1, size_header_cryptofile, cryptofile) != size_header_cryptofile)
            {
                fprintf(stderr, "Fatal error: error of writing header of cryptofile\n");
                free(iteration_keys);
                if (initial_vector != NULL)
                {
                    free(initial_vector);
                }
                return 3;
            }
            free(header_cryptofile);
            String path;
            String name;
            uint64_t size_file;
            for (int i = index_begining_names; i < index_begining_names + count_names; i++)
            {
                path.value = argv[i];
                path.len = strlen(argv[i]);
                if(path.value[path.len - 1] == '\\' || path.value[path.len - 1] == '/')
                {
                    path.value[path.len - 1] = '\0';
                    path.len--;
                }
                path = getAbsolutePath(path.value);
                if (path.value == NULL)
                {
                    free(iteration_keys);
                    if (initial_vector != NULL)
                    {
                        free(initial_vector);
                    }
                    return 1;
                }
                switch (getTypeFile(path))
                {
                case REGFILE:
                {
                    name = getName(path);
                    if (name.value == NULL)
                    {
                        fprintf(stderr, "Fatal error: error of malloc: %d\n", __LINE__);
                        free(iteration_keys);
                        if (initial_vector != NULL)
                        {
                            free(initial_vector);
                        }
                        return 1;
                    }
                    printf("File: %s\n", name.value);
                    result = writeFile(path.value, name.value, cryptofile);
                    free(name.value);
                    if (result != 0)
                    {
                        fprintf(stderr, "Fatal error: error of writing file: %d\n", __LINE__);
                        free(iteration_keys);
                        if (initial_vector != NULL)
                        {
                            free(initial_vector);
                        }
                        return 3;
                    }
                    break;
                }
                case DIRECTORY:
                {
                    name = getName(path);
                    if (name.value == NULL)
                    {
                        free(iteration_keys);
                        if (initial_vector != NULL)
                        {
                            free(initial_vector);
                        }
                        return 1;
                    }

                    printf("Directory: %s\n", name.value);
                    result = writeDirectory(path, name, cryptofile);
                    free(name.value);
                    if (result != 0)
                    {
                        fprintf(stderr, "Fatal error: error of writing directory: %d\n", __LINE__);
                        free(iteration_keys);
                        if (initial_vector != NULL)
                        {
                            free(initial_vector);
                        }
                        return 3;
                    }
                    break;
                }
                }
            free(path.value);
            }
            
            fclose(cryptofile);
        } // mode_encryption == IMITO
        else
        {
            String path;
            for (int i = index_begining_names; i < index_begining_names + count_names; i++)
            {
                path.value = argv[i];
                path.len = strlen(path.value);
                if(path.value[path.len - 1] == '\\' || path.value[path.len - 1] == '/')
                {
                    path.value[path.len - 1] = '\0';
                    path.len--;
                }
                switch (getTypeFile(path))
                {
                case REGFILE:
                {
                    printMACFile(argv[i]);
                    break;
                }
                case DIRECTORY:
                {
                    printMACDirectory(argv[i]);
                    break;
                }
                }
            }
        }
    }
    else
    {
        if (count_names > 1)
        {
            printf("Will be decrypted only %s\n", argv[index_begining_names]);
        }
        FILE *cryptofile = fopen(argv[index_begining_names], "rb");
        if (cryptofile == NULL)
        {
            fprintf(stderr, "Fatal error: error of opening %s : %d\n", argv[index_begining_names], __LINE__);
            free(iteration_keys);
            return 3;
        }
        uint64_t size_cryptofile = getSizeFile(cryptofile);
        char header_cryptofile[16];
        if (fread(header_cryptofile, 1, 16, cryptofile) != 16)
        {
            fprintf(stderr, "Fatal error: error of writing header of cryptofile\n");
            free(iteration_keys);
            return 3;
        }
        decryptBlockKuz((vector128_t *)header_cryptofile, iteration_keys);
        uint32_t size_header_cryptofile = *((uint32_t *)header_cryptofile);
        mode_encryption = header_cryptofile[4];
        mode_padding_nulls = header_cryptofile[5];
        size_block_in_bytes = header_cryptofile[6];
        size_register_in_bytes = *(((uint32_t *)header_cryptofile) + 2);
        if( size_header_cryptofile != size_register_in_bytes + 16 )
        {
            printf("Uncorrect key\n");
            free(iteration_keys);
            return 0;
        }
        initial_vector = (vector128_t *)malloc(size_register_in_bytes);
        if (initial_vector == NULL)
        {
            fprintf(stderr, "Fatal error: error of malloc: %d\n", __LINE__);
            free(iteration_keys);
            return 1;
        }
        if (fread(initial_vector, 1, size_register_in_bytes, cryptofile) != size_register_in_bytes)
        {
            fprintf(stderr, "Fatal error: error of malloc: %d\n", __LINE__);
            free(iteration_keys);
            free(initial_vector);
            return 3;
        }
        for (int i = 0; i < size_register_in_bytes / SIZE_BLOCK; i++)
        {
            decryptBlockKuz(((vector128_t *)initial_vector) + i, iteration_keys);
        }

        result = createDirectory(output_name, 0777);
        if (result != 0)
        {
            fprintf(stderr, "Fatal error: error of create directory %s : %d\n", output_name, __LINE__);
            free(iteration_keys);
            free(initial_vector);
            return 3;
        }
        String absolute_path = getAbsolutePath(output_name);
        uint64_t size_data = size_cryptofile - ftell(cryptofile);
        result = readCryptofile(cryptofile, absolute_path, size_data);
        if (result != 0)
        {
            fprintf(stderr, "Fatal error: error of readCryptofile\n");
        }
        free(absolute_path.value);
        fclose(cryptofile);
    }

    free(iteration_keys);
    if (initial_vector != NULL)
    {
        free(initial_vector);
    }
    return 0;
}

/// @brief Finction checks number of input parameter.
/// @param prm pointer to the parameter in format "-*\0"
/// @return 0-10 is number of parameter, -1 is error.
int parameterDefinition(char *prm)
{
    if (prm[0] != '-' || prm[2] != 0)
    {
        return -1;
    }
    switch (prm[1])
    {
    case 'i':
        return 1;
    case 'o':
        return 2;
    case 'k':
        return 3;
    case 'm':
        return 4;
    case 'p':
        return 5;
    case 'c':
        return 6;
    case 's':
        return 7;
    case 'r':
        return 8;
    case 'b':
        return 9;
    case 'h':
        return 10;
    default:
        return -1;
    }
}

/// @brief Function compares for equal two strings. Function don't check null parameters.
/// @return 1 is equal, 0 is not equal.
int strEQ(char *strFirst, char *strSecond)
{
    int index = 0;
    while (strFirst[index] == strSecond[index])
    {
        if (strFirst[index] == '\0')
        {
            return 1;
        }
        index++;
    }
    return 0;
}

/// @brief Function returns the number of mode.
/// @param mode string with name of the mode.
/// @return 1-6 is number of mode, 0 if mode don't exist.
int modeDefinition(char *mode)
{
    if (strEQ(mode, "ECB"))
    {
        return ECB;
    }
    else if (strEQ(mode, "CBC"))
    {
        return CBC;
    }
    else if (strEQ(mode, "CTR"))
    {
        return CTR;
    }
    else if (strEQ(mode, "OFB"))
    {
        return OFB;
    }
    else if (strEQ(mode, "CFB"))
    {
        return CFB;
    }
    else if (strEQ(mode, "IMITO"))
    {
        return IMITO;
    }
    return 0;
}

/// @brief Function create initial vector and save result to @initial_vector.
/// @return 0 is good, 1 is error of malloc, 3 is error of fread.
int createInitialVector()
{
    int size_initial_vector;
    if (mode_encryption == CTR)
    {
        size_initial_vector = 8;
        size_register_in_bytes = 8;
    }
    else
    {
        size_initial_vector = size_register_in_bytes;
    }
    initial_vector = (vector128_t *)malloc(size_initial_vector);
    if (initial_vector == NULL)
    {
        return 1;
    }
#ifdef _WIN32
    HCRYPTPROV hCryptProv; // cryptographic context
    if (CryptAcquireContextA(&hCryptProv, NULL, (LPCSTR) "Microsoft Base Cryptographic Provider v1.0", PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
    {
        if (CryptGenRandom(hCryptProv, size_initial_vector, (BYTE *)initial_vector))
        {
            return 0;
        }
    }
    free(initial_vector);
    fprintf(stderr, "Fatal error: get random data\n");
    return 3;
#else
    FILE *random = fopen("/dev/random", "r");
    if (fread(initial_vector, 1, size_initial_vector, random) != size_initial_vector)
    {
        free(initial_vector);
        fprintf(stderr, "Fatal error: get random data\n");
        return 3;
    }
    fclose(random);
#endif
    return 0;
}

/// @brief Function checks of type of file with @path.
/// @param path path to file.
/// @return REGFILE, DIRECTORY or 0 in often cases.
int getTypeFile(String path)
{
    struct stat path_stat;
    if (stat(path.value, &path_stat) == -1)
    {
        fprintf(stderr, "Error: stat for \'%s\'. Maybe file don't exist\n", path);
        return 0;
    }
    if ((path_stat.st_mode & 0170000) == S_IFREG)
    {
        return REGFILE;
    }
    else if ((path_stat.st_mode & 0170000) == S_IFDIR)
    {
        return DIRECTORY;
    }
    fprintf(stderr, "File %s unsupported\n", path.value);
    return 0;
}

/// @brief Function create new memory and saves size of this memory in @size.
/// @param size pointer to memory, in which will saved size of memory.
/// @return pointer on memory.
char *createHeaderCryptofile(uint32_t *size)
{
    /// header of cryptofile has next structure:
    /// * size of cryptofile's header (4 bytes)
    /// * mode of encryption (1 byte)
    /// * mode of padding nulls (1 byte)
    /// * size of block in bytes (1 byte)
    /// * null (1 butes)
    /// * size of initial_vector/register (4 byte)
    /// * four nulls (4 bytes)
    /// * initial_vector
    uint32_t size_header_cryptofile = 16 + size_register_in_bytes;
    *size = size_header_cryptofile;
    char *header_cryptofile = (char *)malloc(size_header_cryptofile);
    if (header_cryptofile == NULL)
    {
        fprintf(stderr, "Fatal error: error of malloc: %d", __LINE__);
        return NULL;
    }
    *((uint32_t *)header_cryptofile) = size_header_cryptofile;
    header_cryptofile[4] = (char)mode_encryption;
    header_cryptofile[5] = (char)mode_padding_nulls;
    header_cryptofile[6] = (char)size_block_in_bytes;
    header_cryptofile[7] = 0;
    *(((uint32_t *)header_cryptofile) + 2) = size_register_in_bytes;
    *(((uint32_t *)header_cryptofile) + 3) = 0;
    if (mode_encryption != ECB)
    {
        for (int i = 0; i < size_register_in_bytes; i++)
        {
            header_cryptofile[16 + i] = ((char *)initial_vector)[i];
        }
    }
    else
    {
        memset(header_cryptofile + 16, 0, size_register_in_bytes);
    }
    return header_cryptofile;
}

/// @brief Function encrypts file @input with size @size_input_file and writes result to @output
/// @param input pointer of input file for encrypt, opened by "rb".
/// @param output pointer of output file for writing result, opened by "wb".
/// @param size_input_file size of @input file in bytes.
/// @return result of encryption operation: 0 is good, result < 0 is error.
int encryptFile(FILE *input, FILE *output, uint64_t size_input_file)
{
    int result;
    switch (mode_encryption)
    {
    case ECB:
    {
        result = encryptECBKuz(input, output, iteration_keys, mode_padding_nulls, size_input_file);
        break;
    }
    case CBC:
    {
        result = encryptCBCKuz(input, output, iteration_keys, mode_padding_nulls, size_register_in_bytes, initial_vector, size_input_file);
        break;
    }
    case CTR:
    {
        result = encryptCTRKuz(input, output, iteration_keys, size_block_in_bytes, initial_vector, size_input_file);
        initial_vector->half[0] += 1;
        break;
    }
    case OFB:
    {
        result = encryptOFBKuz(input, output, iteration_keys, size_block_in_bytes, size_register_in_bytes, initial_vector, size_input_file);
        break;
    }
    case CFB:
    {
        result = encryptCFBKuz(input, output, iteration_keys, size_block_in_bytes, size_register_in_bytes, (uint8_t *)initial_vector, size_input_file);
        break;
    }
    default:
    {
        fprintf(stderr, "Fatal error: unsupported mode of encryption\n");
        return -2;
    }
    }
    return result;
}

/// @brief Function encrypts file @input with size @size_input_file and writes result to @output
/// @param input pointer of input file for encrypt, opened by "rb".
/// @param output pointer of output file for writing result, opened by "wb".
/// @param size_input_file size of @input file in bytes.
/// @param length_last_block length of last block of @input file in bytes. Need for first mode of padding nulls.
/// @return result of encryption operation: 0 is good, result < 0 is error.
int decryptFile(FILE *input, FILE *output, uint64_t size_input_file, uint8_t length_last_block)
{
    int result;
    switch (mode_encryption)
    {
    case ECB:
    {
        result = decryptECBKuz(input, output, iteration_keys, mode_padding_nulls, length_last_block, size_input_file);
        break;
    }
    case CBC:
    {
        result = decryptCBCKuz(input, output, iteration_keys, mode_padding_nulls, length_last_block, size_register_in_bytes, initial_vector, size_input_file);
        break;
    }
    case CTR:
    {
        result = decryptCTRKuz(input, output, iteration_keys, size_block_in_bytes, initial_vector, size_input_file);
        initial_vector->half[0] += 1;
        break;
    }
    case OFB:
    {
        result = decryptOFBKuz(input, output, iteration_keys, size_block_in_bytes, size_register_in_bytes, initial_vector, size_input_file);
        break;
    }
    case CFB:
    {
        result = decryptCFBKuz(input, output, iteration_keys, size_block_in_bytes, size_register_in_bytes, (uint8_t *)initial_vector, size_input_file);
        break;
    }
    default:
    {
        fprintf(stderr, "Fatal error: unsupported mode of decryption\n");
        return -2;
    }
    }
    return result;
}

/// @brief Function fills with zero of memory @str.value with size @size after '\0'.
/// @param str structure with with array of characters and '\0' terminated.
/// @param size size memory which will be filled with zero.
void cleanMemory(String str, int size)
{
    for (uint64_t i = str.len; i < size; i++)
    {
        str.value[i] = '\0';
    }
}

/// @brief Function encrypts directory with path @path and writes result to @output. 
/// @param path path to directory.
/// @param name name of directory.
/// @param output pointer of output file for writing result, opened by "wb".
/// @return 0 is good, -1 if error with io, -2 if error with malloc.
int writeDirectory(String path, String name, FILE *output)
{
    DIR *dir = opendir(path.value);
    if (dir == NULL)
    {
        fprintf(stderr, "Fatal error: cannot open directory\n");
        return -1;
    }
    long offset_to_start_data;
    vector256_t sha256_sum;
    sha256(name.value, name.len, &sha256_sum);
    char *header = createHeader(name.value, 'd', 0, sha256_sum);
    if (header == NULL)
    {
        fprintf(stderr, "Fatal error: cannot create header for directory: %d\n", __LINE__);
        closedir(dir);
        return -1;
    }
    for (int i = 0; i < 19; i++) // 19 is 304/SIZE_BLOCK
    {
        encryptBlockKuz(((vector128_t *)header) + i, iteration_keys);
    }
    if (fwrite(header, 1, 304, output) != 304)
    {
        fprintf(stderr, "Fatal error: failed to write header\n");
        closedir(dir);
        free(header);
        return -1;
    }
    free(header);
    offset_to_start_data = ftell(output);
    struct dirent *dir_entry;
    String new_path;
    int result;
    while ((dir_entry = readdir(dir)) != NULL)
    {
        if (strEQ(dir_entry->d_name, ".") || strEQ(dir_entry->d_name, ".."))
        {
            continue;
        }
        if (dir_entry->d_type == DT_REG)
        {
            String name_file;
            name_file.value = malloc(257);
            if (name_file.value == NULL)
            {
                fprintf(stderr, "Fatal error: error of malloc: %d\n", __LINE__);
                closedir(dir);
                return -2;
            }
            strcpy(name_file.value, dir_entry->d_name);
            name_file.len = strlen(name_file.value);
            cleanMemory(name_file, 257);
            new_path = createPath(path, name_file);
            result = writeFile(new_path.value, name_file.value, output);
            if (result < 0)
            {
                fprintf(stderr, "Fatal error: failed to write in file %s\n", new_path.value);
                closedir(dir);
                free(new_path.value);
                free(name_file.value);
                return result;
            }
            free(new_path.value);
            free(name_file.value);
        }
        else if (dir_entry->d_type == DT_DIR)
        {
            String name_dir;
            name_dir.value = malloc(257);
            if (name_dir.value == NULL)
            {
                fprintf(stderr, "Fatal error: error of malloc: %d\n", __LINE__);
                return -2;
            }
            strcpy(name_dir.value, dir_entry->d_name);
            name_dir.len = strlen(name_dir.value);
            cleanMemory(name_dir, 257);
            new_path = createPath(path, name_dir);
            result = writeDirectory(new_path, name_dir, output);
            if (result < 0)
            {
                fprintf(stderr, "Fatal error: failed to write of directory %s\n", new_path.value);
                closedir(dir);
                free(new_path.value);
                free(name_dir.value);
                return result;
            }
            free(new_path.value);
            free(name_dir.value);
        }
    }
    closedir(dir);
    long current_offset = ftell(output);
    uint64_t size_dir = (uint64_t)current_offset - offset_to_start_data;
    vector128_t block = {(uint64_t)'d', size_dir};
    encryptBlockKuz(&block, iteration_keys);
    fseek(output, offset_to_start_data - sizeof(vector256_t) - 2 * sizeof(uint64_t), SEEK_SET);
    if (fwrite(&block, SIZE_BLOCK, 1, output) != 1)
    {
        fprintf(stderr, "Fatal error: failed to write: %d\n", __LINE__);
        closedir(dir);
        return -1;
    }
    fseek(output, current_offset, SEEK_SET);
    return 0;
}

/// @brief Function creates new string with path to file or directory with name @name. Result: @path+'/'+@name or @path+'\\'+@name. 
/// @param path struct String with path to file or directory.
/// @param name struct String with name of file or directory.
/// @return resulting struct string with new path to file or directory.
String createPath(String path, String name)
{
    String new_path;
    new_path.value = (char *)malloc(path.len + name.len + 2);
    if (new_path.value == NULL)
    {
        fprintf(stderr, "Fatal error: error of malloc: %d\n", __LINE__);
        return new_path;
    }
    new_path.len = path.len + name.len + 1;
    for (int i = 0; i < path.len; i++)
    {
        new_path.value[i] = path.value[i];
    }
#ifdef _WIN32
    new_path.value[path.len] = '\\';
#else
    new_path.value[path.len] = '/';
#endif
    for (int i = 0; i < name.len; i++)
    {
        new_path.value[path.len + 1 + i] = name.value[i];
    }
    new_path.value[new_path.len] = '\0';
    return new_path;
}

/// @brief Function encrypts file with path @path and name @name and writes result to @output.
/// @param path pointer on path to file.
/// @param name pointer on name of file.
/// @param output pointer of output file for writing result, opened by "wb".
/// @return 0 is good, -1 if error with io, -2 if error with malloc.
int writeFile(char *path, char *name, FILE *output)
{
    FILE *file = fopen(path, "rb");
    if (file == NULL)
    {
        fprintf(stderr, "Fatal error: failed to open: %d\n", __LINE__);
        return -1;
    }
    uint64_t size_file = getSizeFile(file);
    vector256_t sha256_sum;
    sha256(name, strlen(name), &sha256_sum);
    char *header = createHeader(name, 'f', size_file, sha256_sum);
    if (header == NULL)
    {
        fprintf(stderr, "Fatal error: cannot create header for file: %d\n", __LINE__);
        return -2;
    }
    if (mode_padding_nulls == PROC_ADD_NULLS_1)
    {
        header[257] = (char)size_file % SIZE_BLOCK;
    }
    for (int i = 0; i < 19; i++) // 19 is 304/SIZE_BLOCK
    {
        encryptBlockKuz(((vector128_t *)header) + i, iteration_keys);
    }
    if (fwrite(header, 1, 304, output) != 304)
    {
        fprintf(stderr, "Fatal error: failed to write header\n");
        return -1;
    }
    int result = encryptFile(file, output, size_file);
    free(header);
    fclose(file);
    return result;
}

/// @brief Function creates header for file of directory.
/// Header has next structure:
/// - 256 bytes for name;
/// - byte for type: 'f' or 'd' + 7 nulls bytes;
/// - 8 bytes for size of file or directory (in output file);
/// - 32 bytes for hash sum.
/// @param name name of file or directory.
/// @param type 'f' is file, 'd' is directory.
/// @param size size of file or directory (in output file).
/// @param sha256_sum hash sum.
/// @return pointer on block of memory with size 304 bytes.
char *createHeader(char *name, char type, uint64_t size, vector256_t sha256_sum)
{
    char *header = (char *)malloc(304);
    if (header == NULL)
    {
        return NULL;
    }
    memset(header, 0, 304);
    for (int i = 0; i < 256; i++)
    {
        header[i] = name[i];
    }
    header[256] = type;
    *((uint64_t *)(header + 264)) = size;
    *((vector256_t *)(header + 272)) = sha256_sum;
    return header;
}

/// @brief Function return last name in path in string with new memory.
String getName(String path)
{
    String name;
#ifdef _WIN32
    char *ptr_on_name = strrchr(path.value, '\\');
#else
    char *ptr_on_name = strrchr(path.value, '/');
#endif
    if (ptr_on_name != NULL)
    {
        ptr_on_name++; // Skip the separator
    }
    else
    {
        ptr_on_name = path.value;
    }

    name.value = (char *)malloc(256);
    if (name.value == NULL)
    {
        fprintf(stderr, "Fatal error: error of malloc: %d\n", __LINE__);
        return name;
    }
    name.len = strlen(ptr_on_name);
    if (name.len > 255)
    {
        name.len = 255;
    }
    memcpy(name.value, ptr_on_name, name.len);
    cleanMemory(name, 256);
    return name;
}


/// @brief Function returns string with new absolute path to file or directory.
/// @param path path to file or directory.
String getAbsolutePath(char *path)
{
    String absolutePath = {NULL, 0};
    absolutePath.value = malloc(PATH_MAX + 1);
    if (absolutePath.value == NULL)
    {
        fprintf(stderr, "Fatal error: error allocating memory for absolute path\n");
        return absolutePath;
    }
#ifdef _WIN32
    int result = GetFullPathName(path, PATH_MAX, absolutePath.value, NULL);
    if (result == 0)
    {
        fprintf(stderr, "Fatal error: failed to get absolute path\n");
        free(absolutePath.value);
        absolutePath.value = NULL;
        return absolutePath;
    }
    absolutePath.len = strlen(absolutePath.value);
#else
    // memset(absolutePath.value, 0, PATH_MAX + 1);
    realpath(path, absolutePath.value);
    absolutePath.len = strlen(absolutePath.value);
#endif
    return absolutePath;
}

/// @brief Function read header from @input file and writes this header to struct @header
/// @return 0 is good, -1 is error of read file, -2 is error of malloc.
int readHeader(FILE *input, struct header *header)
{
    uint8_t *data = (uint8_t *)malloc(304);
    if(data == NULL)
    {
        fprintf(stderr, "Fatal error: error of malloc: %d\n", __LINE__);
        return -2;
    }
    int result = fread(data, 1, 304, input);
    if (result != 304)
    {
        free(data);
        return -1;
    }
    for (int i = 0; i < 19; i++) // 19 is 304/SIZE_BLOCK
    {
        decryptBlockKuz(((vector128_t *)data) + i, iteration_keys);
    }
    header->name = data;
    header->type = *((char *)data + 256);
    header->size = *((uint64_t *)(data + 264));
    header->sha256_sum = *((vector256_t *)(data + 272));
    return 0;
}

/// @brief Function creates directory in the path @path and mode @mode.
/// @return 0 is good, -1 is error of create directory.
int createDirectory(char *path, int mode)
{
#ifdef _WIN32
    if (CreateDirectory(path, NULL) == 0)
    {
        if (GetLastError() == ERROR_ALREADY_EXISTS)
        {
            return 0;
        }
        fprintf(stderr, "Fatal error: error of creating directory %s\n", path);
        return -1;
    }
#else
    if (mkdir(path, mode) == -1)
    {
        if (errno == EEXIST)
        {
            return 0;
        }
        fprintf(stderr, "Fatal error: error of creating directory %s\n", path);
        return -1;
    }
#endif
    return 0;
}

/// @brief Functuon read from cryptofile @size bytes and decrypted files.
/// @param input cryptofile opened by "rb".
/// @param path path on directory in which will saved files.
/// @param size count of bytes for decryption.
/// @return 0 is good, often is error. 
int readCryptofile(FILE *input, String path, uint64_t size)
{
    struct header header;
    int result;
    String new_path = {NULL, 0};
    String name = {NULL, 0};
    FILE *file = NULL;
    vector256_t hash;
    char count_errors = 0;
    uint64_t readable_size = 0;
    if(size == 0)
    {
        return 0;
    }
    while (!feof(input) && !ferror(input))
    {
        result = readHeader(input, &header);
        if (result != 0)
        {
            if (count_errors != 2)
            {
                count_errors++;
                continue;
            }
            else
            {
                fprintf(stderr, "Fatal error: error of read cryptofile: %d", __LINE__);
                return -1;
            }
        }
        readable_size += 304; 
        printf("Read header: %s\n", header.name);
        if (header.type == 'd')
        {
            name.value = header.name;
            name.len = strlen(header.name);
            new_path = createPath(path, name);
            if (new_path.value == NULL)
            {
                free(header.name);
                return -2;
            }
            sha256(name.value, name.len, &hash);
            if (hash.qwords[0] == header.sha256_sum.qwords[0] && hash.qwords[1] == header.sha256_sum.qwords[1] &&
                hash.qwords[2] == header.sha256_sum.qwords[2] && hash.qwords[3] == header.sha256_sum.qwords[3])
            {
                result = createDirectory(new_path.value, 0777);
                if (result < 0)
                {
                    free(header.name);
                    return -3;
                }
                readCryptofile(input, new_path, header.size);
            }
            else
            {
                fprintf(stderr, "Fatal error: hash sums don't equals for %s\n", header.name);
            }
            free(new_path.value);
        }
        else if (header.type == 'f')
        {
            name.value = header.name;
            name.len = strlen(header.name);
            new_path = createPath(path, name);
            if (new_path.value == NULL)
            {
                return -2;
            }
            file = fopen(new_path.value, "wb");
            if (file == NULL)
            {
                fprintf(stderr, "Fatal error: error of open file %s: %d", new_path.value, __LINE__);
                free(new_path.value);
                free(header.name);
                return -1;
            }
            sha256(name.value, name.len, &hash);
            if (hash.qwords[0] == header.sha256_sum.qwords[0] && hash.qwords[1] == header.sha256_sum.qwords[1] &&
                hash.qwords[2] == header.sha256_sum.qwords[2] && hash.qwords[3] == header.sha256_sum.qwords[3])
            {
                decryptFile(input, file, header.size, (uint8_t)(header.name[257]));
            }
            else
            {
                fprintf(stderr, "Fatal error: hash sums don't equals for %s\n", header.name);
            }
            fclose(file);
            free(new_path.value);
        }
        else
        {
            fprintf(stderr, "Error: unknown type header: %d\nWith name: %s\nSize: %llu\n", header.type, header.name, header.size);
            sha256(header.name, strlen(header.name), &hash);
            if (hash.qwords[0] == header.sha256_sum.qwords[0] && hash.qwords[1] == header.sha256_sum.qwords[1] &&
                hash.qwords[2] == header.sha256_sum.qwords[2] && hash.qwords[3] == header.sha256_sum.qwords[3])
            {
                fprintf(stderr, "Hash equals\n");
            }
            else
            {
                fprintf(stderr, "Fatal error: hash sums don't equals for %s\n", header.name);
            }
        }
        readable_size += header.size;
        if( readable_size == size )
        {
            free(header.name);
            return 0;    
        }
        free(header.name);
    }
    return 0;
}

/// @brief Function print MAC of file.
/// @param path path to the file.
/// @return 0 is good, of is error.
int printMACFile(char *path)
{
    FILE *file = fopen(path, "rb");
    if (file == NULL)
    {
        fprintf(stderr, "Fatal error: error opening %s\n", path);
        return 3;
    }
    uint64_t size_file = getSizeFile(file);
    int size_MAC_in_bytes = size_MAC / 8 + (size_MAC % 8 != 0 ? 1 : 0);
    uint8_t MAC[size_MAC_in_bytes];
    int result = createMAC(file, MAC, iteration_keys, size_MAC, size_file);
    if (result != 0)
    {
        return result;
    }
    printf("MAC of %s:\n0x", path);
    for (int i = size_MAC_in_bytes - 1; i >= 0; i--)
    {
        printf("%02X", MAC[i]);
    }
    printf("\n");
    return 0;
}

/// @brief Function print MAC of directory (all files in this directory).
/// @param path path to the directory.
/// @return 0 is good, of is error.
int printMACDirectory(char *path)
{
    DIR *dir = opendir(path);
    if (dir == NULL)
    {
        fprintf(stderr, "Fatal error: cannot open directory\n");
        return 3;
    }
    String path_str = {path, strlen(path)};
    String name;
    String new_path;
    struct dirent *dir_entry;
    while ((dir_entry = readdir(dir)) != NULL)
    {
        if (strEQ(dir_entry->d_name, ".") || strEQ(dir_entry->d_name, ".."))
        {
            continue;
        }
        if (dir_entry->d_type == DT_REG)
        {
            name.value = dir_entry->d_name;
            name.len = strlen(name.value);
            new_path = createPath(path_str, name);
            if (new_path.value == NULL)
            {
                fprintf(stderr, "Fatal error: error of malloc: %d\n", __LINE__);
                return 1;
            }
            printMACFile(new_path.value);
        }
        else if (dir_entry->d_type == DT_DIR)
        {
            name.value = dir_entry->d_name;
            name.len = strlen(name.value);
            new_path = createPath(path_str, name);
            if (new_path.value == NULL)
            {
                fprintf(stderr, "Fatal error: error of malloc: %d\n", __LINE__);
                return 1;
            }
            printMACDirectory(new_path.value);
        }
    }
}