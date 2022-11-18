#include <stdio.h>
#include <sys/types.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include "../include/kuznechik.h"
#include "../include/sha256.h"

struct input_names
{
    char *input_name;
    struct input_names *next;
    struct input_names *prev;
};

int parameterDefinition(char *prm);
int strEQ(char *strFirst, char *strSecond);
int modeDefinition(char *mode);
int readInputNames(char **argv, int argc, int index, struct input_names *root);
// int printMAC( struct input_names * root, vector128_t * iteration_keys, uint8_t size_MAC);
// int encryptInputNames(struct input_names * root, vector128_t * iteration_keys, int mode_of_encryption, int mode_padding);
// int decryptInputNames(struct input_names * root, vector128_t * iteration_keys, int mode_of_encryption, int mode_padding);
int isRegularFile(char *path);
int isDirectory(char *path);
// int encryptDirectory();
// int decryptDirectory();
int encryptFile();
int decryptFile();

/// @brief
/// parameters:
/// *  -i names of input files or directores #1
/// *  -k string with key #2
/// *  -m mode of a encryption or decryption {"ECB", "CBC", "CTR", "OFB", "CFB", "IMITO"} #3
/// *  -p mode of padding block {2 or 3} #4
/// *  -c encrypt or decrypt {e, d} #5
/// *  -s size MAC in bits {1-128} #6
/// *  -h help #7
/// Standart parameters:
/// *    encryption by mode "ECB" with second mode of padding block.
/// *    Size MAC for mode "IMITO" is 64 bits.
/// @param argc
/// @param argv
/// @return 0 is good, 1 is error of malloc, 2 is error in parameters, 3 is error of read/write file or directory;
int main(int argc, char **argv)
{
    struct input_names list_names;
    char *key_str = NULL;
    int mode = 'e';
    int mode_of_encryption = ECB;
    int mode_padding = PROC_ADD_NULLS_2;
    uint8_t size_MAC = 64;

    for (int index = 1; index < argc; index++)
    {
        switch (parameterDefinition(argv[index]))
        {
        case 1:
        { // -i
            index++;
            if (index == argc)
            {
                fprintf(stderr, "Fatal error: empty parameter -p\n");
                return 2;
            }
            index = readInputNames(argv, argc, index, &list_names);
            if (parameterDefinition(list_names.input_name) != -1)
            {
                fprintf(stderr, "Fatal error: empty parameter -p\n");
                return 2;
            }
            break;
        }
        case 2:
        { // -k
            index++;
            if (index == argc)
            {
                fprintf(stderr, "Fatal error: empty parameter -k\n");
                return 2;
            }
            key_str = argv[index];
            if (parameterDefinition(key_str) != -1)
            {
                fprintf(stderr, "Fatal error: empty parameter -k\n");
                return 2;
            }
            break;
        }
        case 3:
        { // -m
            index++;
            if (index == argc)
            {
                fprintf(stderr, "Fatal error: empty parameter -m\n");
                return 2;
            }
            mode_of_encryption = modeDefinition(argv[index]);
            if (mode_of_encryption == 0)
            {
                fprintf(stderr, "Fatal error: unknown mode in parameter -m\n");
                return 2;
            }
        }
        case 4:
        { // -p
            index++;
            if (index == argc)
            {
                fprintf(stderr, "Fatal error: empty parameter -p\n");
                return 2;
            }
            mode_padding = *(argv[index]) - '0';
            if (mode_padding < 1 || mode_padding > 3)
            {
                fprintf(stderr, "Fatal error: invalid mode of padding block\n");
                return 2;
            }
        }
        case 5:
        { // -c
            index++;
            if (index == argc)
            {
                fprintf(stderr, "Fatal error: empty parameter -c\n");
                return 2;
            }
            mode = *(argv[index]);
            if (mode != 'e' && mode != 'd')
            {
                fprintf(stderr, "Fatal error: invalid mode encrypt or decrypt\n");
                return 2;
            }
            break;
        }
        case 6:
        { // -s
            index++;
            if (index == argc)
            {
                fprintf(stderr, "Fatal error: empty parameter -s\n");
                return 2;
            }
            size_MAC = (uint8_t)atoi(argv[index]);
            if (size_MAC > 128 || size_MAC < 1)
            {
                fprintf(stderr, "Fatal error: invalid size MAC\n");
                return 2;
            }
        }
        case 7:
        { // -h
            fprintf(stderr, "Parameters:\n*  -i name input file\n* -k string with key\n*  -m mode {ECB, CBC, CTR, OFB, CFB, IMITO}\n*  -p mode of padding block {1-3}\n*  -c encrypt or decrypt {e, d}\n*  -b count byte in last block for first mode of padding block {1-8}\n*  -s size MAC {1-128}\n*  -h help\n");
            return 0;
        }
        case -1:
        {
            fprintf(stderr, "Fatal error: invalid parameter\n");
            return 2;
        }
        }
    }

    if (list_names.input_name == NULL || key_str == NULL)
    {
        fprintf(stderr, "Fatal error: insufficient parameters\n");
        return 2;
    }

    vector128_t key_vec[2];
    int result = sha256((uint8_t *)key_str, strlen(key_str), key_vec);
    if (result < 0)
    {
        fprintf(stderr, "Fatal error: error of getting hash of key\n Result: %d\n", result);
    }
    vector128_t iteration_keys[10];
    result = createIterationKeysKuz(key_vec, iteration_keys);
    if (result < 0)
    {
        fprintf(stderr, "Fatal error: error of creating of iteration keys\n Result: %d\n", result);
    }

    if (mode_of_encryption == IMITO)
    {
        printMAC(&list_names, iteration_keys, size_MAC);
    }
    else if (mode == ENCRYPT)
    {
        encryptInputNames(&list_names, iteration_keys, mode_of_encryption, mode_padding);
    }
    else
    {
        decryptInputNames(&list_names, iteration_keys, mode_of_encryption, mode_padding);
    }

    struct input_names *node = &list_names;
    struct input_names *tmp = NULL;
    while (node->next != NULL)
    {
        node = node->next;
    }
    while (node->prev != &list_names)
    {
        tmp = node;
        node = node->prev;
        free(tmp);
    }

    return 0;
}

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
    case 'k':
        return 2;
    case 'm':
        return 3;
    case 'p':
        return 4;
    case 'c':
        return 5;
    case 's':
        return 6;
    case 'h':
        return 7;
    default:
        return -1;
    }
}

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

int readInputNames(char **argv, int argc, int index, struct input_names *root)
{
    struct input_names *node = root;
    while (index < argc)
    {
        if (parameterDefinition(argv[index]) != -1)
        {
            return index - 1;
        }
        node->input_name = argv[index];
        node->next = (struct input_names *)malloc(sizeof(struct input_names));
        if (node->next == NULL)
        {
            fprintf(stderr, "Fatal error: error of malloc\n Line: %d\n", __LINE__);
            exit(1);
        }
        node->next->prev = node;
        node = node->next;
        index++;
    }
    return index;
}

// int printMAC( struct input_names * node, vector128_t * iteration_keys, uint8_t size_MAC) {

// }

int isRegularFile(char *path)
{
    struct stat path_stat;
    stat(path, &path_stat);
    return S_ISREG(path_stat.st_mode);
}

int isDirectory(char *path)
{
    struct stat path_stat;
    stat(path, &path_stat);
    return S_ISDIR(path_stat.st_mode);
}

// TODO: change in all src key on iteration_keys and change tests
int encryptFile(char *name_input_file, FILE *output_fp, vector128_t *iteration_keys,
                int mode_of_encryption, int mode_padding, vector128_t *initial_vector)
{
    FILE *input_fp = fopen(name_input_file, "r");
    if (input_fp == NULL)
    {
        fprintf(stderr, "Fatal error: error of fopen\n Line: %d\n", __LINE__);
        return 3;
    }
    int result;
    if (mode_of_encryption == ECB)
    {
        result = encryptECBKuz(input_fp, output_fp, iteration_keys, mode_padding);
    }
    else if (mode_of_encryption == CBC)
    {
        result = encryptCBCKuz(input_fp, output_fp)
    }
    fclose(input_fp);
}
int decryptFile();