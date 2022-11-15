#include <stdio.h>
#include <sys/types.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include "../include/kuznechik.h"
#include "../include/sha256.h"

int parameterDefinition(char* prm);
int strEQ(char* strFirst,char * strSecond);
int modeDefinition(char* mode);
int isRegularFile(char *path);
int isDirectory(char *path);


uint64_t main(int argc, char** argv)
/*parameters: 
*  -i names of input files or directores #1
*  -k string with key #2
*  -m mode of a encryption or decryption {"ECB", "CBC", "CTR", "OFB", "CFB", "IMITO"} #3
*  -p mode of padding block {1-3} #4
*  -c encrypt or decrypt {e, d} #5
*  -b count byte in last block for first mode padding block {1-8} #6
*  -s size MAC in bits {1-128} #7
*  -h help #8
*/
{
    // standard parameters
    char* name_input = NULL;
    char* name_output =  NULL;
    int mode = 'e';
    int mode_of_encryption = ECB;
    int mode_padding = PROC_ADD_NULLS_2;
    uint8_t countByteInLastBlock = 0; 
    uint8_t sizeMAC  = 64; 
    // read input parameters
    for(int index = 1; index < argc; index++)
    {
        switch(parameterDefinition(argv[index]))
        {
            case 1: 
                index++;
                if(index == argc)
                {
                    printf("Fatal error: empty parameter\n");
                    return 0;
                }
                nameInputFile = argv[index];
                break;
            case 2: 
                index++;
                if(index == argc)
                {
                    printf("Fatal error: empty parameter\n");
                    return 0;
                }
                nameFileWithKey = argv[index];
                break;
            case 3: 
                index++;
                if(index == argc)
                {
                    printf("Fatal error: empty parameter\n");
                    return 0;
                }
                if((mode = modeDefinition(argv[index])) == 0)
                {
                    printf("Fatal error: unknown mode\n");
                    return 0;
                }
                if(mode == 6 || mode == 1)
                {
                    break;    
                }
                else
                {
                    printf("Fatal error: invalid mode\n");
                    return 0;
                }
            case 4: 
                index++;
                if(index == argc)
                {
                    printf("Fatal error: empty parameter\n");
                    return 0;
                }
                modePadding = *(argv[index]) - '1' + 1;
                if(modePadding >= 1 && modePadding <=3)
                {
                    break;
                }
                else
                {
                    printf("Fatal error: invalid modePadding\n");
                    return 0;
                }
            case 6: 
                index++;
                if(index == argc)
                {
                    printf("Fatal error: empty parameter\n");
                    return 0;
                }
                crypt = *(argv[index]);
                if(crypt != 'e' && crypt != 'd')
                {
                    printf("Fatal error: invalid mode crypt\n");
                    return 0;
                }
                break;
             case 6: 
                index++;
                if(index == argc)
                {
                    printf("Fatal error: empty parameter\n");
                    return 0;
                }
                countByteInLastBlock = *(argv[index]) - '1' + 1;
                if(countByteInLastBlock <= 8 && countByteInLastBlock >= 1)
                {
                    break;    
                }
                else
                {
                    printf("Fatal error: invalid countByteInLastBlock\n");
                    return 0;
                }
            case 7: 
                index++;
                if(index == argc)
                {
                    printf("Fatal error: empty parameter\n");
                    return 0;
                }
                sizeMAC = (uint8_t)atoi(argv[index]);
                if(sizeMAC <= 64 && sizeMAC >= 1)
                {
                    break;    
                }
                else
                {
                    printf("Fatal error: invalid sizeMAC\n");
                    return 0;
                }
            case 8:
                printf("Parameters:\n*  -i name input file\n* -k string with key\n*  -m mode {ECB, CBC, CTR, OFB, CFB, IMITO}\n*  -p mode of padding block {1-3}\n*  -c encrypt or decrypt {e, d}\n*  -b count byte in last block for first mode of padding block {1-8}\n*  -s size MAC {1-128}\n*  -h help\n");
                return 1;
            case -1: 
                printf("Fatal error: invalid parameter\n");
                return 0;
        }
    }
    //check
    if(nameInputFile == NULL && nameFileWithKey == NULL)
    {
        printf("Fatal error: insufficient parameters\n");
        return 0;
    }
    //read key
    uint32_t key[8];
    FILE* fileWithKey = fopen(nameFileWithKey, "r");
    if(fileWithKey == NULL)
    {
        printf("Fatal error: could not open file with key\n");
        return 0;
    }
    if(fread(key, 4, 8, fileWithKey) != 8)
    {
        printf("Fatal error: could not read file with key\n");
        return 0;
    }
    fclose(fileWithKey);
    //begin
    switch(mode)
    {
        case ECB:
           if(crypt == 'e')
           {
               if(EncryptECB(nameInputFile, nameOutputFile, key, modePadding) != 1)
               {
                    printf("Fatal error: failed to complete EncryptECB");
                    return 0;
               }
           }
           else
           {
                if(DecryptECB(nameInputFile, nameOutputFile, key, modePadding, countByteInLastBlock) != 1)
               {
                    printf("Fatal error: failed to complete DecryptECB");
                    return 0;
               }
           }
           break;
        case IMITO:
           {
           uint64_t result = getMAC(nameInputFile, key, sizeMAC);
           printf("%lld\n", result);
           return result;
           }
    }
    return 1;
}

int parameterDefinition(char* prm)
{
    if(*prm != '-')
    {
        return -1;
    }
    switch(prm[1])
    {
        case 'i': 
            if(prm[2] != 0)
            {
                return -1;
            }
            return 1;
        case 'k': 
            if(prm[2] != 0)
            {
                return -1;
            }
            return 2;
        case 'm': 
            if(prm[2] != 0)
            {
                return -1;
            }
            return 3;
        case 'p': 
            if(prm[2] != 0)
            {
                return -1;
            }
            return 4;
        case 'c': 
            if(prm[2] != 0)
            {
                return -1;
            }
            return 5;
        case 'b': 
            if(prm[2] != 0)
            {
                return -1;
            }
            return 6;
        case 's': 
            if(prm[2] != 0)
            {
                return -1;
            }
            return 7;
        case 'h': 
            if(prm[2] != 0)
            {
                return -1;
            }
            return 8;
        default: return -1;
    }
}

int strEQ(char* strFirst,char * strSecond)
{
    int index = 0;
    while(strFirst[index] == strSecond[index])
    {
        if(strFirst[index] == '\0')
        {
            return 1;
        }
        index++;
    }
    return 0;
}

int modeDefinition(char* mode) {
    if(strEQ(mode, "ECB")) {
        return ECB;
    }
    else if(strEQ(mode, "CBC")) {
        return CBC;
    }
    else if(strEQ(mode, "CTR")) {
        return CTR;
    }
    else if(strEQ(mode, "OFB")) {
        return OFB;
    }
    else if(strEQ(mode, "CFB"))  {
        return CFB;
    }
    else if(strEQ(mode, "IMITO")) {
        return IMITO;
    }
    return 0;
}

int isRegularFile(char *path) {
    struct stat path_stat;
    stat(path, &path_stat);
    return S_ISREG(path_stat.st_mode);
}

int isDirectory(char *path) {
    struct stat path_stat;
    stat(path, &path_stat);
    return S_ISDIR(path_stat.st_mode);
}

