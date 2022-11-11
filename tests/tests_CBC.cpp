#include "../src/Kuznechik.c"
#include "../src/CBC.c"
#include "./gtest/include/gtest/gtest.h"
#include <sys/time.h>

TEST(ECB, TestFromGOST) {
    FILE * open_text = fopen("OpenText.txt", "w");
    FILE * close_text;
    if(open_text == NULL)
    {
        printf("Error of open file: %d\n", __LINE__);
        return;
    }

    vector128bit initial_vector[2];
    initial_vector[0].half[0] = 0x1213141516171819;
    initial_vector[0].half[1] = 0x2334455667788990;
    initial_vector[1].half[0] = 0xa1b2c3d4e5f00112;
    initial_vector[1].half[1] = 0x1234567890abcef0;

    vector128bit key[2];
    key[0].half[0] = 0x0123456789abcdef;
    key[0].half[1] = 0xfedcba9876543210;
    key[1].half[0] = 0x0011223344556677;
    key[1].half[1] = 0x8899aabbccddeeff;
    
    vector128bit block;
    block.half[0] = 0xffeeddccbbaa9988;
    block.half[1] = 0x1122334455667700; 
    fwrite(&block, SIZE_BLOCK, 1, open_text);
    block.half[0] = 0x8899aabbcceeff0a;
    block.half[1] = 0x0011223344556677; 
    fwrite(&block, SIZE_BLOCK, 1, open_text);
    block.half[0] = 0x99aabbcceeff0a00;
    block.half[1] = 0x1122334455667788; 
    fwrite(&block, SIZE_BLOCK, 1, open_text);
    block.half[0] = 0xaabbcceeff0a0011;
    block.half[1] = 0x2233445566778899; 
    fwrite(&block, SIZE_BLOCK, 1, open_text);
    fclose(open_text);

    open_text = fopen("OpenText.txt", "r");
    close_text = fopen("CloseText.txt", "w");
    EXPECT_EQ(0, encryptCBCKuz(open_text, close_text, key, PROC_ADD_NULLS_2, 32, initial_vector));
    fclose(open_text);
    fclose(close_text);

    close_text = fopen("CloseText.txt", "r");
    fread(&block, SIZE_BLOCK, 1, close_text);
    EXPECT_EQ(0x90e52e3d6d7dcc27, block.half[0]);
    EXPECT_EQ(0x689972d4a085fa4d, block.half[1]);
    fread(&block, SIZE_BLOCK, 1, close_text);
    EXPECT_EQ(0xaf1e8e448d5ea5ac, block.half[0]);
    EXPECT_EQ(0x2826e661b478eca6, block.half[1]);
    fread(&block, SIZE_BLOCK, 1, close_text);
    EXPECT_EQ(0x5640e8b0f49d90d0, block.half[0]);
    EXPECT_EQ(0xfe7babf1e91999e8, block.half[1]);
    fread(&block, SIZE_BLOCK, 1, close_text);
    EXPECT_EQ(0x1a2d9a1560b63970, block.half[0]);
    EXPECT_EQ(0x167688065a895c63, block.half[1]);
    EXPECT_EQ(SIZE_BLOCK, fread(&block, 1, SIZE_BLOCK+1, close_text));
    EXPECT_NE(feof(close_text), 0);
    fclose(close_text);

    open_text = fopen("OpenText.txt", "w");
    close_text = fopen("CloseText.txt", "r");
    EXPECT_EQ(0, decryptCBCKuz(close_text, open_text, key, PROC_ADD_NULLS_2, 0, 32, initial_vector));
    fclose(open_text);
    fclose(close_text);


    open_text = fopen("OpenText.txt", "r");
    fread(&block, SIZE_BLOCK, 1, open_text);
    EXPECT_EQ(0xffeeddccbbaa9988, block.half[0]);
    EXPECT_EQ(0x1122334455667700, block.half[1]);
    fread(&block, SIZE_BLOCK, 1, open_text);
    EXPECT_EQ(0x8899aabbcceeff0a, block.half[0]);
    EXPECT_EQ(0x0011223344556677, block.half[1]);
    fread(&block, SIZE_BLOCK, 1, open_text);
    EXPECT_EQ(0x99aabbcceeff0a00, block.half[0]);
    EXPECT_EQ(0x1122334455667788, block.half[1]);
    fread(&block, SIZE_BLOCK, 1, open_text);
    EXPECT_EQ(0xaabbcceeff0a0011, block.half[0]);
    EXPECT_EQ(0x2233445566778899, block.half[1]);
    fread(&block, SIZE_BLOCK, 1, open_text);
    EXPECT_NE(feof(open_text), 0);
    fclose(open_text);
}

TEST(ECB, PROC_ADD_NULLS_1_full) {
    FILE * open_text = fopen("OpenText.txt", "w");
    FILE * close_text;
    if(open_text == NULL)
    {
        printf("Error of open file: %d\n", __LINE__);
        return;
    }

    vector128bit initial_vector[2];
    initial_vector[0].half[0] = 0x1213141516171819;
    initial_vector[0].half[1] = 0x2334455667788990;
    initial_vector[1].half[0] = 0xa1b2c3d4e5f00112;
    initial_vector[1].half[1] = 0x1234567890abcef0;

    vector128bit key[2];
    key[0].half[0] = 0x0123456789abcdef;
    key[0].half[1] = 0xfedcba9876543210;
    key[1].half[0] = 0x0011223344556677;
    key[1].half[1] = 0x8899aabbccddeeff;
    
    vector128bit block;
    block.half[0] = 0xffeeddccbbaa9988;
    block.half[1] = 0x1122334455667700; 
    for(int i = 0; i < 10; i++) {
        fwrite(&block, SIZE_BLOCK, 1, open_text);
    }
    fclose(open_text);

    open_text = fopen("OpenText.txt", "r");
    close_text = fopen("CloseText.txt", "w");
    EXPECT_EQ(0, encryptCBCKuz(open_text, close_text, key, PROC_ADD_NULLS_1, 32, initial_vector));
    fclose(open_text);
    fclose(close_text);

    open_text = fopen("OpenText.txt", "w");
    close_text = fopen("CloseText.txt", "r");
    EXPECT_EQ(0, decryptCBCKuz(close_text, open_text, key, PROC_ADD_NULLS_1, 16, 32, initial_vector));
    fclose(open_text);
    fclose(close_text);

    open_text = fopen("OpenText.txt", "r");
    for(int i = 0; i < 10; i++) {
        fread(&block, SIZE_BLOCK, 1, open_text);
        EXPECT_EQ(0xffeeddccbbaa9988, block.half[0]);
        EXPECT_EQ(0x1122334455667700, block.half[1]);
    }
    EXPECT_EQ(0, fread(&block, 1, SIZE_BLOCK, open_text));
    EXPECT_NE(feof(open_text), 0);
    fclose(open_text);
}

TEST(ECB, PROC_ADD_NULLS_1_not_full) {
    FILE * open_text = fopen("OpenText.txt", "w");
    FILE * close_text;
    if(open_text == NULL)
    {
        printf("Error of open file: %d\n", __LINE__);
        return;
    }

    vector128bit initial_vector[2];
    initial_vector[0].half[0] = 0x1213141516171819;
    initial_vector[0].half[1] = 0x2334455667788990;
    initial_vector[1].half[0] = 0xa1b2c3d4e5f00112;
    initial_vector[1].half[1] = 0x1234567890abcef0;

    vector128bit key[2];
    key[0].half[0] = 0x0123456789abcdef;
    key[0].half[1] = 0xfedcba9876543210;
    key[1].half[0] = 0x0011223344556677;
    key[1].half[1] = 0x8899aabbccddeeff;
    
    vector128bit block;
    block.half[0] = 0xffeeddccbbaa9988;
    block.half[1] = 0x1122334455667700; 
    for(int i = 0; i < 10; i++) {
        fwrite(&block, SIZE_BLOCK, 1, open_text);
    }
    fwrite(&block, 4, 1, open_text);
    fclose(open_text);

    open_text = fopen("OpenText.txt", "r");
    close_text = fopen("CloseText.txt", "w");
    EXPECT_EQ(0, encryptCBCKuz(open_text, close_text, key, PROC_ADD_NULLS_1, 32, initial_vector));
    fclose(open_text);
    fclose(close_text);

    open_text = fopen("OpenText.txt", "w");
    close_text = fopen("CloseText.txt", "r");
    EXPECT_EQ(0, decryptCBCKuz(close_text, open_text, key, PROC_ADD_NULLS_1, 4, 32, initial_vector));
    fclose(open_text);
    fclose(close_text);

    open_text = fopen("OpenText.txt", "r");
    for(int i = 0; i < 10; i++) {
        fread(&block, SIZE_BLOCK, 1, open_text);
        EXPECT_EQ(0xffeeddccbbaa9988, block.half[0]);
        EXPECT_EQ(0x1122334455667700, block.half[1]);
    }
    EXPECT_EQ(4, fread(&block, 1, 5, open_text));
    EXPECT_NE(feof(open_text), 0);
    fclose(open_text);
}

TEST(ECB, PROC_ADD_NULLS_2_full) {
    FILE * open_text = fopen("OpenText.txt", "w");
    FILE * close_text;
    if(open_text == NULL)
    {
        printf("Error of open file: %d\n", __LINE__);
        return;
    }

    vector128bit initial_vector[2];
    initial_vector[0].half[0] = 0x1213141516171819;
    initial_vector[0].half[1] = 0x2334455667788990;
    initial_vector[1].half[0] = 0xa1b2c3d4e5f00112;
    initial_vector[1].half[1] = 0x1234567890abcef0;

    vector128bit key[2];
    key[0].half[0] = 0x0123456789abcdef;
    key[0].half[1] = 0xfedcba9876543210;
    key[1].half[0] = 0x0011223344556677;
    key[1].half[1] = 0x8899aabbccddeeff;
    
    vector128bit block;
    block.half[0] = 0xffeeddccbbaa9988;
    block.half[1] = 0x1122334455667700; 
    for(int i = 0; i < 10; i++) {
        fwrite(&block, SIZE_BLOCK, 1, open_text);
    }
    fclose(open_text);

    open_text = fopen("OpenText.txt", "r");
    close_text = fopen("CloseText.txt", "w");
    EXPECT_EQ(0, encryptCBCKuz(open_text, close_text, key, PROC_ADD_NULLS_2, 32, initial_vector));
    fclose(open_text);
    fclose(close_text);

    open_text = fopen("OpenText.txt", "w");
    close_text = fopen("CloseText.txt", "r");
    EXPECT_EQ(0, decryptCBCKuz(close_text, open_text, key, PROC_ADD_NULLS_2, 0, 32, initial_vector));
    fclose(open_text);
    fclose(close_text);

    open_text = fopen("OpenText.txt", "r");
    for(int i = 0; i < 10; i++) {
        fread(&block, SIZE_BLOCK, 1, open_text);
        EXPECT_EQ(0xffeeddccbbaa9988, block.half[0]);
        EXPECT_EQ(0x1122334455667700, block.half[1]);
    }
    EXPECT_EQ(0, fread(&block, 1, SIZE_BLOCK, open_text));
    EXPECT_NE(feof(open_text), 0);
    fclose(open_text);
}

TEST(ECB, PROC_ADD_NULLS_2_not_full) {
    FILE * open_text = fopen("OpenText.txt", "w");
    FILE * close_text;
    if(open_text == NULL)
    {
        printf("Error of open file: %d\n", __LINE__);
        return;
    }

    vector128bit initial_vector[2];
    initial_vector[0].half[0] = 0x1213141516171819;
    initial_vector[0].half[1] = 0x2334455667788990;
    initial_vector[1].half[0] = 0xa1b2c3d4e5f00112;
    initial_vector[1].half[1] = 0x1234567890abcef0;

    vector128bit key[2];
    key[0].half[0] = 0x0123456789abcdef;
    key[0].half[1] = 0xfedcba9876543210;
    key[1].half[0] = 0x0011223344556677;
    key[1].half[1] = 0x8899aabbccddeeff;
    
    vector128bit block;
    block.half[0] = 0xffeeddccbbaa9988;
    block.half[1] = 0x1122334455667700; 
    for(int i = 0; i < 10; i++) {
        fwrite(&block, SIZE_BLOCK, 1, open_text);
    }
    fwrite(&block, 4, 1, open_text);
    fclose(open_text);

    open_text = fopen("OpenText.txt", "r");
    close_text = fopen("CloseText.txt", "w");
    EXPECT_EQ(0, encryptCBCKuz(open_text, close_text, key, PROC_ADD_NULLS_2, 32, initial_vector));
    fclose(open_text);
    fclose(close_text);

    open_text = fopen("OpenText.txt", "w");
    close_text = fopen("CloseText.txt", "r");
    EXPECT_EQ(0, decryptCBCKuz(close_text, open_text, key, PROC_ADD_NULLS_2, 0, 32, initial_vector));
    fclose(open_text);
    fclose(close_text);

    open_text = fopen("OpenText.txt", "r");
    for(int i = 0; i < 10; i++) {
        fread(&block, SIZE_BLOCK, 1, open_text);
        EXPECT_EQ(0xffeeddccbbaa9988, block.half[0]);
        EXPECT_EQ(0x1122334455667700, block.half[1]);
    }
    EXPECT_EQ(4, fread(&block, 1, 5, open_text));
    EXPECT_NE(feof(open_text), 0);
    fclose(open_text);
}

TEST(ECB, PROC_ADD_NULLS_3_full) {
    FILE * open_text = fopen("OpenText.txt", "w");
    FILE * close_text;
    if(open_text == NULL)
    {
        printf("Error of open file: %d\n", __LINE__);
        return;
    }

    vector128bit initial_vector[2];
    initial_vector[0].half[0] = 0x1213141516171819;
    initial_vector[0].half[1] = 0x2334455667788990;
    initial_vector[1].half[0] = 0xa1b2c3d4e5f00112;
    initial_vector[1].half[1] = 0x1234567890abcef0;

    vector128bit key[2];
    key[0].half[0] = 0x0123456789abcdef;
    key[0].half[1] = 0xfedcba9876543210;
    key[1].half[0] = 0x0011223344556677;
    key[1].half[1] = 0x8899aabbccddeeff;
    
    vector128bit block;
    block.half[0] = 0xffeeddccbbaa9988;
    block.half[1] = 0x1122334455667700; 
    for(int i = 0; i < 10; i++) {
        fwrite(&block, SIZE_BLOCK, 1, open_text);
    }
    fclose(open_text);

    open_text = fopen("OpenText.txt", "r");
    close_text = fopen("CloseText.txt", "w");
    EXPECT_EQ(0, encryptCBCKuz(open_text, close_text, key, PROC_ADD_NULLS_3, 32, initial_vector));
    fclose(open_text);
    fclose(close_text);

    open_text = fopen("OpenText.txt", "w");
    close_text = fopen("CloseText.txt", "r");
    EXPECT_EQ(0, decryptCBCKuz(close_text, open_text, key, PROC_ADD_NULLS_3, 0, 32, initial_vector));
    fclose(open_text);
    fclose(close_text);

    open_text = fopen("OpenText.txt", "r");
    for(int i = 0; i < 10; i++) {
        fread(&block, SIZE_BLOCK, 1, open_text);
        EXPECT_EQ(0xffeeddccbbaa9988, block.half[0]);
        EXPECT_EQ(0x1122334455667700, block.half[1]);
    }
    EXPECT_EQ(0, fread(&block, 1, SIZE_BLOCK, open_text));
    EXPECT_NE(feof(open_text), 0);
    fclose(open_text);
}

TEST(ECB, PROC_ADD_NULLS_3_not_full) {
    FILE * open_text = fopen("OpenText.txt", "w");
    FILE * close_text;
    if(open_text == NULL)
    {
        printf("Error of open file: %d\n", __LINE__);
        return;
    }

    vector128bit initial_vector[2];
    initial_vector[0].half[0] = 0x1213141516171819;
    initial_vector[0].half[1] = 0x2334455667788990;
    initial_vector[1].half[0] = 0xa1b2c3d4e5f00112;
    initial_vector[1].half[1] = 0x1234567890abcef0;

    vector128bit key[2];
    key[0].half[0] = 0x0123456789abcdef;
    key[0].half[1] = 0xfedcba9876543210;
    key[1].half[0] = 0x0011223344556677;
    key[1].half[1] = 0x8899aabbccddeeff;
    
    vector128bit block;
    block.half[0] = 0xffeeddccbbaa9988;
    block.half[1] = 0x1122334455667700; 
    for(int i = 0; i < 10; i++) {
        fwrite(&block, SIZE_BLOCK, 1, open_text);
    }
    fwrite(&block, 4, 1, open_text);
    fclose(open_text);

    open_text = fopen("OpenText.txt", "r");
    close_text = fopen("CloseText.txt", "w");
    EXPECT_EQ(0, encryptCBCKuz(open_text, close_text, key, PROC_ADD_NULLS_3, 32, initial_vector));
    fclose(open_text);
    fclose(close_text);

    open_text = fopen("OpenText.txt", "w");
    close_text = fopen("CloseText.txt", "r");
    EXPECT_EQ(0, decryptCBCKuz(close_text, open_text, key, PROC_ADD_NULLS_3, 0, 32, initial_vector));
    fclose(open_text);
    fclose(close_text);

    open_text = fopen("OpenText.txt", "r");
    for(int i = 0; i < 10; i++) {
        fread(&block, SIZE_BLOCK, 1, open_text);
        EXPECT_EQ(0xffeeddccbbaa9988, block.half[0]);
        EXPECT_EQ(0x1122334455667700, block.half[1]);
    }
    EXPECT_EQ(4, fread(&block, 1, 5, open_text));
    EXPECT_NE(feof(open_text), 0);
    fclose(open_text);
}

TEST(ECB, SpeedlessKb) {
    FILE * open_text = fopen("OpenText.txt", "w");
    FILE * close_text;
    if(open_text == NULL)
    {
        printf("Error of open file: %d\n", __LINE__);
        return;
    }

    vector128bit initial_vector[2];
    initial_vector[0].half[0] = 0x1213141516171819;
    initial_vector[0].half[1] = 0x2334455667788990;
    initial_vector[1].half[0] = 0xa1b2c3d4e5f00112;
    initial_vector[1].half[1] = 0x1234567890abcef0;

    vector128bit key[2];
    key[0].half[0] = 0x0123456789abcdef;
    key[0].half[1] = 0xfedcba9876543210;
    key[1].half[0] = 0x0011223344556677;
    key[1].half[1] = 0x8899aabbccddeeff;
    
    vector128bit block;
    block.half[0] = 0xffeeddccbbaa9988;
    block.half[1] = 0x1122334455667700; 
    for(int i = 0; i < 50; i++) {
        fwrite(&block, SIZE_BLOCK, 1, open_text);
    }
    fclose(open_text);
    double size_text = (double)50*16; // Bytes

    open_text = fopen("OpenText.txt", "r");
    close_text = fopen("CloseText.txt", "w");
    
    struct timeval t;

    gettimeofday(&t, NULL);
    double start = (double)t.tv_sec * 1000 + t.tv_usec / 1000;
    EXPECT_EQ(0, encryptCBCKuz(open_text, close_text, key, PROC_ADD_NULLS_2, 32, initial_vector));
    gettimeofday(&t, NULL);
    printf("Speed of encrypt: %lf MB/sec\n", size_text*1000/((((double)t.tv_sec * 1000 + t.tv_usec / 1000) - start)*1024*1024));
    fclose(open_text);
    fclose(close_text);

    open_text = fopen("OpenText.txt", "w");
    close_text = fopen("CloseText.txt", "r");
    gettimeofday(&t, NULL);
    start = (long long)t.tv_sec * 1000 + t.tv_usec / 1000;
    EXPECT_EQ(0, decryptCBCKuz(close_text, open_text, key, PROC_ADD_NULLS_2, 0, 32, initial_vector));
    gettimeofday(&t, NULL);
    size_text += 16;
    printf("Speed of decrypt: %lf Mb/sec\n", size_text*1000/((((double)t.tv_sec * 1000 + t.tv_usec / 1000) - start)*1024*1024));
    fclose(open_text);
    fclose(close_text);
}

TEST(ECB, SpeedmoreKb) {
    FILE * open_text = fopen("OpenText.txt", "w");
    FILE * close_text;
    if(open_text == NULL)
    {
        printf("Error of open file: %d\n", __LINE__);
        return;
    }

    vector128bit initial_vector[2];
    initial_vector[0].half[0] = 0x1213141516171819;
    initial_vector[0].half[1] = 0x2334455667788990;
    initial_vector[1].half[0] = 0xa1b2c3d4e5f00112;
    initial_vector[1].half[1] = 0x1234567890abcef0;

    vector128bit key[2];
    key[0].half[0] = 0x0123456789abcdef;
    key[0].half[1] = 0xfedcba9876543210;
    key[1].half[0] = 0x0011223344556677;
    key[1].half[1] = 0x8899aabbccddeeff;
    
    vector128bit block;
    block.half[0] = 0xffeeddccbbaa9988;
    block.half[1] = 0x1122334455667700; 
    for(int i = 0; i < 1000; i++) {
        fwrite(&block, SIZE_BLOCK, 1, open_text);
    }
    fclose(open_text);
    double size_text = (double)1000*16; // Bytes

    open_text = fopen("OpenText.txt", "r");
    close_text = fopen("CloseText.txt", "w");
    
    struct timeval t;

    gettimeofday(&t, NULL);
    double start = (double)t.tv_sec * 1000 + t.tv_usec / 1000;
    EXPECT_EQ(0, encryptCBCKuz(open_text, close_text, key, PROC_ADD_NULLS_2, 32, initial_vector));
    gettimeofday(&t, NULL);
    printf("Speed of encrypt: %lf MB/sec\n", size_text*1000/((((double)t.tv_sec * 1000 + t.tv_usec / 1000) - start)*1024*1024));
    fclose(open_text);
    fclose(close_text);

    open_text = fopen("OpenText.txt", "w");
    close_text = fopen("CloseText.txt", "r");
    gettimeofday(&t, NULL);
    start = (long long)t.tv_sec * 1000 + t.tv_usec / 1000;
    EXPECT_EQ(0, decryptCBCKuz(close_text, open_text, key, PROC_ADD_NULLS_2, 0, 32, initial_vector));
    gettimeofday(&t, NULL);
    size_text += 16;
    printf("Speed of decrypt: %lf Mb/sec\n", size_text*1000/((((double)t.tv_sec * 1000 + t.tv_usec / 1000) - start)*1024*1024));
    fclose(open_text);
    fclose(close_text);
}

TEST(ECB, SpeedmoreMb) {
    FILE * open_text = fopen("OpenText.txt", "w");
    FILE * close_text;
    if(open_text == NULL)
    {
        printf("Error of open file: %d\n", __LINE__);
        return;
    }

    vector128bit initial_vector[2];
    initial_vector[0].half[0] = 0x1213141516171819;
    initial_vector[0].half[1] = 0x2334455667788990;
    initial_vector[1].half[0] = 0xa1b2c3d4e5f00112;
    initial_vector[1].half[1] = 0x1234567890abcef0;

    vector128bit key[2];
    key[0].half[0] = 0x0123456789abcdef;
    key[0].half[1] = 0xfedcba9876543210;
    key[1].half[0] = 0x0011223344556677;
    key[1].half[1] = 0x8899aabbccddeeff;
    
    vector128bit block;
    block.half[0] = 0xffeeddccbbaa9988;
    block.half[1] = 0x1122334455667700; 
    for(int i = 0; i < 1000000; i++) {
        fwrite(&block, SIZE_BLOCK, 1, open_text);
    }
    fclose(open_text);
    double size_text = (double)1000000*16; // Bytes

    open_text = fopen("OpenText.txt", "r");
    close_text = fopen("CloseText.txt", "w");
    
    struct timeval t;

    gettimeofday(&t, NULL);
    double start = (double)t.tv_sec * 1000 + t.tv_usec / 1000;
    EXPECT_EQ(0, encryptCBCKuz(open_text, close_text, key, PROC_ADD_NULLS_2, 32, initial_vector));
    gettimeofday(&t, NULL);
    printf("Speed of encrypt: %lf MB/sec\n", size_text*1000/((((double)t.tv_sec * 1000 + t.tv_usec / 1000) - start)*1024*1024));
    fclose(open_text);
    fclose(close_text);

    open_text = fopen("OpenText.txt", "w");
    close_text = fopen("CloseText.txt", "r");
    gettimeofday(&t, NULL);
    start = (long long)t.tv_sec * 1000 + t.tv_usec / 1000;
    EXPECT_EQ(0, decryptCBCKuz(close_text, open_text, key, PROC_ADD_NULLS_2, 0, 32, initial_vector));
    gettimeofday(&t, NULL);
    size_text += 16;
    printf("Speed of decrypt: %lf Mb/sec\n", size_text*1000/((((double)t.tv_sec * 1000 + t.tv_usec / 1000) - start)*1024*1024));
    fclose(open_text);
    fclose(close_text);
}

int main(int argc, char **argv)
{
	testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}