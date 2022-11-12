#include "../src/Kuznechik.c"
#include "../src/CTR.c"
#include "./gtest/include/gtest/gtest.h"
#include <sys/time.h>

TEST(CTR, TestFromGOST) {
    FILE * open_text = fopen("OpenText.txt", "w");
    FILE * close_text;
    if(open_text == NULL)
    {
        printf("Error of open file: %d\n", __LINE__);
        return;
    }

    vector128bit initial_vector;
    initial_vector.half[0] = 0x1234567890abcef0;

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
    EXPECT_EQ(0, encryptCTRKuz(open_text, close_text, key, 16, &initial_vector));
    fclose(open_text);
    fclose(close_text);

    close_text = fopen("CloseText.txt", "r");
    fread(&block, SIZE_BLOCK, 1, close_text);
    EXPECT_EQ(0xd57b5fa240bda1b8, block.half[0]);
    EXPECT_EQ(0xf195d8bec10ed1db, block.half[1]);
    fread(&block, SIZE_BLOCK, 1, close_text);
    EXPECT_EQ(0xf33ce4b33c45dee4, block.half[0]);
    EXPECT_EQ(0x85eee733f6a13e5d, block.half[1]);
    fread(&block, SIZE_BLOCK, 1, close_text);
    EXPECT_EQ(0xd5e877f13564a3a5, block.half[0]);
    EXPECT_EQ(0xa5eae88be6356ed3, block.half[1]);
    fread(&block, SIZE_BLOCK, 1, close_text);
    EXPECT_EQ(0xd1c6d15820bdba73, block.half[0]);
    EXPECT_EQ(0xcb91fab1f20cbab6, block.half[1]);
    EXPECT_EQ(0, fread(&block, 1, SIZE_BLOCK+1, close_text));
    EXPECT_NE(feof(close_text), 0);
    fclose(close_text);

    open_text = fopen("OpenText.txt", "w");
    close_text = fopen("CloseText.txt", "r");
    EXPECT_EQ(0, decryptCTRKuz(close_text, open_text, key, 16, &initial_vector));
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

TEST(CTR, TestOnNotFullLastBlock) {
    FILE * open_text = fopen("OpenText.txt", "w");
    FILE * close_text;
    if(open_text == NULL)
    {
        printf("Error of open file: %d\n", __LINE__);
        return;
    }

    vector128bit initial_vector;
    initial_vector.half[0] = 0x1234567890abcef0;

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
    fwrite(&block, 4, 1, open_text);
    fclose(open_text);

    open_text = fopen("OpenText.txt", "r");
    close_text = fopen("CloseText.txt", "w");
    EXPECT_EQ(0, encryptCTRKuz(open_text, close_text, key, 16, &initial_vector));
    fclose(open_text);
    fclose(close_text);

    close_text = fopen("CloseText.txt", "r");
    fread(&block, SIZE_BLOCK, 1, close_text);
    EXPECT_EQ(0xd57b5fa240bda1b8, block.half[0]);
    EXPECT_EQ(0xf195d8bec10ed1db, block.half[1]);
    fread(&block, SIZE_BLOCK, 1, close_text);
    EXPECT_EQ(0xf33ce4b33c45dee4, block.half[0]);
    EXPECT_EQ(0x85eee733f6a13e5d, block.half[1]);
    fread(&block, SIZE_BLOCK, 1, close_text);
    EXPECT_EQ(0xd5e877f13564a3a5, block.half[0]);
    EXPECT_EQ(0xa5eae88be6356ed3, block.half[1]);
    EXPECT_EQ(4, fread(&block, 1, 5, close_text));
    EXPECT_NE(feof(close_text), 0);
    fclose(close_text);

    open_text = fopen("OpenText.txt", "w");
    close_text = fopen("CloseText.txt", "r");
    EXPECT_EQ(0, decryptCTRKuz(close_text, open_text, key, 16, &initial_vector));
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
    block.half[0] = 0;
    fread(&block, 4, 1, open_text);
    EXPECT_EQ(0x00000000ff0a0011, block.half[0]);
    fread(&block, 1, 1, open_text);
    EXPECT_NE(feof(open_text), 0);
    fclose(open_text);
}

TEST(CTR, SpeedlessKb) {
    FILE * open_text = fopen("OpenText.txt", "w");
    FILE * close_text;
    if(open_text == NULL)
    {
        printf("Error of open file: %d\n", __LINE__);
        return;
    }

    vector128bit initial_vector;
    initial_vector.half[0] = 0x1234567890abcef0;

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
    EXPECT_EQ(0, encryptCTRKuz(open_text, close_text, key, 16, &initial_vector));
    gettimeofday(&t, NULL);
    printf("Speed of encrypt: %lf MB/sec\n", size_text*1000/((((double)t.tv_sec * 1000 + t.tv_usec / 1000) - start)*1024*1024));
    fclose(open_text);
    fclose(close_text);

    open_text = fopen("OpenText.txt", "w");
    close_text = fopen("CloseText.txt", "r");
    gettimeofday(&t, NULL);
    start = (long long)t.tv_sec * 1000 + t.tv_usec / 1000;
    EXPECT_EQ(0, decryptCTRKuz(close_text, open_text, key, 16, &initial_vector));
    gettimeofday(&t, NULL);
    size_text += 16;
    printf("Speed of decrypt: %lf Mb/sec\n", size_text*1000/((((double)t.tv_sec * 1000 + t.tv_usec / 1000) - start)*1024*1024));
    fclose(open_text);
    fclose(close_text);
}

TEST(CTR, SpeedmoreKb) {
    FILE * open_text = fopen("OpenText.txt", "w");
    FILE * close_text;
    if(open_text == NULL)
    {
        printf("Error of open file: %d\n", __LINE__);
        return;
    }

    vector128bit initial_vector;
    initial_vector.half[0] = 0x1234567890abcef0;

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
    EXPECT_EQ(0, encryptCTRKuz(open_text, close_text, key, 16, &initial_vector));
    gettimeofday(&t, NULL);
    printf("Speed of encrypt: %lf MB/sec\n", size_text*1000/((((double)t.tv_sec * 1000 + t.tv_usec / 1000) - start)*1024*1024));
    fclose(open_text);
    fclose(close_text);

    open_text = fopen("OpenText.txt", "w");
    close_text = fopen("CloseText.txt", "r");
    gettimeofday(&t, NULL);
    start = (long long)t.tv_sec * 1000 + t.tv_usec / 1000;
    EXPECT_EQ(0, decryptCTRKuz(close_text, open_text, key, 16, &initial_vector));
    gettimeofday(&t, NULL);
    size_text += 16;
    printf("Speed of decrypt: %lf Mb/sec\n", size_text*1000/((((double)t.tv_sec * 1000 + t.tv_usec / 1000) - start)*1024*1024));
    fclose(open_text);
    fclose(close_text);
}

TEST(CTR, SpeedmoreMb) {
    FILE * open_text = fopen("OpenText.txt", "w");
    FILE * close_text;
    if(open_text == NULL)
    {
        printf("Error of open file: %d\n", __LINE__);
        return;
    }

    vector128bit initial_vector;
    initial_vector.half[0] = 0x1234567890abcef0;

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
    EXPECT_EQ(0, encryptCTRKuz(open_text, close_text, key, 16, &initial_vector));
    gettimeofday(&t, NULL);
    printf("Speed of encrypt: %lf MB/sec\n", size_text*1000/((((double)t.tv_sec * 1000 + t.tv_usec / 1000) - start)*1024*1024));
    fclose(open_text);
    fclose(close_text);

    open_text = fopen("OpenText.txt", "w");
    close_text = fopen("CloseText.txt", "r");
    gettimeofday(&t, NULL);
    start = (long long)t.tv_sec * 1000 + t.tv_usec / 1000;
    EXPECT_EQ(0, decryptCTRKuz(close_text, open_text, key,  16, &initial_vector));
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