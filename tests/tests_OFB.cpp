#include "../src/Kuznechik.c"
#include "../src/OFB.c"
#include "./gtest/include/gtest/gtest.h"
#include <sys/time.h>

TEST(OFB, TestFromGOST) {
    FILE * open_text = fopen("OpenText.txt", "w");
    FILE * close_text;
    if(open_text == NULL)
    {
        printf("Error of open file: %d\n", __LINE__);
        return;
    }

    vector128_t initial_vector[2];
    initial_vector[0].half[0] = 0x1213141516171819;
    initial_vector[0].half[1] = 0x2334455667788990;
    initial_vector[1].half[0] = 0xa1b2c3d4e5f00112;
    initial_vector[1].half[1] = 0x1234567890abcef0;

    vector128_t key[2];
    key[0].half[0] = 0x0123456789abcdef;
    key[0].half[1] = 0xfedcba9876543210;
    key[1].half[0] = 0x0011223344556677;
    key[1].half[1] = 0x8899aabbccddeeff;
    
    vector128_t block;
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
    EXPECT_EQ(0, encryptOFBKuz(open_text, close_text, key, 16, 32, initial_vector));
    fclose(open_text);
    fclose(close_text);

    close_text = fopen("CloseText.txt", "r");
    fread(&block, SIZE_BLOCK, 1, close_text);
    EXPECT_EQ(0xff1f795e897abd95, block.half[0]);
    EXPECT_EQ(0x81800a59b1842b24, block.half[1]);
    fread(&block, SIZE_BLOCK, 1, close_text);
    EXPECT_EQ(0x8fb521369d9326bf, block.half[0]);
    EXPECT_EQ(0xed5b47a7048cfab4, block.half[1]);
    fread(&block, SIZE_BLOCK, 1, close_text);
    EXPECT_EQ(0xc80fe7fc10288a13, block.half[0]);
    EXPECT_EQ(0x66a257ac3ca0b8b1, block.half[1]);
    fread(&block, SIZE_BLOCK, 1, close_text);
    EXPECT_EQ(0xa0292243f6903150, block.half[0]);
    EXPECT_EQ(0x203ebbc066138660, block.half[1]);
    EXPECT_EQ(0, fread(&block, 1, SIZE_BLOCK+1, close_text));
    EXPECT_NE(feof(close_text), 0);
    fclose(close_text);

    open_text = fopen("OpenText.txt", "w");
    close_text = fopen("CloseText.txt", "r");
    EXPECT_EQ(0, decryptOFBKuz(close_text, open_text, key, 16, 32, initial_vector));
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

TEST(OFB, TestOnNotFullLastBlock) {
    FILE * open_text = fopen("OpenText.txt", "w");
    FILE * close_text;
    if(open_text == NULL)
    {
        printf("Error of open file: %d\n", __LINE__);
        return;
    }

    vector128_t initial_vector[2];
    initial_vector[0].half[0] = 0x1213141516171819;
    initial_vector[0].half[1] = 0x2334455667788990;
    initial_vector[1].half[0] = 0xa1b2c3d4e5f00112;
    initial_vector[1].half[1] = 0x1234567890abcef0;

    vector128_t key[2];
    key[0].half[0] = 0x0123456789abcdef;
    key[0].half[1] = 0xfedcba9876543210;
    key[1].half[0] = 0x0011223344556677;
    key[1].half[1] = 0x8899aabbccddeeff;
    
    vector128_t block;
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
    EXPECT_EQ(0, encryptOFBKuz(open_text, close_text, key, 16, 32, initial_vector));
    fclose(open_text);
    fclose(close_text);

    open_text = fopen("OpenText.txt", "w");
    close_text = fopen("CloseText.txt", "r");
    EXPECT_EQ(0, decryptOFBKuz(close_text, open_text, key, 16, 32, initial_vector));
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

TEST(OFB, SpeedlessKb) {
    FILE * open_text = fopen("OpenText.txt", "w");
    FILE * close_text;
    if(open_text == NULL)
    {
        printf("Error of open file: %d\n", __LINE__);
        return;
    }

    vector128_t initial_vector[2];
    initial_vector[0].half[0] = 0x1213141516171819;
    initial_vector[0].half[1] = 0x2334455667788990;
    initial_vector[1].half[0] = 0xa1b2c3d4e5f00112;
    initial_vector[1].half[1] = 0x1234567890abcef0;

    vector128_t key[2];
    key[0].half[0] = 0x0123456789abcdef;
    key[0].half[1] = 0xfedcba9876543210;
    key[1].half[0] = 0x0011223344556677;
    key[1].half[1] = 0x8899aabbccddeeff;
    
    vector128_t block;
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
    EXPECT_EQ(0, encryptOFBKuz(open_text, close_text, key, 16, 32, initial_vector));
    gettimeofday(&t, NULL);
    printf("Speed of encrypt: %lf MB/sec\n", size_text*1000/((((double)t.tv_sec * 1000 + t.tv_usec / 1000) - start)*1024*1024));
    fclose(open_text);
    fclose(close_text);

    open_text = fopen("OpenText.txt", "w");
    close_text = fopen("CloseText.txt", "r");
    gettimeofday(&t, NULL);
    start = (long long)t.tv_sec * 1000 + t.tv_usec / 1000;
    EXPECT_EQ(0, decryptOFBKuz(close_text, open_text, key, 16, 32, initial_vector));
    gettimeofday(&t, NULL);
    size_text += 16;
    printf("Speed of decrypt: %lf Mb/sec\n", size_text*1000/((((double)t.tv_sec * 1000 + t.tv_usec / 1000) - start)*1024*1024));
    fclose(open_text);
    fclose(close_text);
}

TEST(OFB, SpeedmoreKb) {
    FILE * open_text = fopen("OpenText.txt", "w");
    FILE * close_text;
    if(open_text == NULL)
    {
        printf("Error of open file: %d\n", __LINE__);
        return;
    }

    vector128_t initial_vector[2];
    initial_vector[0].half[0] = 0x1213141516171819;
    initial_vector[0].half[1] = 0x2334455667788990;
    initial_vector[1].half[0] = 0xa1b2c3d4e5f00112;
    initial_vector[1].half[1] = 0x1234567890abcef0;

    vector128_t key[2];
    key[0].half[0] = 0x0123456789abcdef;
    key[0].half[1] = 0xfedcba9876543210;
    key[1].half[0] = 0x0011223344556677;
    key[1].half[1] = 0x8899aabbccddeeff;
    
    vector128_t block;
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
    EXPECT_EQ(0, encryptOFBKuz(open_text, close_text, key, 16, 32, initial_vector));
    gettimeofday(&t, NULL);
    printf("Speed of encrypt: %lf MB/sec\n", size_text*1000/((((double)t.tv_sec * 1000 + t.tv_usec / 1000) - start)*1024*1024));
    fclose(open_text);
    fclose(close_text);

    open_text = fopen("OpenText.txt", "w");
    close_text = fopen("CloseText.txt", "r");
    gettimeofday(&t, NULL);
    start = (long long)t.tv_sec * 1000 + t.tv_usec / 1000;
    EXPECT_EQ(0, decryptOFBKuz(close_text, open_text, key, 16, 32, initial_vector));
    gettimeofday(&t, NULL);
    size_text += 16;
    printf("Speed of decrypt: %lf Mb/sec\n", size_text*1000/((((double)t.tv_sec * 1000 + t.tv_usec / 1000) - start)*1024*1024));
    fclose(open_text);
    fclose(close_text);
}

TEST(OFB, SpeedmoreMb) {
    FILE * open_text = fopen("OpenText.txt", "w");
    FILE * close_text;
    if(open_text == NULL)
    {
        printf("Error of open file: %d\n", __LINE__);
        return;
    }

    vector128_t initial_vector[2];
    initial_vector[0].half[0] = 0x1213141516171819;
    initial_vector[0].half[1] = 0x2334455667788990;
    initial_vector[1].half[0] = 0xa1b2c3d4e5f00112;
    initial_vector[1].half[1] = 0x1234567890abcef0;

    vector128_t key[2];
    key[0].half[0] = 0x0123456789abcdef;
    key[0].half[1] = 0xfedcba9876543210;
    key[1].half[0] = 0x0011223344556677;
    key[1].half[1] = 0x8899aabbccddeeff;
    
    vector128_t block;
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
    EXPECT_EQ(0, encryptOFBKuz(open_text, close_text, key, 16, 32, initial_vector));
    gettimeofday(&t, NULL);
    printf("Speed of encrypt: %lf MB/sec\n", size_text*1000/((((double)t.tv_sec * 1000 + t.tv_usec / 1000) - start)*1024*1024));
    fclose(open_text);
    fclose(close_text);

    open_text = fopen("OpenText.txt", "w");
    close_text = fopen("CloseText.txt", "r");
    gettimeofday(&t, NULL);
    start = (long long)t.tv_sec * 1000 + t.tv_usec / 1000;
    EXPECT_EQ(0, decryptOFBKuz(close_text, open_text, key,  16, 32, initial_vector));
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