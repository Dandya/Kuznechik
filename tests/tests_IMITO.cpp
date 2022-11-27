#include "../src/Kuznechik.c"
#include "../src/IMITO.c"
#include "./gtest/include/gtest/gtest.h"
#include <sys/time.h>

TEST(IMITO_TESTS, creationKeys)
{
    vector128_t key[2];
    key[0].half[0] = 0x0123456789abcdef;
    key[0].half[1] = 0xfedcba9876543210;
    key[1].half[0] = 0x0011223344556677;
    key[1].half[1] = 0x8899aabbccddeeff;
    vector128_t iteration_keys[10];
    createIterationKeysKuz(key, iteration_keys);

    vector128_t helping_key = createHelpingKey(iteration_keys, CREATE_KEY_1);
    EXPECT_EQ(0x0de0573298151dc7, helping_key.half[0]);
    EXPECT_EQ(0x297d82bc4d39e3ca, helping_key.half[1]);

    helping_key = createHelpingKey(iteration_keys, CREATE_KEY_2);
    EXPECT_EQ(0x1bc0ae65302a3b8e, helping_key.half[0]);
    EXPECT_EQ(0x52fb05789a73c794, helping_key.half[1]);
}

TEST(IMITO_TESTS, creationMAC)
{
    FILE *input_text = fopen("OpenText.txt", "w");
    if (input_text == NULL)
    {
        printf("Error of open file: %d\n", __LINE__);
        return;
    }

    vector128_t block;
    block.half[0] = 0xffeeddccbbaa9988;
    block.half[1] = 0x1122334455667700;
    fwrite(&block, SIZE_BLOCK, 1, input_text);
    block.half[0] = 0x8899aabbcceeff0a;
    block.half[1] = 0x0011223344556677;
    fwrite(&block, SIZE_BLOCK, 1, input_text);
    block.half[0] = 0x99aabbcceeff0a00;
    block.half[1] = 0x1122334455667788;
    fwrite(&block, SIZE_BLOCK, 1, input_text);
    block.half[0] = 0xaabbcceeff0a0011;
    block.half[1] = 0x2233445566778899;
    fwrite(&block, SIZE_BLOCK, 1, input_text);
    fclose(input_text);

    vector128_t key[2];
    key[0].half[0] = 0x0123456789abcdef;
    key[0].half[1] = 0xfedcba9876543210;
    key[1].half[0] = 0x0011223344556677;
    key[1].half[1] = 0x8899aabbccddeeff;

    vector128_t iteration_keys[10];
    int result = createIterationKeysKuz(key, iteration_keys);
    if (result < 0)
    {
        fprintf(stderr, "Error create iteration keys\n");
        return;
    }

    input_text = fopen("OpenText.txt", "r");
    uint64_t size_input_file = getSizeFile(input_text);
    uint64_t MAC;
    EXPECT_EQ(0, createMAC(input_text, (uint8_t *)&MAC, iteration_keys, 64, size_input_file));
    EXPECT_EQ(0x336f4d296059fbe3, MAC);
    fclose(input_text);
}

TEST(IMITO_TESTS, SmallBlock)
{
    FILE *input_text = fopen("OpenText.txt", "w");
    if (input_text == NULL)
    {
        printf("Error of open file: %d\n", __LINE__);
        return;
    }

    vector128_t key[2];
    key[0].half[0] = 0x0123456789abcdef;
    key[0].half[1] = 0xfedcba9876543210;
    key[1].half[0] = 0x0011223344556677;
    key[1].half[1] = 0x8899aabbccddeeff;

    vector128_t iteration_keys[10];
    int result = createIterationKeysKuz(key, iteration_keys);
    if (result < 0)
    {
        fprintf(stderr, "Error create iteration keys\n");
        return;
    }

    vector128_t block;
    block.half[0] = 0xffeeddccbbaa9988;
    block.half[1] = 0x1122334455667700;
    fwrite(&block, 8, 1, input_text);
    fclose(input_text);

    input_text = fopen("OpenText.txt", "r");
    uint64_t size_input_file = getSizeFile(input_text);
    uint64_t MAC;
    EXPECT_EQ(0, createMAC(input_text, (uint8_t *)&MAC, iteration_keys, 64, size_input_file));
    fclose(input_text);
}

TEST(IMITO_TESTS, SpeedlessKb)
{
    FILE *open_text = fopen("OpenText.txt", "w");
    FILE *close_text;
    if (open_text == NULL)
    {
        printf("Error of open file: %d\n", __LINE__);
        return;
    }

    vector128_t key[2];
    key[0].half[0] = 0x0123456789abcdef;
    key[0].half[1] = 0xfedcba9876543210;
    key[1].half[0] = 0x0011223344556677;
    key[1].half[1] = 0x8899aabbccddeeff;

    uint64_t size_input_file;
    vector128_t iteration_keys[10];
    int result = createIterationKeysKuz(key, iteration_keys);
    if (result < 0)
    {
        fprintf(stderr, "Error create iteration keys\n");
        return;
    }

    vector128_t block;
    block.half[0] = 0xffeeddccbbaa9988;
    block.half[1] = 0x1122334455667700;
    for (int i = 0; i < 50; i++)
    {
        fwrite(&block, SIZE_BLOCK, 1, open_text);
    }
    fclose(open_text);
    double size_text = (double)50 * 16; // Bytes

    open_text = fopen("OpenText.txt", "r");
    size_input_file = getSizeFile(open_text);
    uint64_t MAC;

    struct timeval t;

    gettimeofday(&t, NULL);
    double start = (double)t.tv_sec * 1000 + t.tv_usec / 1000;
    EXPECT_EQ(0, createMAC(open_text, (uint8_t *)&MAC, iteration_keys, 64, size_input_file));
    gettimeofday(&t, NULL);
    printf("Speed of createMAC: %lf MB/sec\n", size_text * 1000 / ((((double)t.tv_sec * 1000 + t.tv_usec / 1000) + 1 - start) * 1024 * 1024));
    fclose(open_text);
}

TEST(IMITO_TESTS, SpeedmoreKb)
{
    FILE *open_text = fopen("OpenText.txt", "w");
    if (open_text == NULL)
    {
        printf("Error of open file: %d\n", __LINE__);
        return;
    }

    vector128_t key[2];
    key[0].half[0] = 0x0123456789abcdef;
    key[0].half[1] = 0xfedcba9876543210;
    key[1].half[0] = 0x0011223344556677;
    key[1].half[1] = 0x8899aabbccddeeff;

    uint64_t size_input_file;
    vector128_t iteration_keys[10];
    int result = createIterationKeysKuz(key, iteration_keys);
    if (result < 0)
    {
        fprintf(stderr, "Error create iteration keys\n");
        return;
    }

    vector128_t block;
    block.half[0] = 0xffeeddccbbaa9988;
    block.half[1] = 0x1122334455667700;
    for (int i = 0; i < 1000; i++)
    {
        fwrite(&block, SIZE_BLOCK, 1, open_text);
    }
    fclose(open_text);
    double size_text = (double)1000 * 16; // Bytes

    open_text = fopen("OpenText.txt", "r");
    size_input_file = getSizeFile(open_text);
    uint64_t MAC;

    struct timeval t;

    gettimeofday(&t, NULL);
    double start = (double)t.tv_sec * 1000 + t.tv_usec / 1000;
    EXPECT_EQ(0, createMAC(open_text, (uint8_t *)&MAC, iteration_keys, 64, size_input_file));
    gettimeofday(&t, NULL);
    printf("Speed of createMAC: %lf MB/sec\n", size_text * 1000 / ((((double)t.tv_sec * 1000 + t.tv_usec / 1000) - start) * 1024 * 1024));
    fclose(open_text);
}

TEST(IMITO_TESTS, SpeedmoreMb)
{
    FILE *open_text = fopen("OpenText.txt", "w");
    if (open_text == NULL)
    {
        printf("Error of open file: %d\n", __LINE__);
        return;
    }

    vector128_t key[2];
    key[0].half[0] = 0x0123456789abcdef;
    key[0].half[1] = 0xfedcba9876543210;
    key[1].half[0] = 0x0011223344556677;
    key[1].half[1] = 0x8899aabbccddeeff;

    uint64_t size_input_file;
    vector128_t iteration_keys[10];
    int result = createIterationKeysKuz(key, iteration_keys);
    if (result < 0)
    {
        fprintf(stderr, "Error create iteration keys\n");
        return;
    }

    vector128_t block;
    block.half[0] = 0xffeeddccbbaa9988;
    block.half[1] = 0x1122334455667700;
    for (int i = 0; i < 1000000; i++)
    {
        fwrite(&block, SIZE_BLOCK, 1, open_text);
    }
    fclose(open_text);
    double size_text = (double)1000000 * 16; // Bytes

    open_text = fopen("OpenText.txt", "r");
    size_input_file = getSizeFile(open_text);
    uint64_t MAC;

    struct timeval t;

    gettimeofday(&t, NULL);
    double start = (double)t.tv_sec * 1000 + t.tv_usec / 1000;
    EXPECT_EQ(0, createMAC(open_text, (uint8_t *)&MAC, iteration_keys, 64, size_input_file));
    gettimeofday(&t, NULL);
    printf("Speed of createMAC: %lf MB/sec\n", size_text * 1000 / ((((double)t.tv_sec * 1000 + t.tv_usec / 1000) - start) * 1024 * 1024));
    fclose(open_text);
}

int main(int argc, char **argv)
{
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}