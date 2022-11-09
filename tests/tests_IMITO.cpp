#include "../src/Kuznechik.c"
#include "../src/IMITO.c"
#include "./gtest/include/gtest/gtest.h"
#include <sys/time.h>

TEST(IMITO, creationKeys) {
    vector128bit key[2];
    key[0].half[0] = 0x0123456789abcdef;
    key[0].half[1] = 0xfedcba9876543210;
    key[1].half[0] = 0x0011223344556677;
    key[1].half[1] = 0x8899aabbccddeeff;
    vector128bit iteration_keys[10];
    createIterationKeysKuz(key, iteration_keys);

    vector128bit helping_key = createHelpingKey(iteration_keys, CREATE_KEY_1);
    EXPECT_EQ(0x0de0573298151dc7, helping_key.half[0]);
    EXPECT_EQ(0x297d82bc4d39e3ca, helping_key.half[1]);

    helping_key = createHelpingKey(iteration_keys, CREATE_KEY_2);
    EXPECT_EQ(0x1bc0ae65302a3b8e, helping_key.half[0]);
    EXPECT_EQ(0x52fb05789a73c794, helping_key.half[1]);
}

TEST(IMITO, creationMAC) {
    FILE * input_text = fopen("OpenText.txt", "w");
    if(input_text == NULL)
    {
        printf("Error of open file: %d\n", __LINE__);
        return;
    }
    
    vector128bit block;
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

    vector128bit key[2];
    key[0].half[0] = 0x0123456789abcdef;
    key[0].half[1] = 0xfedcba9876543210;
    key[1].half[0] = 0x0011223344556677;
    key[1].half[1] = 0x8899aabbccddeeff;

    input_text = fopen("OpenText.txt", "r");
    uint64_t MAC;
    EXPECT_EQ(0, createMAC(input_text, (uint8_t *)&MAC, key, 64));
    EXPECT_EQ(0x336f4d296059fbe3, MAC);
    fclose(input_text);
}

int main(int argc, char **argv)
{
	testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}