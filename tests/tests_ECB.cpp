#include "../src/Kuznechik.c"
#include "../src/ECB.c"
#include "./gtest/include/gtest/gtest.h"

TEST(ECB, TestFromGOST) {
    FILE * open_text = fopen("OpenText.txt", "w");
    FILE * close_text;
    if(open_text == NULL)
    {
        printf("Error of open file: %d\n", __LINE__);
        return;
    }

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
    EXPECT_EQ(0, encryptECBKuz(open_text, close_text, key, PROC_ADD_NULLS_2));
    fclose(open_text);
    fclose(close_text);

    close_text = fopen("CloseText.txt", "r");
    fread(&block, SIZE_BLOCK, 1, close_text);
    EXPECT_EQ(0x5a468d42b9d4edcd, block.half[0]);
    EXPECT_EQ(0x7f679d90bebc2430, block.half[1]);
    fread(&block, SIZE_BLOCK, 1, close_text);
    EXPECT_EQ(0x285452d76718d08b, block.half[0]);
    EXPECT_EQ(0xb429912c6e0032f9, block.half[1]);
    fread(&block, SIZE_BLOCK, 1, close_text);
    EXPECT_EQ(0xf3f5a5313bd4b157, block.half[0]);
    EXPECT_EQ(0xf0ca33549d247cee, block.half[1]);
    fread(&block, SIZE_BLOCK, 1, close_text);
    EXPECT_EQ(0x3a02c4c5aa8ada98, block.half[0]);
    EXPECT_EQ(0xd0b09ccde830b9eb, block.half[1]);
    fread(&block, SIZE_BLOCK, 1, close_text);
    EXPECT_EQ(feof(close_text), 0);
    fclose(close_text);

    open_text = fopen("OpenText.txt", "w");
    close_text = fopen("CloseText.txt", "r");
    EXPECT_EQ(0, decryptECBKuz(close_text, open_text, key, PROC_ADD_NULLS_2, 0));
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
    EXPECT_EQ(0, encryptECBKuz(open_text, close_text, key, PROC_ADD_NULLS_2));
    fclose(open_text);
    fclose(close_text);

    close_text = fopen("CloseText.txt", "r");
    for(int i = 0; i < 10; i++) {
        fread(&block, SIZE_BLOCK, 1, close_text);
        EXPECT_EQ(0x5a468d42b9d4edcd, block.half[0]);
        EXPECT_EQ(0x7f679d90bebc2430, block.half[1]);
    }
    EXPECT_EQ(0, fread(&block, SIZE_BLOCK, 1, close_text));
    EXPECT_NE(feof(close_text), 0);
    fclose(close_text);

    open_text = fopen("OpenText.txt", "w");
    close_text = fopen("CloseText.txt", "r");
    EXPECT_EQ(0, decryptECBKuz(close_text, open_text, key, PROC_ADD_NULLS_2, 0));
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

TEST(ECB, Speed) {
    FILE * open_text = fopen("Arch.ova", "a+");
    FILE * close_text = fopen("CLoseText.ova", "w");
    if(open_text == NULL)
    {
        printf("Error of open file: %d\n", __LINE__);
        return;
    }

    vector128bit key[2];
    key[0].half[0] = 0x0123456789abcdef;
    key[0].half[1] = 0xfedcba9876543210;
    key[1].half[0] = 0x0011223344556677;
    key[1].half[1] = 0x8899aabbccddeeff;

    encryptECBKuz(open_text, close_text, key, PROC_ADD_NULLS_2);

    // fseek(open_text, 0, SEEK_SET);
    // fseek(close_text, 0, SEEK_SET);

    // cryptECBKuz(DECRYPT, close_text, open_text, key);

    fclose(open_text);
    fclose(close_text);
}

int main(int argc, char **argv)
{
	testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}