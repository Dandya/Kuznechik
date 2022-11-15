#include "../src/Kuznechik.c"
#include "./gtest/include/gtest/gtest.h"

vector128_t v, result;
vector128_t key[2];
vector128_t iteration_keys[10];

TEST(Base, sizeVector) {
    EXPECT_EQ(16, sizeof(vector128_t));
}

TEST(Base, substitutionFuncEncrypt) 
{
    v.half[0] = 0x1122334455667700;
    v.half[1] = 0xffeeddccbbaa9988;
    result.half[0] = 0x7765aeea0c9a7efc;
    result.half[1] = 0xb66cd8887d38e8d7;
    substitutionFunc(&v, ENCRYPT);
    EXPECT_EQ(result.half[0], v.half[0]);
    EXPECT_EQ(result.half[1], v.half[1]);
    result.half[0] = 0x7e7b262523280d39;
    result.half[1] = 0x559d8dd7bd06cbfe;
    substitutionFunc(&v, ENCRYPT);
    EXPECT_EQ(result.half[0], v.half[0]);
    EXPECT_EQ(result.half[1], v.half[1]);
    result.half[0] = 0x0d80ef5c5a81c50b;
    result.half[1] = 0x0c3322fed531e463;
    substitutionFunc(&v, ENCRYPT);
    EXPECT_EQ(result.half[0], v.half[0]);
    EXPECT_EQ(result.half[1], v.half[1]);
    result.half[0] = 0xc5df529c13f5acda;
    result.half[1] = 0x23ae65633f842d29;
    substitutionFunc(&v, ENCRYPT);
    EXPECT_EQ(result.half[0], v.half[0]);
    EXPECT_EQ(result.half[1], v.half[1]);
}

TEST(Base, relocateBytesEncrypt) {
    v.half[0] = 0x0000000000000100;
    v.half[1] = 0x0000000000000000;
    result.half[0] = 0x0000000000000001;
    result.half[1] = 0x9400000000000000;
    relocateBytes(&v, ENCRYPT);
    EXPECT_EQ(result.half[0], v.half[0]);
    EXPECT_EQ(result.half[1], v.half[1]);
    result.half[0] = 0x0000000000000000;
    result.half[1] = 0xa594000000000000;
    relocateBytes(&v, ENCRYPT);
    EXPECT_EQ(result.half[0], v.half[0]);
    EXPECT_EQ(result.half[1], v.half[1]);
    result.half[0] = 0x0000000000000000;
    result.half[1] = 0x64a5940000000000;
    relocateBytes(&v, ENCRYPT);
    EXPECT_EQ(result.half[0], v.half[0]);
    EXPECT_EQ(result.half[1], v.half[1]);
    result.half[0] = 0x0000000000000000;
    result.half[1] = 0x0d64a59400000000;
    relocateBytes(&v, ENCRYPT);
    EXPECT_EQ(result.half[0], v.half[0]);
    EXPECT_EQ(result.half[1], v.half[1]);
}

TEST(Base, linearFuncEncrypt){
    v.half[0] = 0x0000000000000000;
    v.half[1] = 0x64a5940000000000;
    result.half[0] = 0xc3166e4b7fa2890d;
    result.half[1] = 0xd456584dd0e3e84c;
    linearFunc(&v, ENCRYPT);
    EXPECT_EQ(result.half[0], v.half[0]);
    EXPECT_EQ(result.half[1], v.half[1]);
    result.half[0] = 0xd42fbc4ffea5de9a;
    result.half[1] = 0x79d26221b87b584c;
    linearFunc(&v, ENCRYPT);
    EXPECT_EQ(result.half[0], v.half[0]);
    EXPECT_EQ(result.half[1], v.half[1]);
    result.half[0] = 0x8b7b68f66b513c13;
    result.half[1] = 0x0e93691a0cfc6040;
    linearFunc(&v, ENCRYPT);
    EXPECT_EQ(result.half[0], v.half[0]);
    EXPECT_EQ(result.half[1], v.half[1]);
    result.half[0] = 0xfd97bcb0b44b8580;
    result.half[1] = 0xe6a8094fee0aa204;
    linearFunc(&v, ENCRYPT);
    EXPECT_EQ(result.half[0], v.half[0]);
    EXPECT_EQ(result.half[1], v.half[1]);
}

TEST(Base, substitutionFuncDecrypt) 
{
    v.half[0] = 0xc5df529c13f5acda;
    v.half[1] = 0x23ae65633f842d29;
    result.half[0] = 0x0d80ef5c5a81c50b;
    result.half[1] = 0x0c3322fed531e463;
    substitutionFunc(&v, DECRYPT);
    EXPECT_EQ(result.half[0], v.half[0]);
    EXPECT_EQ(result.half[1], v.half[1]);
    result.half[0] = 0x7e7b262523280d39;
    result.half[1] = 0x559d8dd7bd06cbfe;
    substitutionFunc(&v, DECRYPT);
    EXPECT_EQ(result.half[0], v.half[0]);
    EXPECT_EQ(result.half[1], v.half[1]);
    result.half[0] = 0x7765aeea0c9a7efc;
    result.half[1] = 0xb66cd8887d38e8d7;
    substitutionFunc(&v, DECRYPT);
    EXPECT_EQ(result.half[0], v.half[0]);
    EXPECT_EQ(result.half[1], v.half[1]);
    result.half[0] = 0x1122334455667700;
    result.half[1] = 0xffeeddccbbaa9988;
    substitutionFunc(&v, DECRYPT);
    EXPECT_EQ(result.half[0], v.half[0]);
    EXPECT_EQ(result.half[1], v.half[1]);
}

TEST(Base, relocateBytesDecrypt) {
    v.half[0] = 0x0000000000000000;
    v.half[1] = 0x0d64a59400000000;
    result.half[0] = 0x0000000000000000;
    result.half[1] = 0x64a5940000000000;
    relocateBytes(&v, DECRYPT);
    EXPECT_EQ(result.half[0], v.half[0]);
    EXPECT_EQ(result.half[1], v.half[1]);
    result.half[0] = 0x0000000000000000;
    result.half[1] = 0xa594000000000000;
    relocateBytes(&v, DECRYPT);
    EXPECT_EQ(result.half[0], v.half[0]);
    EXPECT_EQ(result.half[1], v.half[1]);
    result.half[0] = 0x0000000000000001;
    result.half[1] = 0x9400000000000000;
    relocateBytes(&v, DECRYPT);
    EXPECT_EQ(result.half[0], v.half[0]);
    EXPECT_EQ(result.half[1], v.half[1]);
    result.half[0] = 0x0000000000000100;
    result.half[1] = 0x0000000000000000;
    relocateBytes(&v, DECRYPT);
    EXPECT_EQ(result.half[0], v.half[0]);
    EXPECT_EQ(result.half[1], v.half[1]);
}

TEST(Base, linearFuncDecrypt){
    v.half[0] = 0xfd97bcb0b44b8580;
    v.half[1] = 0xe6a8094fee0aa204;
    result.half[0] = 0x8b7b68f66b513c13;
    result.half[1] = 0x0e93691a0cfc6040;
    linearFunc(&v, DECRYPT);
    EXPECT_EQ(result.half[0], v.half[0]);
    EXPECT_EQ(result.half[1], v.half[1]);
    result.half[0] = 0xd42fbc4ffea5de9a;
    result.half[1] = 0x79d26221b87b584c;
    linearFunc(&v, DECRYPT);
    EXPECT_EQ(result.half[0], v.half[0]);
    EXPECT_EQ(result.half[1], v.half[1]);
    result.half[0] = 0xc3166e4b7fa2890d;
    result.half[1] = 0xd456584dd0e3e84c;
    linearFunc(&v, DECRYPT);
    EXPECT_EQ(result.half[0], v.half[0]);
    EXPECT_EQ(result.half[1], v.half[1]);
    result.half[0] = 0x0000000000000000;
    result.half[1] = 0x64a5940000000000;
    linearFunc(&v, DECRYPT);
    EXPECT_EQ(result.half[0], v.half[0]);
    EXPECT_EQ(result.half[1], v.half[1]);
}

TEST(Base, createKeys) {
    createIterationKeysKuz(key, iteration_keys);
    //key 0
    EXPECT_EQ(0x0011223344556677, iteration_keys[0].half[0]);
    EXPECT_EQ(0x8899aabbccddeeff, iteration_keys[0].half[1]);
    //key 1
    EXPECT_EQ(0x0123456789abcdef, iteration_keys[1].half[0]);
    EXPECT_EQ(0xfedcba9876543210, iteration_keys[1].half[1]);
    //key 2
    EXPECT_EQ(0x228d6aef8cc78c44, iteration_keys[2].half[0]);
    EXPECT_EQ(0xdb31485315694343, iteration_keys[2].half[1]);
    //key 3
    EXPECT_EQ(0x15ebadc40a9ffd04, iteration_keys[3].half[0]);
    EXPECT_EQ(0x3d4553d8e9cfec68, iteration_keys[3].half[1]);
    //key 4
    EXPECT_EQ(0xd3e59246f429f1ac, iteration_keys[4].half[0]);
    EXPECT_EQ(0x57646468c44a5e28, iteration_keys[4].half[1]);
    //key 5
    EXPECT_EQ(0xb532e82834da581b, iteration_keys[5].half[0]);
    EXPECT_EQ(0xbd079435165c6432, iteration_keys[5].half[1]);
    //key 6
    EXPECT_EQ(0x705727265a0098b1, iteration_keys[6].half[0]);
    EXPECT_EQ(0x51e640757e8745de, iteration_keys[6].half[1]);
    //key 7
    EXPECT_EQ(0xd72a91a22286f984, iteration_keys[7].half[0]);
    EXPECT_EQ(0x5a7925017b9fdd3e, iteration_keys[7].half[1]);
    //key 8
    EXPECT_EQ(0xa5f32f73cdb6e517, iteration_keys[8].half[0]);
    EXPECT_EQ(0xbb44e25378c73123, iteration_keys[8].half[1]);
    //key 9
    EXPECT_EQ(0x755dbaa88e4a4043, iteration_keys[9].half[0]);
    EXPECT_EQ(0x72e9dd7416bcf45b, iteration_keys[9].half[1]);
}

TEST(Base, BlockEncryptKuz) {
    v.half[0] = 0xffeeddccbbaa9988;
    v.half[1] = 0x1122334455667700;
    encryptBlockKuz(&v, iteration_keys);
    EXPECT_EQ(0x5a468d42b9d4edcd, v.half[0]);
    EXPECT_EQ(0x7f679d90bebc2430, v.half[1]);
}

TEST(Base, BlockDecryptKuz) {
    v.half[0] = 0x5a468d42b9d4edcd;
    v.half[1] = 0x7f679d90bebc2430;
    decryptBlockKuz(&v, iteration_keys);
    EXPECT_EQ(0xffeeddccbbaa9988, v.half[0]);
    EXPECT_EQ(0x1122334455667700, v.half[1]);
}

TEST(Base, SizeOfFile) {
    FILE * file = fopen("test_text.txt", "w");
    fwrite("12345\0 8\nA", 10, 1, file);
    fseek(file, 0, SEEK_SET);
    EXPECT_EQ(10, getSizeFile(file));
    fclose(file);
}

TEST(Base, paddingNullls) {
    vector128_t block;
    block.half[0] = 0x1122334455667700;
    block.half[1] = 0x0000000000000000;
    procPaddingNulls((uint8_t *) &block, 9, PROC_ADD_NULLS_1);
    EXPECT_EQ(0x0022334455667700, block.half[0]);
    EXPECT_EQ(0x0000000000000000, block.half[1]);
    procPaddingNulls((uint8_t *) &block, 9, PROC_ADD_NULLS_2);
    EXPECT_EQ(0x0122334455667700, block.half[0]);
    EXPECT_EQ(0x0000000000000000, block.half[1]);
}

TEST(Base, ReadLastBlock) {
    FILE * file = fopen("test_text.txt", "r"); // watch test SizeOfFile
    vector128_t block;
    readLastBlock(file, &block, PROC_ADD_NULLS_1, 10);
    EXPECT_EQ(0x3820003534333231, block.half[0]);
    EXPECT_EQ(0x000000000000410A, block.half[1]);
    fseek(file, 0, SEEK_SET);
    readLastBlock(file, &block, PROC_ADD_NULLS_2, 10);
    EXPECT_EQ(0x3820003534333231, block.half[0]);
    EXPECT_EQ(0x000000000001410A, block.half[1]);
}

TEST(Base, CountForWrite) {
    vector128_t block;
    block.half[0] = 0x3820003534333231;
    block.half[1] = 0x000000000001410A;
    EXPECT_EQ(10, getCountBytesInLastBlock((uint8_t*)&block));
    block.half[0] = 0x0120003534333231;
    block.half[1] = 0x0000000000000000;
    EXPECT_EQ(7, getCountBytesInLastBlock((uint8_t*)&block));
    block.half[0] = 0x0000000000000001;
    block.half[1] = 0x0000000000000000;
    EXPECT_EQ(0, getCountBytesInLastBlock((uint8_t*)&block));
    block.half[0] = 0xaaaaaaaaaaaaaaaa;
    block.half[1] = 0xaaaaaaaaaaaaaaaa;
    EXPECT_EQ(16, getCountBytesInLastBlock((uint8_t*)&block));
}

int main(int argc, char **argv)
{
    key[0].half[0] = 0x0123456789abcdef;
    key[0].half[1] = 0xfedcba9876543210;
    key[1].half[0] = 0x0011223344556677;
    key[1].half[1] = 0x8899aabbccddeeff;
    createIterationKeysKuz(key, iteration_keys);
	testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}