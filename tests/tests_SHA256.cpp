#include "../src/SHA256.c"
#include "./gtest/include/gtest/gtest.h"
#include <sys/time.h>
#include <string.h>

TEST(SHA256, OneBlockMessage) {
    char msg[] = "abc";
    vector256_t result; 
    EXPECT_EQ(0, sha256((uint8_t *)msg, strlen(msg), &result)); 
    EXPECT_EQ(0xb410ff61f20015ad, result.qwords[0]);
    EXPECT_EQ(0xb00361a396177a9c, result.qwords[1]);
    EXPECT_EQ(0x414140de5dae2223, result.qwords[2]);
    EXPECT_EQ(0xba7816bf8f01cfea, result.qwords[3]);
}

TEST(SHA256, MultyBlockMessage) {
    char msg[] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    vector256_t result; 
    EXPECT_EQ(0, sha256((uint8_t *)msg, strlen(msg), &result)); 
    EXPECT_EQ(0xf6ecedd419db06c1, result.qwords[0]);
    EXPECT_EQ(0xa33ce45964ff2167, result.qwords[1]);
    EXPECT_EQ(0xe5c026930c3e6039, result.qwords[2]);
    EXPECT_EQ(0x248d6a61d20638b8, result.qwords[3]);
}

TEST(SHA256, LongBlockMessage) {
    char * msg = (char*)malloc(1000001);
    for(int i = 0; i < 1000000; i++) {
        msg[i] = 'a';
    }
    msg[1000000] = 0;
    vector256_t result; 
    EXPECT_EQ(0, sha256((uint8_t *)msg, 1000000, &result)); 
    EXPECT_EQ(0x046d39ccc7112cd0, result.qwords[0]);
    EXPECT_EQ(0xf1809a48a497200e, result.qwords[1]);
    EXPECT_EQ(0x81a1c7e284d73e67, result.qwords[2]);
    EXPECT_EQ(0xcdc76e5c9914fb92, result.qwords[3]);
}

int main(int argc, char **argv)
{
	testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}