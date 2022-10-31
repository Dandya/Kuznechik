#include "kuznechik.h"
#include "kuznechik.c"
#include "./gtest/include/gtest/gtest.h"

TEST(Base, Sbox) 
{
    vector128bit v, result;
    v.half[0] = 0x1122334455667700;
    v.half[1] = 0xffeeddccbbaa9988;
    result.half[0] = 0x7765aeea0c9a7efc;
    result.half[1] = 0xb66cd8887d38e8d7;
    SboxEncrypt(&v);
    EXPECT_EQ(result.half[0], v.half[0]);
    EXPECT_EQ(result.half[1], v.half[1]);
}

int main(int argc, char **argv)
{
	testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}