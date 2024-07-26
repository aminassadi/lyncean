#include "gtest/gtest.h"


class bpf_test_fixture : public ::testing::Test 
{ 
private:
    
protected:
    static constexpr auto kDefaultNiceValue{0}; 
    static constexpr auto kMaxNiceValue{-20};
    static constexpr auto kMinNiceValue{19};
     bpf_test_fixture() 
    {
        // This method will be called before each test.
       // Reset();
    }

    void SetUp() override 
    {
    }

    void TearDown() override 
    {
    }

};
