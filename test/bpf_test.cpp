#include "gtest/gtest.h"
#include "../src/bpf_helper.h"
#include <memory>

struct event_struct
{
    std::unique_ptr<char> buff;
    unsigned int size;
};

event_struct event{};

static void handle_event(void *ctx, int cpu, void *data, unsigned int data_sz)
{
    EXPECT_EQ(data_sz, event.size);
    EXPECT_EQ(memcmp(event.buff.get(), reinterpret_cast<char*>(data), data_sz), 0);
}

class bpf_test_fixture : public ::testing::Test 
{ 
private:
    void load_bpf()
    {
        auto skel{load_bpf_skeleton(getpid())};
        ASSERT_TRUE(skel.has_value());
        _skel = skel.value();
        _perf_buff = perf_buffer__new(bpf_map__fd(_skel->maps.perf_buff), 1024, handle_event, NULL, NULL, NULL);
    }
    lynceanbpf_bpf *_skel{};
    perf_buffer *_perf_buff{};
protected:
    bpf_test_fixture() 
    {
        // This method will be called before each test.
        load_bpf();
    }

    void SetUp() override 
    {
    }

    void TearDown() override 
    {
    }

};
