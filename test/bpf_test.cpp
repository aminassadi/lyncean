#include "gtest/gtest.h"
#include "../src/bpf_helper.h"
#include <memory>
#include <sys/stat.h>
#include <fcntl.h>
#include <filesystem>
#include <thread>

using namespace std::literals;

struct event_struct
{
    std::unique_ptr<char> buff;
    unsigned int size;
};

event_struct global_event{};

static void handle_event(void *ctx, int cpu, void *data, unsigned int data_sz)
{
    EXPECT_EQ(data_sz, global_event.size);
    EXPECT_EQ(memcmp(global_event.buff.get(), reinterpret_cast<char *>(data), data_sz), 0);
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

protected:
    lynceanbpf_bpf *_skel{};
    perf_buffer *_perf_buff{};
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
        if (_skel)
        {
            lynceanbpf_bpf::destroy(_skel);
        }
    }
};

TEST_F(bpf_test_fixture, read_system_call)
{   
    char* pathname = "./test_files/test_read.txt";
    int fd = open(pathname, O_RDONLY);
    ASSERT_FALSE(fd < 0);
    std::string buff(40, 0);
    int ret = read(fd, buff.data(), 40);
    ASSERT_FALSE(ret == -1);
    ASSERT_TRUE((buff == std::string("this is test file and suppose to be read")));
    struct_read_syscall event;
    event.syscallid = SYS_read;
    event.count = ret;
    event.fd = fd;
    event.rc = ret;
    memcpy(event.buff, buff.data(), ret);
    global_event.buff = std::make_unique<char> (sizeof(struct_read_syscall));
    memcpy(global_event.buff.get(), (void*)&event, sizeof(struct_read_syscall));
    global_event.size = sizeof(struct_read_syscall);
    std::this_thread::sleep_for(100ms);
    int err = perf_buffer__poll(_perf_buff, 100);
    ASSERT_FALSE(err < 0);
}

