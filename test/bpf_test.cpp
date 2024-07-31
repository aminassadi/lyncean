#include "gtest/gtest.h"
#include "../src/bpf_helper.h"
#include <memory>
#include <sys/stat.h>
#include <fcntl.h>
#include <filesystem>
#include <thread>

using namespace std::literals;
static constexpr size_t kMaximumEventSize{65532};
struct event_struct
{
    char buff[kMaximumEventSize];
    int syscallid;
};

event_struct global_event{};

static void global_handle_event(void *ctx, int cpu, void *data, unsigned int data_sz)
{
    EXPECT_EQ(*reinterpret_cast<int *>(data), global_event.syscallid);
    switch (global_event.syscallid)
    {
    case SYS_read:
    {
        auto actual_event{reinterpret_cast<struct_read_syscall *>(data)};
        auto expected_event{reinterpret_cast<struct_read_syscall *>(global_event.buff)};
        EXPECT_EQ(actual_event->count, expected_event->count);
        EXPECT_EQ(actual_event->fd, expected_event->fd);
        EXPECT_EQ(actual_event->rc, expected_event->rc);
        EXPECT_EQ(memcmp(actual_event->buff, expected_event->buff, actual_event->rc), 0);
        break;
    }
    case SYS_write:
    {
        auto actual_event{reinterpret_cast<struct_write_syscall *>(data)};
        auto expected_event{reinterpret_cast<struct_write_syscall *>(global_event.buff)};
        EXPECT_EQ(actual_event->count, expected_event->count);
        EXPECT_EQ(actual_event->fd, expected_event->fd);
        EXPECT_EQ(actual_event->rc, expected_event->rc);
        EXPECT_EQ(memcmp(actual_event->buff, expected_event->buff, actual_event->rc), 0);
        break;
    }
    case SYS_open:
    {
        auto actual_event{reinterpret_cast<struct_open_syscall*>(data)};
        auto expected_event{reinterpret_cast<struct_open_syscall*>(global_event.buff)};
        EXPECT_EQ(actual_event->flag, expected_event->flag);
        EXPECT_EQ(actual_event->mode, expected_event->mode);
        EXPECT_EQ(actual_event->rc, expected_event->rc);
        EXPECT_EQ(memcmp(actual_event->pathname, expected_event->pathname, strlen(expected_event->pathname)), 0);
        break;
    }
    default:
        break;
    }
}

class bpf_test_fixture : public ::testing::Test
{
private:
    void load_bpf()
    {
        auto skel{load_bpf_skeleton(getpid())};
        ASSERT_TRUE(skel.has_value());
        _skel = skel.value();
        _perf_buff = perf_buffer__new(bpf_map__fd(_skel->maps.perf_buff), 1024, global_handle_event, NULL, NULL, NULL);
        ASSERT_TRUE(_perf_buff);
    }

protected:
    static lynceanbpf_bpf *_skel;
    static perf_buffer *_perf_buff;
    bpf_test_fixture()
    {
        // load bfp once
        if (!_skel)
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

lynceanbpf_bpf *bpf_test_fixture::_skel = nullptr;
perf_buffer *bpf_test_fixture::_perf_buff = nullptr;

TEST_F(bpf_test_fixture, read_system_call)
{
    const char *pathname = "./test_files/test_read.txt";
    int fd = open(pathname, O_RDONLY);
    ASSERT_FALSE(fd < 0);
    std::string buff(40, 0);
    int ret = read(fd, buff.data(), 40);
    ASSERT_FALSE(ret == -1);
    ASSERT_TRUE((buff == std::string("this is test file and suppose to be read")));
    struct_read_syscall event{};
    memset(&event, 0, sizeof(struct_read_syscall));
    event.syscallid = SYS_read;
    event.count = ret;
    event.fd = fd;
    event.rc = ret;
    memcpy(event.buff, buff.data(), ret);
    memset(&global_event, 0, sizeof(event_struct));
    memcpy(global_event.buff, (void *)&event, sizeof(struct_read_syscall));
    global_event.syscallid = SYS_read;
    std::this_thread::sleep_for(100ms);
    int err = perf_buffer__poll(_perf_buff, 100);
    EXPECT_FALSE(err == 0);
}

TEST_F(bpf_test_fixture, open_system_call)
{
    const char* pathname = "./test_files/test_read.txt";
    mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
    int flags = O_RDONLY;
    int fd = open(pathname, flags, mode);
    ASSERT_FALSE(fd < 0);
    struct_open_syscall event;
    memset(&event, 0, sizeof(struct_open_syscall));
    event.syscallid = SYS_open;
    event.flag = flags;
    memcpy(event.pathname, pathname, strlen(pathname));
    memset(&global_event, 0, sizeof(event_struct));
    memcpy(global_event.buff, (void *)&event, sizeof(struct_open_syscall));
    global_event.syscallid = SYS_open;
    std::this_thread::sleep_for(100ms);
    int err = perf_buffer__poll(_perf_buff, 100);
    EXPECT_FALSE(err == 0);
}

TEST_F(bpf_test_fixture, write_systemcall)
{
    const char *pathname = "./test_files/write_test.txt";
    int fd = open(pathname, O_WRONLY | O_TRUNC);
    ASSERT_FALSE(fd < 0);
    std::string buff("lyncean open source project.");
    int ret = write(fd, buff.data(), buff.length());
    ASSERT_TRUE(ret == buff.length());
    struct_write_syscall event{};
    memset(&event, 0, sizeof(struct_write_syscall));
    event.syscallid = SYS_write;
    event.count = ret;
    event.fd = fd;
    event.rc = ret;
    memcpy(event.buff, buff.data(), ret);
    memset(&global_event, 0, sizeof(event_struct));
    memcpy(global_event.buff, (void *)&event, sizeof(struct_write_syscall));
    global_event.syscallid = SYS_write;
    std::this_thread::sleep_for(100ms);
    int err = perf_buffer__poll(_perf_buff, 100);
    EXPECT_FALSE(err == 0);
}
