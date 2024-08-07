#ifndef LYNCEAN_BPF_HELPER_HEADER
#define LYNCEAN_BPF_HELPER_HEADER
#include "kern/shared.h"
#include "lynceanbpf.skel.h"
#include "bpf/bpf.h"
#include <optional>
#include <array>

static constexpr std::array<int, 5> kActiveSyscalls{
    SYS_read,
    SYS_write,
    SYS_open,
    SYS_openat,
    SYS_close,
};

static inline int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
}

static inline std::optional<lynceanbpf_bpf *> load_bpf_skeleton()
{
    auto skel{lynceanbpf_bpf::open()};
    if (skel == nullptr)
    {
        std::cerr << "open bpf skeleton failed\n";
        return std::nullopt;
    }
#ifdef _DEBUG
    libbpf_set_print(libbpf_print_fn);
#endif
    do
    {
        int ret = bpf_program__set_type(skel->progs.tail_raw_syscall_read_exit, BPF_PROG_TYPE_RAW_TRACEPOINT);
        ret = ret ?: bpf_program__set_type(skel->progs.tail_raw_syscall_write_exit, BPF_PROG_TYPE_RAW_TRACEPOINT);
        ret = ret ?: bpf_program__set_type(skel->progs.tail_raw_syscall_open_exit, BPF_PROG_TYPE_RAW_TRACEPOINT);
        ret = ret ?: bpf_program__set_type(skel->progs.tail_raw_syscall_close_exit, BPF_PROG_TYPE_RAW_TRACEPOINT);
        ret = ret ?: bpf_object__load(skel->obj);
        if (ret)
        {
            std::cerr << "load bpf skeleton failed\n";
            break;
        }
        bpf_config_struct config{};
        config.follow_childs = false;
        memset(config.active, 0, SYSCALL_COUNT_SIZE);
        auto config_fd{bpf_map__fd(skel->maps.config_map)};
        if (config_fd == -1)
        {
            break;
        }
        int key = 0;
        if (bpf_map_update_elem(config_fd, &key, &config, BPF_ANY))
        {
            break;
        }
        auto raw_sys_enter_link = bpf_program__attach_raw_tracepoint(skel->progs.generic_raw_sys_enter, "sys_enter");
        if (libbpf_get_error(raw_sys_enter_link))
        {
            std::cerr << "Attaching raw_tracepoint/sys_enter failed with error\n";
            break;
        }
        auto raw_sys_exit_link = bpf_program__attach_raw_tracepoint(skel->progs.generic_raw_sys_exit, "sys_exit");
        if (libbpf_get_error(raw_sys_exit_link))
        {
            std::cerr << "Attaching raw_tracepoint/sys_exit failed with error\n";
            break;
        }
        return skel;

    } while (false);
    skel->destroy(skel);
    return std::nullopt;
}

static inline bool set_bpf_config(const lynceanbpf_bpf *skel, const bpf_config_struct &conf, uint32_t target_pid)
{
    auto config_fd{bpf_map__fd(skel->maps.config_map)};
    if (config_fd == -1)
    {
        return false;
    }
    int key = 0;
    if (bpf_map_update_elem(config_fd, &key, &conf, BPF_ANY))
    {
        return false;
    }
    auto process_fd{bpf_map__fd(skel->maps.target_tasks_map)};
    if(process_fd == -1)
    {
        return false;
    }
    bool value = true;
    if(bpf_map_update_elem(process_fd, &target_pid, &value, BPF_ANY))
    {
        return false;
    }
    return true;
}

#endif