#ifndef LYNCEAN_BPF_HELPER_HEADER
#define LYNCEAN_BPF_HELPER_HEADER
#include "kern/shared.h"
#include "lynceanbpf.skel.h"
#include "bpf/bpf.h"
#include <optional>

inline static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
}

inline std::optional<lynceanbpf_bpf *> load_bpf_skeleton(int pid)
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
        bpf_config_struct config;
        memset(config.active, 1, sizeof(bool) * SYSCALL_COUNT_SIZE); // active all syscalls //todo:
        config.target_pid = pid;                                     // todo: fix config
        int key = 0;
        int ret = bpf_program__set_type(skel->progs.tail_raw_syscall_read_exit, BPF_PROG_TYPE_RAW_TRACEPOINT);
        ret = ret ?: bpf_program__set_type(skel->progs.tail_raw_syscall_write_exit, BPF_PROG_TYPE_RAW_TRACEPOINT);
        ret = ret ?: bpf_program__set_type(skel->progs.tail_raw_syscall_open_exit, BPF_PROG_TYPE_RAW_TRACEPOINT);
        ret = ret ?: bpf_object__load(skel->obj);
        if (ret)
        {
            std::cerr << "load bpf skeleton failed\n";
            break;
        }
        auto config_fd{bpf_map__fd(skel->maps.config_map)};
        if (config_fd == -1)
        {
            std::cerr << "cannot access to config_map";
            break;
        }
        ret = bpf_map_update_elem(config_fd, &key, &config, BPF_ANY);
        if (ret)
        {
            std::cerr << "update config map failed\n";
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
#endif