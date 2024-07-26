#include <iostream>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "lynceanbpf.skel.h"
#include "kern/shared.h"
#include <sys/syscall.h>
#include <unistd.h>
#include <optional>

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

std::optional<lynceanbpf_bpf*> load_bpf_skeleton()
{
    auto skel{lynceanbpf_bpf::open()};
    if(skel == nullptr)
    {
        std::cerr << "open bpf skeleton failed\n";
        return std::nullopt;
    }
    #ifdef _DEBUG
        libbpf_set_print(libbpf_print_fn);
    #endif
    do
    {
        config_struct config;
        memset(config.active, 1, sizeof(bool) * SYSCALL_COUNT_SIZE); // active all syscalls //todo: 
        config.target_pid = 29443; //todo: fix config
        int key = 0;
        int ret = bpf_program__set_type(skel->progs.tail_raw_syscall_read_exit, BPF_PROG_TYPE_RAW_TRACEPOINT);
        ret = ret ? : bpf_object__load(skel->obj);
        if(ret)
        {
            std::cerr << "load bpf skeleton failed\n";
            break;            
        }
        auto config_fd{bpf_map__fd(skel->maps.config_map)};
        if(config_fd == -1)
        {
            std::cerr<<"cannot access to config_map";
            break;
        }
        ret = bpf_map_update_elem(config_fd, &key, &config, BPF_ANY);
        if(ret)
        {
            std::cerr << "update config map failed\n";
            break;
        }
        auto raw_sys_enter_link =  bpf_program__attach_raw_tracepoint(skel->progs.generic_raw_sys_enter, "sys_enter");
        if(libbpf_get_error(raw_sys_enter_link))
        {
            std::cerr << "Attaching raw_tracepoint/sys_enter failed with error\n";
            break;
        } 
        auto raw_sys_exit_link = bpf_program__attach_raw_tracepoint(skel->progs.generic_raw_sys_exit, "sys_exit");
        if(libbpf_get_error(raw_sys_exit_link))
        {
            std::cerr << "Attaching raw_tracepoint/sys_exit failed with error\n";
            break;
        }
        return skel;
        
    } while (false);
    skel->destroy(skel);
    return std::nullopt;   
}

static void handle_event(void *ctx, int cpu, void *data, unsigned int data_sz)
{
	std::cout << *reinterpret_cast<unsigned long*>(data) <<" sizeof data: " << data_sz << '\n';
    switch (*reinterpret_cast<unsigned long*>(data))
    {
        case SYS_read:
        {
            auto event{reinterpret_cast<struct_read_syscall*>(data)};
            std::cout<<"nr: "<<event->syscallid<<" count: "<<event->count << " rc: " << event->rc 
            <<std::endl << "data: "<<event->buff<<std::endl;
            break;
        }            
        case SYS_write:
            break;
        
        default:
            break;
    }
}


int main(int argc, char** argv)
{
   
    //todo: spawn a child process
    auto skel{load_bpf_skeleton()};
    if(!skel.has_value())
    {
        exit(EXIT_FAILURE);
    }
    std::cout<<"hello";

    auto perf_buff{perf_buffer__new(bpf_map__fd(skel.value()->maps.perf_buff), 1024, handle_event, NULL, NULL, NULL)};
    while (!exiting) {
        int err = perf_buffer__poll(perf_buff, 100 /* timeout, ms */);
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            printf("Error polling perf buffer: %d\n", err);
            break;
        }
    }
}
