#include <iostream>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "lynceanbpf.skel.h"
#include "kern/shared.h"
#include <sys/syscall.h>
#include <unistd.h>

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
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

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

int main(int argc, char** argv)
{
    auto skel{lynceanbpf_bpf::open()};
    if(skel == nullptr)
    {
        std::cerr << "Loading bpf skeleton failed\n";
        return -1;
    }
    ////////
    // pid_t pid = fork();
    // if(pid == -1)
    // {
    //     perror("fork failed\n");
    //     exit(1);
    // }
    // else if(pid == 0)
    // {
    //      execlp("/usr/bin/ls", "/usr/bin/ls", NULL);

    // }
    
    //////

    libbpf_set_print(libbpf_print_fn);
    bpf_program__set_type(skel->progs.tail_raw_syscall_read_exit, BPF_PROG_TYPE_RAW_TRACEPOINT);
    bpf_object__load(skel->obj);
    config_struct config;
    memset(config.active, 1, sizeof(bool) * SYSCALL_COUNT_SIZE); // active all syscalls
    config.target_pid = 29443;
    auto config_fd{bpf_map__fd(skel->maps.config_map)};
    int key = 0;
    bpf_map_update_elem(config_fd, &key, &config, BPF_ANY); 

    // auto tail_callProgs_fd{bpf_map__fd(skel->maps.prog_array_tailcalls)};
    // __u32 mapkey = 1;
    // __u32 value = bpf_program__fd(skel->progs.read_sys_exit);
    // bpf_map_update_elem(tail_callProgs_fd,&mapkey , &value, BPF_ANY);
    auto raw_sys_enter_link =  bpf_program__attach_raw_tracepoint(skel->progs.generic_raw_sys_enter, "sys_enter"); 
    auto raw_sys_exit_link = bpf_program__attach_raw_tracepoint(skel->progs.generic_raw_sys_exit, "sys_exit");
    //auto err{lynceanbpf_bpf::attach(skel)};
    if(libbpf_get_error(raw_sys_exit_link))
    {
        std::cerr << "Attaching bpf failed with error\n";
    }
    auto perf_buff{perf_buffer__new(bpf_map__fd(skel->maps.perf_buff), 1024, handle_event, NULL, NULL, NULL)};
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
    skel->destroy(skel);
}
