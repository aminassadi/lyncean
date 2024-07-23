#include <iostream>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "lynceanbpf.skel.h"
#include "kern/shared.h"
#include <unistd.h>

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

static void handle_event(void *ctx, int cpu, void *data, unsigned int data_sz)
{
	std::cout << *reinterpret_cast<unsigned long*>(data) << '\n';
}


int main(int argc, char** argv)
{
    auto skel{lynceanbpf_bpf::open_and_load()};
    if(skel == nullptr)
    {
        std::cerr << "Loading bpf skeleton failed\n";
        return -1;
    }

    config_struct config;
    memset(config.active, 1, sizeof(bool) * SYSCALL_COUNT_SIZE); // active all syscalls
    config.target_pid = getpid();
    auto config_fd{bpf_map__fd(skel->maps.config_map)};
    int key = 0;
    bpf_map_update_elem(config_fd, &key, &config, BPF_ANY);

    auto err{lynceanbpf_bpf::attach(skel)};
    if(err)
    {
        std::cerr << "Attaching bpf failed with error: " << err << '\n';
    }
    auto perf_buff{perf_buffer__new(bpf_map__fd(skel->maps.perf_buff), 1024, handle_event, NULL, NULL, NULL)};
     while (!exiting) {
            err = perf_buffer__poll(perf_buff, 100 /* timeout, ms */);
            /* Ctrl-C will cause -EINTR */
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