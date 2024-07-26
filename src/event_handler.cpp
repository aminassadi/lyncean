#include "event_handler.h"
#include <iostream>
#include "kern/shared.h"
#include <sys/syscall.h>

static void handle_event(void *ctx, int cpu, void *data, unsigned int data_sz)
{
    std::cout << *reinterpret_cast<unsigned long *>(data) << " sizeof data: " << data_sz << '\n';
    switch (*reinterpret_cast<unsigned long *>(data))
    {
    case SYS_read:
    {
        auto event{reinterpret_cast<struct_read_syscall *>(data)};
        std::cout << "nr: " << event->syscallid << " count: " << event->count << " rc: " << event->rc
                  << std::endl
                  << "data: " << event->buff << std::endl;
        break;
    }
    case SYS_write:
        break;

    default:
        break;
    }
}

event_handler::event_handler(lynceanbpf_bpf *skel) : _skel(skel)
{
    _perf_buff = perf_buffer__new(bpf_map__fd(_skel->maps.perf_buff), 1024, handle_event, NULL, NULL, NULL);
}

void event_handler::start()
{
    _active_token = true;
    while (_active_token)
    {
        int err = perf_buffer__poll(_perf_buff, 100);
        if (err == -EINTR)
        {
            err = 0;
            break;
        }
        if (err < 0)
        {
            printf("Error polling perf buffer: %d\n", err);
            break;
        }
    }
}

void event_handler::stop()
{
    _active_token = false;
}
