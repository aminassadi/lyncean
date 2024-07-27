#include "event_handler.h"
#include <iostream>
#include "kern/shared.h"
#include <sys/syscall.h>

event_handler *global_handler = nullptr;

static void global_handle_event(void *ctx, int cpu, void *data, unsigned int data_sz)
{
    global_handler->handle_event(ctx, cpu, data, data_sz);
}

event_handler::event_handler(lynceanbpf_bpf *skel, serializer *sr) : _skel(skel), _serializer(sr)
{
    _perf_buff = perf_buffer__new(bpf_map__fd(_skel->maps.perf_buff), 1024, global_handle_event, NULL, NULL, NULL);
    global_handler = this;
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

void event_handler::handle_event(void *ctx, int cpu, void *data, unsigned int data_sz)
{
   // std::cout << *reinterpret_cast<unsigned long *>(data) << " sizeof data: " << data_sz << '\n';
    switch (*reinterpret_cast<unsigned long *>(data))
    {
    case SYS_read:
    {
        std::cout<<_serializer->serialize_read_event(reinterpret_cast<struct_read_syscall*>(data))<<std::endl;
        // auto event{reinterpret_cast<struct_read_syscall *>(data)};
        // std::cout << "nr: " << event->syscallid << " count: " << event->count << " rc: " << event->rc
        //           << std::endl
        //           << "data: " << event->buff << std::endl;
        break;
    }
    case SYS_write:
        break;

    default:
        break;
    }
}
