#ifndef LYNCEAN_EVENT_HADNLER_HEADER
#define LYNCEAN_EVENT_HADNLER_HEADER

#include "lynceanbpf.skel.h"
#include "serializer.h"

class event_handler
{
public:
    event_handler(lynceanbpf_bpf *skel, serializer *sr);
    void start();
    void stop();
    void handle_event(void *ctx, int cpu, void *data, unsigned int data_sz);

private:
    lynceanbpf_bpf *_skel{};
    perf_buffer *_perf_buff{};
    bool _active_token{};
    serializer *_serializer;
};

#endif