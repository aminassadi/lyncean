#ifndef LYNCEAN_EVENT_HADNLER_HEADER
#define LYNCEAN_EVENT_HADNLER_HEADER

#include "lynceanbpf.skel.h"

class event_handler
{
public:
    event_handler(lynceanbpf_bpf *skel);
    void start();
    void stop();

private:
    lynceanbpf_bpf *_skel{};
    perf_buffer *_perf_buff{};
    bool _active_token{};
};

#endif