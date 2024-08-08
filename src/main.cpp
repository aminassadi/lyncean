#include <iostream>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <unistd.h>
#include <signal.h>
#include "bpf_helper.h"
#include "serializer.h"
#include "input_parser.h"
#include "main_operation.h"

using namespace std::literals;

realastic_impl sr;
std::optional<lynceanbpf_bpf *> skel{};
std::unique_ptr<event_handler> bpf_event_handler;

static void handle_terminate_signal(int sig)
{
    if (bpf_event_handler)
        bpf_event_handler->stop();
}

int main(int argc, char **argv)
{
    auto [pid, command, params] = InputParser::get_input_parameters(argc, argv);

    signal(SIGINT, handle_terminate_signal);
    signal(SIGTERM, handle_terminate_signal);

    if (pid)
    {
        MainOperaion::run_sync_task(skel, bpf_event_handler, sr, pid);
        return 0;
    }

    pid = fork();

    if (pid < 0)
    {
        perror("Fork failed");
        return 1;
    }
    else if (pid == 0)
    {
        MainOperaion::child_operaion(command, params);
    }
    else
    {
        MainOperaion::run_async_task(skel, bpf_event_handler, sr, pid);
    }
}
