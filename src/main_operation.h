#pragma once
#include "pch.h"
#include <sys/wait.h>
#include <sys/ptrace.h>
#include "event_handler.h"
#include "bpf_helper.h"

class MainOperaion
{
public:
    static void initialize(std::optional<lynceanbpf_bpf *> &skel, int pid);
    static void child_operaion(std::string &command, std::vector<std::string> &params);
    static void run_sync_task(std::optional<lynceanbpf_bpf *> &skel,
                              std::unique_ptr<event_handler> &bpf_event_handler,
                              realastic_impl &serializer, int pid);
    static void run_async_task(std::optional<lynceanbpf_bpf *> &skel,
                               std::unique_ptr<event_handler> &bpf_event_handler,
                               realastic_impl &serializer, int pid);

private:
};
