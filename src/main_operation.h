#pragma once
#include "pch.h"
#include <sys/wait.h>
#include <sys/ptrace.h>
#include "event_handler.h"
#include "bpf_helper.h"

class main_operation
{
public:
    static void initialize(std::optional<lynceanbpf_bpf *> &skel, const setting stg);
    static void child_operaion(std::string &command, std::vector<std::string> &params);
    static void run_sync_task(std::optional<lynceanbpf_bpf *> &skel,
                              std::unique_ptr<event_handler> &bpf_event_handler,
                              serializer* serializer, const setting stg);
    static void run_async_task(std::optional<lynceanbpf_bpf *> &skel,
                               std::unique_ptr<event_handler> &bpf_event_handler,
                               serializer* serializer, const setting stg);

private:
};
