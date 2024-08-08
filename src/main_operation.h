#pragma once
#include "pch.h"
#include <sys/wait.h>
#include <sys/ptrace.h>
#include "event_handler.h"
#include "bpf_helper.h"

class MainOperaion
{
public:
    static void Initialize(std::optional<lynceanbpf_bpf *> &skel, int pid);
    static void ChildOperaion(std::string &command, std::vector<std::string> &params);
    static void SyncTask(std::optional<lynceanbpf_bpf *> &skel,
                         std::unique_ptr<event_handler> &bpf_event_handler,
                         realastic_impl &serializer, int pid);
    static void AsyncTask(std::optional<lynceanbpf_bpf *> &skel,
                          std::unique_ptr<event_handler> &bpf_event_handler,
                          realastic_impl &serializer, int pid);

private:
};
