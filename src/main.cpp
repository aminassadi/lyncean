#include <iostream>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <unistd.h>
#include <signal.h>
#include <memory>
#include "event_handler.h"
#include "argparse/argparse.hpp"
#include "bpf_helper.h"

std::unique_ptr<event_handler> bpf_event_hadnler;

static void handle_terminate_signal(int sig)
{
    if (bpf_event_hadnler)
        bpf_event_hadnler->stop();
}

int main(int argc, char **argv)
{
    argparse::ArgumentParser program("lyncean");
    program.add_argument("--pid")
        .required()
        .help("whcih process id to watching.")
        .scan<'i', int>();

    try
    {
        program.parse_args(argc, argv);
        signal(SIGINT, handle_terminate_signal);
        signal(SIGTERM, handle_terminate_signal);
        auto skel{load_bpf_skeleton(program.get<int>("pid"))};
        if (!skel.has_value())
        {
            exit(EXIT_FAILURE);
        }
        bpf_event_hadnler = std::make_unique<event_handler>(skel.value());
        bpf_event_hadnler->start();
        lynceanbpf_bpf::destroy(skel.value());
    }
    catch (const std::exception &err)
    {
        std::cerr << err.what() << std::endl;
        std::cerr << program;
        std::exit(1);
    }

    // todo: spawn a child process
}
