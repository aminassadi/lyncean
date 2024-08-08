#include <iostream>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <unistd.h>
#include <signal.h>
#include <memory>
#include "event_handler.h"
#include "bpf_helper.h"
#include <string>
#include <future>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include "serializer.h"
#include "input_parser.h"

using namespace std::literals;

std::unique_ptr<event_handler> bpf_event_handler;

static void handle_terminate_signal(int sig)
{
    if (bpf_event_handler)
        bpf_event_handler->stop();
}

int main(int argc, char **argv)
{
    auto [pid, command, params] = InputParser::GetInputParameters(argc, argv);
    if (!pid)
    {
        signal(SIGINT, handle_terminate_signal);
        signal(SIGTERM, handle_terminate_signal);

        int status{};
        pid = fork();
        std::future<void> future{};

        if (pid < 0)
        {
            perror("Fork failed");
            return 1;
        }
        else if (pid == 0) // Child process
        {
            perror("Child started!\n");
            if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1)
            {
                perror("ptrace TRACEME failed");
                exit(1);
            }

            if (params.size())
            {
                char *argv[] = {command.data(), params.data(), NULL};
                execvp(argv[0], argv);
            }
            else
            {
                char *argv[] = {command.data(), NULL, NULL};
                execvp(argv[0], argv);
            }

            perror("execvp failed!!!\n");
            exit(1);
        }
        else // Parent process
        {
            std::optional<lynceanbpf_bpf *> skel{};
            try
            {
                skel = load_bpf_skeleton();
                if (!skel.has_value())
                {
                    exit(EXIT_FAILURE);
                }
                bpf_config_struct config{};
                config.target_pid = pid;
                memset(config.active, 0, SYSCALL_COUNT_SIZE);
                for (auto sys : kActiveSyscalls)
                {
                    config.active[sys] = true;
                }
                set_bpf_config(skel.value(), config);

                realastic_impl sr;
                bpf_event_handler = std::make_unique<event_handler>(skel.value(), &sr);
                future = std::async(std::launch::async, &event_handler::start, bpf_event_handler.get());
            }
            catch (const std::exception &err)
            {
                std::cerr << err.what() << std::endl;
                std::exit(1);
            }

            std::future_status futureStatus = future.wait_for(std::chrono::milliseconds(10));
            if (futureStatus == std::future_status::ready)
            {
                // int result = future.get(); // Retrieve the result
                std::cout << "Something is wrong!\n";
                exit(EXIT_FAILURE);
            }

            // Wait for the child to stop on exec
            if (waitpid(pid, &status, 0) == -1)
            {
                perror("waitpid failed");
                return 1;
            }

            // Resume the child process
            if (ptrace(PTRACE_DETACH, pid, NULL, SIGCONT) == -1)
            {
                perror("ptrace DETACH failed");
                return 1;
            }

            // Wait for the child process to complete
            if (waitpid(pid, &status, 0) == -1)
            {
                perror("waitpid failed");
                return 1;
            }
            std::this_thread::sleep_for(1s);
            bpf_event_handler->stop();
            lynceanbpf_bpf::destroy(skel.value());

            try
            {
                future.get();
            }
            catch (const std::exception &e)
            {
                std::cerr << e.what() << '\n';
            }

            printf("Child process finished execution.\n");
            return 0;
        }
    }

    try
    {
        auto skel{load_bpf_skeleton()};
        if (!skel.has_value())
        {
            exit(EXIT_FAILURE);
        }
        bpf_config_struct config{};
        config.target_pid = pid;
        memset(config.active, 0, SYSCALL_COUNT_SIZE);
        for (auto sys : kActiveSyscalls)
        {
            config.active[sys] = true;
        }
        set_bpf_config(skel.value(), config);
        realastic_impl sr;
        bpf_event_handler = std::make_unique<event_handler>(skel.value(), &sr);
        bpf_event_handler->start();
        lynceanbpf_bpf::destroy(skel.value());
    }
    catch (const std::exception &err)
    {
        std::cerr << err.what() << std::endl;
        std::exit(1);
    }
}
