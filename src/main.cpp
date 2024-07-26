#include <iostream>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <unistd.h>
#include <signal.h>
#include <memory>
#include "event_handler.h"
#include "argparse/argparse.hpp"
#include "bpf_helper.h"
#include <string>
#include <future>
#include <sys/wait.h>
#include <sys/ptrace.h>

using namespace std::literals;

std::unique_ptr<event_handler> bpf_event_handler;

static void handle_terminate_signal(int sig)
{
    if (bpf_event_handler)
        bpf_event_handler->stop();
}

int main(int argc, char **argv)
{
    argparse::ArgumentParser program("lyncean");

    program.add_argument("--pid")
        .default_value(0)
        .help("whcih process id to watching.")
        .action([](const std::string &value)
                {
            try 
            {
                auto tmp = std::stoi(value);
                if(tmp < 0)
                {
                    throw std::invalid_argument("");
                }
                return tmp;
            } 
            catch (const std::invalid_argument &) 
            {
                std::cerr << "Error: --pid requires an integer value greater than zero." << std::endl;
                exit(EXIT_FAILURE);
            } 
            catch (const std::out_of_range &) 
            {
                std::cerr << "Error: --pid value is out of range." << std::endl;
                exit(EXIT_FAILURE);
            } });

    program.add_argument("--command")
        .default_value(std::string(""))
        .help("The command to execute");

    program.add_argument("--params")
        .default_value(std::string(""))
        .help("Parameters for the command")
        .remaining();

    try
    {
        program.parse_args(argc, argv);
    }
    catch (const std::runtime_error &err)
    {
        std::cerr << "Error parsing arguments: " << err.what() << std::endl;
        std::cerr << program;
        return EXIT_FAILURE;
    }

    if (!program.is_used("--pid") && !program.is_used("--command"))
    {
        std::cerr << "Error: You must specify exactly one of --pid or --command." << std::endl;
        std::cerr << program;
        return EXIT_FAILURE;
    }

    int pid{};
    if (program.is_used("--pid"))
    {
        pid = program.get<int>("pid");
    }

    std::string command{};
    if (program.is_used("--command"))
    {
        command = program.get<std::string>("command");
    }

    if (!pid && command.empty())
    {
        std::cerr << "Error: You must specify exactly one of --pid or --command." << std::endl;
        std::cerr << program;
        return EXIT_FAILURE;
    }

    std::string params{};
    if (program.is_used("--params"))
    {
        params = program.get<std::string>("params");
    }

    if (pid && command.empty())
    {
        std::cout << "Your entered pid is: " << pid << '\n';
    }
    else if (pid && command.size())
    {
        std::cerr << "Warning: You entered both --pid and --command, so the code works based on --pid!\n";
        std::cout << "Your entered pid is: " << pid << '\n';
    }
    else if (command.size())
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

            // Execute the command
            char *argv[] = {"date", NULL, NULL};
            std::this_thread::sleep_for(2000ms);
            execvp(argv[0], argv);

            // If execvp fails
            perror("execvp failed");
            exit(1);
        }
        else // Parent process
        {
            // TODO
            std::optional<lynceanbpf_bpf *> skel{};
            try
            {
                skel =load_bpf_skeleton(pid) ;
                if (!skel.has_value())
                {
                    exit(EXIT_FAILURE);
                }
                bpf_event_handler = std::make_unique<event_handler>(skel.value());
                future = std::async(std::launch::async, &event_handler::start, bpf_event_handler.get());
            }
            catch (const std::exception &err)
            {
                std::cerr << err.what() << std::endl;
                std::cerr << program;
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

            if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP)
            {
                printf("Child process with PID: %d is stopped before execution.\n", pid);
            }
            else
            {
                fprintf(stderr, "Child did not stop as expected.\n");
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
            bpf_event_handler->stop();
            lynceanbpf_bpf::destroy(skel.value());

            try
            {
                future.get();
            }
            catch(const std::exception& e)
            {
                std::cerr << e.what() << '\n';
            }            

            printf("Child process finished execution.\n");
            return 0;
        }
    }

    try
    {
        auto skel{load_bpf_skeleton(program.get<int>("pid"))};
        if (!skel.has_value())
        {
            exit(EXIT_FAILURE);
        }
        bpf_event_handler = std::make_unique<event_handler>(skel.value());
        bpf_event_handler->start();
        lynceanbpf_bpf::destroy(skel.value());
    }
    catch (const std::exception &err)
    {
        std::cerr << err.what() << std::endl;
        std::cerr << program;
        std::exit(1);
    }
}
