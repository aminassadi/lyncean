#include "main_operation.h"

void MainOperaion::run_sync_task(std::optional<lynceanbpf_bpf *> &skel,
                            std::unique_ptr<event_handler> &bpf_event_handler,
                            realastic_impl &serializer, int pid)
{
    try
    {
        MainOperaion::initialize(skel, pid);
        bpf_event_handler = std::move(std::make_unique<event_handler>(skel.value(), &serializer));
        bpf_event_handler->start();
        lynceanbpf_bpf::destroy(skel.value());
    }
    catch (const std::exception &err)
    {
        std::cerr << err.what() << std::endl;
        std::exit(1);
    }
}

void MainOperaion::run_async_task(std::optional<lynceanbpf_bpf *> &skel,
                             std::unique_ptr<event_handler> &bpf_event_handler,
                             realastic_impl &serializer, int pid)
{
    std::future<void> future{};

    try
    {
        MainOperaion::initialize(skel, pid);
        bpf_event_handler = std::move(std::make_unique<event_handler>(skel.value(), &serializer));
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
        std::cout << "Something is wrong!\n";
        std::exit(1);
    }

    // Wait for the child to stop on exec
    int status{};
    if (waitpid(pid, &status, 0) == -1)
    {
        perror("waitpid failed");
        std::exit(1);
    }

    // Resume the child process
    if (ptrace(PTRACE_DETACH, pid, NULL, SIGCONT) == -1)
    {
        perror("ptrace DETACH failed");
        std::exit(1);
    }

    // Wait for the child process to complete
    if (waitpid(pid, &status, 0) == -1)
    {
        perror("waitpid failed");
        std::exit(1);
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
}

void MainOperaion::child_operaion(std::string &command, std::vector<std::string> &params)
{
    perror("Child started!\n");
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1)
    {
        perror("ptrace TRACEME failed");
        exit(1);
    }

    if (params.size())
    {
        std::vector<char *> argv;
        argv.push_back(command.data());
        for (auto &arg : params)
        {
            argv.push_back(&arg[0]);
        }
        argv.push_back(NULL);
        execvp(argv[0], argv.data());
    }
    else
    {
        char *argv[] = {command.data(), NULL, NULL};
        execvp(argv[0], argv);
    }

    perror("execvp failed!!!\n");
    exit(1);
}

void MainOperaion::initialize(std::optional<lynceanbpf_bpf *> &skel, int pid)
{
    skel = load_bpf_skeleton();
    if (!skel.has_value())
    {
        std::exit(1);
    }
    bpf_config_struct config{};
    config.target_pid = pid;
    memset(config.active, 0, SYSCALL_COUNT_SIZE);
    for (auto sys : kActiveSyscalls)
    {
        config.active[sys] = true;
    }
    set_bpf_config(skel.value(), config);
}
