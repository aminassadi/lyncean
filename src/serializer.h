#ifndef LYNCEAN_SERIALIZER_HEADER
#define LYNCEAN_SERIALIZER_HEADER
#include <string>
#include "kern/shared.h"

struct setting
{
    const int target_pid;
    const bool follow_fokrs;
};

class serializer
{
public:
    ~serializer() = default;
    virtual std::string serialize_read_event(struct_read_syscall *event) = 0;
    virtual std::string serialize_write_event(struct_write_syscall *event) = 0;
    virtual std::string serialize_open_event(struct_open_syscall *event) = 0;
    virtual std::string serialize_close_event(struct_close_syscall *event) = 0;
    virtual std::string serialize_creat_event(struct_creat_syscall *event) = 0;
     virtual std::string serialize_fork_event(struct_fork_syscall *event) = 0;
    virtual std::string serialize_clone_event(struct_clone_syscall *event) = 0;
    virtual std::string serialize_openat_event(struct_openat_syscall *event) = 0;
     virtual std::string serialize_unlink_event(struct_unlink_syscall *event) = 0;
};

class realastic_impl : public serializer
{
private:
    const setting _setting;

public:
    realastic_impl(setting stg) : _setting(stg) {};
    std::string serialize_read_event(struct_read_syscall *event) override;
    std::string serialize_write_event(struct_write_syscall *event) override;
    std::string serialize_open_event(struct_open_syscall *event) override;
    std::string serialize_close_event(struct_close_syscall *event) override;
    std::string serialize_creat_event(struct_creat_syscall *event) override;
     std::string serialize_fork_event(struct_fork_syscall *event) override;
    std::string serialize_clone_event(struct_clone_syscall *event) override;
    std::string serialize_openat_event(struct_openat_syscall *event) override;
     std::string serialize_unlink_event(struct_unlink_syscall *event) override;
};

#endif