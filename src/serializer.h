#ifndef LYNCEAN_SERIALIZER_HEADER
#define LYNCEAN_SERIALIZER_HEADER
#include <string>
#include "kern/shared.h"
class serializer
{
public:
    virtual std::string serialize_read_event(struct_read_syscall *event) = 0;
    virtual std::string serialize_write_event(struct_write_syscall *event) = 0;
    virtual std::string serialize_open_event(struct_open_syscall *event) = 0;
    virtual std::string serialize_close_event(struct_close_syscall *event) = 0;
};

class realastic_impl : public serializer
{
public:
    std::string serialize_read_event(struct_read_syscall *event) override;
    std::string serialize_write_event(struct_write_syscall *event) override;
    std::string serialize_open_event(struct_open_syscall *event) override;
    std::string serialize_close_event(struct_close_syscall *event) override;
};

#endif