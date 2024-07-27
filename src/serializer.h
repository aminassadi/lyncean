#ifndef LYNCEAN_SERIALIZER_HEADER
#define LYNCEAN_SERIALIZER_HEADER
#include <string>
#include "kern/shared.h"
class serializer
{
public:
    virtual std::string serialize_read_event(struct_read_syscall *event) = 0;
};

class realastic_impl : public serializer
{
public:
    std::string serialize_read_event(struct_read_syscall *event) override;
};

#endif