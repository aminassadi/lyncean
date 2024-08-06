#include "serializer.h"
#include <sstream>

static constexpr size_t kMaximumOutputBufferSize{32};

std::string escape_special_charachter(const std::string &input)
{
    std::string result;
    for (char c : input)
    {
        switch (c)
        {
        case '\t':
            result += ("\\t");
            break;
        case '\n':
            result += ("\\n");
            break;
        case '\v':
            result += ("\\v");
            break;
        case '\f':
            result += ("\\f");
            break;
        case '\r':
            result += ("\\r");
            break;
        case '\e':
            result += ("\\e"); // equal to '\u001B'
            break;
        default:
            result.push_back(c);
        }
    }
    return result;
}

std::string realastic_impl::serialize_read_event(struct_read_syscall *event)
{
    std::string buff;
    if (event->rc < kMaximumOutputBufferSize)
    {
        buff = std::move(escape_special_charachter(std::string(event->buff, event->buff + event->rc)));
        buff += "\"";
    }
    else
    {
        buff = std::move(escape_special_charachter(std::string(event->buff, event->buff + kMaximumOutputBufferSize)));
        buff += "\"...";
    }
    std::stringstream ss;
    ss << "read(" << event->fd << ", \"" << buff << ", " << event->count;
    ss << ") = " << event->rc;
    return ss.str();
}

std::string realastic_impl::serialize_write_event(struct_write_syscall *event)
{
    std::string buff;
    if (event->rc < kMaximumOutputBufferSize)
    {
        buff = std::move(escape_special_charachter(std::string(event->buff, event->buff + event->rc)));
        buff += "\"";
    }
    else
    {
        buff = std::move(escape_special_charachter(std::string(event->buff, event->buff + kMaximumOutputBufferSize)));
        buff += "\"...";
    }
    std::stringstream ss;
    ss << "write(" << event->fd << ", \"" << buff << ", " << event->count;
    ss << ") = " << event->rc;
    return ss.str();
}

std::string realastic_impl::serialize_open_event(struct_open_syscall *event)
{
    std::string buff;
    if (event->rc > 0)
    {
        buff = std::move(escape_special_charachter(std::string(event->pathname)));
        buff += "\"";
    }

    std::stringstream ss;
    ss << "open(" << event->rc << ", \"" << buff << ", ";
    ss << ") = " << event->rc;
    return ss.str();
}

std::string realastic_impl::serialize_close_event(struct_close_syscall *event)
{
    std::stringstream ss;
    ss << "close(" << event->fd << ") = " << event->rc;
    return ss.str();
}
