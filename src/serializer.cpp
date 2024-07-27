#include "serializer.h"
#include <sstream>

static constexpr size_t kMaximumOutputBufferSize{24};

std::string escapeControlCharacters(const std::string &input)
{
    std::string result;
    for (char c : input)
    {
        // Check if the character is a control character
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
        buff = std::move(escapeControlCharacters(std::string(event->buff, event->buff + event->rc)));
        buff += "\"";
    }
    else
    {
        buff = std::move(escapeControlCharacters(std::string(event->buff, event->buff + kMaximumOutputBufferSize)));
        buff += "\"...";
    }
    std::stringstream ss;
    ss << "read(" << event->fd << ", \"" << buff << ',' << event->count;
    ss << ") = " << event->rc;
    return ss.str();
}

std::string realastic_impl::serialize_write_event(struct_write_syscall *event)
{
    std::string buff;
    if (event->rc < kMaximumOutputBufferSize)
    {
        buff = std::move(escapeControlCharacters(std::string(event->buff, event->buff + event->rc)));
        buff += "\"";
    }
    else
    {
        buff = std::move(escapeControlCharacters(std::string(event->buff, event->buff + kMaximumOutputBufferSize)));
        buff += "\"...";
    }
    std::stringstream ss;
    ss << "write(" << event->fd << ", \"" << buff << ',' << event->count;
    ss << ") = " << event->rc;
    return ss.str();
}
