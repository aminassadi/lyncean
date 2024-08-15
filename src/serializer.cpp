#include "serializer.h"
#include <sstream>
#include <string.h>

static constexpr size_t kMaximumOutputBufferSize{32};

std::string escape_special_character(const std::string &input)
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
        buff = escape_special_character(std::string(event->buff, event->buff + event->rc));
        buff += "\"";
    }
    else
    {
        buff = escape_special_character(std::string(event->buff, event->buff + kMaximumOutputBufferSize));
        buff += "\"...";
    }
    std::stringstream ss;
    if (_setting.follow_fokrs)
    {
        if (event->pid != _setting.target_pid)
        {
            ss << "[pid=" << event->pid << "] ";
        }
    }
    ss << "read(" << event->fd << ", \"" << buff << ", " << event->count;
    ss << ") = " << event->rc;
    return ss.str();
}

std::string realastic_impl::serialize_write_event(struct_write_syscall *event)
{
    std::string buff;
    if (event->rc < kMaximumOutputBufferSize)
    {
        buff = escape_special_character(std::string(event->buff, event->buff + event->rc));
        buff += "\"";
    }
    else
    {
        buff = escape_special_character(std::string(event->buff, event->buff + kMaximumOutputBufferSize));
        buff += "\"...";
    }
    std::stringstream ss;
    if (_setting.follow_fokrs)
    {
        if (event->pid != _setting.target_pid)
        {
            ss << "[pid=" << event->pid << "] ";
        }
    }
    ss << "write(" << event->fd << ", \"" << buff << ", " << event->count;
    ss << ") = " << event->rc;
    return ss.str();
}

std::string realastic_impl::serialize_open_event(struct_open_syscall *event)
{
    std::stringstream ss;
    if (_setting.follow_fokrs)
    {
        if (event->pid != _setting.target_pid)
        {
            ss << "[pid=" << event->pid << "] ";
        }
    }
    ss << "open(" << event->rc << ", \"" << event->pathname << ", ";
    ss << ") = " << event->rc;
    return ss.str();
}

std::string realastic_impl::serialize_creat_event(struct_creat_syscall *event)
{
    std::stringstream ss;
    if (_setting.follow_fokrs)
    {
        if (event->pid != _setting.target_pid)
        {
            ss << "[pid=" << event->pid << "] ";
        }
    }
    ss << "creat(" << event->pathname;
    ss << ") = " << event->rc;
    return ss.str();
}

std::string realastic_impl::serialize_close_event(struct_close_syscall *event)
{
    std::stringstream ss;
    if (_setting.follow_fokrs)
    {
        if (event->pid != _setting.target_pid)
        {
            ss << "[pid=" << event->pid << "] ";
        }
    }
    ss << "close(" << event->fd << ") = " << event->rc;
    return ss.str();
}


std::string realastic_impl::serialize_unlinkat_event(struct_unlinkat_syscall *event)
{
    std::stringstream ss;
    if (_setting.follow_fokrs)
    {
        if (event->pid != _setting.target_pid)
        {
            ss << "[pid=" << event->pid << "] ";
        }
    }
    ss << "unlinkat(" << event->dirfd << ", " << event->pathname << ", ";
    ss << event->flag << ") = " << event->rc;
    return ss.str();
}


std::string realastic_impl::serialize_openat_event(struct_openat_syscall *event)
{
    std::stringstream ss;
    if (_setting.follow_fokrs)
    {
        if (event->pid != _setting.target_pid)
        {
            ss << "[pid=" << event->pid << "] ";
        }
    }
    ss << "openat(" << event->dirfd << ", " << event->pathname << ", ";
    ss << event->flag << ", " << event->mode << ") = " << event->rc;
    return ss.str();
}


std::string realastic_impl::serialize_unlink_event(struct_unlink_syscall *event)
{
    std::stringstream ss;
    if (_setting.follow_fokrs)
    {
        if (event->pid != _setting.target_pid)
        {
            ss << "[pid=" << event->pid << "] ";
        }
    }
    ss << "unlink(" << event->pathname << ") = ";
    ss <<  event->rc;
    return ss.str();
}


std::string realastic_impl::serialize_fork_event(struct_fork_syscall *event)
{
    std::stringstream ss;
    if (_setting.follow_fokrs)
    {
        if (event->pid != _setting.target_pid)
        {
            ss << "[pid=" << event->pid << "] ";
        }
    }
    ss << "fork() = " << event->rc;
    return ss.str();
}

std::string realastic_impl::serialize_clone_event(struct_clone_syscall *event)
{
    std::stringstream ss;
    if (_setting.follow_fokrs)
    {
        if (event->pid != _setting.target_pid)
        {
            ss << "[pid=" << event->pid << "] ";
        }
    }
    ss << "clone(...," << " flags=" << event->flags << ", ...) = " << event->rc;
    return ss.str();
}
