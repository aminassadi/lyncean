#include "serializer.h"
#include <sstream>


std::string realastic_impl::serialize_read_event(struct_read_syscall *event)
{
    std::string buff(event->buff, event->buff + event->rc);
    std::stringstream ss;
    ss << "read(" << event->fd << ", \"" << buff << '\"' << ',' << event->fd;
    ss << ")->" << event->rc;
    return ss.str();
}