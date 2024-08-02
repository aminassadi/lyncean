#ifndef LYNCEAN_BPF_COMMON_HEADER
#define LYNCEAN_BPF_COMMON_HEADER
#include "types.h"

#define BPF_PRINTK(format, ...) \
    char fmt[] = format;        \
    bpf_trace_printk(fmt, sizeof(fmt), ##__VA_ARGS__);

#define PT_REGS_ORIG_AX(x) ((x)->orig_ax)

__attribute__((always_inline)) static inline bool set_args(unsigned long *arg, const struct pt_regs *regs)
{
    int ret = 0;
    ret |= bpf_probe_read(&arg[0], sizeof(arg[0]), &regs->di);
    ret |= bpf_probe_read(&arg[1], sizeof(arg[1]), &regs->si);
    ret |= bpf_probe_read(&arg[2], sizeof(arg[2]), &regs->dx);
    ret |= bpf_probe_read(&arg[3], sizeof(arg[3]), &regs->r10);
    ret |= bpf_probe_read(&arg[4], sizeof(arg[4]), &regs->r8);
    ret |= bpf_probe_read(&arg[5], sizeof(arg[5]), &regs->r9);
    if (!ret)
        return true;
    else
        return false;
}
#endif
