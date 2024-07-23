#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <stdint.h>
#include "vmlinux.h"
#include "types.h"

SEC("raw_tracepoint/sys_enter")
int genericRawEnter(struct __raw_tracepoint_args *ctx)
{
    uint64_t pidtid = bpf_get_current_pid_tgid();
    uint32_t cpu = bpf_get_smp_processor_id();
    uint32_t syscallid = ctx->args[1];
    config_struct* config = NULL;
    config = bpf_map_lookup_elem(&config_map, 0);
    if(!config)
    {
        //todo: ERROR handling
        return 0;
    }
    uint32_t pid = pidtid >> 32;
    if(config->active_syscalls[syscallid] && config->target_pid == pid)
    {
        syscall_args* args = NULL;
        args = bpf_map_lookup_elem(&syscall_args_pool, &cpu);
        if (!args) {
            //todo: ERROR handling
            return 0;
        }
        args->syscallid = syscallid;
        const void *task = NULL;
    }    
    return 0;
}




