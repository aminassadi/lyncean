#include "types.h"
#include "common.h"


SEC("lyncean/raw_syscalls/read_exit")
int generic_raw_syscall_read_exit(struct __raw_tracepoint_args* ctx)
{
    uint64_t pidtid = bpf_get_current_pid_tgid();
    syscall_args* args = NULL;
    args = bpf_map_lookup_elem(&syscall_args_map, &pidtid);
    if(!args)
    {
        return 0;
    }
    int ret = bpf_perf_event_output(ctx, &perf_buff, BPF_F_CURRENT_CPU, &args->syscallid, sizeof(unsigned long));
    if(ret != 0)
    {
        BPF_PRINTK("ERROR, output to perf buffer, code: %ld", ret);   
    }
    return 0;
}

__attribute__((always_inline))
static inline bool set_args(unsigned long *arg, const struct pt_regs *regs)
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

SEC("raw_tracepoint/sys_enter")
int generic_raw_sys_enter(struct __raw_tracepoint_args *ctx)
{
    uint64_t pidtid = bpf_get_current_pid_tgid();
    uint32_t cpu = bpf_get_smp_processor_id();
    uint32_t syscallid = ctx->args[1];
    config_struct* config = NULL;
    int config_key = 0;
    config = bpf_map_lookup_elem(&config_map, &config_key);
    if(!config)
    {
        BPF_PRINTK("ERROR, lookup from config map failed\n");
        return 0;
    }
    uint32_t pid = pidtid >> 32;
    if(config->active[syscallid & (SYSCALL_COUNT_SIZE-1)] && config->target_pid == pid)
    {
        syscall_args* args = NULL;
        args = bpf_map_lookup_elem(&syscall_args_pool, &cpu);
        if (!args) {
            BPF_PRINTK("ERROR, cannot retrieve from args pool\n");
            return 0;
        }
        memset(args, 0, sizeof(syscall_args));
        args->syscallid = syscallid;
        const struct pt_regs *regs = (const struct pt_regs *)ctx->args[0];
        if (!set_args(args->arg, regs))
        {
            BPF_PRINTK("ERROR, setting syscall args failed\n");
            return 0;
        }
        if (bpf_map_update_elem(&syscall_args_map, &pidtid, args, BPF_ANY) != 0)
        {
            BPF_PRINTK("ERROR, failed to update args map\n");   
        }
    }    
    return 0;
}

SEC("raw_tracepoint/sys_exit")
int generic_raw_sys_exit(struct __raw_tracepoint_args *ctx)
{  
    bpf_tail_call(ctx, &prog_array_init, ctx->args[1]);
    return 0;
}


char LICENSE[] SEC("license") = "Dual BSD/GPL";


