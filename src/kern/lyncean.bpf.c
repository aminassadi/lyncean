#include "types.h"
#include "common.h"

SEC("lyncean/raw_syscalls/read_exit")
int tail_raw_syscall_read_exit(struct __raw_tracepoint_args *ctx)
{
    uint64_t pidtid = bpf_get_current_pid_tgid();
    syscall_args *args = NULL;
    args = bpf_map_lookup_elem(&syscall_args_map, &pidtid);
    if (!args)
    {
        return 0;
    }
    uint32_t cpu = bpf_get_smp_processor_id();
    struct_read_syscall *read_struct = NULL;
    read_struct = bpf_map_lookup_elem(&read_struct_pool, &cpu);
    if (!read_struct)
    {
        BPF_PRINTK("ERROR, lookup from read_struct_pool failed\n");
        goto out;
    }
    memset(read_struct, 0, sizeof(read_struct));
    read_struct->syscallid = args->syscallid;
    read_struct->count = args->arg[2];
    if (bpf_probe_read(&read_struct->rc, sizeof(int64_t), (void *)&PT_REGS_RC((struct pt_regs *)ctx->args[0])) != 0)
    {
        BPF_PRINTK("ERROR, failed to get return code\n");
    }

    u32 size = read_struct->rc;
    asm volatile("%[size] &= 16383\n"
                 : [size] "+&r"(size));
    if (bpf_probe_read(read_struct->buff, size, (void *)args->arg[1]) != 0)
    {
        BPF_PRINTK("ERROR, tail_raw_syscall_read_exit, bpd_probe_read failed.\n");
    }
    int ret = bpf_perf_event_output(ctx, &perf_buff, BPF_F_CURRENT_CPU, read_struct, sizeof(struct_read_syscall));
    if (ret != 0)
    {
        BPF_PRINTK("ERROR, output to perf buffer, code: %ld", ret);
    }
out:
    bpf_map_delete_elem(&syscall_args_map, &pidtid);
    return 0;
}

SEC("raw_tracepoint/sys_enter")
int generic_raw_sys_enter(struct __raw_tracepoint_args *ctx)
{
    uint64_t pidtid = bpf_get_current_pid_tgid();
    uint32_t cpu = bpf_get_smp_processor_id();
    uint32_t syscallid = ctx->args[1];
    bpf_config_struct *config = NULL;
    int config_key = 0;
    config = bpf_map_lookup_elem(&config_map, &config_key);
    if (!config)
    {
        BPF_PRINTK("ERROR, lookup from config map failed\n");
        return 0;
    }
    uint32_t pid = pidtid >> 32;
    if (config->active[syscallid & (SYSCALL_COUNT_SIZE - 1)] && config->target_pid == pid)
    {
        syscall_args *args = NULL;
        args = bpf_map_lookup_elem(&syscall_args_pool, &cpu);
        if (!args)
        {
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
    struct pt_regs *regs = (struct pt_regs *)(ctx->args[0]);
    unsigned long syscallid;
    if (bpf_probe_read(&syscallid, sizeof(int64_t), &regs->orig_ax) != 0)
    {
        BPF_PRINTK("ERROR, failed to get syscall id \n");
    }
    bpf_tail_call(ctx, &prog_array_tailcalls, syscallid);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
