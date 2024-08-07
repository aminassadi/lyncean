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
    read_struct = bpf_map_lookup_elem(&event_pool, &cpu);
    if (!read_struct)
    {
        BPF_PRINTK("ERROR, lookup from read_struct_pool failed\n");
        goto out;
    }
    void *ptr_start = (void *)read_struct;
    void *ptr_end = (void *)read_struct->buff;
    read_struct->fd = args->arg[0];
    read_struct->syscallid = args->syscallid;
    read_struct->count = args->arg[2];
    if (bpf_probe_read(&read_struct->rc, sizeof(int64_t), (void *)&PT_REGS_RC((struct pt_regs *)ctx->args[0])) != 0)
    {
        BPF_PRINTK("ERROR, failed to get return code\n");
    }
    u32 size = read_struct->rc;
    asm volatile("%[size] &= 16383\n"
                 : [size] "+&r"(size));
    if (bpf_probe_read(read_struct->buff, size, (void *)args->arg[1]) == 0)
    {
        ptr_end += size;
    }
    else
    {
        BPF_PRINTK("ERROR, tail_raw_syscall_read_exit, bpd_probe_read failed.\n");
    }
    __u64 len = ptr_end - ptr_start;
    int ret = bpf_perf_event_output(ctx, &perf_buff, BPF_F_CURRENT_CPU, ptr_start, len < MAX_EVENT_SIZE ? len : 0);
    if (ret != 0)
    {
        BPF_PRINTK("ERROR, output to perf buffer, code:%ld, syscallid:%d", ret, args->syscallid);
    }
out:
    bpf_map_delete_elem(&syscall_args_map, &pidtid);
    return 0;
}

SEC("lyncean/raw_syscalls/write_exit")
int tail_raw_syscall_write_exit(struct __raw_tracepoint_args *ctx)
{
    uint64_t pidtid = bpf_get_current_pid_tgid();
    syscall_args *args = NULL;
    args = bpf_map_lookup_elem(&syscall_args_map, &pidtid);
    if (!args)
    {
        return 0;
    }
    uint32_t cpu = bpf_get_smp_processor_id();
    struct_write_syscall *write_struct = NULL;
    write_struct = bpf_map_lookup_elem(&event_pool, &cpu);
    if (!write_struct)
    {
        BPF_PRINTK("ERROR, lookup from write_struct_pool failed\n");
        goto out;
    }
    void *ptr_start = (void *)write_struct;
    void *ptr_end = (void *)write_struct->buff;
    write_struct->fd = args->arg[0];
    write_struct->syscallid = args->syscallid;
    write_struct->count = args->arg[2];
    if (bpf_probe_read(&write_struct->rc, sizeof(int64_t), (void *)&PT_REGS_RC((struct pt_regs *)ctx->args[0])) != 0)
    {
        BPF_PRINTK("ERROR, failed to get return code\n");
    }

    u32 size = write_struct->rc;
    asm volatile("%[size] &= 16383\n"
                 : [size] "+&r"(size));
    if (bpf_probe_read(write_struct->buff, size, (void *)args->arg[1]) == 0)
    {
        ptr_end += size;
    }
    else
    {
        BPF_PRINTK("ERROR, tail_raw_syscall_write_exit, bpd_probe_read failed.\n");
    }
    __u64 len = ptr_end - ptr_start;
    int ret = bpf_perf_event_output(ctx, &perf_buff, BPF_F_CURRENT_CPU, ptr_start, len < MAX_EVENT_SIZE ? len : 0);
    if (ret != 0)
    {
        BPF_PRINTK("ERROR, output to perf buffer, code:%ld, syscallid:%d", ret, args->syscallid);
    }
out:
    bpf_map_delete_elem(&syscall_args_map, &pidtid);
    return 0;
}

SEC("lyncean/raw_syscalls/open_exit")
int tail_raw_syscall_open_exit(struct __raw_tracepoint_args *ctx)
{
    uint64_t pidtid = bpf_get_current_pid_tgid();
    syscall_args *args = NULL;
    args = bpf_map_lookup_elem(&syscall_args_map, &pidtid);
    if (!args)
    {
        return 0;
    }
    uint32_t cpu = bpf_get_smp_processor_id();
    struct_open_syscall *open_struct = NULL;
    open_struct = bpf_map_lookup_elem(&event_pool, &cpu);
    if (!open_struct)
    {
        BPF_PRINTK("ERROR, lookup from open_struct_pool failed\n");
        goto out;
    }
    void *ptr_start = (void *)open_struct;
    void *ptr_end = (void *)open_struct->pathname;
    open_struct->syscallid = args->syscallid;
    open_struct->flag = args->arg[1];
    open_struct->mode = args->arg[2];
    if (bpf_probe_read(&open_struct->rc, sizeof(int), (void *)&PT_REGS_RC((struct pt_regs *)ctx->args[0])) != 0)
    {
        BPF_PRINTK("ERROR, failed to get return code\n");
    }
    long size = bpf_probe_read_str(open_struct->pathname, MAX_PATH, (void *)args->arg[0]);
    if (size > 0)
    {
        ptr_end += size;
    }
    else
    {
        BPF_PRINTK("ERROR, tail_raw_syscall_open_exit, bpd_probe_open failed.\n");
    }
    __u64 len = ptr_end - ptr_start;
    int ret = bpf_perf_event_output(ctx, &perf_buff, BPF_F_CURRENT_CPU, ptr_start, len < MAX_EVENT_SIZE ? len : 0);
    if (ret != 0)
    {
        BPF_PRINTK("ERROR, output to perf buffer, code:%ld, syscallid:%d", ret, args->syscallid);
    }
out:
    bpf_map_delete_elem(&syscall_args_map, &pidtid);
    return 0;
}

SEC("lyncean/raw_syscalls/close_exit")
int tail_raw_syscall_close_exit(struct __raw_tracepoint_args *ctx)
{
    uint64_t pidtid = bpf_get_current_pid_tgid();
    syscall_args *args = NULL;
    args = bpf_map_lookup_elem(&syscall_args_map, &pidtid);
    if (!args)
    {
        return 0;
    }
    uint32_t cpu = bpf_get_smp_processor_id();
    struct_close_syscall *close_struct = NULL;
    close_struct = bpf_map_lookup_elem(&event_pool, &cpu);
    if (!close_struct)
    {
        BPF_PRINTK("ERROR, lookup from open_struct_pool failed\n");
        goto out;
    }
    close_struct->syscallid = args->syscallid;
    close_struct->fd = args->arg[0];
    if (bpf_probe_read(&close_struct->rc, sizeof(int), (void *)&PT_REGS_RC((struct pt_regs *)ctx->args[0])) != 0)
    {
        BPF_PRINTK("ERROR, failed to get return code\n");
    }
    int ret = bpf_perf_event_output(ctx, &perf_buff, BPF_F_CURRENT_CPU, close_struct, sizeof(struct_close_syscall));
    if (ret != 0)
    {
        BPF_PRINTK("ERROR, output to perf buffer, code:%ld, syscallid:%d", ret, args->syscallid);
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
    bool *target_pid_active_token = NULL;
    target_pid_active_token = bpf_map_lookup_elem(&target_tasks_map, &pid);
    if (!target_pid_active_token)
        return 0;
    if (config->active[syscallid & (SYSCALL_COUNT_SIZE - 1)] && *target_pid_active_token)
    {
        BPF_PRINTK("new syscall\n");
        syscall_args *args = NULL;
        args = bpf_map_lookup_elem(&syscall_args_pool, &cpu);
        if (!args)
        {
            BPF_PRINTK("ERROR, cannot retrieve from args pool\n");
            return 0;
        }
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
