
#ifndef LYNCEAN_BPF_TYPES_HEADER
#define LYNCEAN_BPF_TYPES_HEADER

#include <linux/version.h>
#include <linux/bpf.h>
#include <linux/string.h>
#include <linux/limits.h>
#include <asm/ptrace.h>

#define MAX_CPU 512
#define MAX_RUNNING_THREADS 4096
#define SYSCALL_COUNT_SIZE 512;
struct __raw_tracepoint_args {
    __u64 args[0];
};

// syscall arguments structure
typedef struct 
{
    unsigned long      syscallid;
    unsigned long      arg[8]; 
    unsigned long      returncode;
}syscall_args;

typedef struct
{
    unsigned int       target_pid;
    bool               active_syscalls[SYSCALL_COUNT_SIZE];
}config_struct;

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, uint32_t);
    __type(value, config_struct);
    __uint(max_entries, 1);
} config_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_RUNNING_THREADS);
    __type(key, uint64_t);
    __type(value, syscall_args);
} syscall_args_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, uint32_t);
    __type(value, syscall_args);
    __uint(max_entries, MAX_CPU);
} syscall_args_pool SEC(".maps");

#endif
