
#ifndef LYNCEAN_BPF_TYPES_HEADER
#define LYNCEAN_BPF_TYPES_HEADER

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "shared.h"
#define MAX_CPU 512
#define MAX_RUNNING_THREADS 4096

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

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(uint32_t));
    __uint(max_entries, 100*1024);
} perf_buff SEC(".maps");

#endif
