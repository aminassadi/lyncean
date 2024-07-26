#ifndef LYNCEAN_BPF_SHARED_HEADER
#define LYNCEAN_BPF_SHARED_HEADER

#define SYSCALL_COUNT_SIZE 512
#define MAX_DATA_WR_RD 16384
typedef struct
{
    unsigned int target_pid;
    bool active[SYSCALL_COUNT_SIZE];
} bpf_config_struct;

typedef struct
{
    unsigned long syscallid;
    int fd;
    unsigned long count;
    unsigned long rc;
    char buff[MAX_DATA_WR_RD];
} __attribute__((aligned(8))) struct_read_syscall;

#endif
