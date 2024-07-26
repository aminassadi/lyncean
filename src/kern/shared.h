#ifndef LYNCEAN_BPF_SHARED_HEADER
#define LYNCEAN_BPF_SHARED_HEADER

#define SYSCALL_COUNT_SIZE 512
#define MAX_DATA_WR_RD 16384
typedef struct
{
    unsigned int       target_pid;
    bool               active[SYSCALL_COUNT_SIZE];
}config_struct;

typedef struct
{
    unsigned long syscallid;
    int fd;
    char buff[MAX_DATA_WR_RD];
    unsigned long count;
    unsigned long rc;
}struct_read_syscall;
#endif
