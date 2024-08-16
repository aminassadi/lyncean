#ifndef LYNCEAN_BPF_SHARED_HEADER
#define LYNCEAN_BPF_SHARED_HEADER

#define SYSCALL_COUNT_SIZE 512
#define MAX_DATA_WR_RD 16384
#define MAX_PATH 4096
#define MAX_ARGS 16384

typedef struct
{
    bool active[SYSCALL_COUNT_SIZE];
    bool follow_childs;
} bpf_config_struct;

typedef struct
{
    unsigned long syscallid;
    int pid;
} __attribute__((aligned(8))) event_header;

typedef struct
{
    event_header header;
    int fd;
    unsigned long count;
    unsigned long rc;
    char buff[MAX_DATA_WR_RD];
} __attribute__((aligned(8))) struct_read_syscall;

typedef struct
{
    event_header header;
    int flag; // except creat syscall where the flags equal to O_CREAT|O_WRONLY|O_TRUNC
    mode_t mode;
    int rc;
    char pathname[MAX_PATH];
} __attribute__((aligned(8))) struct_open_syscall;

typedef struct
{
    event_header header;
    int dirfd;
    int flag;
    mode_t mode;
    int rc;
    char pathname[MAX_PATH];
} __attribute__((aligned(8))) struct_openat_syscall;

typedef struct_open_syscall struct_creat_syscall;

typedef struct
{
    event_header header;
    int fd;
    unsigned long count;
    unsigned long rc;
    char buff[MAX_DATA_WR_RD];
} __attribute__((aligned(8))) struct_write_syscall;

typedef struct
{
    event_header header;
    int fd;
    unsigned long rc;
} __attribute__((aligned(8))) struct_close_syscall;

typedef struct
{
    event_header header;
    int rc;
} __attribute__((aligned(8))) struct_fork_syscall;

typedef struct
{
    event_header header;
    unsigned long flags;
    unsigned long rc;
} __attribute__((aligned(8))) struct_clone_syscall;

typedef struct
{
    event_header header;
    int rc;
    char pathname[MAX_PATH];
} __attribute__((aligned(8))) struct_unlink_syscall;

typedef struct
{
    event_header header;
    int rc;
    int dirfd;
    int flag;
    char pathname[MAX_PATH];
} __attribute__((aligned(8))) struct_unlinkat_syscall;

#endif
