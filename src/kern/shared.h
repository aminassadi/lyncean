#ifndef LYNCEAN_BPF_SHARED_HEADER
#define LYNCEAN_BPF_SHARED_HEADER

#define SYSCALL_COUNT_SIZE 512
#define MAX_DATA_WR_RD 16384
#define MAX_PATH 4096

typedef struct
{
    bool active[SYSCALL_COUNT_SIZE];
    bool follow_childs;
} bpf_config_struct;

typedef struct
{
    unsigned long syscallid;
    int fd;
    unsigned long count;
    unsigned long rc;
    char buff[MAX_DATA_WR_RD];
} __attribute__((aligned(8))) struct_read_syscall;

typedef struct 
{
    unsigned long syscallid;
    int flag; //except creat syscall where the flags equal to O_CREAT|O_WRONLY|O_TRUNC
    mode_t mode;
    int rc;
    char pathname[MAX_PATH];
} __attribute__((aligned(8))) struct_open_syscall;

typedef struct 
{
    unsigned long syscallid;
    int fd;
    unsigned long count;
    unsigned long rc;
    char buff[MAX_DATA_WR_RD];    
} __attribute__((aligned(8))) struct_write_syscall;

typedef struct
{
    unsigned long syscallid;
    int fd;
    unsigned long rc;
}__attribute__((aligned(8))) struct_close_syscall;


#endif
