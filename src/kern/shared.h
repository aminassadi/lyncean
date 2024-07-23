


#define SYSCALL_COUNT_SIZE 512

typedef struct
{
    unsigned int       target_pid;
    bool               active[SYSCALL_COUNT_SIZE];
}config_struct;