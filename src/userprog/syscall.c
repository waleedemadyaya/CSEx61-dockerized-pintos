#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

#include "lib/stdio.h"
#include "lib/kernel/stdio.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "devices/shutdown.h"
#include "devices/input.h"

#define USER_ASSERT(CONDITION) \
    if (CONDITION) {}          \
    else {exit(-1);}   


static struct open_file
{
    int fd;
    struct file *file;
    struct list_elem elem;
};

static void syscall_handler (struct intr_frame *);

static bool is_valid_ptr(const void *ptr);
static bool is_user_mem(const void *start, size_t size); // check if it is a valid virtual user memory
static bool is_valid_str(const char *str);
static struct open_file *get_file_by_fd(const int fd); // search for the file by fd in the file list of a process

static void halt(void) NO_RETURN;
static void exit(int status) NO_RETURN;
static pid_t exec(const char *file);
static int wait(pid_t);
static bool create(const char *file, unsigned initial_size);
static bool remove(const char *file);
static int open(const char *file);
static int filesize(int fd);
static int read(int fd, void *buffer, unsigned length);
static int write(int fd, const void *buffer, unsigned length);
static void seek(int fd, unsigned position);
static unsigned tell(int fd);
static void close(int fd);


static struct lock file_lock; // semaphore to protect  files 

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  // initialize the lock
  lock_init(&file_lock);
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  //printf ("system call!\n");
  // Get  the system call number from the interrupt frame 
  void *args[4];
    for (size_t i = 0; i != 4; ++i)
        args[i] = f->esp + i * sizeof(void *); // take arguments from the stack 

    int syscall_num = *(int *)args[0];

   /* Check validation. */
    switch (syscall_num)
    {
    case SYS_READ:
    case SYS_WRITE:
        USER_ASSERT(is_user_mem(args[3], sizeof(void *)));
    case SYS_CREATE:
    case SYS_SEEK:
        USER_ASSERT(is_user_mem(args[2], sizeof(void *)));
    case SYS_EXIT:
    case SYS_EXEC:
    case SYS_WAIT:
    case SYS_REMOVE:
    case SYS_OPEN:
    case SYS_FILESIZE:
    case SYS_TELL:
    case SYS_CLOSE:
        USER_ASSERT(is_user_mem(args[1], sizeof(void *)));
    case SYS_HALT:
        break;
    default:
        NOT_REACHED();
    }

  switch (syscall_num)
    {
    case SYS_HALT:
        halt();
        NOT_REACHED();
    case SYS_EXIT:
        exit(*(int *)args[1]);
        NOT_REACHED();
    case SYS_EXEC:
        f->eax = exec(*(const char **)args[1]);
        break;
    case SYS_WAIT:
        f->eax = wait(*(pid_t *)args[1]);
        break;
    case SYS_CREATE:
        f->eax = create(*(const char **)args[1], *(unsigned *)args[2]);
        break;
    case SYS_REMOVE:
        f->eax = remove(*(const char **)args[1]);
        break;
    case SYS_OPEN:
        f->eax = open(*(const char **)args[1]);
        break;
    case SYS_FILESIZE:
        f->eax = filesize(*(int *)args[1]);
        break;
    case SYS_READ:
        f->eax = read(*(int *)args[1], *(void **)args[2], *(unsigned *)args[3]);
        break;
    case SYS_WRITE:
        f->eax = write(*(int *)args[1], *(const void **)args[2], *(unsigned *)args[3]);
        break;
    case SYS_SEEK:
        seek(*(int *)args[1], *(unsigned *)args[2]);
        break;
    case SYS_TELL:
        f->eax = tell(*(int *)args[1]);
        break;
    case SYS_CLOSE:
        close(*(int *)args[1]);
        break;
    default:
        NOT_REACHED();
    }
}

/* Terminates Pintos by calling shutdown_power_off()
    (declaredin‘devices/shutdown.h’). This should be
    seldom used, because you losesome information
    about possible deadlock situations, etc. */
static void halt(void)
{
  shutdown_power_off();
}

/* Terminates the current user program, returning
    STATUS to the kernel. If the process’s parent
    waits for it, this is the status that will be
    returned. Conventionally, a status of 0 indicates
    success and nonzero values indicate errors. */
static void exit(int status)
{
    struct process *parent  = thread_current()->process;

    while (!list_empty(&parent->files))
    {
        struct open_file *f = list_entry(list_back(&parent->files),
                                         struct open_file, elem);
        close(f->fd);
    }

    parent->exit_code = status;

    thread_exit();
}

/* Runs the executable whose name is given in CMD_LINE,
    passing any given arguments, and returns the new
    process’s program id (pid). Must return pid -1,
    which otherwise should not be a valid pid, if
    the program cannot load or run for any reason.
    Thus, the parent process cannot return from the
    exec until it knows whether the child process
    successfully loaded its executable. Use appropriate
    synchronization to ensure this. */
static pid_t exec(const char *cmd_line)
{
    USER_ASSERT(is_valid_str(cmd_line));

    lock_acquire(&file_lock);
    pid_t pid = process_execute(cmd_line);
    lock_release(&file_lock);

    if (pid == TID_ERROR)
        return -1;

    struct process *child = get_child(pid);
    sema_down(&child->sema_load); // wait until the loading compelete 

    if (child->status == PROCESS_FAILED)
    {
        sema_down(&child->sema_wait); // wait for parent to know that it fails ==> release from wait
        palloc_free_page(child);
        return -1;
    }
    else
    {
        ASSERT(child->status == PROCESS_NORMAL);
        return pid;
    }
}

static int wait(pid_t pid)
{
    return process_wait(pid);
}


/* Returns true if PTR is not a null pointer,
    a pointer to kernel virtual address space
    or a pointer to unmapped virtual memory. */
static bool is_valid_ptr(const void *ptr)
{
    return ptr != NULL && is_user_vaddr(ptr) && pagedir_get_page(thread_current()->pagedir, ptr) != NULL;
}

/* Returns true if [START, START + SIZE) is all valid. */
static bool is_user_mem(const void *start, size_t size)
{
    for (const void *ptr = start; ptr < start + size; ptr += PGSIZE)
    {
        if (!is_valid_ptr(ptr))
            return false;
    }

    if (size > 1 && !is_valid_ptr(start + size - 1))
        return false;

    return true;
}
/* Returns true if STR is a valid string in user space. */
static bool is_valid_str(const char *str)//for ensuring that a string pointer points to a valid memory location in user space
{
    if (!is_valid_ptr(str))
        return false;

    for (const char *c = str; *c != '\0';)
    {
        ++c;
        if (c - str + 2 == PGSIZE || !is_valid_ptr(c))
            return false;
    }

    return true;
}
  