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




/* Writes SIZE bytes from buffer to the open file FD. Returns the
    number of bytes actually written, which may be less than SIZE if
    some bytes could not be written.

    Writing past end-of-file would normally extend the file, but file
    growth is not implemented by the basic file system. The expected
    behavior is to write as many bytes as possible up to end-of-file
    and return the actual number written, or 0 if no bytes could be
    written at all.

    Fd 1 writes to the console. The code to write to the console should
    write all of buffer in one call to putbuf(), at least as long as SIZE
    is not bigger than a few hundred bytes. (It is reasonable to break up
    larger buffers.) Otherwise, lines of text output by different processes
    may end up interleaved on the console, confusing both human readers and
    the grading scripts. */
static int write(int fd, const void *buffer, unsigned length){

    // Check if buffer is valid user memory and if fd is not STDIN_FILENO
    USER_ASSERT(is_user_mem(buffer, length));
    USER_ASSERT(fd != STDIN_FILENO);

    // If writing to STDOUT_FILENO (console)
    if (fd == STDOUT_FILENO)
    {
      // Write buffer to console using putbuf
      putbuf((const char *)buffer, length);
      return length;  // Return the number of bytes written
    }

    // If writing to a regular file
    struct open_file *f = get_file_by_fd(fd); // Get the file struct by fd
    
    // Acquire lock to ensure exclusive access to files
    lock_acquire(&file_lock);
    // Write to file using file_write
    int bytes_written  = file_write(f->file, buffer, length);
    // Release lock
    lock_release(&file_lock);

  return bytes_written;
}


/* Creates a new file called FILE initially INITIAL_SIZE bytes in size.
    Returns true if successful, false otherwise. Creating a new file
    does not open it: opening the new file is a separate operation which
    would require a open system call. */
static bool create(const char *file, unsigned initial_size){
  // Check if file pointer is valid
  USER_ASSERT(is_valid_str(file));

  // Acquire file lock to ensure exclusive access to file system
    lock_acquire(&file_lock);

  // Create the file using filesys_create
  bool success = filesys_create(file, initial_size);

  // Release file lock
  lock_release(&file_lock);

  return success; // Return true if successful, false otherwise
}


static bool remove(const char *file) {
    // Check if file pointer is valid
    USER_ASSERT(is_valid_str(file));

    // Acquire file lock to ensure exclusive access to file system
    lock_acquire(&file_lock);

    // Remove the file using filesys_remove
    bool success = filesys_remove(file);

    // Release file lock
    lock_release(&file_lock);

    return success; // Return true if successful, false otherwise
}


static int open(const char *file){
  // Check if file pointer is valid
  USER_ASSERT(is_valid_str(file));

  // Acquire file lock to ensure exclusive access to file system
  lock_acquire(&file_lock);
  // Open the file using filesys_open
  struct file *opened_file = filesys_open(file);
  // Release file lock
  lock_release(&file_lock);

  // If file couldn't be opened, return -1
  if (opened_file == NULL)
    return -1;


  struct process *current = thread_current()->process;                  //Edit

  // Otherwise, create a new entry for the file descriptor
  struct open_file *new_open_file = malloc(sizeof(struct open_file));

  if (new_open_file == NULL) {
    file_close(opened_file); // Close the file if memory allocation failed
    return -1;
  }

  // Populate the new open file entry
  new_open_file->fd = current->fd++;
  new_open_file->file = opened_file;

  // Add the new open file entry to the current process's file list
  list_push_back(&current->files, &new_open_file->elem);

  // Return the file descriptor
  return new_open_file->fd;

}


static int filesize(int fd){
  // Find the file associated with the file descriptor
  struct open_file *file = get_file_by_fd(fd);

  if (file == NULL || file->file == NULL)
    return -1; // Return -1 if file descriptor is invalid or file is not open

  // Acquire file lock to ensure exclusive access to file
  lock_acquire(&file_lock);

  // Get the size of the file using file_length
  int size = file_length(file->file);

  // Release file lock
  lock_release(&file_lock);

  return size; // Return the size of the file

}

static int read(int fd, void *buffer, unsigned length){
  // Check if buffer pointer is valid
  USER_ASSERT(is_user_mem(buffer, length));
  USER_ASSERT(fd != STDOUT_FILENO);

  // If reading from the keyboard (stdin)
  if (fd == STDIN_FILENO) {
    uint8_t *buf = buffer;
    unsigned i;
    for (i = 0; i < length; i++) {
      buf[i] = input_getc(); // Read character from keyboard
      if (buf[i] == '\0')
      break;
    }
    return i; // Return the number of bytes actually read
  }

  // Find the file associated with the file descriptor
  struct open_file *file = get_file_by_fd(fd);
  if (file == NULL || file->file == NULL)
    return -1; // Return -1 if file descriptor is invalid or file is not open

  // Acquire file lock to ensure exclusive access to file
  lock_acquire(&file_lock);
  // Read from file into buffer using file_read
  int bytes_read = file_read(file->file, buffer, length);
  // Release file lock
  lock_release(&file_lock);

  return bytes_read; // Return the number of bytes actually read

}


static void seek(int fd, unsigned position) {
    // Find the file associated with the file descriptor
    struct open_file *file = get_file_by_fd(fd);
    if (file == NULL || file->file == NULL)
        return; // Do nothing if file descriptor is invalid or file is not open

    // Acquire file lock to ensure exclusive access to file
    lock_acquire(&file_lock);
    // Seek to the specified position using file_seek
    file_seek(file->file, position);
    // Release file lock
    lock_release(&file_lock);
}


static unsigned tell(int fd) {
    // Find the file associated with the file descriptor
    struct open_file *file = get_file_by_fd(fd);
    if (file == NULL || file->file == NULL)
        return -1; // Return -1 if file descriptor is invalid or file is not open

    // Acquire file lock to ensure exclusive access to file
    lock_acquire(&file_lock);
    // Get the current position within the file using file_tell
    unsigned position = file_tell(file->file);
    // Release file lock
    lock_release(&file_lock);

    return position; // Return the current position within the file
}


static void close(int fd) {
    // Find the file associated with the file descriptor
    struct open_file *file = get_file_by_fd(fd);
    if (file == NULL || file->file == NULL)
        return; // Do nothing if file descriptor is invalid or file is not open

    // Acquire file lock to ensure exclusive access to file
    lock_acquire(&file_lock);
    // Close the file using file_close
    file_close(file->file);
    // Remove the open file entry from the process's file list
    list_remove(&file->elem);
    // Free the open file entry
    free(file);
    // Release file lock
    lock_release(&file_lock);
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
  