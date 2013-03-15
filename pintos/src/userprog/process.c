#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "threads/malloc.h"


struct lock lock_filesys; /* a coarse global lock restricting access 
                            to the file system */

/* This struct contains all the information related to a process */
struct process_info
{
  pid_t pid;						/* unique process id (same as thread tid) */
  struct lock lock;			/* lock for concurrent access to this info struct */
  int exit_code;				/* the status code set by the process during exit, 
                           only valid if is_alive is false */
  bool has_been_waited;	/* indicates if the parent process has waited on 
                           this child process already */
  bool is_alive;				/* indicates whether this process has exited */
  bool is_parent_alive;	/* indicates whether the parent has exited. used for
                           memory management by the process when exiting. */
  struct condition cond;			/* used to implement the sys_wait system call */
  struct list_elem child_elem;   /* elem in parent process' child list */
  struct list children;          /* list of this process' children */
  struct list fd_list;   /* list of file descriptors and associated files
                             used by this process. */
  struct file *exec_file;    /* a pointer to this process' executable
                                file that its thread is running. used to deny
                                write access to the file while the process is 
                                running  */ 
  int next_fd;              /* fd counter localized to this process only */
};


/* This struct is used to pass more than one variable between a parent process' process_execute call and a child process' start_process function. */

struct process_init_data
{
  char *args;					/* string containing name of executable and args 
                         of/to the program. */
  struct semaphore sema;		/* synchronization mechanism enabling parent 
                               process to wait for the child to finish
                               loading its executable */
  bool load_status;				/* represents if load of child process was  
                             successful. used to signal to parent process. */
  struct process_info *info;	/* the child process' information struct 
                                 initialized by its parent process */
};

/* This struct is an element in a linked list of file descriptors 
   mapping to open files. */

struct file_desc
{
  int fd;						      /* the file descriptor associated with the file */
  union fd_content content;			/* a handle to the file struct associated with fd */
  enum fd_type type;
  struct list_elem elem;	/* a list elem used to embed this struct within a 
                            process' list of active files */
};


#if (DEBUG & DEBUG_PROCESS)
#define DEBUG_PROCESS_CHDIR      1
#define DEBUG_PROCESS_START      1
#define DEBUG_GET_START_DIR      1
#else
#define DEBUG_PROCESS_CHDIR      0
#define DEBUG_PROCESS_START      0
#define DEBUG_GET_START_DIR      0
#endif

#if DEBUG_PROCESS_CHDIR
#define PRINT_PROCESS_CHDIR(X) {printf("(process_chdir) "); printf(X);}
#define PRINT_PROCESS_CHDIR_2(X,Y) {printf("(process_chdir) "); printf(X,Y);}
#else
#define PRINT_PROCESS_CHDIR(X) do {} while(0)
#define PRINT_PROCESS_CHDIR_2(X,Y) do {} while(0)
#endif

#if DEBUG_PROCESS_START
#define PRINT_PROCESS_START(X) {printf("(process_start) "); printf(X);}
#define PRINT_PROCESS_START_2(X,Y) {printf("(process_start) "); printf(X,Y);}
#else
#define PRINT_PROCESS_START(X) do {} while(0)
#define PRINT_PROCESS_START_2(X,Y) do {} while(0)
#endif

#if DEBUG_GET_START_DIR
#define PRINT_GET_START_DIR(X) {printf("(process-get-start-dir) "); printf(X);}
#define PRINT_GET_START_DIR_2(X,Y) {printf("(process-get-start-dir) "); printf(X,Y);}
#else
#define PRINT_GET_START_DIR(X) do {} while(0)
#define PRINT_GET_START_DIR_2(X,Y) do {} while(0)
#endif

/* skip STDIN(0) and STDOUT(1) */
#define FILE_DESCRIPTOR_START 2


typedef void process_action_func (struct process_info *info, void *aux);
static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp, struct file **file);
void push_stack(void **stack_, void *data, size_t n);
void push_stack_int(void **stack_, int val);
void push_stack_char(void **stack_, char c);
bool parse_args(const char *args, void **esp, char **file_name);

void process_foreach (struct list *list, process_action_func *func, void *aux);
void set_parent_dead(struct process_info *info, void* aux UNUSED);
struct process_info * process_get_info(struct process_info *parent_info, pid_t child_pid);
void process_free_children (struct process_info* info); 
bool initialize_process_info(struct process_info **child_info_ptr);
void process_set_init_data(struct process_init_data *init_data, char *args_copy);
void release_children_locks(struct process_info *info, void* aux UNUSED);


struct file_desc* process_fd_get(int fd);
void process_fd_close_all(struct process_info *info);

bool process_chdir(const char *path);

/* Initializes the process control block.
  Sets process info for the main thread */
void process_init(void)
{
  struct process_info *main_info;  
  bool result = initialize_process_info(&main_info);
  
  ASSERT(result);
  ASSERT(main_info != NULL);
  
  main_info->is_parent_alive = false; /* main thread has no parent */
  
  struct thread *t = thread_current();
  t->process_info = main_info;
}

/* Initialize data needed to start a process. The sema and load_status are used
to synchronize the parent waiting till load is complete */
void process_set_init_data(struct process_init_data *init_data, char *args_copy){
  init_data->args = args_copy;
  sema_init(&(init_data->sema), 0);
  init_data->load_status = false;
}



/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
pid_t
process_execute (const char *args) 
{
  char *args_copy;
  tid_t tid;

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  args_copy = palloc_get_page (0);
  if (args_copy == NULL)
    return TID_ERROR;
  strlcpy (args_copy, args, PGSIZE);

/* Extract executable name from argument string to set as thread name */
  char tmp[strnlen(args_copy, PGSIZE)];
  strlcpy (tmp, args_copy, PGSIZE);
  
  char *thread_name, *save_ptr;
  thread_name = strtok_r (tmp, " ", &save_ptr);
  ASSERT(thread_name != NULL);

  /* setup the data struct to pass to start_process */
  struct process_init_data init_data;
  process_set_init_data(&init_data, args_copy);
  
  /* initialize the child process' info struct */
  struct process_info *child_info;
  if (!initialize_process_info(&child_info))
    return -1;

  init_data.info = child_info;
  
  /* add the new child to current processes' children */
  struct process_info *info = thread_current()->process_info;
  list_push_back(&(info->children), &(child_info->child_elem)); /* add to children list */

  tid = thread_create (thread_name, PRI_DEFAULT, start_process, (void *)&init_data);
  
  if(tid != TID_ERROR)
  {
    sema_down(&(init_data.sema));
  }
    
  palloc_free_page (args_copy); 
  
  if (!init_data.load_status){
    return TID_ERROR;
  }

  return (pid_t) tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void * init_data_)
{
  struct process_init_data *init_data = (struct process_init_data *)init_data_;
  char *args = init_data->args;

  struct intr_frame if_;
  bool success;

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (args, &if_.eip, &if_.esp, &(init_data->info->exec_file));
  
  init_data->load_status = success;
  struct thread *t = thread_current();
  init_data->info->pid = (pid_t) t->tid;
  t->process_info = init_data->info;
  
  sema_up(&(init_data->sema));
  
  /* If load failed, quit. */

  if (!success){
    process_close(-1);
    thread_exit ();
  }
    

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.
 */
int
process_wait (pid_t child_pid) 
{
  struct process_info *child_info = 
    process_get_info(thread_current()->process_info,child_pid);
  
  if (child_info == NULL)
    return -1;
  
  int result = -1;
  lock_acquire(&(child_info->lock));
  
  if(!child_info->has_been_waited && child_info->is_alive) {
    cond_wait(&(child_info->cond),&(child_info->lock));
  }
  result = child_info->exit_code;
  child_info->has_been_waited = true;
  child_info->exit_code = -1;
  lock_release(&(child_info->lock));
  
  return result;
}

/* Set the exit code for the current process */
void
process_close(int status){
  struct process_info *info = thread_current()->process_info;
  lock_acquire(&(info->lock));
  info->exit_code = status;
  lock_release(&(info->lock));
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *t = thread_current ();
  uint32_t *pd;

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = t->pagedir;
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      t->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }

  struct process_info *info = t->process_info;  
  
  /* Close any files opened by this process */
  process_fd_close_all(info);

  /* allow writes to the executable */
  if(!lock_held_by_current_thread(&lock_filesys))
    lock_acquire(&lock_filesys);
  file_close(info->exec_file);
  lock_release(&lock_filesys);

  if(!lock_held_by_current_thread(&info->lock))
    lock_acquire(&(info->lock));

  /* mark the current process as dead */
  info->is_alive = false;
 
  /* Release all children's locks that this process might 
     be holding upon exiting. */
  process_foreach(&(info->children), &release_children_locks, NULL);

  /* tell all children that the current (parent) process is dead */
  process_foreach (&(info->children), &set_parent_dead, NULL);
  
  /* free all dead child processes */
  process_free_children (info);
  
  printf ("%s: exit(%d)\n", t->name, info->exit_code);
  
  /* free self if parent is dead */
  if (!info->is_parent_alive)
  {
    /* no race conditions since parent is dead */
    lock_release(&(info->lock));
    free(info);
    info = NULL;
  }
  else
  {
    cond_signal(&(info->cond),&(info->lock));
    lock_release(&(info->lock));
  } 
  
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Pushes data of length n bytes onto a user stack. assumes the 
   stack is always pointing to last byte of valid data. The
   function will maintain this invariant.*/
void 
push_stack(void **stack_, void *data, size_t n)
{
  char **stack = (char **)stack_;
  *stack -= n;
  memcpy(*stack,data,n);
}

/* pushes an integer value onto a user stack. see push_stack
   for implementation details */
void 
push_stack_int(void **stack_, int val)
{
  push_stack(stack_,&val,sizeof(int));
}

/* Pushes a character onto a user stack. see push_stack for
   implementation details. */
void 
push_stack_char(void **stack_, char c)
{
  push_stack(stack_,&c,sizeof(char));
}

/* Parses a command line string and prepares the user stack pointed
   to by esp for execution. The function parses the string and places
   the arguments on the user stack in preparation for a "int main(argv,argc)"
   call. Function sets file_name to point to the executable file name 
   located on the user stack.*/

#define MAX_PADDING 4

bool 
parse_args(const char *args, void **esp, char **file_name)
{

  /* +1 is to include the null terminating character */
  int arglen = strnlen(args,PGSIZE) + 1;
  if (arglen > PGSIZE-MAX_PADDING)
    return false;
  push_stack(esp,(void *)args,arglen);
  
  char *args_stack = *esp;

  /* word align the stack address */
  int padding = ((int) (*esp)) % 4;
  int i;
  for(i=0; i<padding; i++) {
    push_stack_char(esp,0);
  }
  
  /* tokenize */
  char *token, *save_ptr;
  int argc = 0;

  char **tmp = (char **) args;

  for (token = strtok_r (args_stack, " ", &save_ptr); token != NULL;
       token = strtok_r (NULL, " ", &save_ptr)) {
    tmp[argc] = token;
    argc++;
  }

  /* check that setting up the stack will not exceed page boundary */

  int *page_bottom =  (int *)pg_round_down (esp);
  if ((int *)esp - (argc + 4) < page_bottom) 
      return false;

  push_stack_int(esp,0);
  for (i = argc-1; i >= 0; i--) {
    push_stack_int(esp,(int) tmp[i]);
  }

  (*file_name) = *((char **)(*esp));

  push_stack_int(esp,(int) *esp);
  push_stack_int(esp,argc);
  push_stack_int(esp,0);

  return true;

}

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *args, void (**eip) (void), void **esp, struct file **file)
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

  /* Set up stack. */
  if (!setup_stack (esp))
    goto done;

  /* Parse command line arguments and push them onto user stack */
  char *file_name;
  if (!parse_args(args,esp,&file_name))
    goto done;

  lock_acquire(&lock_filesys);

  struct dir *wdir = process_get_wdir();

  (*file) = filesys_open_file (wdir, file_name);
  if (*file == NULL) 
    {
      printf ("load: %s: open failed\n", file_name);
      goto done; 
    }
  
  file_deny_write (*file);

  /* Read and verify executable header. */
  if (file_read (*file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (*file))
        goto done;
      file_seek (*file, file_ofs);

      if (file_read (*file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, *file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (*file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }


  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
  if (!success) {
    file_close (*file);
    (*file) = NULL;
  }

  lock_release(&lock_filesys);

  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Get a page of memory. */
      uint8_t *kpage = palloc_get_page (PAL_USER);
      if (kpage == NULL)
        return false;

      /* Load this page. */
      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        {
          palloc_free_page (kpage);
          return false; 
        }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      /* Add the page to the process's address space. */
      if (!install_page (upage, kpage, writable)) 
        {
          palloc_free_page (kpage);
          return false; 
        }

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp) 
{
  uint8_t *kpage;
  bool success = false;

  kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  if (kpage != NULL) 
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      if (success)
        *esp = PHYS_BASE;
      else
        palloc_free_page (kpage);
    }
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}

/* Invoke function 'func' on all processes in the given list, 
   passing along 'aux'. */
void
process_foreach (struct list *list, process_action_func *func, void *aux)
{
  struct list_elem *e;

  for (e = list_begin (list); e != list_end (list);
       e = list_next (e))
    {
      struct process_info *info = list_entry (e, struct process_info,child_elem);
      
      func (info, aux);
    }
}

/* Checks to see if current threads owns childs lock, and if so, releases it */
void
release_children_locks(struct process_info *info, void* aux UNUSED){
  if(lock_held_by_current_thread (&(info->lock)))
    lock_release(&(info->lock));
}

/* Sets a child's is_parent_alive flag to false */
void
set_parent_dead(struct process_info *info, void* aux UNUSED)
{
  lock_acquire(&(info->lock));
  info->is_parent_alive = false;
  lock_release(&(info->lock));
}

/* Retrieves the process info of a child process using a given child pid */
struct process_info *
process_get_info(struct process_info *parent_info,pid_t child_pid) 
{
  struct list_elem *e;
  struct list *list = &(parent_info->children);
  
  for (e = list_begin (list); e != list_end (list); e = list_next (e)) {
      struct process_info *info = list_entry (e, struct process_info,
                                              child_elem);
      if (info->pid == child_pid)
        return info;
  }
  return NULL;
}

/* Frees all children of the current process that 
   have already exited. Invoked by the parent process
   before exiting. */
void
process_free_children (struct process_info* parent_info)
{
  struct list *list = &(parent_info->children);
  struct list_elem *e;
  struct list_elem *ne;

  e = list_begin (list);
  while ( e != list_end (list) )
  {
    struct process_info *child_info = 
      list_entry (e, struct process_info, child_elem);
    
    ne = list_next (e);
    
    lock_acquire(&(child_info->lock)); 
    if (!child_info->is_alive)
    {
      list_remove(e);
      free(child_info);
    } 
    else 
      lock_release(&(child_info->lock));
    e = ne;    
  }
}

/* Initialize the process info struct for a new process. */
bool
initialize_process_info(struct process_info **child_info_ptr)
{
  struct process_info *child_info = *child_info_ptr;
  
  child_info = malloc(sizeof(struct process_info));
  
  if (child_info == NULL)
    return false;
  
  child_info->exit_code       = 0;
  child_info->is_alive        = true;
  child_info->is_parent_alive = true;
  child_info->has_been_waited = false;
  
  lock_init(&(child_info->lock));
  cond_init(&(child_info->cond));
  list_init(&(child_info->children));
  list_init(&(child_info->fd_list));

  child_info->next_fd = FILE_DESCRIPTOR_START;
  child_info->exec_file = NULL;
  child_info->pid = -1;

  *child_info_ptr = child_info;
  return true;
}

/* Adds a file descriptor to the current process' list */

struct file_desc* 
process_fd_get(int fd)
{
  struct process_info *info = thread_current()->process_info;
  struct list *fd_list = &(info->fd_list);
  
  struct list_elem *e;
  for (e = list_begin (fd_list); e != list_end (fd_list); e = list_next (e)){
    struct file_desc *desc = list_entry(e,struct file_desc, elem);
    if (desc->fd == fd) {
      return desc;
    }
  }
  
  return NULL;
}


int process_fd_add(union fd_content content, enum fd_type type)
{
  struct process_info *info = thread_current()->process_info;
  struct list *fd_list = &(info->fd_list);

  struct file_desc *desc = malloc(sizeof(struct file_desc));
  if (desc == NULL)
    return -1;

  desc->type = type;
  desc->fd = info->next_fd;
  info->next_fd++;
  desc->content = content;

  list_push_back(fd_list,&(desc->elem));
  return desc->fd;
}

/*
int 
process_fd_add_file(struct file *file)
{
  union fd_content content;
  content.file = file;
  return process_fd_add(content, FD_FILE);
}

int 
process_fd_add_dir(struct dir *dir)
{
  union fd_content content;
  content.dir = dir;
  return process_fd_add(content, FD_DIR);
}
*/

/*
int process_fd_add_desc(struct file_desc *desc)
{
  struct process_info *info = thread_current()->process_info;
  struct list *fd_list = &(info->fd_list);

  desc->fd = info->next_fd;
  info->next_fd++;

  list_push_back(fd_list,&(desc->elem));
  return desc->fd;
}
*/

/* Retrieves the file associated with a given file descriptor for the 
   current thread*/
struct file* 
process_fd_get_file(int fd)
{
  struct file_desc *file_desc = process_fd_get(fd);
  if (file_desc == NULL || file_desc->type != FD_FILE)
    return NULL;
  return file_desc->content.file;
}

struct dir* 
process_fd_get_dir(int fd)
{
  struct file_desc *file_desc = process_fd_get(fd);
  if (file_desc == NULL || file_desc->type != FD_DIR)
    return NULL;
  return file_desc->content.dir;
}

/* Removes the given open file from current threads list of open files */
void 
process_fd_remove(int fd)
{
  struct process_info *info = thread_current()->process_info;
  struct list *fd_list = &(info->fd_list);
  struct list_elem *e;
  for (e = list_begin (fd_list); e != list_end (fd_list); e = list_next (e)){
    struct file_desc *desc = list_entry(e,struct file_desc, elem);
    if (desc->fd == fd) {
      list_remove(e);
      free(desc);
      return;
    }
  }
}


bool process_chdir(const char *path)
{
  struct thread *t = thread_current();
  struct dir *start_dir = process_get_start_dir(path);
  /* assume no spaces before absolute paths */

  PRINT_PROCESS_CHDIR_2("Path is: %s\n", path);
  bool success;
  struct dir *new_wdir = filesys_open_dir(start_dir,path);
  PRINT_PROCESS_CHDIR_2("new_wdir is: %p\n", new_wdir);

  if (new_wdir != NULL) {
    dir_close(t->wdir);
    t->wdir = new_wdir;
    success = true;
  } else {
    success = false;
  }
  
  /* need to close what you have opened */
  dir_close(start_dir);

  return success;
}

/* Caller must close directory */
struct dir*
process_get_start_dir(const char *path){
  PRINT_GET_START_DIR_2("path: %s\n",path);
  struct dir *start_dir;
  if (path[0] == '/') {
    PRINT_GET_START_DIR("absolute path detected\n");
    start_dir = dir_open_root();
  } else {
    PRINT_GET_START_DIR("relative path detected\n");
    start_dir = dir_reopen(thread_current()->wdir);
  }
  PRINT_GET_START_DIR_2("start_dir sector: %d\n",dir_get_sector(start_dir));
  return start_dir;
}

/*
struct file *
process_open_file(const char *name)
{
  struct dir *start_dir = process_get_start_dir(name);
  return filesys_open (start_dir,name);
}
*/

bool
process_create_file(const char *path, off_t size, bool is_dir){
  struct dir *start_dir = process_get_start_dir(path);
  bool result = filesys_create(start_dir, path, size, is_dir);
  dir_close(start_dir);
  return result;
}

bool
process_remove_file(const char *path){
  struct dir *start_dir = process_get_start_dir(path);
  bool result = filesys_remove(start_dir, path);
  dir_close(start_dir);
  return result;
}

bool
process_fd_close(int fd) 
{
  struct file_desc* desc = process_fd_get(fd);
  if (desc == NULL)
    return false;

  if (desc->type == FD_FILE)
    file_close(desc->content.file);
  else
    dir_close(desc->content.dir);
  return true;
}

/* Close all files currently opened by the exiting thread */
void process_fd_close_all(struct process_info *info)
{
   /* close all open files */
  struct list_elem *e;

  for (e = list_begin (&(info->fd_list)); e != list_end (&(info->fd_list));) {
    struct list_elem *ne;
    ne = list_next (e);
    list_remove(e);
    struct file_desc *desc = list_entry(e,struct file_desc, elem);
    lock_acquire(&lock_filesys);

    if (desc->type == FD_FILE)
      file_close(desc->content.file);
    else
      dir_close(desc->content.dir);

    lock_release(&lock_filesys);
    free(desc);
    e = ne;
  }
}

struct dir* 
process_get_wdir(void)
{
  return thread_current()->wdir;
}

void 
process_set_wdir(struct dir *wdir)
{
  thread_current()->wdir = wdir;
}

union fd_content 
process_fd_open(const char *path, bool *is_dir)
{
  struct dir* start_dir = process_get_start_dir(path);
  union fd_content content = filesys_open (start_dir, path, is_dir);
  dir_close(start_dir);
  return content;
}

int 
process_fd_inumber(int fd)
{
  struct file_desc* desc = process_fd_get(fd);
  if (desc == NULL)
    return -1;

  if (desc->type == FD_FILE)
    return file_get_inumber(desc->content.file);
  else
    return dir_get_inumber(desc->content.dir);

  return -1;
}
