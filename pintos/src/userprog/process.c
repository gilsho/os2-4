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

static int curr_pid;
static struct lock lock_pid;

struct process_info
{
  pid_t pid;
  struct lock lock;
  int exit_code;
  bool has_been_waited;
  bool is_alive;
  bool is_parent_alive;
  struct condition cond;
  struct list_elem child_elem; /* elem in parent list */
  struct list children;   /* list of child processes (struct process_info) */
};

struct process_init_data
{
  char *args;
  struct semaphore sema;
  bool load_status;
  struct process_info *info;
};


typedef void process_action_func (struct process_info *info, void *aux);
static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);
void push_stack(void **stack_, void *data, size_t n);
void push_stack_int(void **stack_, int val);
void push_stack_char(void **stack_, char c);
void parse_args(const char *args, void **esp, char **file_name);

/* Invoke function 'func' on all threads, passing along 'aux'.
   This function must be called with interrupts off. */
void process_foreach (struct list *list, process_action_func *func, void *aux);
void set_parent_dead(struct process_info *info, void* aux UNUSED);
void free_dead_process(struct process_info *info, void* aux UNUSED);
struct process_info * process_get_info(struct process_info *parent_info, pid_t child_pid); 

void process_init(void){
  
  struct process_info *main_info = malloc(sizeof(struct process_info));
  
  ASSERT(main_info != NULL);
    
  main_info->pid             = 0;
  lock_init(&main_info->lock);
  main_info->exit_code       = 0;
  main_info->has_been_waited = false;
  main_info->is_alive        = true;
  main_info->is_parent_alive = false; /* main thread has no parent */
  
  cond_init(&(main_info->cond));
  list_init(&(main_info->children));
  
  struct thread *t = thread_current();
  t->process_info = main_info;

  lock_init(&lock_pid);
  lock_acquire(&lock_pid);
  curr_pid = 0;
  lock_release(&lock_pid);
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
  int child_pid;

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  args_copy = palloc_get_page (0);
  if (args_copy == NULL)
    return TID_ERROR;
  strlcpy (args_copy, args, PGSIZE);

  struct process_init_data init_data;
  init_data.args = args_copy;
  sema_init(&(init_data.sema), 0);
  init_data.load_status = false;
  init_data.info = NULL;
  
  char tmp[strnlen(args_copy, PGSIZE)];
  strlcpy (tmp, args_copy, PGSIZE);
  
  char *thread_name = NULL;
  char *save_ptr;
  thread_name = strtok_r (tmp, " ", &save_ptr);
  ASSERT(thread_name != NULL);
  
  printf("PARENT: curr_pid: %d, name: %s\n", thread_current()->process_info->pid, thread_current()->name);
  
  struct process_info *child_info = NULL;
  child_info = malloc(sizeof(struct process_info));
  
  if (child_info == NULL)
    return -1;
  
  child_info->exit_code       = 0;
  lock_init(&(child_info->lock));
  child_info->is_alive        = true;
  child_info->is_parent_alive = true;
  child_info->has_been_waited = false;
  
  lock_acquire(&lock_pid);
  curr_pid++;
  child_info->pid = curr_pid;
  lock_release(&lock_pid);
   
  printf("[process_execute] info.pid of child: %d\n", child_info->pid);
  child_pid = child_info->pid;  
  
  cond_init(&(child_info->cond));
  list_init(&(child_info->children));
  
  init_data.info = child_info;
  
  /* add the new child to current processes' children */
  struct process_info *info = thread_current()->process_info;
  list_push_back(&(info->children), &(child_info->child_elem)); /* add to children list */

  tid = thread_create (thread_name, PRI_DEFAULT, start_process, (void *)&init_data);

  printf("child tid: %d\n", tid);
  
  if(tid != TID_ERROR)
  {
    printf("about to sema_down: %s\n", thread_current()->name);
    sema_down(&(init_data.sema));
  }
  
  printf("process_execute, load_status: %d name: %s\n", (int)init_data.load_status, thread_current()->name);
  
  palloc_free_page (args_copy); 
  
  if (!init_data.load_status){
    return -1;
  }

  return child_pid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void * init_data_)
{
  printf("start process 1, name: %s\n", thread_current()->name);
  struct process_init_data *init_data = (struct process_init_data *)init_data_;
  char *args = init_data->args;

  /*char *args = args_;*/
  struct intr_frame if_;
  bool success;

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (args, &if_.eip, &if_.esp);

  printf("start process 2, name: %s, success: %d\n", thread_current()->name, (int)success);
  /*printf("in start_process, success: %d\n", (int)success);*/
  
  init_data->load_status = success;
  thread_current()->process_info = init_data->info;
  
  /* printf("CHILD pid: %d name: %s\n", thread_current()->pid, thread_current()->name); */
  /* printf("~~~~IN start_process load_status: %d\n", (int)init_data->load_status); */
  
  printf("about to sema_up: %s\n", thread_current()->name);
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

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (pid_t child_pid) 
{
  /* printf("in process_wait, current: %s, child_pid: %d\n", thread_current()->name, child_pid); */

  struct process_info *child_info = 
    process_get_info(thread_current()->process_info,child_pid);
  
  if (child_info != NULL)
    return -1;
  
  int result = -1;
  lock_acquire(&(child_info->lock));
  if(!child_info->has_been_waited && child_info->is_alive) {
    cond_wait(&(child_info->cond),&(child_info->lock));
  }
  child_info->has_been_waited = true;
  result = child_info->exit_code;
  lock_release(&(child_info->lock));
  
  /*printf("leaving process_wait...\n");*/
  return result;

}

void
process_close(int status){
  /* printf("process_close -> name: %s pid: %d status: %d\n", thread_current()->name, (int) pid, status); */
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
  
  /*printf("In process exit, current: %s\n", cur->name);*/

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

  /* allow writes to the executable */
  file_close(t->exec_file);

  struct process_info *info = t->process_info;  
  lock_acquire(&(info->lock));

  /* kill the current process */
  info->is_alive = false;
  
  /* tell all children that we are dead */
  process_foreach (&(info->children), &set_parent_dead, NULL);
  
  /* free all dead children */
  process_foreach (&(info->children), &free_dead_process, NULL);
  
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
  
    /*printf("exit code: %d, has waited: %d, is_alive: %d, parent id: %d\n", info.exit_code, info.has_been_waited, info.is_alive, info.parent_pid);*/
  /*printf("curr pid: %d, curr name: %s\n", cur->pid, cur->name); */
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
void push_stack(void **stack_, void *data, size_t n)
{
  char **stack = (char **)stack_;
  *stack -= n;
  memcpy(*stack,data,n);
}

/* pushes an integer value onto a user stack. see push_stack
   for implementation details */
void push_stack_int(void **stack_, int val)
{
  push_stack(stack_,&val,sizeof(int));
}

/* Pushes a character onto a user stack. see push_stack for
   implementation details. */
void push_stack_char(void **stack_, char c)
{
  push_stack(stack_,&c,sizeof(char));
}

/* Parses a command line string and prepares the user stack pointed
   to by esp for execution. The function parses the string and places
   the arguments on the user stack in preparation for a "int main(argv,argc)"
   call. Function sets file_name to point to the executable file name 
   located on the user stack.*/
void parse_args(const char *args, void **esp, char **file_name)
{
  /* +1 is to include the null terminating character */
  int arglen = strnlen(args,PGSIZE) + 1;
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

  /* what if stack exceeds full page ? */

  push_stack_int(esp,0);
  for (i = argc-1; i >= 0; i--) {
    push_stack_int(esp,(int) tmp[i]);
  }

  (*file_name) = *((char **)(*esp));

  push_stack_int(esp,(int) *esp);
  push_stack_int(esp,argc);
  push_stack_int(esp,0);

}

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *args, void (**eip) (void), void **esp)
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
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
  parse_args(args,esp,&file_name);
  
  file = filesys_open (file_name);
  if (file == NULL) 
    {
      printf ("load: %s: open failed\n", file_name);
      goto done; 
    }
  
  file_deny_write (file);

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
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

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
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
          if (validate_segment (&phdr, file)) 
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
              if (!load_segment (file, file_page, (void *) mem_page,
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
  if (!success)
    file_close (file);
  else
    t->exec_file = file;
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

/* Invoke function 'func' on all threads, passing along 'aux'.
   This function must be called with interrupts off. */
void
process_foreach (struct list *list, process_action_func *func, void *aux)
{
  struct list_elem *e;

  for (e = list_begin (list); e != list_end (list);
       e = list_next (e))
    {
      struct process_info *info = list_entry (e, struct process_info,         child_elem);
      lock_acquire(&(info->lock));
      func (info, aux);
      lock_release(&(info->lock));
    }
}

void
set_parent_dead(struct process_info *info, void* aux UNUSED)
{
  info->is_parent_alive = false;
}

void
free_dead_process(struct process_info *info, void* aux UNUSED)
{
  if (!info->is_alive)
    free(info);
}

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
