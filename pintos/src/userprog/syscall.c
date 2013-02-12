#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "threads/synch.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "devices/shutdown.h"
#include <string.h>

#define FILENAME_MAX 14

extern struct lock lock_filesys;

int pop_arg(int **ustack_);
bool valid_user_addr(void *uaddr);
bool valid_user_page(void *uaddr);
bool valid_str(const char *s, unsigned max_len);

bool sys_halt(int *stack);
bool sys_exit(int *stack);
bool sys_exec(int *stack, uint32_t *eax);
bool sys_wait(int *stack, uint32_t *eax);
bool sys_create(int *stack, uint32_t *eax);
bool sys_remove(int *stack, uint32_t *eax);
bool sys_open(int *stack, uint32_t *eax);
bool sys_filesize(int *stack, uint32_t *eax);
bool sys_read(int *stack, uint32_t *eax);
bool sys_write(int *stack, uint32_t *eax);
bool sys_seek(int *stack);
bool sys_tell(int *stack, uint32_t *eax);
bool sys_close(int *stack);

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init (&lock_filesys);
}

static void
syscall_handler (struct intr_frame *f) 
{
  bool success = false;
	int *ustack =  f->esp;
	uint32_t *ueax   =  &(f->eax);
  
	int syscall_num = pop_arg(&ustack);
	
	switch(syscall_num) {
		case SYS_HALT:
			success = sys_halt(ustack);  
			break;                 
		case SYS_EXIT:
			success = sys_exit(ustack);                   
			break; 
    case SYS_EXEC:                   
			success = sys_exec(ustack, ueax);
			break; 
    case SYS_WAIT: 
    	success = sys_wait(ustack, ueax);                  
			break; 
    case SYS_CREATE:  
    	success = sys_create(ustack, ueax);
			break; 
    case SYS_REMOVE:                 
			success = sys_remove(ustack, ueax);
			break; 
    case SYS_OPEN:                   
			success = sys_open(ustack, ueax);
			break; 
    case SYS_FILESIZE:               
			success = sys_filesize(ustack, ueax);
			break; 
    case SYS_READ:                 
			success = sys_read(ustack, ueax);
			break; 
    case SYS_WRITE:                 
			success = sys_write(ustack, ueax);
			break; 
    case SYS_SEEK:                   
			success = sys_seek(ustack);
			break; 
    case SYS_TELL:                  
			success = sys_tell(ustack, ueax);
			break; 
    case SYS_CLOSE:                  
			success = sys_close(ustack);
			break; 

    /* Project 3 and optionally project 4. */
    	case SYS_MMAP:                 /* Map a file into memory. */
    	case SYS_MUNMAP:               /* Remove a memory mapping. */

    /* Project 4 only. */
    	case SYS_CHDIR:                /* Change the current directory. */
    	case SYS_MKDIR:                /* Create a directory. */
    	case SYS_READDIR:              /* Reads a directory entry. */
    	case SYS_ISDIR:                /* Tests if a fd represents a directory. */
    	case SYS_INUMBER:              /* Returns the inode number for a fd. */
		default:
			success = false;
			printf("unrecognized system call\n");
			break;
	}

	//if failure occured, kill process gracefully
	if (!success) {
      process_close(-1);
  		thread_exit ();
  	}
}


int 
pop_arg(int **ustack)
{
  if (!valid_user_addr((*ustack)+1))
  {
    process_close(-1);
    thread_exit();
  }
  
	int arg = (**ustack);
	(*ustack)++;
	return arg;
}

bool 
valid_user_addr(void *uaddr)
{
	if (uaddr == NULL)
		return false;
	
	if (!is_user_vaddr(uaddr))
		return false;

	uint32_t *pd = thread_current()->pagedir;
	if (!pagedir_get_page (pd,uaddr))
		return false;

	return true;
}

bool
valid_user_page(void* uaddr)
{
  if (!is_user_vaddr(uaddr))
		return false;

	uint32_t *pd = thread_current()->pagedir;
	if (!pagedir_get_page (pd,uaddr))
		return false;
	
	return true;
}


/* Halt the operating system. */
bool sys_halt(int *stack UNUSED)
{
	shutdown_power_off();
	return true;	
}

/* Terminate this process. */
bool sys_exit(int *stack)
{
	int status = pop_arg(&stack);
	process_close(status);
	thread_exit();
	
	return true;		
}

bool 
valid_str(const char *s, unsigned max_len)
{
  /* round to the nearest page boundary and validate the 
  current page. cache the result and search the page for 
  the end of the string (null terminator). repeat if the 
  search continues across a page boundary. */
  
  /*
  printf("start ptr:   %p\n", s);
  printf("top of page: %p\n", pg_round_up(s) - 1);
  printf("bot of page: %p\n", pg_round_down(s));
  */
  
  
  void* pg_top = pg_round_up (s) - 1;
  
  if (!valid_user_addr(pg_top))
    return false;
  
  unsigned c;
  for (c = 0; c < max_len; c++)
  {
    if (s+c > pg_top)
    {
      /* determine the next page */
      pg_top = pg_round_up(s+c+1) - 1;
      if (!valid_user_addr(pg_top))
        return false;
    }
    if (s[c] == '\0')
      return true;
  }
  return false;
  
  
  /* PSEUDOCODE
  validate page boundary
  run for loop
    if NOT index is on the valid page (pg_end)
      calc next page boundary
      if (not valid next page)
    if null terminator
      return true;
  return false;
  */
  
  /*
  int c;
  for (c = 0; c < max_len; c++)
  {
    if (!valid_user_addr(s+c) )
      return false;
    if (s[c] == '\0')
      return true;
  }
  return false;
  */
}

/* Start another process. */
bool sys_exec(int *stack, uint32_t *eax)
{
	const char *cmdline = (char *) pop_arg(&stack);
		
	if (!valid_str(cmdline, PGSIZE))
	  return false;
	
	pid_t pid = process_execute (cmdline);
		  
	/* push syscall result to the user program */
  memcpy(eax, &pid, sizeof(pid_t));
	
	return true;	
}

/* Wait for a child process to die. */
bool sys_wait(int *stack, uint32_t *eax)
{
	pid_t child_pid = pop_arg(&stack);
	int status = process_wait (child_pid);

	memcpy(eax, &status, sizeof(int));
	
	return true;		
}

/* Create a file. */
bool sys_create(int *stack, uint32_t *eax)
{
	const char *file = (const char *) pop_arg(&stack);
	unsigned size = (unsigned) pop_arg(&stack);

  if (!valid_user_addr((void *)file))
    return false;
  
  int result = 0;
  int fname_len = strnlen (file, FILENAME_MAX+1);
  if (fname_len > 0 && fname_len <= FILENAME_MAX)
  {
    lock_acquire(&lock_filesys);
    result = (int) filesys_create (file, (off_t) size);
    lock_release(&lock_filesys);
  }
  
  /* push syscall result to the user program */
  memcpy(eax, &result, sizeof(uint32_t));
  
	return true;	
}

/* Delete a file. */
bool sys_remove(int *stack, uint32_t *eax)
{
	const char *file = (const char *) pop_arg(&stack);
	
	if (!valid_user_addr((void *)file))
    return false;
   
  int result;
  lock_acquire(&lock_filesys);
  result = (int)filesys_remove (file);
  lock_release(&lock_filesys);
  
  /* push syscall result to the user program */
  memcpy(eax, &result, sizeof(uint32_t));
  
	return true;		
}

/* Open a file. */
bool sys_open(int *stack, uint32_t *eax)
{
	const char *name = (const char *) pop_arg(&stack);

  if (!valid_user_addr((void *)name))
    return false;
    
	struct file *f;
	
	lock_acquire(&lock_filesys);
	f = filesys_open (name);
	lock_release(&lock_filesys);
	
	/* obtain a new file descriptor from the thread's table */
	int fd = -1;
	if (f != NULL)
	  fd = process_add_file_desc(f);
	
	/* push syscall result to the user program */
  memcpy(eax, &fd, sizeof(uint32_t));
	
	return true;		
}

/* Obtain a file's size. */
bool sys_filesize(int *stack, uint32_t *eax)
{
	int fd = pop_arg(&stack);
	
	struct file *file = process_get_file_desc(fd);
	if (file == NULL)
	  return false;
	
	uint32_t file_len;
	
	lock_acquire(&lock_filesys);
	file_len = (uint32_t) file_length (file);
	lock_release(&lock_filesys);
	
	/* push syscall result to the user program */
  memcpy(eax, &file_len, sizeof(uint32_t));
	
	return true;		
}

 /* Read from a file. */
bool sys_read(int *stack, uint32_t *eax)
{
	int fd = pop_arg(&stack);
	void *buffer = (void *) pop_arg(&stack);
	unsigned size = (unsigned) pop_arg(&stack);
	
	void *buffer_end = ((char *) buffer) + size;

	if (!valid_user_addr(buffer) ||
		!valid_user_addr(buffer_end))
	  return false;
	  
	struct file *file = process_get_file_desc(fd);
	if (file == NULL || fd == 1)
	  return false;
	
	lock_acquire(&lock_filesys);
	int bytes_read = (int) file_read (file, buffer, (off_t) size);
	lock_release(&lock_filesys);
	
	/* push syscall result to the user program */
  memcpy(eax, &bytes_read, sizeof(uint32_t));
	
	return true;		
}

/* Write to a file. */
bool sys_write(int *stack, uint32_t *eax)
{
	int fd = pop_arg(&stack);
	const void *buffer = (const void *) pop_arg(&stack);
	unsigned size = (unsigned) pop_arg(&stack);

	void *buffer_end = ((char *) buffer) + size;

	if (!valid_user_addr(buffer) ||
		!valid_user_addr(buffer_end))
	  return false;

  /* check for console descriptor */
	if (fd == 1) {
		putbuf(buffer,size);
		return true;
	}
	
	struct file *file = process_get_file_desc(fd);
	if (file == NULL || fd == 0)
	  return false;
	
	lock_acquire(&lock_filesys);
	int bytes_written = (int) file_write (file, buffer, (off_t) size); 
	lock_release(&lock_filesys);	
	
	/* push syscall result to the user program */
  memcpy(eax, &bytes_written, sizeof(uint32_t));
	
	return true;		
}

/* Change position in a file. */
bool sys_seek(int *stack)
{
	int fd = pop_arg(&stack);
	unsigned new_pos = pop_arg(&stack);
	
	struct file *file = process_get_file_desc(fd);
	if (file == NULL)
	  return false;

	lock_acquire(&lock_filesys);
	file_seek (file, (off_t) new_pos);
	lock_release(&lock_filesys);
	
	return true;		
}

/* Report current position in a file. */
bool sys_tell(int *stack, uint32_t *eax)
{
	int fd = pop_arg(&stack);
	
	struct file *file = process_get_file_desc(fd);
	if (file == NULL)
	  return false;
	
	unsigned pos;
	
	lock_acquire(&lock_filesys);
	pos = (unsigned) file_tell (file); 
	lock_release(&lock_filesys);
	
	/* push syscall result to the user program */
  memcpy(eax, &pos, sizeof(uint32_t));
	
	return true;		
}

/* Close a file. */
bool sys_close(int *stack)
{
	int fd = pop_arg(&stack);
	
	struct file *file = process_get_file_desc(fd);
	if (file == NULL || fd < 2)
	  return false;
	
	lock_acquire(&lock_filesys);
	file_close (file);
	lock_release(&lock_filesys);
	
	process_remove_file_desc(fd);
	
	return true;	
}

