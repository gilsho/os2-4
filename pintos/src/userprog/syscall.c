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
#include "devices/input.h"

#define FILENAME_MAX 14

extern struct lock lock_filesys;

void syscall_init (void);
static void syscall_handler (struct intr_frame *);

int pop_arg(int **ustack_);
bool valid_user_addr(void *uaddr);
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



void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init (&lock_filesys);
}

/* Handler for all system calls */
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

	/*if failure occured in sys_call, kill process gracefully*/
	if (!success) {
      process_close(-1);
  		thread_exit ();
  	}
}


/* This function pops a word from the stack and returns it. 
	We check if the stack is a valid user address before popping
	next argument */
int 
pop_arg(int **ustack)
{
  if ( !valid_user_addr((*ustack)) ||
       !valid_user_addr((*ustack)+1) )
  {
    process_close(-1);
    thread_exit();
  }
  
	int arg = (**ustack);
	(*ustack)++;
	return arg;
}

/* Performs checks to make sure we our pointer
	is a valid user address. */
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

/* Validate the user memory addresses for the given
   character string of unknown length. Assume that it
   is null terminated and not longer than max_len.
  
   Algorithm:
   round to the nearest page boundary and validate the 
   current page. cache the result and search the page for 
   the end of the string (null terminator). repeat if the 
   search continues across a page boundary. */
bool 
valid_str(const char *s, unsigned max_len)
{
  void* pg_top = pg_round_up (s) - 1;
  
  /* validate the current page */
  
  if (!valid_user_addr(pg_top))
    return false;
  
  unsigned c;
  for (c = 0; c < max_len; c++)
  {
    if ((void*)(s+c) > pg_top)
    {
      /* find & validate the next page */
      pg_top = pg_round_up(s+c+1) - 1;
      if (!valid_user_addr(pg_top))
        return false;
    }
    if (s[c] == '\0')
      return true;
  }
  return false;
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
	const char *file_name = (const char *) pop_arg(&stack);
	unsigned size = (unsigned) pop_arg(&stack);

  /*if (!valid_user_addr((void *)file))*/
  if (!valid_str(file_name, PGSIZE))
    return false;
  
  int result = 0;
  int fname_len = strnlen (file_name, FILENAME_MAX+1);
  if (fname_len > 0 && fname_len <= FILENAME_MAX)
  {
    lock_acquire(&lock_filesys);
    result = (int) filesys_create (file_name, (off_t) size);
    lock_release(&lock_filesys);
  }
  
  /* push syscall result to the user program */
  memcpy(eax, &result, sizeof(uint32_t));
  
	return true;	
}

/* Delete a file. */
bool sys_remove(int *stack, uint32_t *eax)
{
	const char *file_name = (const char *) pop_arg(&stack);
	
	/*if (!valid_user_addr((void *)file))*/
	if (!valid_str(file_name, PGSIZE))
    return false;
   
  int result;
  lock_acquire(&lock_filesys);
  result = (int)filesys_remove (file_name);
  lock_release(&lock_filesys);
  
  /* push syscall result to the user program */
  memcpy(eax, &result, sizeof(uint32_t));
  
	return true;		
}

/* Open a file. */
bool sys_open(int *stack, uint32_t *eax)
{
	const char *name = (const char *) pop_arg(&stack);

  if (!valid_str(name, PGSIZE))
    return false;
    
	struct file *f;
	
	lock_acquire(&lock_filesys);
	f = filesys_open (name);
	lock_release(&lock_filesys);
	
	/* add a new file descriptor to the thread's fd list */
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

 /* Read user data from a file. */
bool sys_read(int *stack, uint32_t *eax)
{
  bool result = true;
	int fd = pop_arg(&stack);
	char *buffer = (void *) pop_arg(&stack);
	unsigned size = (unsigned) pop_arg(&stack);
	
	char *buffer_end = ((char *) buffer) + size;

	if (!valid_user_addr(buffer) ||
		!valid_user_addr(buffer_end))
	  return false;
	  
	unsigned bytes_read = 0;  
	  
	/* special case: read from STDIN */
	if (fd == 0) 
	{
	  uint8_t c;	  
	  while (bytes_read < size)
	  {
	    c = input_getc ();
	    memcpy(&(buffer[bytes_read]), &c, sizeof(uint8_t));
	    bytes_read++;
	  }
	}
	else
	{
	  /* check for invalid file or STDOUT */
	  struct file *file = process_get_file_desc(fd);
	  if (file == NULL || fd == 1)
	  {
	    result = false;
	  }
	  else /* valid file found */
	  {
	    lock_acquire(&lock_filesys);
	    bytes_read = (int) file_read (file, (void *)buffer, (off_t) size);
	    lock_release(&lock_filesys);
    }
  }
  	
	/* push syscall result to the user program */
  memcpy(eax, &bytes_read, sizeof(uint32_t));
	
	return result;		
}

/* Write to a file. */
bool sys_write(int *stack, uint32_t *eax)
{
  bool result = true;
	int fd = pop_arg(&stack);
	const void *buffer = (const void *) pop_arg(&stack);
	unsigned size = (unsigned) pop_arg(&stack);

	void *buffer_end = ((char *) buffer) + size;

	if (!valid_user_addr((void *)buffer) ||
		!valid_user_addr(buffer_end))
	  return false;

	unsigned bytes_written = 0;

  /* special case: write to STDOUT */
	if (fd == 1) {
		putbuf(buffer,size);
		bytes_written = size;
	}
	else {
	  /* check for invalid file or STDIN */
	  struct file *file = process_get_file_desc(fd);
	  if (file == NULL || fd == 0)
	  {
	    result = false;
	  }
	  else /* valid file found */
	  {
		  lock_acquire(&lock_filesys);
	    bytes_written = (int) file_write (file, buffer, (off_t) size); 
	    lock_release(&lock_filesys);	
	  }
	}
	
	/* push syscall result to the user program */
  memcpy(eax, &bytes_written, sizeof(uint32_t));
	
	return result;		
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
	
	/* return false is file not found or 
	   user tries to close STDIN/STDOUT */
	struct file *file = process_get_file_desc(fd);
	if (file == NULL || fd < 2)
	  return false;
	
	lock_acquire(&lock_filesys);
	file_close (file);
	lock_release(&lock_filesys);
	
	process_remove_file_desc(fd);
	
	return true;	
}

