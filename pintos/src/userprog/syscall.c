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
bool sys_chdir(int *stack, uint32_t *eax);
bool sys_mkdir(int *stack, uint32_t *eax);
bool sys_readdir(int *stack, uint32_t *eax);
bool sys_isdir(int *stack, uint32_t *eax);
bool sys_inumber(int *stack, uint32_t *eax);



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
		case SYS_CHDIR:
			success = sys_chdir(ustack,ueax);
			break;
		case SYS_MKDIR:
			success = sys_mkdir(ustack,ueax);
			break;
		case SYS_READDIR:
			success = sys_readdir(ustack,ueax);
			break;
		case SYS_ISDIR:
			success = sys_isdir(ustack,ueax);
			break;
		case SYS_INUMBER:
			success = sys_inumber(ustack,ueax);
			break;

		default:
			success = false;
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
    result = (int) process_create_file (file_name, (off_t) size, false);
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
  result = (int)process_remove_file(file_name);
  lock_release(&lock_filesys);
  
  /* push syscall result to the user program */
  memcpy(eax, &result, sizeof(uint32_t));
  
	return true;		
}

/* Open a file or directory. */
bool sys_open(int *stack, uint32_t *eax)
{
	const char *path = (const char *) pop_arg(&stack);

	int fd = -1;

  if (!valid_str(path, PGSIZE))
    return false;

	if(strnlen(path, PGSIZE) > 0){
		lock_acquire(&lock_filesys);
		fd = process_fd_open(path);
		lock_release(&lock_filesys);
	}

	/* push syscall result to the user program */
  memcpy(eax, &fd, sizeof(uint32_t));
	
	return true;		
}

/* Obtain a file's size. */
bool sys_filesize(int *stack, uint32_t *eax)
{
	int fd = pop_arg(&stack);
	
	struct file *file = process_fd_get_file(fd);
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
	  struct file *file = process_fd_get_file(fd);
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
	  struct file *file = process_fd_get_file(fd);
	  if (file == NULL || fd == 0 || file_is_dir(file))
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
	
	struct file *file = process_fd_get_file(fd);
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
	
	struct file *file = process_fd_get_file(fd);
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
	int fd = (int) pop_arg(&stack);

	/* return false is file not found or 
	   user tries to close STDIN/STDOUT */
	if (fd < 2)
	  return false;

	return process_fd_close(fd);
}

/* Changes the current working directory of the process to dir,
 which may be relative or absolute. Returns true if successful, 
 false on failure.
*/
bool sys_chdir(int *stack, uint32_t *eax)
{
	char *dir_name = (char *)pop_arg(&stack);

	int success = (int) process_chdir(dir_name);
	memcpy(eax, &success, sizeof(uint32_t));
	return true;
}

/* Creates the directory named dir, which may be relative or absolute. 
  Returns true if successful, false on failure. Fails if dir already 
  exists or if any directory name in dir, besides the last, 
  does not already exist.
 */
bool 
sys_mkdir(int *stack, uint32_t *eax)
{
	char *dir_name = (char *)pop_arg(&stack);
	int result = 0;
	if(strnlen(dir_name, PGSIZE) > 0)
    result = (int)process_create_file(dir_name, 0, true);

  memcpy(eax, &result, sizeof(uint32_t));

  return true;

}

/* Reads a directory entry from file descriptor fd, 
   which must represent a directory. If successful, stores the 
   null-terminated file name in name, which must have 
   room for READDIR_MAX_LEN + 1 bytes, and returns true. 
   If no entries are left in the directory, returns false.
*/
bool 
sys_readdir(int *stack, uint32_t *eax)
{
	int fd = (int)pop_arg(&stack);
	char *name = (char *)pop_arg(&stack);
	struct dir *dir = process_fd_get_dir(fd);
	int result = 0;
	if(dir != NULL) {
		result = (int)dir_readdir(dir, name);
	}

	memcpy(eax, &result, sizeof(uint32_t));
	return true;
}


/* Returns true if fd represents a directory, 
   false if it represents an ordinary file.
   */
bool 
sys_isdir(int *stack, uint32_t *eax)
{
	int fd = (int)pop_arg(&stack);
	struct dir *dir = process_fd_get_dir(fd);
	int result = 0;
	if(dir != NULL)
		result = 1;

	memcpy(eax, &result, sizeof(uint32_t));
	return true;

}

/* Returns the inode number of the inode associated with fd, 
   which may represent an ordinary file or a directory. */
bool 
sys_inumber(int *stack, uint32_t *eax)
{
	int fd = (int) pop_arg(&stack);

	if (fd < 2)
		return false;

	int inumber = process_fd_inumber(fd);

	if (inumber < 0)
		return false;

	memcpy(eax, &inumber, sizeof(uint32_t));
	return true;
}




