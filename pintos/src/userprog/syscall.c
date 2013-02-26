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
#include "vm/mmap.h"
#include "vm/pagesup.h"
#include "vm/vman.h"

#define FILENAME_MAX 14

#if (DEBUG & DEBUG_SYS_CALL)
#define PRINT_SYS_READ_2(X,Y) {printf("sys_read: "); printf(X,Y);}
#define PRINT_SYS_MMAP_2(X,Y) {printf("sys_mmap: "); printf(X,Y);}
#define PRINT_SYS_MMAP(X) printf(X)
#define PRINT_VALID(X) printf(X)
#define PRINT_VALID_2(X,Y) {printf("valid: "); printf(X,Y);}
#else
#define PRINT_SYS_READ_2(X,Y) do {} while(0)
#define PRINT_SYS_MMAP(X) do {} while(0)
#define PRINT_SYS_MMAP_2(X,Y) do {} while(0)
#define PRINT_VALID(X) do {} while(0)
#define PRINT_VALID_2(X,Y) do {} while(0)
#endif


extern struct lock lock_filesys;

void syscall_init (void);
static void syscall_handler (struct intr_frame *);

int pop_arg(int **ustack_);
bool valid_user_addr(void *uaddr);
bool valid_str(const char *s, unsigned max_len);
bool is_user_buffer(void *s, unsigned len);
bool valid_range(void *_uaddr_start,void *_uaddr_end,bool check_writable);

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
bool sys_mmap(int *stack, uint32_t *eax);
bool sys_munmap(int *stack);


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
      success = sys_mmap(ustack, ueax);
    	break;
    case SYS_MUNMAP:               /* Remove a memory mapping. */
      success = sys_munmap(ustack);
      break;
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

bool
valid_range(void *_uaddr_start,void *_uaddr_end,bool check_writable)
{
	uint8_t *uaddr = (uint8_t *) _uaddr_start;
	uint8_t *uaddr_end = (uint8_t *) _uaddr_end;
	struct thread *t = thread_current();

	while (uaddr <= uaddr_end) {
		void *upage = pg_round_down(uaddr);
		if (!page_supplement_is_mapped(&t->pst,upage))
			return false;

		if(check_writable) {
			struct pagesup_entry *pse = page_supplement_get_entry(&t->pst,upage);
			if (!page_supplement_is_writable(pse))
				return false;
		}

		uaddr += PGSIZE;
	}
	return true;
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

	pagesup_table *pst = &(thread_current()->pst);
	if (!page_supplement_is_mapped(pst,uaddr))
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

/* assumes _s is page aligned */
bool 
is_user_buffer(void *upage, unsigned len)
{	
	char *s = (char *)upage;

  int npages = num_pages(len);
  int i;
  for (i=0; i<npages; i++) {
  	if (!is_user_vaddr(s)) {
  		PRINT_VALID_2("invalid buffer: %p\n", s);
  		return false;
  	}
    s += PGSIZE;
  }
  
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

	if (fd < 0) {
		lock_acquire(&lock_filesys);
		file_close (f);
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
	int fd = pop_arg(&stack);
	uint8_t *buffer = (uint8_t *) pop_arg(&stack);
	unsigned size = (unsigned) pop_arg(&stack);
	
	uint8_t *buffer_end = ((uint8_t *) buffer) + size;

	PRINT_SYS_READ_2("buffer: %p, ",buffer);
	PRINT_SYS_READ_2("buffer_end: %p\n", buffer_end);
	PRINT_SYS_READ_2("valid_user_addr(buffer): %d, ", valid_user_addr(buffer));
	PRINT_SYS_READ_2("valid_user_addr(buffer_end): %d\n",valid_user_addr(buffer_end));

	if (!valid_user_addr(buffer) ||
		!valid_user_addr(buffer_end) ||
		!valid_range(buffer,buffer_end,true))
	  return false;
	  
	int cummulative_bytes_read = 0;
	  
	/* special case: read from STDIN */
	if (fd == 0) 
	{
	  uint8_t c;	  
	  while (cummulative_bytes_read < (int) size)
	  {
	    c = input_getc ();
	    memcpy(&(buffer[cummulative_bytes_read]), &c, sizeof(uint8_t));
	    cummulative_bytes_read++;
	  }
	}
	else if (fd == 1)
	{
		return false;
	}
	else 
	{
	  /* check for invalid file or STDOUT */
	  struct file *file = process_get_file_desc(fd);
	  PRINT_SYS_READ_2("fd: %d, ",fd);
	  PRINT_SYS_READ_2("file (after opening): %p\n", file);
	  if (file == NULL)
	  {
	    cummulative_bytes_read = -1;
	  }
	  else /* valid file found */
	  {
	    uint8_t *cur_buf = buffer;
	    int bytes_remaining = (int) size;
	    while (bytes_remaining > 0)
	    {

	    	int bytes_to_end = PGSIZE - pg_ofs(cur_buf);
	    	int bytes_to_read = bytes_remaining > bytes_to_end ? bytes_to_end : bytes_remaining; 


	    	/* pin page */
	    	void *upage = pg_round_down(cur_buf);
	    	vman_pin_page(upage);

	    	lock_acquire(&lock_filesys);
	    	int bytes_read = (int) file_read (file,cur_buf, (off_t) bytes_to_read);
	    	lock_release(&lock_filesys);

	    	/* unpin page */
	    	vman_unpin_page(upage);

	    	cummulative_bytes_read += bytes_read;
	    	if (bytes_read != bytes_to_read)
	    		break;

	    	cur_buf += bytes_read;
	    	bytes_remaining -= bytes_read;

	    }

    }
  }
  	
	/* push syscall result to the user program */
  memcpy(eax, &cummulative_bytes_read, sizeof(uint32_t));
	
	return true;	
}

/* Write to a file. */
bool sys_write(int *stack, uint32_t *eax)
{
	int fd = pop_arg(&stack);
	void *buffer = (void *) pop_arg(&stack);
	unsigned size = (unsigned) pop_arg(&stack);

	void *buffer_end = ((char *) buffer) + size;

	if (!valid_user_addr((void *)buffer) ||
		!valid_user_addr(buffer_end) ||
		!valid_range(buffer,buffer_end,false))
	  return false;

	int cummulative_bytes_written = 0;

  /* special case: write to STDOUT */
	if (fd == 1) {
		putbuf(buffer,size);
		cummulative_bytes_written = size;
	}
	else if (fd == 0) {
		return false;
	} else {
	  /* check for invalid file or STDIN */
	  struct file *file = process_get_file_desc(fd);
	  if (file == NULL)
	  {
	    cummulative_bytes_written = -1;
	  }
	  else /* valid file found */
	  {
	  	uint8_t *cur_buf = buffer;
	    int bytes_remaining = (int) size;
	    while (bytes_remaining > 0)
	    {

	  		int bytes_to_end = PGSIZE - pg_ofs(cur_buf);
	    	int bytes_to_write = bytes_remaining > bytes_to_end ? bytes_to_end : bytes_remaining;

	    	void *upage = pg_round_down(cur_buf);

	    	/* pin page */
	    	vman_pin_page(upage);

		  	lock_acquire(&lock_filesys);
	    	int bytes_written = (int) file_write (file, cur_buf, (off_t) bytes_to_write); 
	    	lock_release(&lock_filesys);	

	    	/* unpin page */
	    	vman_unpin_page(upage);

	    	cummulative_bytes_written += bytes_written;
	    	if (bytes_written != bytes_to_write)
	    		break;

	    	cur_buf += bytes_written;
	    	bytes_remaining -= bytes_written;

	    }
	  }
	}
	
	/* push syscall result to the user program */
  memcpy(eax, &cummulative_bytes_written, sizeof(uint32_t));
	
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


bool
sys_mmap(int *stack, uint32_t *eax)
{
  int fd = pop_arg(&stack);
  char *addr = (char *)pop_arg(&stack);

  mapid_t mid = -1;

  PRINT_SYS_MMAP_2("fd: %d,",fd);
  PRINT_SYS_MMAP_2("addr: %p\n",addr);

  /* addr must not be 0 (reserved) and must be page-aligned 
  	 and the user vaddr range is valid */
  if ( (addr != 0) && (pg_ofs((void *)addr) == 0) )
  {
  	struct file *old_file = process_get_file_desc(fd);
  	if (old_file != NULL)
  	{
		  struct file *file = file_reopen (old_file);

		  PRINT_SYS_MMAP_2("file: %p,",file);

		  if (file != NULL)
		  {
			  uint32_t file_len;
				lock_acquire(&lock_filesys);
				file_len = (uint32_t) file_length (file);
				lock_release(&lock_filesys);
				PRINT_SYS_MMAP_2("file_len: %d\n",file_len);

				/* verify that file_len is nonzero and memory range is valid user space */
				if ( file_len > 0 && is_user_buffer(addr, file_len))
				{	
					PRINT_SYS_MMAP("obtaining mid in sys_mmap\n");
			    mid = process_map_file(addr, file, file_len);
			    PRINT_SYS_MMAP_2("mid = %d\n", mid);
			  }
			}

		}
	}
  
	/* push syscall result to the user program */
  memcpy(eax, &mid, sizeof(uint32_t));

  return true;
}

bool
sys_munmap(int *stack)
{
  mapid_t mid = (mapid_t)pop_arg(&stack);

  return process_unmap_file(mid);
}
