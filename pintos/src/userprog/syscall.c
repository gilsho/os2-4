#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"

/* Interrupt stack frame.
struct intr_frame
  {
    /* Pushed by intr_entry in intr-stubs.S.
       These are the interrupted task's saved registers.
    uint32_t edi;               /* Saved EDI. 
    uint32_t esi;               /* Saved ESI. *
    uint32_t ebp;               /* Saved EBP. *
    uint32_t esp_dummy;         /* Not used. *
    uint32_t ebx;               /* Saved EBX. *
    uint32_t edx;               /* Saved EDX. *
    uint32_t ecx;               /* Saved ECX. *
    uint32_t eax;               /* Saved EAX. *
    uint16_t gs, :16;           /* Saved GS segment register. *
    uint16_t fs, :16;           /* Saved FS segment register. *
    uint16_t es, :16;           /* Saved ES segment register. *
    uint16_t ds, :16;           /* Saved DS segment register. *

    /* Pushed by intrNN_stub in intr-stubs.S. 
    uint32_t vec_no;            /* Interrupt vector number. *

    /* Sometimes pushed by the CPU,
       otherwise for consistency pushed as 0 by intrNN_stub.
       The CPU puts it just under `eip', but we move it here. *
    uint32_t error_code;        /* Error code. *

    /* Pushed by intrNN_stub in intr-stubs.S.
       This frame pointer eases interpretation of backtraces. *
    void *frame_pointer;        /* Saved EBP (frame pointer). *

    /* Pushed by the CPU.
       These are the interrupted task's saved registers. *
    void (*eip) (void);         /* Next instruction to execute. *
    uint16_t cs, :16;           /* Code segment for eip. *
    uint32_t eflags;            /* Saved CPU flags. *
    void *esp;                  /* Saved stack pointer. *
    uint16_t ss, :16;           /* Data segment for esp. *
  };
*/

int pop_arg(int **ustack_);
bool valid_user_addr(void *uaddr);

bool sys_halt(int *stack);
bool sys_exit(int *stack);
bool sys_exec(int *stack);
bool sys_wait(int *stack);
bool sys_create(int *stack);
bool sys_remove(int *stack);
bool sys_open(int *stack);
bool sys_filesize(int *stack);
bool sys_read(int *stack);
bool sys_write(int *stack);
bool sys_seek(int *stack);
bool sys_tell(int *stack);
bool sys_close(int *stack);

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
	int *ustack =  f->esp;

	int syscall_num = pop_arg(&ustack);
	bool success = false;
	switch(syscall_num) {
		case SYS_HALT:
			success = sys_halt(ustack);  
			break;                 
		case SYS_EXIT:
			success = sys_exit(ustack);                   
			break; 
    case SYS_EXEC:                   
			success = sys_exec(ustack);
			break; 
    case SYS_WAIT: 
    	success = sys_wait(ustack);                  
			break; 
    case SYS_CREATE:  
    	success = sys_create(ustack);
			break; 
    case SYS_REMOVE:                 
			success = sys_remove(ustack);
			break; 
    case SYS_OPEN:                   
			success = sys_open(ustack);
			break; 
    case SYS_FILESIZE:               
			success = sys_filesize(ustack);
			break; 
    case SYS_READ:                 
			success = sys_read(ustack);
			break; 
    case SYS_WRITE:                 
			success = sys_write(ustack);
			break; 
    case SYS_SEEK:                   
			success = sys_seek(ustack);
			break; 
    case SYS_TELL:                  
			success = sys_tell(ustack);
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
  		thread_exit ();
  	}
}


int 
pop_arg(int **ustack)
{
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



/* Halt the operating system. */
bool sys_halt(int *stack)
{
	/* Change once implemented */
	return false;	
}

/* Terminate this process. */
bool sys_exit(int *stack)
{
	int status = pop_arg(&stack);
	/* Change once implemented */
	return false;		
}

/* Start another process. */
bool sys_exec(int *stack)
{
	const char *cmdline = (char *) pop_arg(&stack);
	/* Change once implemented */
	return false;	
}

/* Wait for a child process to die. */
bool sys_wait(int *stack)
{
	int pid = pop_arg(&stack);
	/* Change once implemented */
	return false;		
}

/* Create a file. */
bool sys_create(int *stack)
{
	const char *file = (const char *) pop_arg(&stack);
	unsigned size = (unsigned) pop_arg(&stack);

	/* Change once implemented */
	return false;	
}

/* Delete a file. */
bool sys_remove(int *stack)
{
	const char *file = (const char *) pop_arg(&stack);

	/* Change once implemented */
	return false;		
}

/* Open a file. */
bool sys_open(int *stack)
{
	const char *file = (const char *) pop_arg(&stack);
	/* Change once implemented */
	return false;		
}

/* Obtain a file's size. */
bool sys_filesize(int *stack)
{
	int fd = pop_arg(&stack);
	/* Change once implemented */
	return false;		
}

 /* Read from a file. */
bool sys_read(int *stack)
{
	int fd = pop_arg(&stack);
	void *buffer = (void *) pop_arg(&stack);
	unsigned size = (unsigned) pop_arg(&stack);
	/* Change once implemented */
	return false;		
}

/* Write to a file. */
bool sys_write(int *stack)
{
	int fd = pop_arg(&stack);
	const void *buffer = (const void *) pop_arg(&stack);
	unsigned size = (unsigned) pop_arg(&stack);
	/*printf(" <- In sys_write() fd: %d, buf: %s, size: %d -> \n",fd,(char *)buffer,size);*/

	if (!valid_user_addr(buffer)) 
			return false;

	/* Change once implemented */
	if (fd = 1) {
		putbuf(buffer,size);
		return true;
	}
	return false;		
}

/* Change position in a file. */
bool sys_seek(int *stack)
{
	int fd = pop_arg(&stack);
	unsigned position = pop_arg(&stack);
	/* Change once implemented */
	return false;		
}

/* Report current position in a file. */
bool sys_tell(int *stack)
{
	int fd = pop_arg(&stack);
	/* Change once implemented */
	return false;		
}

/* Close a file. */
bool sys_close(int *stack)
{
	int fd = pop_arg(&stack);
	/* Change once implemented */
	return false;	
}





