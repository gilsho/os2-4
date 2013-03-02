#include "vm/vman.h"
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
#include "vm/frame.h"
#include "vm/pagesup.h"
#include "vm/mmap.h"
#include "vm/swap.h"


/* Virtual Memory Manager 
	 ---------------------
	 this module manages the virtual memory for a process.
	 all request to allocate/deallocate memory should be tunneled
	 through the interface provided by vman.h
 */

extern struct lock lock_filesys; /* a coarse global lock for synchronizing access 
				                            to the file system */

extern struct lock lock_frame;	 /* a lock for synchronizing access to the frame
																		table */


void vman_load_page_helper(struct pagesup_entry *pse);

/* initialize the virtual memory manager */
void vman_init(void)
{
	frame_init_table(); 
}

/* checks whether a region in virtual memory is unmapped. */
bool 
vman_upages_unmapped(void *upage_head, int npages)
{
	ASSERT (pg_ofs (upage_head) == 0);
	struct thread *t = thread_current();
	int i;
	for (i=0;i<npages;i++) {
		char *cur_upage = ((char *)upage_head)+i*PGSIZE;
		if (page_supplement_get_entry(&(t->pst),cur_upage) != NULL)
			return false;
	}
	return true;
}

/* creates a mapping in the page supplemental table for a mem-mapped file. 
	 returns true if operation was successful */
bool 
vman_map_file(void *upage, struct file *file, uint32_t file_len)
{
	struct thread *t = thread_current();
	int npages = num_pages(file_len);

	if (!vman_upages_unmapped(upage, npages))
		return false;

	int bytes_remaining = file_len;
	int i;
	for (i=0;i<npages;i++) {
		int valid_bytes = bytes_remaining < PGSIZE ? bytes_remaining : PGSIZE;
		void *cur_upage = (void *)(((uint8_t *)upage) + i*PGSIZE);
		off_t cur_offset = i*PGSIZE;
		page_supplement_install_filepage(&t->pst,cur_upage,valid_bytes,file,cur_offset);
		bytes_remaining -= valid_bytes;
	}
	ASSERT(bytes_remaining == 0);

	return true;
}

/* creates a mapping in the supplemental table for a data segment. returns true
   if the operation was successful. */
bool 
vman_map_segment (void *upage, struct file *file, off_t offset, int init_data_bytes, 
									int uninit_data_bytes, bool writable) 
{
	struct thread *t = thread_current();
	int total_bytes = init_data_bytes + uninit_data_bytes;
	int npages = num_pages(total_bytes);

	if (!vman_upages_unmapped(upage, npages))
		return false;

	file_seek (file, offset);
	int bytes_remaining = init_data_bytes;
	int i;
	for (i=0;i<npages;i++) {
		int valid_bytes = bytes_remaining < PGSIZE ? bytes_remaining : PGSIZE;
		void *cur_upage = (void *)(((uint8_t *)upage) + i*PGSIZE);
		off_t cur_offset = offset + i*PGSIZE;
		page_supplement_install_segpage(&t->pst,cur_upage,valid_bytes,file,cur_offset,writable);
		bytes_remaining -= valid_bytes;
	}
	ASSERT(bytes_remaining == 0);

	return true;
}

/* loads a page into memory. exact behavior depends on type of the page.
   stack pages are paged in from swap, data segements are either lazy 
   loaded from file or paged in from swap, and code segements and memory
    mapped files are always read from file.

    IMPORTANT: the lock on the supplementary page table entry remains
    					 held after the termination of this function.
 */
void
vman_load_page_helper(struct pagesup_entry *pse)
{

	ASSERT(pse->ploc != ploc_memory);

	struct thread *t = thread_current();

	/* acquire locks in order */
	lock_acquire(&lock_frame);
	lock_acquire(&pse->lock);

	void *kpage = frame_alloc();

	/* once a frame has been found, release frame lock and
		 keep supplemental page table entry lock */
	lock_release(&lock_frame);

  /* load the actual data from an external location if necessary */
  off_t bytes_read;
  switch (pse->ptype) {
  	case ptype_stack:
  		if(pse->ploc == ploc_swap) {
  			swap_read_slot(pse->info.s.slot_index, kpage);
  		}
  		break;
  	case ptype_segment:
  		ASSERT(pse->ploc != ploc_none);
  		if (pse->ploc == ploc_file) {
	  		bytes_read = file_read_at (pse->info.f.file, kpage, pse->valid_bytes, pse->info.f.offset);
	  		ASSERT(bytes_read == pse->valid_bytes);
	  		memset(kpage + pse->valid_bytes,0,PGSIZE-pse->valid_bytes);
	  		pse->valid_bytes = PGSIZE;
  		}
  		else if(pse->ploc == ploc_swap) {
  			swap_read_slot(pse->info.s.slot_index, kpage);
  		}
  		break;
   	case ptype_segment_readonly:
  	case ptype_file:
  		bytes_read = file_read_at (pse->info.f.file, kpage, pse->valid_bytes, pse->info.f.offset);
  		ASSERT(bytes_read == pse->valid_bytes);
  		break;
  }

	pse->ploc = ploc_memory;
  frame_install(pse, kpage);

  /* update page directory */
  bool writable = page_supplement_is_writable(pse);
  pagedir_set_page(t->pagedir, pse->upage, kpage, writable);
  pagedir_set_accessed (t->pagedir, pse->upage, true);
}

/* external interface for loading a page into memory. the function calls 
	 vman_load_page_helper and immediately releases the lock on the supplemental
	 page table entry */
void
vman_load_page(void *upage)
{
	struct thread *t = thread_current();
  struct pagesup_entry *pse = page_supplement_get_entry(&t->pst, upage); 

  vman_load_page_helper(pse);
  lock_release(&pse->lock);
	
}

/* pins a page into memory. utilizes vman_load_page_helper. the lock for the 
	 page supplemental table entry is held after the function finishes execution,
	 preventing the page from being evicted to memory.
	 */
void
vman_pin_page(void *upage)
{

	pagesup_table *pst = &(thread_current()->pst);
	struct pagesup_entry *pse = page_supplement_get_entry(pst,upage);

	if (pse->ploc != ploc_memory)
		vman_load_page_helper(pse);
	else
		lock_acquire(&pse->lock);

}

/* unpins a page, allowing it to be evicted from memory. this is achieved
	 by releasing the lock on the page's supplemental page table entry */
void
vman_unpin_page(void *upage)
{
	pagesup_table *pst = &(thread_current()->pst);
	struct pagesup_entry *pse = page_supplement_get_entry(pst,upage);
	lock_release(&(pse->lock));
}


/* grows the stack by allocating a new page beneath the 
	 current page of the stack */
bool 
vman_grow_stack(void)
{
  struct thread *t = thread_current();
  ASSERT (pg_ofs (t->stack_base) == 0);

  void *upage = (void *)((uint8_t *)t->stack_base - PGSIZE);

  if (!vman_upages_unmapped(upage, 1))
  	return false;

	page_supplement_install_stackpage(&t->pst,upage);
	vman_load_page(upage);
	t->stack_base = upage;
  return true;
}

/* unmaps a memory mapped file mapped to a given user virtual address */
void
vman_unmap_file(void *upage, uint32_t file_len)
{
	int npages = num_pages(file_len);
	struct thread *t = thread_current();
	uint32_t *pd = t->pagedir;
	pagesup_table *pst = &t->pst;
	struct pagesup_entry *pse;

	int i;
	for (i=0;i<npages;i++) {

		void *cur_upage = (void *)(((uint8_t *)upage) + i*PGSIZE);

		lock_acquire(&lock_frame);

		pse = page_supplement_get_entry(pst, cur_upage);
		lock_acquire(&pse->lock);
		ASSERT( pse != NULL);


		/* write to disk if necessary */
		
		if (pse->ploc == ploc_memory && pagedir_is_dirty (pd, cur_upage)){
			lock_acquire(&lock_filesys);
			off_t bytes_written = file_write_at (pse->info.f.file, pse->kpage, 
																					 pse->valid_bytes, pse->info.f.offset);
			lock_release(&lock_filesys);
			ASSERT(bytes_written == pse->valid_bytes); 
		}

		/* clear the page directory entry */
		pagedir_clear_page (pd, cur_upage);

		/* free the physical frame & frame table entry */
		frame_release(pse);

		lock_release(&pse->lock);

		lock_release(&lock_frame);

		/* remove the supplemental page table entry */
		page_supplement_free(pst, pse);
	}
}


/* destroy the virtual memory of a process. free all frames currently occupied
	 and all data structures associated with memory management. */
void
vman_free_all_pages(void)
{
	struct thread *t = thread_current();
	pagesup_table *pst = &(t->pst);
	uint32_t *pd = t->pagedir;
	lock_acquire(&lock_frame);

	page_supplement_destroy(pst,&frame_release);

	/* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  
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


	lock_release(&lock_frame);
}
