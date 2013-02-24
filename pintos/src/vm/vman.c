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

#if (DEBUG & DEBUG_STACK)
#define PRINT_GROW_STACK(__VA_ARGS__) printf(__VA_ARGS__)
#define PRINT_GROW_STACK_2(X,Y) {printf("vman_grow_stack: "); printf(X,Y);}
#else
#define PRINT_GROW_STACK(X) do {} while(0)
#define PRINT_GROW_STACK_2(X,Y) do {} while(0)
#endif

#if (DEBUG & DEBUG_MAP_SEGMENT)
#define PRINT_MAP_SEGMENT_2(X,Y) {printf("vman_map_segment: "); printf(X,Y);}
#else
#define PRINT_MAP_SEGMENT_2(X,Y) do {} while (0)
#endif

#if (DEBUG & DEBUG_MAP_FILE)
#define PRINT_MAP_FILE_2(X,Y) {printf("vman_map_file: "); printf(X,Y);}
#else
#define PRINT_MAP_FILE_2(X,Y) do {} while (0)
#endif

#if (DEBUG & DEBUG_UNMAP_FILE)
#define PRINT_UNMAP_FILE_2(X,Y) {printf("vman_unmap_file: "); printf(X,Y);}
#else
#define PRINT_UNMAP_FILE_2(X,Y) do {} while (0)
#endif

extern struct lock lock_filesys; /* a coarse global lock restricting access 
                            to the file system */

void vman_init(void)
{
	frame_init_table(); 
}

bool 
vman_upages_available(void *upage_head, int npages)
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

/* install a mem-mapped file into the supplementary table,
	 by determining the number of pages needed */
bool 
vman_map_file(void *upage, struct file *file, uint32_t file_len)
{
	struct thread *t = thread_current();
	int npages = num_pages(file_len);

	PRINT_MAP_FILE_2("file_len: %d, ",file_len);
	PRINT_MAP_FILE_2("npages: %d\n",npages);

	if (!vman_upages_available(upage, npages))
		return false;

	int bytes_remaining = file_len;
	int i;
	for (i=0;i<npages;i++) {
		int valid_bytes = bytes_remaining < PGSIZE ? bytes_remaining : PGSIZE;
		void *cur_upage = (void *)(((uint8_t *)upage) + i*PGSIZE);
		off_t cur_offset = i*PGSIZE;
		page_supplement_install_filepage(&t->pst,cur_upage,valid_bytes,file,cur_offset);
		PRINT_MAP_FILE_2("cur_upage: %p, ",cur_upage);
		PRINT_MAP_FILE_2("bytes_remaining: %d\n",bytes_remaining);
		bytes_remaining -= valid_bytes;
	}
	ASSERT(bytes_remaining == 0);

	return true;
}

bool 
vman_map_segment (void *upage, struct file *file, off_t offset, int init_data_bytes, 
									int uninit_data_bytes, bool writable) 
{
	struct thread *t = thread_current();
	int total_bytes = init_data_bytes + uninit_data_bytes;
	int npages = num_pages(total_bytes);

	PRINT_MAP_SEGMENT_2("init_data_bytes: %d, ",init_data_bytes);
	PRINT_MAP_SEGMENT_2("uninit_data_bytes: %d, ",uninit_data_bytes);	
	PRINT_MAP_SEGMENT_2("npages: %d\n",npages);

	if (!vman_upages_available(upage, npages))
		return false;

	file_seek (file, offset);
	int bytes_remaining = init_data_bytes;
	int i;
	for (i=0;i<npages;i++) {
		int valid_bytes = bytes_remaining < PGSIZE ? bytes_remaining : PGSIZE;
		void *cur_upage = (void *)(((uint8_t *)upage) + i*PGSIZE);
		off_t cur_offset = offset + i*PGSIZE;
		page_supplement_install_segpage(&t->pst,cur_upage,valid_bytes,file,cur_offset,writable);
		PRINT_MAP_SEGMENT_2("cur_upage: %p, ",cur_upage);
		PRINT_MAP_SEGMENT_2("bytes_remaining: %d\n",bytes_remaining);
		bytes_remaining -= valid_bytes;
	}
	ASSERT(bytes_remaining == 0);

	return true;
}

void
vman_load_page(void *upage)
{
	struct thread *t = thread_current();
	ASSERT(!vman_upages_available(upage, 1));

	void *kpage = frame_alloc();

  /* udpate frame & page supplementary tables */
  struct pagesup_entry *pse = page_supplement_get_entry(&t->pst, upage);
  frame_install(pse, kpage);

  /* load the actual data */
  off_t bytes_read;
  switch (pse->ptype) {
  	case ptype_stack:
  		break;
  	case ptype_segment:
  		bytes_read = file_read_at (pse->file, kpage, pse->valid_bytes, pse->offset);
  		ASSERT(bytes_read == pse->valid_bytes);
  		memset(kpage + pse->valid_bytes,0,PGSIZE-pse->valid_bytes);
  		pse->valid_bytes = PGSIZE;
  		pse->file = NULL;
  		pse->offset = -1;
  		break;
   	case ptype_segment_readonly:
  	case ptype_file:
  		bytes_read = file_read_at (pse->file, kpage, pse->valid_bytes, pse->offset);
  		ASSERT(bytes_read == pse->valid_bytes);
  		break;
  }

  /* update page directory */
  bool writable = page_supplement_is_writable(pse);
  pagedir_set_page(t->pagedir, upage, kpage, writable);
  pse->kpage = kpage;



	/*
		1. validation:
				- check that pst is installed, and is not loaded (fte == NULL)
		2. lock frame
		3. vman should do clok algorithm and get next frame table entry . 
		4. Check if frame is currently occupied, if so [ HANDLE EVICTION ]
		5. Assume ALL NEW PAGES. call palloc from User pool.
		6. install into page directory.
		7. update "fte" in supplemental page table
		8. update fte
		9.release frame lock

	*/

}


bool 
vman_grow_stack(void)
{
  struct thread *t = thread_current();
  ASSERT (pg_ofs (t->stack_base) == 0);

  PRINT_GROW_STACK("->entering vman_grow_stack:\n");
  PRINT_GROW_STACK_2("t->stack_base: %p", t->stack_base);
  void *upage = (void *)((uint8_t *)t->stack_base - PGSIZE);
  /* get rid of this once we EVICTION is implemented */
  ASSERT(pagedir_get_page(t->pagedir,upage) == NULL);

  if (!vman_upages_available(upage, 1))
  	return false;

	page_supplement_install_stackpage(&t->pst,upage);
	vman_load_page(upage);
	PRINT_GROW_STACK("->leaving vman_grow_stack.\n");
	t->stack_base = upage;
  return true;
}

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

		pse = page_supplement_get_entry(pst, cur_upage);
		ASSERT( pse != NULL);

		PRINT_UNMAP_FILE_2("cur_upage: %p\n", cur_upage);
		PRINT_UNMAP_FILE_2("pse->upage: %p\n", pse->upage);
		PRINT_UNMAP_FILE_2("pse->kpage: %p\n", pse->kpage);
		PRINT_UNMAP_FILE_2("pse->file: %p\n", pse->file);
		PRINT_UNMAP_FILE_2("pse->offset: %d\n", pse->offset);
		PRINT_UNMAP_FILE_2("pse->valid_bytes: %d\n", pse->valid_bytes);
		PRINT_UNMAP_FILE_2("pse->ptype: %d\n", pse->ptype);

		/* write to disk if necessary */
		if (pse->kpage != NULL && pagedir_is_dirty (pd, cur_upage)){
			lock_acquire(&lock_filesys);
			off_t bytes_written = file_write (pse->file, pse->kpage, pse->valid_bytes);
			lock_release(&lock_filesys);
			ASSERT(bytes_written == pse->valid_bytes); 
		}

		/* clear the page directory entry */
		pagedir_clear_page (pd, cur_upage);

		/* free the physical frame & frame table entry */
		frame_remove(pse);

		/* remove the supplemental page table entry */
		page_supplement_free(pst, pse);
	}
}
