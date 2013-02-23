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
#define PRINT_GROW_STACK(__VA_ARGS__) do {} while(0)
#define PRINT_GROW_STACK_2(X,Y) do {} while(0)
#endif

#if (DEBUG & DEBUG_MAP_SEGMENT)
#define PRINT_MAP_SEGMENT_2(X,Y) {printf("vman_map_segment: "); printf(X,Y);}
#else
#define PRINT_MAP_SEGMENT_2(X,Y) do {} while (0)
#endif


static struct lock lock_frame;

void vman_init(void)
{
	lock_init(&lock_frame);
	frame_init_table(); 
}

bool 
vman_map_segment (void *upage, struct file *file, off_t offset, int init_data_bytes, 
									int uninit_data_bytes, bool writable) 
{

	/*static int klm = 0;
	klm++;*/
	struct thread *t = thread_current();
	int total_bytes = init_data_bytes + uninit_data_bytes;
	int npages = total_bytes/PGSIZE;
	npages += (total_bytes % PGSIZE == 0) ? 0 : 1;

	PRINT_MAP_SEGMENT_2("init_data_bytes: %d, ",init_data_bytes);
	PRINT_MAP_SEGMENT_2("uninit_data_bytes: %d, ",uninit_data_bytes);	
	PRINT_MAP_SEGMENT_2("npages: %d\n",npages);
	/*if (klm > 1)
		npages = npages + 5;*/

	int i;
	for (i=0;i<npages;i++) {
		if (!vman_upage_available(upage+i*PGSIZE))
			return false;
	}

	file_seek (file, offset);
	int bytes_remaining = init_data_bytes;
	for (i=0;i<npages;i++) {
		int valid_bytes = bytes_remaining < PGSIZE ? bytes_remaining : PGSIZE;
		void *cur_upage = (void *)(((uint8_t *)upage) + i*PGSIZE);
		off_t cur_offset = offset + i*PGSIZE;
		page_supplement_install_segpage(t->pst,cur_upage,valid_bytes,file,cur_offset,writable);
		PRINT_MAP_SEGMENT_2("cur_upage: %p, ",cur_upage);
		PRINT_MAP_SEGMENT_2("bytes_remaining: %d\n",bytes_remaining);
		bytes_remaining -= valid_bytes;
	}
	ASSERT(bytes_remaining == 0);


	/*
  while (read_bytes > 0 || zero_bytes > 0) 
    {
          Calculate how to fill this page.
         	We will read PAGE_READ_BYTES bytes from FILE
         	and zero the final PAGE_ZERO_BYTES bytes.
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;


      
      if (!vman_map_mempage(upage,writable))
        return false;

      uint8_t *kpage = pagedir_get_page(t->pagedir, upage);

      if(file_read(file, kpage, page_read_bytes) != (int)page_read_bytes)
      {
        vman_unmap_page(upage);
        return false;
      }
      Advance.
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }*/

	return true;
}

void
vman_load_page(void *upage)
{
	struct thread *t = thread_current();
	ASSERT(!vman_upage_available(upage));
	
	lock_acquire(&lock_frame);

	/*printf("before palloc \n");*/
	void *kpage = palloc_get_page(PAL_USER | PAL_ZERO);
	/*printf("after palloc \n");*/
  if (kpage == NULL) 
  	PANIC("eviction not implemented");

  /* udpate frame table */
  frame_insert(t,upage,kpage);

  /* update page directory and page supplementary tables */
  struct pagesup_entry *pse = page_supplement_get_entry(t->pst,upage);

  off_t bytes_read;
  switch (pse->ptype) {
  	case ptype_stack:
  		break;
  	case ptype_segment:
  		bytes_read = file_read_at (pse->file, kpage, pse->valid_bytes, pse->offset);
  		ASSERT(bytes_read == pse->valid_bytes);
  		memset(kpage + pse->valid_bytes,0,PGSIZE-pse->valid_bytes);
  		pse->valid_bytes = PGSIZE;
  		break;
   	case ptype_segment_readonly:
  	case ptype_file:
  		bytes_read = file_read_at (pse->file, kpage, pse->valid_bytes, pse->offset);
  		ASSERT(bytes_read == pse->valid_bytes);
  		break;
  }

  bool writable = page_supplement_is_writable(pse);
  pagedir_set_page(t->pagedir, upage, kpage, writable);
  pse->kpage = kpage;

	lock_release(&lock_frame);

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


/* returns true if upage is umapped in the supplemental
	 page table */
bool vman_upage_available(void *upage) {
	ASSERT (pg_ofs (upage) == 0);
	struct thread *t = thread_current();
	return (page_supplement_get_entry(t->pst,upage) == NULL);
}

bool vman_grow_stack(void)
{
  struct thread *t = thread_current();
  ASSERT (pg_ofs (t->stack_base) == 0);

  PRINT_GROW_STACK("->entering vman_grow_stack:\n");
  PRINT_GROW_STACK_2("t->stack_base: %p", t->stack_base);
  void *upage = (void *)((uint8_t *)t->stack_base - PGSIZE);
  /* get rid of this once we EVICTION is implemented */
  ASSERT(pagedir_get_page(t->pagedir,upage) == NULL);

  if (!vman_upage_available(upage))
  	return false;

	page_supplement_install_stackpage(t->pst,upage);
	vman_load_page(upage);
	PRINT_GROW_STACK("->leaving vman_grow_stack.\n");
	t->stack_base = upage;
  return true;
}

