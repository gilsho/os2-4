#include "vm/frame.h"
#include "vm/pagesup.h"
#include "threads/synch.h"
#include "threads/palloc.h"
#include "userprog/pagedir.h"
#include "vm/swap.h"
#include "threads/vaddr.h"
#include <stdio.h>
#include <string.h>

extern struct lock lock_filesys;

/* A lock for the frame table */
struct lock lock_frame;

/* Frame table is stored as a list data structure */
struct list frame_list;

/* The clock hand is stored as a pointer to an list element */
static struct list_elem *clock_hand;

void frame_clock_advance(void);
void frame_swap_out(struct pagesup_entry *pse, void *buff);

void 
frame_init_table() 
{
	lock_init(&lock_frame);
	list_init(&frame_list);
	clock_hand = list_head(&frame_list);
}

/* This function will return a frame for use. First it tries to get a frame from the
free page pool. If it cannot find one there, it uses the clock algorithm
to evict a current page and return that frame. */
void *
frame_alloc(void)
{	
	void *kpage = palloc_get_page(PAL_USER | PAL_ZERO);
  if (kpage == NULL) 
  {
  	/* CLOCK ALGORITHM */
  	while (true) 
  	{
  		frame_clock_advance();

  		struct pagesup_entry *pse = list_entry(clock_hand, struct pagesup_entry, frame_elem);
  		
  		/* Must have the lock for this entry before trying to evict it */
  		if (lock_try_acquire(&pse->lock))
  		{
  			ASSERT(pse->ploc == ploc_memory);
  			uint32_t *pd = pse->owner->pagedir;
  			if (!pagedir_is_accessed(pd, pse->upage) )
  			{
  				kpage = pse->kpage;
  				frame_evict(pse);
  				lock_release(&pse->lock);
  				break;
  			}
  			else {
  				/* Clear the page accessed bit */
  				pagedir_set_accessed (pd, pse->upage, false);
  			}

  			lock_release(&pse->lock);
  		}
  	}

  }
  memset(kpage, 0, PGSIZE);
  return kpage;
}

/* 
	Installs a frame into the frame table. Caller should be holding
	frame table lock
*/
void
frame_install(struct pagesup_entry *pse, void *kpage)
{
	pse->kpage = kpage;
	list_push_back(&frame_list,&pse->frame_elem);
}

/*
	Releases the frame being held by the give page table entry.
	Must be careful here to update the clock hand if the clock
	hand happens to point to the frame that is being released.
	Caller must have frame table lock.
*/
void 
frame_release(struct pagesup_entry *pse)
{

	if (pse->ploc == ploc_memory) {

		if (clock_hand == &pse->frame_elem) {
			clock_hand = list_next(clock_hand);	
		}

		list_remove(&pse->frame_elem);

		pse->kpage = NULL;
	}
	else if (pse->ploc == ploc_swap)
	{
		swap_release_slot((size_t) pse->info.s.slot_index);
	}	

}

/* 
	Advances the clock hand. Ensures that, at the end of this function
	the clock hand points to an interior element in the list.
	Caller must have frame lock 
*/
void
frame_clock_advance(void)
{

	ASSERT(lock_held_by_current_thread(&lock_frame));
	ASSERT(!list_empty(&frame_list));
	if (clock_hand == list_back(&frame_list) || clock_hand == list_tail(&frame_list))
		clock_hand = list_front(&frame_list);
	else
		clock_hand = list_next(clock_hand); 
	ASSERT(clock_hand != list_head(&frame_list));
	ASSERT(clock_hand != list_tail(&frame_list));
}

/* 
	Evicts the given page entry from the frame table. 
	Correct ordering here is crucial. We must first clear the page
	directory, so that any page accessess will now page fault.
	We then switch on the type of page. If it is code (read-only), then
	there is no need to write to disk. If it is stack or data, it must
	be written to swap. For mmap files, we only write to file if the
	page is dirty
	Caller must hold both the frame table lock and the lock for the given
	PSE 
*/
void
frame_evict(struct pagesup_entry *pse)
{
	ASSERT(lock_held_by_current_thread(&pse->lock));
	ASSERT(lock_held_by_current_thread(&lock_frame));

	void *buff_to_write = pse->kpage;
	pse->kpage = NULL;
	uint32_t *pd = pse->owner->pagedir;

	bool dirty = pagedir_is_dirty (pd, pse->upage);
	pagedir_clear_page (pd, pse->upage);

	struct list_elem *e = list_remove(&pse->frame_elem);
	ASSERT( e != NULL );

	if (clock_hand == &pse->frame_elem) {
		clock_hand = list_next(clock_hand);	
	}

	off_t bytes_written;
	ASSERT(pse->ploc == ploc_memory);

	switch (pse->ptype)
	{
		case ptype_segment_readonly:
			pse->ploc = ploc_file;
			return;
		case ptype_file:
			if (dirty)
			{
				lock_acquire(&lock_filesys);
				bytes_written = file_write_at (pse->info.f.file, 
																			 buff_to_write, 
																			 (off_t) pse->valid_bytes, 
																			 pse->info.f.offset);
				ASSERT(bytes_written == pse->valid_bytes);
				lock_release(&lock_filesys);
			}
			pse->ploc = ploc_file;
			break;
  	case ptype_stack:
  		frame_swap_out(pse, buff_to_write);
  		pse->ploc = ploc_swap;
  		break;
  	case ptype_segment:
  		frame_swap_out(pse, buff_to_write);
  		pse->ploc = ploc_swap;
			break;
		default:
			break;
	}
	ASSERT(pse->ploc != ploc_memory);
}

/* 
	Helper function to write a page to the swap space.
*/
void
frame_swap_out(struct pagesup_entry *pse, void *buff)
{
	pse->info.s.slot_index = swap_write_slot(buff);
}
