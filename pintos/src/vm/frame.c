#include "vm/frame.h"
#include "vm/pagesup.h"
#include "threads/synch.h"
#include "threads/palloc.h"
#include "userprog/pagedir.h"
#include "vm/swap.h"
#include <stdio.h>

struct lock lock_frame;
static struct list frame_list;
struct list_elem *clock_hand;

void frame_clock_advance(void);
void frame_evict(struct pagesup_entry *pse);


void 
frame_init_table() 
{
	lock_init(&lock_frame);
	list_init(&frame_list);
	clock_hand = list_begin(&frame_list);
}

void *
frame_alloc(void)
{	
	void *kpage = palloc_get_page(PAL_USER | PAL_ZERO);
  if (kpage == NULL) 
  {
  	lock_acquire(&lock_frame);
  	while (true) 
  	{
  		frame_clock_advance();

  		struct pagesup_entry *pse = list_entry(clock_hand, struct pagesup_entry, frame_elem);
  		
  		if (lock_try_acquire(&pse->lock))
  		{
  			uint32_t *pd = pse->owner->pagedir;
  			if (!pagedir_is_accessed(pd, pse->upage))
  			{
  				kpage = pse->kpage;
  				frame_evict(pse);
  				lock_release(&pse->lock);
  				break;
  			}
  			else {
  				pagedir_set_accessed (pd, pse->upage, false);
  			}

  			lock_release(&pse->lock);
  		}
  	}

  	lock_release(&lock_frame);
  }
  return kpage;
}

void
frame_install(struct pagesup_entry *pse, void *kpage)
{
	pse->kpage = kpage;
	lock_acquire(&lock_frame);
	list_push_back(&frame_list,&pse->frame_elem);
	lock_release(&lock_frame);
}

void 
frame_remove(struct pagesup_entry *pse)
{
	lock_acquire(&lock_frame);

	if (pse->kpage != NULL) {
		list_remove(&pse->frame_elem);
		palloc_free_page (pse->kpage);
	}
	pse->kpage = NULL;

	lock_release(&lock_frame);
}

void
frame_clock_advance(void)
{
	struct list_elem *elem = list_next(clock_hand);
	if (elem == NULL || elem == list_end(&frame_list))
		clock_hand = list_begin(&frame_list);
	else
		clock_hand = elem; 
}

/* Assumes caller has lock for PSE */
void
frame_evict(struct pagesup_entry *pse)
{
	void *buff_to_write = pse->kpage;
	pse->kpage = NULL;
	uint32_t *pd = pse->owner->pagedir;

	bool dirty = pagedir_is_dirty (pd, pse->upage);
	pagedir_clear_page (pd, pse->upage);

	off_t swap_slot;
	switch (pse->ptype)
	{
		case ptype_segment_readonly:
			return;
		case ptype_file:
			break;
  	case ptype_stack:
  	case ptype_segment:
  		swap_slot = swap_get_slot();
			if (swap_slot < 0)
				PANIC("swap full.");
			pse->file = swap_file;
			pse->offset = swap_slot;
			break;
		default:
			break;
	}
	
	if (dirty)
	{
		off_t bytes_written = file_write_at (pse->file, buff_to_write, (off_t) pse->valid_bytes, pse->offset);
		ASSERT(bytes_written == pse->valid_bytes);
	}
}
