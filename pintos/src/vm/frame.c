#include "vm/frame.h"
#include "vm/pagesup.h"
#include "threads/synch.h"
#include "threads/palloc.h"
#include "userprog/pagedir.h"
#include "vm/swap.h"
#include "threads/vaddr.h"
#include <stdio.h>
#include <string.h>

/*
#if (DEBUG & DEBUG_FRAME)
#define PRINT_FRAME(X) {printf("frame_list: "); printf(X);}
#define PRINT_FRAME_2(X,Y) {printf("frame_list: "); printf(X,Y);}
#else
#define PRINT_FRAME(X) do {} while(0)
#define PRINT_FRAME_2(X,Y) do {} while(0)
#endif
*/

#define PRINT_FRAME(X) do {} while(0)
#define PRINT_FRAME_2(X,Y) do {} while(0)

extern struct lock lock_filesys;

struct lock lock_frame;
static struct list frame_list;
struct list_elem *clock_hand;

void frame_clock_advance(void);
void frame_swap_out(struct pagesup_entry *pse, void *buff);

void 
frame_init_table() 
{
	lock_init(&lock_frame);
	list_init(&frame_list);
	clock_hand = list_head(&frame_list);
}

void *
frame_alloc(void)
{	
	void *kpage = palloc_get_page(PAL_USER | PAL_ZERO);
  if (kpage == NULL) 
  {
  	/* CLOCK ALGORITHM */
  	/*lock_acquire(&lock_frame);*/
  	while (true) 
  	{
  		frame_clock_advance();

  		struct pagesup_entry *pse = list_entry(clock_hand, struct pagesup_entry, frame_elem);
  		
  		if (lock_try_acquire(&pse->lock))
  		{
  			uint32_t *pd = pse->owner->pagedir;
  			if (!pagedir_is_accessed(pd, pse->upage) )
  			{
  				PRINT_FRAME("found pse to evict\n");
  				PRINT_FRAME_2("upage: %p\n", pse->upage);
  				PRINT_FRAME_2("kpage: %p\n", pse->kpage);
  				kpage = pse->kpage;
  				frame_evict(pse);
  				lock_release(&pse->lock);
  				break;
  			}
  			else {
  				pagedir_set_accessed (pd, pse->upage, false);
  				/*
  				PRINT_FRAME("clearing pse access bit\n");
  				PRINT_FRAME_2("upage: %p\n", pse->upage);
  				PRINT_FRAME_2("kpage: %p\n", pse->kpage);
  				*/
  			}

  			lock_release(&pse->lock);
  		}
  	}

  	/*lock_release(&lock_frame);*/
  }
  memset(kpage, 0, PGSIZE);
  return kpage;
}

/* assumes caller has the lock_frame */
void
frame_install(struct pagesup_entry *pse, void *kpage)
{
	PRINT_FRAME_2("installing PSE @ kpage: %p\n", kpage);
	pse->kpage = kpage;
	/*lock_acquire(&lock_frame);*/
	list_push_back(&frame_list,&pse->frame_elem);
	/*lock_release(&lock_frame);*/
}

void 
frame_release(struct pagesup_entry *pse)
{
	/*lock_acquire(&lock_frame);*/

	PRINT_FRAME_2("frame_release upage: %p\n", pse->upage);

	if (pse->ploc == ploc_memory) {
		PRINT_FRAME_2("frame_release kpage: %p\n", pse->kpage);
		list_remove(&pse->frame_elem);
		/* assume pagedir_destroy will free the physical pages */
		/*palloc_free_page (pse->kpage);*/
		pse->kpage = NULL;
	}
	else if (pse->ploc == ploc_swap)
	{
		PRINT_FRAME_2("frame_release swap slot: %p\n", pse->info.s.slot_index);
		swap_release_slot((size_t) pse->info.s.slot_index);
	}	
	/*lock_release(&lock_frame);*/
}

/* caller must have frame lock */
void
frame_clock_advance(void)
{
	ASSERT(lock_held_by_current_thread(&lock_frame));
	struct list_elem *elem = list_next(clock_hand);
	if (elem == list_end(&frame_list))
		clock_hand = list_head(&frame_list);
	else
		clock_hand = elem; 
}

/* Assumes caller has lock for PSE */
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

void
frame_swap_out(struct pagesup_entry *pse, void *buff)
{
	pse->info.s.slot_index = swap_write_slot(buff);
	PRINT_FRAME("writing to swap file\n");
	PRINT_FRAME_2("slot: %d\n", (int)pse->info.s.slot_index);
	PRINT_FRAME_2("upage: %p\n", pse->upage);
}
