#include "vm/frame.h"
#include "vm/pagesup.h"
#include "threads/synch.h"
#include "threads/palloc.h"
#include <stdio.h>

static struct list frame_list;
struct lock lock_frame;
struct list_elem *clock_hand;

void 
frame_init_table() 
{
	lock_init(&lock_frame);
	list_init(&frame_list);
}

void *
frame_alloc(void)
{	
	void *kpage = palloc_get_page(PAL_USER | PAL_ZERO);
  if (kpage == NULL) 
  {
  	PANIC("eviction not implemented");

  	lock_acquire(&lock_frame);

  	lock_release(&lock_frame);
  }
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

