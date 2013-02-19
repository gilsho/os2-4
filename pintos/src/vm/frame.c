#include "vm/frame.h"
#include "userprog/pagedir.h"
#include "threads/synch.h"
#include "threads/malloc.h"
#include <list.h>

static struct list frame_table;
static struct lock lock_frame;

void 
frame_init_table() 
{
	lock_init(&lock_frame);
	list_init(&frame_table);
}


struct frame_entry *
frame_insert(uint8_t *kpage,uint32_t *pagedir, uint8_t *upage) 
{
	struct frame_entry *fte = NULL;
	fte = malloc(sizeof(struct frame_entry));
	
	if (fte == NULL)
	  return fte;
	
  fte->kpage = kpage;
  fte->pagedir = pagedir;
  fte->upage = upage;

	lock_acquire(&lock_frame);
	list_push_back(&frame_table,&fte->elem);
	lock_release(&lock_frame);

	return fte;
}

void 
frame_remove(struct frame_entry *fte)
{
  lock_acquire(&lock_frame);
	list_remove(&fte->elem);
	lock_release(&lock_frame);
	
	free(fte);
	fte = NULL;
}



