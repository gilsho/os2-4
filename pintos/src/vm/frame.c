#include "vm/frame.h"
#include "userprog/pagedir.h"
#include "threads/synch.h"
#include "threads/malloc.h"
#include <hash.h>
#include <stdio.h>

static struct hash frame_table;

unsigned frame_hash(const struct hash_elem *e, void *aux UNUSED);
bool frame_cmp(const struct hash_elem *a,
            						const struct hash_elem *b,
                    		void *aux UNUSED);

void 
frame_init_table() 
{
	hash_init(&frame_table, &frame_hash, &frame_cmp, NULL);
}

bool 
frame_cmp(const struct hash_elem *a,
            						const struct hash_elem *b,
                    		void *aux UNUSED)
{
	struct frame_entry *fte_a = hash_entry(a, struct frame_entry,elem);
	struct frame_entry *fte_b = hash_entry(b, struct frame_entry,elem);
	return fte_a->kpage < fte_b->kpage;
}

unsigned 
frame_hash(const struct hash_elem *e, void *aux UNUSED)
{
	struct frame_entry *fte = hash_entry(e, struct frame_entry,elem);
	return hash_int((int) fte->kpage);
}


void
frame_insert(struct thread *t, uint8_t *upage,uint8_t *kpage)
{
	struct frame_entry *fte = malloc(sizeof(struct frame_entry));
	ASSERT (fte != NULL);
  
  fte->kpage = kpage;
  fte->owner = t;
  fte->upage = upage;

	hash_insert(&frame_table,&(fte->elem));
}

void 
frame_remove(struct frame_entry *fte)
{
	/*list_remove(&fte->elem);*/
	
	free(fte);
	fte = NULL;
}



