#ifndef VM_FRAME_H
#define VM_FRAME_H


#include <inttypes.h>
#include <hash.h>
#include "vm/pagesup.h"
#include "threads/thread.h"

struct frame_entry 
{
	uint8_t *kpage;
	struct thread *owner;
	void *upage;
	struct hash_elem elem;
};

void frame_init_table(void);
void frame_insert(struct thread *t, uint8_t *upage,uint8_t *kpage);
void frame_remove(struct frame_entry *fte);



#endif /* vm/frame.h */
