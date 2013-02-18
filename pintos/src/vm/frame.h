#ifndef VM_FRAME_H
#define VM_FRAME_H


#include <inttypes.h>
#include <list.h>

struct frame_entry 
{
	uint8_t *kpage;
	uint32_t *pagedir;
	uint8_t *upage;
	struct list_elem elem;
};

void frame_init_table(void);
struct frame_entry *frame_insert(uint8_t *kpage,uint32_t *pagedir, uint8_t *upage);
void frame_remove(struct frame_entry *fte);



#endif /* vm/frame.h */
