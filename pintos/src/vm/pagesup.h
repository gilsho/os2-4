#ifndef VM_PAGE_H
#define VM_PAGE_H

#include "filesys/off_t.h"
#include "vm/frame.h"
#include <hash.h>


struct pagesup_entry 
{
	void *upage;
	off_t swap_offset;
	struct frame_entry *fte;
	struct hash_elem elem;
};

void page_supplement_init(struct hash *pagesup_table);
void page_supplement_set(struct hash *pagesup_table, uint8_t *upage, struct frame_entry *fte);
struct frame_entry *page_supplement_get_frame(struct hash *pagesup_table, uint8_t *upage);
void page_supplement_free(struct hash *pagesup_table, uint8_t *upage);

#endif /* vm/page.h */
