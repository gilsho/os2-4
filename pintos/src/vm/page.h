#ifndef VM_PAGE_H
#define VM_PAGE_H

#include "vm/frame.h"

void page_supplement_set(uint32_t *pagedir,uint8_t *upage, struct frame_entry *fte);
struct frame_entry *page_supplement_get_frame(uint32_t *pagedir, uint8_t *upage);
void page_supplement_free(uint32_t *pagedir, uint8_t *upage);


#endif /* vm/page.h */
