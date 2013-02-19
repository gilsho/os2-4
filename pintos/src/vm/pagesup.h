#ifndef VM_PAGE_H
#define VM_PAGE_H

#include "filesys/off_t.h"
#include "vm/frame.h"
#include <hash.h>

typedef struct hash pagesup_table;

enum page_type 
{
  ptype_memory,
  ptype_file
};

struct pagesup_entry 
{
  
	void *upage;
	struct file *file;
	off_t offset;
	int valid_bytes;
	struct frame_entry *fte;
	struct hash_elem elem;
};

void page_supplement_init(pagesup_table *pst);
void page_supplement_set(pagesup_table *pst, uint8_t *upage, struct frame_entry *fte);
struct frame_entry *page_supplement_get_frame(pagesup_table *pst, uint8_t *upage);
void page_supplement_free(pagesup_table *pst, uint8_t *upage);

void page_supplement_destroy(pagesup_table *pst);

#endif /* vm/page.h */
