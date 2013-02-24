#ifndef VM_PAGE_H
#define VM_PAGE_H

#include "filesys/off_t.h"
#include <hash.h>
#include "threads/synch.h"

typedef struct hash pagesup_table;

enum page_type 
{
  ptype_stack,
  ptype_segment,
  ptype_segment_readonly,
  ptype_file
};

struct pagesup_entry 
{
	void *upage; 	/* used to generate hash */
	void *kpage;
	struct file *file;
	off_t offset;
	int valid_bytes;
	enum page_type ptype;
	struct thread *owner;
	struct lock lock;
	struct hash_elem pagesup_elem;
	struct list_elem frame_elem;
};

void page_supplement_init(pagesup_table *pst);

bool page_supplement_is_mapped(pagesup_table *pst, void *uaddr);

struct pagesup_entry *page_supplement_get_entry(pagesup_table *pst, void *upage);

void page_supplement_install_filepage(pagesup_table *pst, void *upage,int valid_bytes, struct file *file,
																		 off_t offset);

void page_supplement_install_segpage(pagesup_table *pst, void *upage,int valid_bytes, struct file *file,
																		 off_t offset, bool writable);

void page_supplement_install_stackpage(pagesup_table *pst, uint8_t *upage);

bool page_supplement_is_writable(struct pagesup_entry *pse);

void page_supplement_free(pagesup_table *pst, struct pagesup_entry *pse);

void page_supplement_destroy(pagesup_table *pst);

#endif /* vm/page.h */
