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

enum page_location
{
	ploc_none,
	ploc_memory,
	ploc_file,
	ploc_swap
};

struct file_info
{
	struct file *file;
	off_t offset;
};

struct swap_info
{
	size_t slot_index;
};

union pagesup_info {
	struct file_info f;
	struct swap_info s;	
};

struct pagesup_entry 
{
	void *upage; 	/* used to generate hash */
	void *kpage;
	int valid_bytes;
	enum page_type ptype;
	enum page_location ploc;
	struct thread *owner;
	struct lock lock;
	struct hash_elem pagesup_elem;
	struct list_elem frame_elem;
	union pagesup_info info;
};

typedef void pse_destroy_func (struct pagesup_entry *pse);

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

void page_supplement_destroy(pagesup_table *pst, pse_destroy_func *func);

#endif /* vm/page.h */
