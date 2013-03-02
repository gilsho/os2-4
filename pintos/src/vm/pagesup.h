#ifndef VM_PAGE_H
#define VM_PAGE_H

#include "filesys/off_t.h"
#include <hash.h>
#include "threads/synch.h"

typedef struct hash pagesup_table;

/* Type of page */
enum page_type 
{
  ptype_stack,
  ptype_segment,
  ptype_segment_readonly,
  ptype_file
};

/* Current location of page */
enum page_location
{
	ploc_none,
	ploc_memory,
	ploc_file,
	ploc_swap
};

/* Relevant information for memory mapped file pages */
struct file_info
{
	struct file *file;
	off_t offset;
};

/* Information for files stored in swap */
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
	void *kpage;    /* Physical address (if any) of page */
	int valid_bytes; /* Number of valid bytes on this page */
	enum page_type ptype; /* Type of page */
	enum page_location ploc; /* Current location of page */
	struct thread *owner; /* Owner of this page */
	struct lock lock; 
	struct hash_elem pagesup_elem;
	struct list_elem frame_elem;
	union pagesup_info info;
};

typedef void pse_destroy_func (struct pagesup_entry *pse);

void page_supplement_init(pagesup_table *pst);

/* Checks to see if a given virtual address has been mapped in the give supplementary page table. */
bool page_supplement_is_mapped(pagesup_table *pst, void *uaddr);

/* Retrieves an entry from the supplementary page table. */
struct pagesup_entry *page_supplement_get_entry(pagesup_table *pst, void *upage);


/* Installs a memory mapped file page into the supplementary page table. */
void page_supplement_install_filepage(pagesup_table *pst, void *upage,int valid_bytes, struct file *file,
																		 off_t offset);

/* Installs a code or data segment page into the supplementary page table. */
void page_supplement_install_segpage(pagesup_table *pst, void *upage,int valid_bytes, struct file *file,
																		 off_t offset, bool writable);

/* Installs a stack page into the supplementary page table. */
void page_supplement_install_stackpage(pagesup_table *pst, uint8_t *upage);

/* Checks to see if a give page entry is writable. */
bool page_supplement_is_writable(struct pagesup_entry *pse);

/* Frees a page entry from the supplementary page table */
void page_supplement_free(pagesup_table *pst, struct pagesup_entry *pse);

/* Destroys the supplementary page table. Destroys the hash table while passing in a destroy helper function. */
void page_supplement_destroy(pagesup_table *pst, pse_destroy_func *func);

#endif /* vm/page.h */
