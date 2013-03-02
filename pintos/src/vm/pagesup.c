
#include <debug.h>
#include <stdio.h>
#include "vm/pagesup.h"
#include "vm/frame.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "threads/thread.h"

bool page_supplement_cmp(const struct hash_elem *a,
            						const struct hash_elem *b,
                    		void *aux);

unsigned page_supplement_hash(const struct hash_elem *e, void *aux UNUSED);
void destroy_helper (struct hash_elem *e, void *aux);


void 
page_supplement_init(pagesup_table *pst)
{
	hash_init(pst, &page_supplement_hash, &page_supplement_cmp, NULL);
}

/*
	########################################################################

	The three functions below all handle installation of virtual address pages
	into the supplementary page table. The three functions handle the installation
	of memory mapped file pages, stack pages, and data/code segment pages respectively.

	Althogh these three functions share a lot of similarity and indeed use some of the 
	same code, we decided that it was worthwhile to split them up into three separate 
	functions, since it made for more readable code, and more importantly, allowed
	us to better handle the subtle differences in how different types of pages are
	handled in memory.

	########################################################################
*/


/*
	Installs a memory mapped file page into the supplementary page table.
*/
void page_supplement_install_filepage(pagesup_table *pst, void *upage,int valid_bytes, struct file *file,
																		 off_t offset)
{
	struct pagesup_entry *pse = malloc(sizeof(struct pagesup_entry));
	ASSERT(pse != NULL);
	pse->upage = upage;
	pse->ptype = ptype_file;
	pse->ploc = ploc_file;
	pse->owner = thread_current();
	pse->valid_bytes = valid_bytes;
	pse->kpage = NULL;
	pse->info.f.file = file;
	pse->info.f.offset = offset;
	lock_init(&pse->lock);
	struct hash_elem *he = hash_insert(pst, &(pse->pagesup_elem));
	ASSERT (he == NULL);
}

/*
	Installs a stack page into the supplementary page table.
*/
void 
page_supplement_install_stackpage(pagesup_table *pst, uint8_t *upage)
{
	struct pagesup_entry *pse = malloc(sizeof(struct pagesup_entry));
	ASSERT(pse != NULL);
	pse->upage = upage;
	pse->ptype = ptype_stack;
	pse->ploc = ploc_none;
	pse->owner = thread_current();
	pse->valid_bytes = PGSIZE;
	pse->kpage = NULL;
	lock_init(&pse->lock);
	struct hash_elem *he = hash_insert(pst, &(pse->pagesup_elem));
	ASSERT (he == NULL)
}

/*
	Installs a code or data segment page into the supplementary page table.
*/
void 
page_supplement_install_segpage(pagesup_table *pst,void *upage,int valid_bytes, struct file *file,
																		 off_t offset, bool writable) {
	struct pagesup_entry *pse = malloc(sizeof(struct pagesup_entry));
	ASSERT(pse != NULL);
	pse->upage = upage;
	pse->ptype = writable ? ptype_segment : ptype_segment_readonly;
	pse->ploc = ploc_file;
	pse->valid_bytes = valid_bytes;
	pse->kpage = NULL;
	pse->owner = thread_current();
	pse->info.f.file = file;
	pse->info.f.offset = offset;
	lock_init(&pse->lock);
	struct hash_elem *he = hash_insert(pst, &(pse->pagesup_elem));
	ASSERT (he == NULL);
}


/* 
	Frees a page entry from the supplementary page table
*/
void 
page_supplement_free(pagesup_table *pst, struct pagesup_entry *pse)
{
	ASSERT (pse != NULL);
	hash_delete(pst, &pse->pagesup_elem);
	free(pse);
}


/*
	Retrieves an entry from the supplementary page table. The key 
	for the hash table is the user virtual address.
*/
struct pagesup_entry *
page_supplement_get_entry(pagesup_table *pst, void *upage)
{
	ASSERT (pg_ofs (upage) == 0);
	struct pagesup_entry temp;
	temp.upage = upage;
	
	struct hash_elem *he = hash_find(pst, &(temp.pagesup_elem));
	
	if (he == NULL)
	  return NULL;
	
	return hash_entry(he, struct pagesup_entry,pagesup_elem);
}

/*
	Checks to see if a given virtual address has been mapped in
	the give supplementary page table. Simply checks to see in the
	page entry exists.
*/

bool 
page_supplement_is_mapped(pagesup_table *pst, void *uaddr)
{
	void *upage = pg_round_down(uaddr);
	struct pagesup_entry *pse = page_supplement_get_entry(pst,upage);
	return (pse != NULL);
}

/* 
	Checks to see if a give page entry is writable.
*/

bool 
page_supplement_is_writable(struct pagesup_entry *pse)
{
	bool writable = (pse->ptype != ptype_segment_readonly);
	return writable;
}

/* 
	Comparator function needed to implement hash table
*/
bool 
page_supplement_cmp(const struct hash_elem *a,
            						const struct hash_elem *b,
                    		void *aux UNUSED)
{
	struct pagesup_entry *pse_a = hash_entry(a, struct pagesup_entry, pagesup_elem);
	struct pagesup_entry *pse_b = hash_entry(b, struct pagesup_entry, pagesup_elem);
	return pse_a->upage < pse_b->upage;
}

/* 
	Hash function needed to implement hash table
*/

unsigned 
page_supplement_hash(const struct hash_elem *e, void *aux UNUSED)
{
	struct pagesup_entry *pse = hash_entry(e, struct pagesup_entry, pagesup_elem);
	return hash_int((int) pse->upage);
}

/*
	Destroys the supplementary page table. Sets an entry destroy function
	as the auxiliary variable on the page table. Destroys the hash table
	while passing in a destroy helper function. 
*/

void
page_supplement_destroy(pagesup_table *pst, pse_destroy_func *func)
{
	pst->aux = func;
	hash_destroy (pst, &destroy_helper); 
}

/*
	Helper function to destroy each entry in the supplementary page table
	We use the auxiliary variable to pass in another function, which releases the 
	page entry from the frame table.
	It is also crucial that we set ploc back to ploc_none
*/
void
destroy_helper (struct hash_elem *e, void *aux)
{
	struct pagesup_entry *pse = hash_entry(e, struct pagesup_entry, pagesup_elem);
	
	pse_destroy_func *frame_release_handle = (pse_destroy_func *)aux;
	frame_release_handle(pse);
	pse->ploc = ploc_none;
}


