
#include <debug.h>
#include <stdio.h>
#include "vm/pagesup.h"
#include "vm/frame.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "threads/thread.h"



#if (DEBUG & DEBUG_IS_MAPPED)
#define PRINT_IS_MAPPED_2(X,Y) {printf("page_supplement_is_mapped: "); printf(X,Y);}
#else
#define PRINT_IS_MAPPED_2(X,Y) do {} while(0)
#endif

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


/* MUST be called before upage is set to NULL */
void 
page_supplement_free(pagesup_table *pst, struct pagesup_entry *pse)
{
	ASSERT (pse != NULL);
	hash_delete(pst, &pse->pagesup_elem);
	free(pse);
}


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

bool 
page_supplement_is_mapped(pagesup_table *pst, void *uaddr)
{
	void *upage = pg_round_down(uaddr);
	struct pagesup_entry *pse = page_supplement_get_entry(pst,upage);
	return (pse != NULL);
}

bool 
page_supplement_is_writable(struct pagesup_entry *pse)
{
	return (pse->ptype != ptype_segment_readonly);
}

bool 
page_supplement_cmp(const struct hash_elem *a,
            						const struct hash_elem *b,
                    		void *aux UNUSED)
{
	struct pagesup_entry *pse_a = hash_entry(a, struct pagesup_entry, pagesup_elem);
	struct pagesup_entry *pse_b = hash_entry(b, struct pagesup_entry, pagesup_elem);
	return pse_a->upage < pse_b->upage;
}

unsigned 
page_supplement_hash(const struct hash_elem *e, void *aux UNUSED)
{
	struct pagesup_entry *pse = hash_entry(e, struct pagesup_entry, pagesup_elem);
	return hash_int((int) pse->upage);
}

void
page_supplement_destroy(pagesup_table *pst, pse_destroy_func *func)
{
	pst->aux = func;
	hash_destroy (pst, &destroy_helper); 
}

void
destroy_helper (struct hash_elem *e, void *aux)
{
	struct pagesup_entry *pse = hash_entry(e, struct pagesup_entry, pagesup_elem);
	
	pse_destroy_func *frame_release_handle = (pse_destroy_func *)aux;
	frame_release_handle(pse);
	pse->ploc = ploc_none;
}


