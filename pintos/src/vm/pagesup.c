
#include <debug.h>
#include "vm/pagesup.h"
#include "vm/frame.h"
#include <hash.h>
#include "threads/malloc.h"
#include "threads/vaddr.h"


bool page_supplement_cmp(const struct hash_elem *a,
            						const struct hash_elem *b,
                    		void *aux);

unsigned page_supplement_hash(const struct hash_elem *e, void *aux UNUSED);
struct pagesup_entry *page_supplement_find_entry(pagesup_table *pst, void *upage);


void 
page_supplement_init(pagesup_table *pst)
{
	hash_init(pst, &page_supplement_hash, &page_supplement_cmp, NULL);
}

/* Creates a new mapping in PST for the given UPAGE and FTE. */
/* TODO: return a value? */
void 
page_supplement_set(pagesup_table *pst, uint8_t *upage, struct frame_entry *fte, page_type type)
{
	/* check if page already exists in table */
	struct pagesup_entry *pse = NULL;
	pse = page_supplement_find_entry(pst, upage);
	ASSERT( pse == NULL);	
	
	pse = malloc(sizeof(struct pagesup_entry));
	if (pse == NULL)
	  PANIC("unable to allocate pse in page_supplement_set.\n");
	  
	pse->swap_offset = -1;
	pse->upage = upage;
	pse->fte = fte;
	
	struct hash_elem *he = hash_insert(pst, &pse->elem);
	if (he != NULL)
	  PANIC("pse already in pagesup_table.\n");
}

/* Returns the FTE associated with the give UPAGE in the 
   supplementary page table PST, or NULL if none exists.*/
struct frame_entry *
page_supplement_get_frame(pagesup_table *pst, uint8_t *upage)
{
	ASSERT (pg_ofs (upage) == 0);
	struct pagesup_entry *pse = page_supplement_find_entry(pst, upage);
	if (pse == NULL)
		return NULL;
	return pse->fte;
}

/* MUST be called before upage is freed */
void 
page_supplement_free(pagesup_table *pst, uint8_t *upage)
{
	ASSERT (pg_ofs (upage) == 0);
	struct pagesup_entry *pse = page_supplement_find_entry(pst, upage);
	ASSERT (pse != NULL);
	hash_delete(pst, &pse->elem);
	free(pse);
}


struct pagesup_entry *
page_supplement_find_entry(pagesup_table *pst, void *upage)
{
	ASSERT (pg_ofs (upage) == 0);
	struct pagesup_entry temp;
	temp.upage = upage;
	
	struct hash_elem *he = hash_find(pst, &temp.elem);
	
	if (he == NULL)
	  return NULL;
	
	return hash_entry(he, struct pagesup_entry,elem);
}

bool 
page_supplement_cmp(const struct hash_elem *a,
            						const struct hash_elem *b,
                    		void *aux UNUSED)
{
	struct pagesup_entry *pse_a = hash_entry(a, struct pagesup_entry,elem);
	struct pagesup_entry *pse_b = hash_entry(b, struct pagesup_entry,elem);
	return pse_a->upage < pse_b->upage;
}

unsigned 
page_supplement_hash(const struct hash_elem *e, void *aux UNUSED)
{
	struct pagesup_entry *pse = hash_entry(e, struct pagesup_entry,elem);
	return hash_int((int) pse->upage);
}

void
page_supplement_destroy(pagesup_table *pst UNUSED){

}









