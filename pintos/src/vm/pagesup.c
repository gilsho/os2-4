
#include <debug.h>
#include "vm/pagesup.h"
#include "vm/frame.h"
#include <hash.h>
#include "threads/malloc.h"
#include "threads/vaddr.h"


bool page_supplement_cmp(const struct hash_elem *a,
            						const struct hash_elem *b,
                    		void *aux);

unsigned  page_supplement_hash(const struct hash_elem *e, void *aux UNUSED);
struct pagesup_entry *page_supplement_find_entry(struct hash *pagesup_table,void *upage);


void 
page_supplement_init(struct hash *pagesup_table)
{
	hash_init(pagesup_table,&page_supplement_hash,&page_supplement_cmp,NULL);
}

void 
page_supplement_set(struct hash *pagesup_table, uint8_t *upage, struct frame_entry *fte)
{
	/* check if page already exists in table? */
	struct pagesup_entry *pse = malloc(sizeof(struct pagesup_entry));
	pse->swap_offset = -1;
	pse->upage = upage;
	pse->fte = fte;
	hash_insert(pagesup_table,&pse->elem);	
}

struct frame_entry *
page_supplement_get_frame(struct hash *pagesup_table, uint8_t *upage)
{
	ASSERT (pg_ofs (upage) == 0);
	struct pagesup_entry *pse = page_supplement_find_entry(pagesup_table,upage);
	if (pse == NULL)
		return NULL;
	return pse->fte;
}

void 
page_supplement_free(struct hash *pagesup_table, uint8_t *upage)
{
	ASSERT (pg_ofs (upage) == 0);
	struct pagesup_entry *pse = page_supplement_find_entry(pagesup_table,upage);
	ASSERT (pse != NULL);
	hash_delete(pagesup_table,&pse->elem);
	free(pse);

}

struct pagesup_entry *
page_supplement_find_entry(struct hash *pagesup_table,void *upage)
{
	ASSERT (pg_ofs (upage) == 0);
	struct pagesup_entry temp;
	temp.upage = upage;
	return hash_entry(hash_find(pagesup_table,&temp.elem),struct pagesup_entry,elem);
}

bool 
page_supplement_cmp(const struct hash_elem *a,
            						const struct hash_elem *b,
                    		void *aux UNUSED)
{
	struct pagesup_entry *pse_a = hash_entry(a,struct pagesup_entry,elem);
	struct pagesup_entry *pse_b = hash_entry(b,struct pagesup_entry,elem);
	return pse_a->upage < pse_b->upage;
}

unsigned 
page_supplement_hash(const struct hash_elem *e, void *aux UNUSED)
{
	struct pagesup_entry *pse = hash_entry(e,struct pagesup_entry,elem);
	return hash_int((int) pse->upage);
}

void
page_supplement_destroy(struct hash *pagesup_table UNUSED){

}









