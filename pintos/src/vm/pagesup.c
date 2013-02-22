
#include <debug.h>
#include "vm/pagesup.h"
#include <hash.h>
#include "threads/malloc.h"
#include "threads/vaddr.h"


#if (DEBUG & DEBUG_IS_MAPPED)
#define PRINT_IS_MAPPED_2(X,Y) {printf("page_supplement_is_mapped: "); printf(X,Y);}
#else
#define PRINT_IS_MAPPED_2(X,Y) do {} while(0)
#endif

bool page_supplement_cmp(const struct hash_elem *a,
            						const struct hash_elem *b,
                    		void *aux);

unsigned page_supplement_hash(const struct hash_elem *e, void *aux UNUSED);


void 
page_supplement_init(pagesup_table *pst)
{
	hash_init(pst, &page_supplement_hash, &page_supplement_cmp, NULL);
}

void page_supplement_install_stackpage(pagesup_table *pst, uint8_t *upage)
{
	struct pagesup_entry *pse = malloc(sizeof(struct pagesup_entry));
	ASSERT(pse != NULL);
	pse->upage = upage;
	pse->file = NULL;
	pse->offset = -1;
	pse->valid_bytes = PGSIZE;
	pse->kpage = NULL;
	pse->ptype = ptype_stack;
	struct hash_elem *he = hash_insert(pst, &(pse->elem));
	ASSERT (he == NULL)
}

void page_supplement_install_segpage(pagesup_table *pst,void *upage,int valid_bytes, struct file *file,
																		 off_t offset, bool writable) {
	struct pagesup_entry *pse = malloc(sizeof(struct pagesup_entry));
	ASSERT(pse != NULL);
	pse->upage = upage;
	pse->file = file;
	pse->offset = offset;
	pse->valid_bytes = valid_bytes;
	pse->kpage = NULL;
	pse->ptype = writable ? ptype_segment : ptype_segment_readonly;
	struct hash_elem *he = hash_insert(pst, &(pse->elem));
	ASSERT (he == NULL);
}
/*
bool
page_supplement_install_memfile(pagesup_table *pst, uint8_t *upage, struct file *file, 
															 off_t offset, int valid_bytes, bool writable)
{
	/* check if page already exists in table *
	struct pagesup_entry *pse = NULL;
	pse = page_supplement_get_entry(pst, upage);
	if(pse != NULL)
		return false;
	
	pse = malloc(sizeof(struct pagesup_entry));
	if (pse == NULL)
	  PANIC("unable to allocate pse in page_supplement_set.\n");

	pse->file = file;
	pse->offset = offset;
	pse->valid_bytes = valid_bytes;
	pse->upage = upage;
	pse->kpage = NULL;
	pse->ptype = ptype_file;

	struct hash_elem *he = hash_insert(pst, &pse->elem);
	ASSERT (he != NULL)
	return true;

}


bool
page_supplement_install_mempage(pagesup_table *pst, uint8_t *upage, bool writable)
{
	/* check if page already exists in table *
	struct pagesup_entry *pse = NULL;
	pse = page_supplement_get_entry(pst, upage);
	if (pse != NULL)
		return false;
	
	pse = malloc(sizeof(struct pagesup_entry));
	if (pse == NULL)
	  PANIC("unable to allocate pse in page_supplement_set.\n");
	  
	pse->file = NULL;
	pse->offset = -1;
	pse->upage = upage;
	pse->kpage = NULL;
	pse->ptype = ptype_memory;
	
	struct hash_elem *he = hash_insert(pst, &pse->elem);
	ASSERT (he != NULL)
	return true;
}

/*
void page_supplement_set_frame(pagesup_table *pst, uint8_t *upage, struct frame_entry *fte)
{
	struct pagesup_entry *pse = page_supplement_get_entry(pst, upage);
	ASSERT( pse != NULL);		
	pse->fte = fte;
}

/* Returns the FTE associated with the give UPAGE in the 
   supplementary page table PST, or NULL if none exists.*
struct frame_entry *
page_supplement_get_frame(pagesup_table *pst, uint8_t *upage)
{
	ASSERT (pg_ofs (upage) == 0);
	struct pagesup_entry *pse = page_supplement_get_entry(pst, upage);
	if (pse == NULL)
		return NULL;
	return pse->fte;
}
*/

/* MUST be called before upage is freed */
void 
page_supplement_free(pagesup_table *pst, uint8_t *upage)
{
	ASSERT (pg_ofs (upage) == 0);
	struct pagesup_entry *pse = page_supplement_get_entry(pst, upage);
	ASSERT (pse != NULL);
	hash_delete(pst, &pse->elem);
	free(pse);
}


struct pagesup_entry *
page_supplement_get_entry(pagesup_table *pst, void *upage)
{
	ASSERT (pg_ofs (upage) == 0);
	struct pagesup_entry temp;
	temp.upage = upage;
	
	struct hash_elem *he = hash_find(pst, &temp.elem);
	
	if (he == NULL)
	  return NULL;
	
	return hash_entry(he, struct pagesup_entry,elem);
}

bool page_supplement_is_mapped(pagesup_table *pst, void *uaddr)
{
	void *upage = pg_round_down(uaddr);
	struct pagesup_entry *pse = page_supplement_get_entry(pst,upage);
	PRINT_IS_MAPPED_2("pg_round_down(uaddr): %p, ",upage);
	PRINT_IS_MAPPED_2("pse: %p\n",pse);
	return (pse != NULL);
}

/*
bool 
page_supplement_is_installed(pagesup_table *pst, void *upage)
{
	return (page_supplement_find_entry(pst,upage) != NULL);
}

enum ptype
page_supplement_get_ptype(pagesup_entry *pst, void *upage)
{
	struct pagesup_entry *pse = page_supplement_find_entry(pst,upage);
	ASSERT (pse == NULL);
	return pse->ptype;
}

struct file*
page_supplement_get_file(pagesup_entry *pst, void *upage)
{
	struct pagesup_entry *pse = page_supplement_find_entry(pst,upage);
	ASSERT (pse == NULL);
	return pse->file;
}

struct file*
page_supplement_get_file(pagesup_entry *pst, void *upage)
{
	struct pagesup_entry *pse = page_supplement_find_entry(pst,upage);
	ASSERT (pse == NULL);
	return pse->file;
}
*/


bool page_supplement_is_writable(struct pagesup_entry *pse)
{
	return (pse->ptype != ptype_segment_readonly);
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









