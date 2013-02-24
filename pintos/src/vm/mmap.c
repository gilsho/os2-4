#include "mmap.h"
#include <debug.h>
#include <hash.h>
#include "threads/malloc.h"
#include "threads/vaddr.h"

/* reserve all pages for a mmap file up front 
   using user-specified address,
   set to not-present, 
   load lazily */
 
bool mmap_cmp(const struct hash_elem *a,
              const struct hash_elem *b,
              void *aux);

void mmap_free(mmap_table *mmt, mapid_t mid);
struct mmap_entry *mmap_find_entry(mmap_table *mmt, mapid_t mid);
unsigned mmap_hash(const struct hash_elem *e, void *aux UNUSED);
void mmap_destroy(mmap_table *mmt UNUSED);


void 
mmap_init(mmap_table *mmt)
{
	hash_init(mmt, &mmap_hash, &mmap_cmp, NULL);
}


void 
mmap_free(mmap_table *mmt, mapid_t mid)
{
	struct mmap_entry *mme = mmap_get_entry(mmt, mid);
	ASSERT (mme != NULL);
	hash_delete(mmt, &mme->elem);
	free(mme);
}


struct mmap_entry *
mmap_get_entry(mmap_table *mmt, mapid_t mid)
{
	struct mmap_entry temp;
	temp.mid = mid;
	
	struct hash_elem *he = hash_find(mmt, &temp.elem);
	
	if (he == NULL)
	  return NULL;
	
	return hash_entry(he, struct mmap_entry,elem);
}

bool 
mmap_cmp(const struct hash_elem *a,
         const struct hash_elem *b,
         void *aux UNUSED)
{
	struct mmap_entry *mme_a = hash_entry(a, struct mmap_entry,elem);
	struct mmap_entry *mme_b = hash_entry(b, struct mmap_entry,elem);
	return mme_a->mid < mme_b->mid;
}

unsigned 
mmap_hash(const struct hash_elem *e, void *aux UNUSED)
{
	struct mmap_entry *mme = hash_entry(e, struct mmap_entry,elem);
	return hash_int((int) mme->mid);
}

void
mmap_destroy(mmap_table *mmt UNUSED){

}


void mmap_install_file(mmap_table *mmt, mapid_t mid, void *upage, struct file *file, uint32_t file_len)
{
	/* check if upage already mapped in table */
	struct mmap_entry *mme = NULL;
	
	mme = malloc(sizeof(struct mmap_entry));
	if (mme == NULL)
	  PANIC("unable to allocate mme in mmap_install_file.\n");
	  
	mme->mid = mid;
	mme->upage = upage;						/* start page */
	mme->file = file;			/* file handler */
	mme->file_len = file_len;						/* byte-size of file */
	
	struct hash_elem *he = hash_insert(mmt, &mme->elem);
	if (he != NULL)
	  PANIC("mme already in mmap_table.\n");
}

